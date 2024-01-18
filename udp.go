package ipproxy

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
	"github.com/miekg/dns"
)

const maxUDPPacketSize = 64 << 10

var udpBufPool = &sync.Pool{
	New: func() any {
		b := make([]byte, maxUDPPacketSize)
		return &b
	},
}

func ipPortOfNetstackAddr(a tcpip.Address, port uint16) (ipp netip.AddrPort, ok bool) {
	if addr, ok := netip.AddrFromSlice(a.AsSlice()); ok {
		return netip.AddrPortFrom(addr, port), true
	}
	return netip.AddrPort{}, false
}

func (p *proxy) onUDP(r *udp.ForwarderRequest) {
	sess := r.ID()
	log.Debugf("UDP ForwarderRequest: %v", stringifyTEI(sess))
	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		log.Errorf("onUDP: could not create endpoint: %v", err)
		return
	}
	dstAddr, ok := ipPortOfNetstackAddr(sess.LocalAddress, sess.LocalPort)
	if !ok {
		ep.Close()
		return
	}
	srcAddr, ok := ipPortOfNetstackAddr(sess.RemoteAddress, sess.RemotePort)
	if !ok {
		ep.Close()
		return
	}

	if dstAddr.Port() == 53 {
		log.Debugf("dns request. addr is %s", dstAddr.Addr().String())
	}

	c := gonet.NewUDPConn(&wq, ep)
	go p.forwardUDP(c, srcAddr, dstAddr)

	/*ft := pkt.ft()
	conn := p.udpConns[ft]
	if conn == nil {
		var err error
		conn, err = p.startUDPConn(ft)
		if err != nil {
			log.Error(err)
			return
		}
		p.udpConns[ft] = conn
		p.addUDPConn()
	}
	inboundPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(pkt.raw),
	})
	defer inboundPkt.DecRef()
	conn.channelEndpoint.InjectInbound(ipv4.ProtocolNumber, inboundPkt)*/
}

func translateDNSQuestion(addr *net.UDPAddr, dnsMsg *dns.Msg) (string, error) {
	var atype string
	qtype := dnsMsg.Question[0].Qtype
	switch qtype {
	case dns.TypeA:
		atype = "A"
	case dns.TypeAAAA:
		atype = "AAAA"
	case dns.TypeNS:
		atype = "NS"
	default:
		str := fmt.Sprintf("%s: invalid qtype: %d", addr, dnsMsg.Question[0].Qtype)
		log.Debug(str)
		return "", fmt.Errorf("%s", str)
	}
	return atype, nil
}

func (p *proxy) handleDNSUDP(srcAddr netip.AddrPort, c *gonet.UDPConn) {
	const readDeadline = 150 * time.Millisecond

	defer c.Close()

	bufp := udpBufPool.Get().(*[]byte)
	defer udpBufPool.Put(bufp)
	q := *bufp

	for {
		c.SetReadDeadline(time.Now().Add(readDeadline))
		n, _, err := c.ReadFrom(q)
		if err != nil {
			if oe, ok := err.(*net.OpError); !(ok && oe.Timeout()) {
				log.Errorf("dns udp read: %v", err) // log non-timeout errors
			}
			return
		}

		raddr, err := net.ResolveUDPAddr("udp", "8.8.8.8:53")
		if err != nil {
			log.Error(err)
			return
		}

		upstream, err := net.DialUDP("udp", nil, raddr)
		if err != nil {
			log.Error(err)
			return
		}
		_, err = upstream.Write(q[:n])
		if err != nil {
			log.Error(err)
			return
		}

		ret := make([]byte, 4096)
		_, _, err = upstream.ReadFromUDP(ret)
		if err != nil {
			log.Error(err)
			return
		}
		c.Write(ret)
	}
}

func (p *proxy) forwardUDP(client *gonet.UDPConn, clientAddr, dstAddr netip.AddrPort) {
	port, srcPort := dstAddr.Port(), clientAddr.Port()
	log.Debugf("forwarding incoming UDP connection on port %v", port)
	var backendListenAddr *net.UDPAddr
	var backendRemoteAddr *net.UDPAddr
	isLocal := isLocalIP( net.IP(dstAddr.Addr().AsSlice()))
	if isLocal {
		backendRemoteAddr = &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: int(port)}
		backendListenAddr = &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: int(srcPort)}
	} else {
		backendRemoteAddr = net.UDPAddrFromAddrPort(dstAddr)
		if dstAddr.Addr().Is4() {
			backendListenAddr = &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: int(srcPort)}
		} else {
			backendListenAddr = &net.UDPAddr{IP: net.ParseIP("::"), Port: int(srcPort)}
		}
	}
	backendConn, err := net.ListenUDP("udp", backendListenAddr)
	if err != nil {
		log.Errorf("netstack: could not bind local port %v: %v, trying again with random port", backendListenAddr.Port, err)
		backendListenAddr.Port = 0
		backendConn, err = net.ListenUDP("udp", backendListenAddr)
		if err != nil {
			log.Errorf("netstack: could not create UDP socket, preventing forwarding to %v: %v", dstAddr, err)
			return
		}
	}
	backendLocalAddr := backendConn.LocalAddr().(*net.UDPAddr)
	backendLocalIPPort := netip.AddrPortFrom(backendListenAddr.AddrPort().Addr().Unmap().WithZone(backendLocalAddr.Zone), backendLocalAddr.AddrPort().Port())
	if !backendLocalIPPort.IsValid() {
		log.Debugf("could not get backend local IP:port from %v:%v", backendLocalAddr.IP, backendLocalAddr.Port)
	}
	ctx, cancel := context.WithCancel(context.Background())
	idleTimeout := 2 * time.Minute
	if port == 53 {
		idleTimeout = 30 * time.Second
	}
	timer := time.AfterFunc(idleTimeout, func() {
		log.Debugf("netstack: UDP session between %s and %s timed out", backendListenAddr, backendRemoteAddr)
		cancel()
		client.Close()
		backendConn.Close()
	})
	extend := func() {
		timer.Reset(idleTimeout)
	}
	startPacketCopy(ctx, cancel, client, net.UDPAddrFromAddrPort(clientAddr), backendConn, extend)
	startPacketCopy(ctx, cancel, backendConn, backendRemoteAddr, client, extend)
	if isLocal {
		<-ctx.Done()
		p.removeSubnetAddress(dstAddr.Addr())
	}
}

func startPacketCopy(ctx context.Context, cancel context.CancelFunc, dst net.PacketConn, dstAddr net.Addr, src net.PacketConn, extend func()) {
	log.Debugf("[v2] netstack: startPacketCopy to %v (%T) from %T", dstAddr, dst, src)
	go func() {
		defer cancel() // tear down the other direction's copy

		bufp := udpBufPool.Get().(*[]byte)
		defer udpBufPool.Put(bufp)
		pkt := *bufp

		for {
			select {
			case <-ctx.Done():
				return
			default:
				n, srcAddr, err := src.ReadFrom(pkt)
				if err != nil {
					if ctx.Err() == nil {
						log.Debugf("read packet from %s failed: %v", srcAddr, err)
					}
					return
				}
				_, err = dst.WriteTo(pkt[:n], dstAddr)
				if err != nil {
					if ctx.Err() == nil {
						log.Debugf("write packet to %s failed: %v", dstAddr, err)
					}
					return
				}
				log.Debugf("wrote UDP packet %s -> %s", srcAddr, dstAddr)
				extend()
			}
		}
	}()
}
