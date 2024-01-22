package ipproxy

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"

	"github.com/getlantern/errors"
	"github.com/getlantern/eventual"
	"github.com/getlantern/netx"
)

const maxUDPPacketSize = 64 << 10

var udpBufPool = &sync.Pool{
	New: func() any {
		b := make([]byte, maxUDPPacketSize)
		return &b
	},
}

func (p *proxy) onUDP(pkt ipPacket) {
	ft := pkt.ft()
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
	conn.channelEndpoint.InjectInbound(ipv4.ProtocolNumber, inboundPkt)
}

func ipPortOfNetstackAddr(a tcpip.Address, port uint16) (ipp netip.AddrPort, ok bool) {
	if addr, ok := netip.AddrFromSlice(a.AsSlice()); ok {
		return netip.AddrPortFrom(addr, port), true
	}
	return netip.AddrPort{}, false
}

func (p *proxy) udpHandlePacket(r *udp.ForwarderRequest) {
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
		c := gonet.NewUDPConn(&wq, ep)
		go p.handleDNSUDP(srcAddr, c)
		return
	}

	//c := gonet.NewUDPConn(&wq, ep)
	//go p.forwardUDP(c, srcAddr, dstAddr)
}

func (p *proxy) fetchUDPInput(c *gonet.UDPConn, pc *net.UDPConn, target *net.UDPAddr) {
	const readDeadline = 150 * time.Millisecond

	defer c.Close()

	bufp := udpBufPool.Get().(*[]byte)
	defer udpBufPool.Put(bufp)
	q := *bufp

	for {
		pc.SetDeadline(time.Now().Add(readDeadline))
		n, _, err := pc.ReadFromUDP(q)
		if err != nil {
			return
		}

		_, err = c.Write(q[:n])
		if err != nil {
			log.Debug("failed to write UDP data to TUN")
			return
		}
	}
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

		resp, n, err := p.opts.DnsGrabServer.ProcessQuery(q[:n])
		if err != nil {
			log.Error(err)
			return
		}

		log.Debug("Got dns response")

		c.Write(resp[:n])
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
	backendConn, err := netx.ListenUDP("udp", backendListenAddr)
	if err != nil {
		log.Errorf("netstack: could not bind local port %v: %v, trying again with random port", backendListenAddr.Port, err)
		backendListenAddr.Port = 0
		backendConn, err = netx.ListenUDP("udp", backendListenAddr)
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

func (p *proxy) startUDPConn(ft fourtuple) (*udpConn, error) {
	upstreamValue := eventual.NewValue()
	downstreamIPAddr := tcpip.AddrFrom4([4]byte(net.ParseIP(ft.src.ip).To4()))
	addr, _ := netip.ParseAddr(ft.dst.ip)
	dst := netip.AddrPortFrom(addr, uint16(ft.dst.port))
	conn := &udpConn{
		origin: *newOrigin(p, udp.NewProtocol, dst, upstreamValue, func(o *origin) error {
			return nil
		}),
		ft: ft,
	}

	go func() {
		upstreamAddr := fmt.Sprintf("%v:%d", ft.dst.ip, ft.dst.port)
		upstream, err := p.opts.DialUDP(context.Background(), "udp", upstreamAddr)
		if err != nil {
			upstreamValue.Cancel()
			conn.closeNow()
			log.Errorf("Unable to dial upstream %v: %v", upstreamAddr, err)
		}
		upstreamValue.Set(upstream)
	}()

	if err := conn.init(udp.ProtocolNumber, tcpip.FullAddress{NIC: nicID, Port: ft.dst.port}); err != nil {
		conn.closeNow()
		return nil, errors.New("Unable to initialize UDP connection for %v: %v", ft, err)
	}

	// to our NIC and routes packets to the downstreamIPAddr as well,
	upstreamSubnet, _ := tcpip.NewSubnet(conn.ipAddr, tcpip.MaskFromBytes(conn.ipAddr.AsSlice()))
	downstreamSubnet, _ := tcpip.NewSubnet(downstreamIPAddr, tcpip.MaskFromBytes(downstreamIPAddr.AsSlice()))

	conn.stack.SetRouteTable([]tcpip.Route{
		{
			Destination: upstreamSubnet,
			Gateway:     tcpip.Address{},
			NIC:         nicID,
		},
		{
			Destination: downstreamSubnet,
			Gateway:     tcpip.Address{},
			NIC:         nicID,
		},
	})

	go conn.copyToUpstream()
	go conn.copyFromUpstream(tcpip.WriteOptions{To: &tcpip.FullAddress{NIC: nicID, Addr: downstreamIPAddr, Port: ft.src.port}})
	return conn, nil
}

type udpConn struct {
	origin
	ft fourtuple
}

func (p *proxy) reapUDP() {
	for ft, conn := range p.udpConns {
		if conn.timeSinceLastActive() > p.opts.IdleTimeout {
			go conn.closeNow()
			delete(p.udpConns, ft)
			p.removeUDPConn()
		}
	}
}

func (p *proxy) closeUDP() {
	for ft, conn := range p.udpConns {
		conn.closeNow()
		delete(p.udpConns, ft)
		p.removeUDPConn()
	}
}
