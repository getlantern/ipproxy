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
	go func() {
		log.Debugf("forwarding udp: %v", stringifyTEI(sess))
		var wq waiter.Queue
		ep, tcpErr := r.CreateEndpoint(&wq)
		if tcpErr != nil {
			log.Errorf("creating endpoint: %s", tcpErr.String())
			return
		}
		src := gonet.NewUDPConn(&wq, ep)
		defer src.Close()

		dstIP, ok := ipPortOfNetstackAddr(sess.LocalAddress, sess.LocalPort)
		if !ok {
			log.Errorf("invalid destination address %s", sess.LocalAddress.String())
			return
		}
		srcIP, ok := ipPortOfNetstackAddr(sess.RemoteAddress, sess.RemotePort)
		if !ok {
			log.Errorf("invalid source address %s", sess.RemoteAddress.String())
			return
		}
		dstAddr := net.UDPAddrFromAddrPort(dstIP)
		localAddr := &net.UDPAddr{IP: net.IP{0, 0, 0, 0}, Port: 0}
		srcAddr := net.UDPAddrFromAddrPort(srcIP)

		// Setup listener to receive UDP packets coming back from target
		dest, err := netx.ListenUDP("udp", localAddr)
		if err != nil {
			log.Errorf("starting udp listener: %v", err)
			return
		}
		defer dest.Close()

		copy := func(ctx context.Context, dst net.PacketConn, dstAddr net.Addr, src net.PacketConn, errC chan<- error) {
			buf := make([]byte, p.opts.MTU)
			for {
				select {
				case <-ctx.Done():
					return
				default:
					var n int
					var err error
					n, _, err = src.ReadFrom(buf)
					if err == nil {
						_, err = dst.WriteTo(buf[:n], dstAddr)
					}
					select {
					case errC <- err:
					default:
					}
				}
			}
		}

		ctx, cancel := context.WithCancel(context.Background())
		errors := make(chan error, 2)
		go copy(ctx, dest, dstAddr, src, errors)
		go copy(ctx, src, srcAddr, dest, errors)

		// Tear down the forwarding if there is no activity after a certain period of time
		for keepGoing := true; keepGoing; {
			select {
			case err := <-errors:
				if err != nil {
					keepGoing = false
				}
			case <-time.After(10 * time.Second):
				keepGoing = false
			}
		}
		cancel()
	}()
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
