package ipproxy

import (
	"context"
	"net"
	"net/netip"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"

	"github.com/getlantern/netx"
)

func ipPortOfNetstackAddr(a tcpip.Address, port uint16) (ipp netip.AddrPort, ok bool) {
	if addr, ok := netip.AddrFromSlice(a.AsSlice()); ok {
		return netip.AddrPortFrom(addr, port), true
	}
	return netip.AddrPort{}, false
}

func (p *proxy) onUDP(r *udp.ForwarderRequest) {
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
		// intercept and reroute DNS traffic to dnsgrab
		if p.dnsGrabUDPAddr != nil && dstAddr.IP.String() != "127.0.0.1" && sess.LocalPort == 53 {
			dstAddr = p.dnsGrabUDPAddr
		}

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
