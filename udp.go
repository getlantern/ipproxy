package ipproxy

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	udpWaitTimeout = 5 * time.Second
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
		if p.opts.DebugPackets {
			log.Debugf("forwarding udp: %v", stringifyTEI(sess))
		}
		var wq waiter.Queue
		ep, tcpErr := r.CreateEndpoint(&wq)
		if tcpErr != nil {
			log.Errorf("creating endpoint: %s", tcpErr.String())
			return
		}

		local := gonet.NewUDPConn(&wq, ep)
		defer local.Close()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		addr := fmt.Sprintf("%s:%d", sess.LocalAddress.String(), sess.LocalPort)
		remote, err := p.opts.DialUDP(ctx, "udp", addr)
		if err != nil {
			log.Error(err)
			return
		}
		defer remote.Close()
		relay(local, remote, udpWaitTimeout)
	}()
}
