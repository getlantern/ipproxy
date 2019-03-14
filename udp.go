package ipproxy

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/google/netstack/tcpip"
	"github.com/google/netstack/tcpip/buffer"
	"github.com/google/netstack/tcpip/network/ipv4"
	"github.com/google/netstack/tcpip/transport/udp"

	"github.com/getlantern/errors"
)

func (p *proxy) onUDP(pkt ipPacket) {
	ft := pkt.ft()
	p.udpConnsMx.Lock()
	conn := p.udpConns[ft]
	p.udpConnsMx.Unlock()
	if conn == nil {
		var err error
		conn, err = p.startUDPConn(ft)
		if err != nil {
			log.Error(err)
			return
		}
		p.udpConnsMx.Lock()
		p.udpConns[ft] = conn
		p.udpConnsMx.Unlock()
	}

	conn.channelEndpoint.Inject(ipv4.ProtocolNumber, buffer.View(pkt.raw).ToVectorisedView())
}

func (p *proxy) startUDPConn(ft fourtuple) (*udpConn, error) {
	upstreamAddr := fmt.Sprintf("%v:%d", ft.dst.ip, ft.dst.port)
	upstream, err := p.opts.DialUDP(context.Background(), "udp", upstreamAddr)
	if err != nil {
		return nil, errors.New("Unable to dial upstream %v: %v", upstreamAddr, err)
	}

	downstreamIPAddr := tcpip.Address(net.ParseIP(ft.src.ip).To4())

	conn := &udpConn{
		origin: *newOrigin(p, udp.ProtocolName, ft.dst, upstream, func(o *origin) error {
			log.Debug("udpConn.finalize")
			p.udpConnsMx.Lock()
			delete(p.udpConns, ft)
			p.udpConnsMx.Unlock()
			log.Debug("udpConn.finalize done")
			return nil
		}),
		ft: ft,
	}

	if err := conn.init(udp.ProtocolNumber, tcpip.FullAddress{nicID, "", ft.dst.port}); err != nil {
		conn.closeNow()
		return nil, errors.New("Unable to initialize UDP connection for %v: %v", ft, err)
	}

	// to our NIC and routes packets to the downstreamIPAddr as well,
	conn.stack.SetRouteTable([]tcpip.Route{
		{
			Destination: conn.ipAddr,
			Mask:        tcpip.AddressMask(conn.ipAddr),
			Gateway:     "",
			NIC:         nicID,
		},
		{
			Destination: downstreamIPAddr,
			Mask:        tcpip.AddressMask(downstreamIPAddr),
			Gateway:     "",
			NIC:         nicID,
		},
	})

	go conn.copyToUpstream(&tcpip.FullAddress{0, "", ft.dst.port})
	go conn.copyFromUpstream(tcpip.WriteOptions{To: &tcpip.FullAddress{0, downstreamIPAddr, ft.src.port}})
	return conn, nil
}

type udpConn struct {
	origin
	ft fourtuple
}

// reapUDP reaps idled UDP connections. We do this on a single goroutine to
// avoid creating a bunch of timers for each connection (which is expensive).
func (p *proxy) reapUDP() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-p.closeCh:
			return
		case <-ticker.C:
			time.Sleep(1 * time.Second)
			p.udpConnsMx.Lock()
			conns := make([]*udpConn, 0, len(p.udpConns))
			for _, conn := range p.udpConns {
				conns = append(conns, conn)
			}
			p.udpConnsMx.Unlock()
			for _, conn := range conns {
				if conn.timeSinceLastActive() > p.opts.IdleTimeout {
					go conn.closeNow()
				}
			}
		}
	}
}

func (p *proxy) finalizeUDP() (err error) {
	p.udpConnsMx.Lock()
	conns := make([]*udpConn, 0)
	for _, conn := range p.udpConns {
		conns = append(conns, conn)
	}
	p.udpConnsMx.Unlock()

	for _, conn := range conns {
		_err := conn.Close()
		if err == nil {
			err = _err
		}
	}

	return
}
