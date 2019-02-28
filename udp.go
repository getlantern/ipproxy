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
	p.udpConnTrackMx.Lock()
	conn := p.udpConnTrack[ft]
	p.udpConnTrackMx.Unlock()
	if conn == nil {
		var err error
		conn, err = p.startUDPConn(ft)
		if err != nil {
			log.Error(err)
			return
		}
		p.udpConnTrackMx.Lock()
		p.udpConnTrack[ft] = conn
		p.udpConnTrackMx.Unlock()
	}

	p.channelEndpoint.Inject(ipv4.ProtocolNumber, buffer.View(pkt.raw).ToVectorisedView())
}

func (p *proxy) startUDPConn(ft fourtuple) (*udpConn, error) {
	upstreamAddr := fmt.Sprintf("%v:%d", ft.dst.ip, ft.dst.port)
	upstream, err := p.opts.DialUDP(context.Background(), "udp", upstreamAddr)
	if err != nil {
		return nil, errors.New("Unable to dial upstream %v: %v", upstreamAddr, err)
	}

	upstreamIPAddr := tcpip.Address(net.ParseIP(ft.dst.ip).To4())
	nicID := p.nextNICID()
	if err := p.stack.CreateNIC(nicID, p.linkID); err != nil {
		return nil, errors.New("Unable to create NIC: %v", err)
	}
	if err := p.stack.AddAddress(nicID, p.proto, upstreamIPAddr); err != nil {
		return nil, errors.New("Unable to assign NIC address: %v", err)
	}

	downstreamIPAddr := tcpip.Address(net.ParseIP(ft.src.ip).To4())

	// Add default route that routes all IPv4 packets for the given upstream address
	// to our NIC and routes packets to the downstreamIPAddr as well,
	p.stack.SetRouteTable([]tcpip.Route{
		{
			Destination: upstreamIPAddr,
			Mask:        tcpip.AddressMask(upstreamIPAddr),
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

	conn := &udpConn{
		baseConn: newBaseConn(p, upstream, func() error {
			p.udpConnTrackMx.Lock()
			delete(p.udpConnTrack, ft)
			p.udpConnTrackMx.Unlock()
			return nil
		}),
		ft: ft,
	}
	conn.markActive()

	if err := conn.init(udp.ProtocolNumber, tcpip.FullAddress{nicID, upstreamIPAddr, ft.dst.port}); err != nil {
		return nil, errors.New("Unable to initialize UDP connection: %v", err)
	}

	go conn.copyToUpstream(&tcpip.FullAddress{0, "", ft.dst.port})
	go conn.copyFromUpstream(tcpip.WriteOptions{To: &tcpip.FullAddress{0, downstreamIPAddr, ft.src.port}})
	return conn, nil
}

type udpConn struct {
	baseConn
	ft fourtuple
}

// reapUDP reaps idled UDP connections. We do this on a single goroutine to
// avoid creating a bunch of timers for each connection (which is expensive).
func (p *proxy) reapUDP() {
	for {
		time.Sleep(1 * time.Second)
		p.udpConnTrackMx.Lock()
		conns := make([]*udpConn, 0)
		for _, conn := range p.udpConnTrack {
			conns = append(conns, conn)
		}
		p.udpConnTrackMx.Unlock()
		for _, conn := range conns {
			if conn.timeSinceLastActive() > p.opts.IdleTimeout {
				go conn.Close()
			}
		}
	}
}

func (p *proxy) finalizeUDP() (err error) {
	p.udpConnTrackMx.Lock()
	conns := make([]*udpConn, 0)
	for _, conn := range p.udpConnTrack {
		conns = append(conns, conn)
	}
	p.udpConnTrackMx.Unlock()

	for _, conn := range conns {
		_err := conn.Close()
		if err == nil {
			err = _err
		}
	}

	return
}
