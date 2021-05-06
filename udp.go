package ipproxy

import (
	"context"
	"fmt"
	"net"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"

	"github.com/getlantern/errors"
	"github.com/getlantern/eventual"
)

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

	conn.channelEndpoint.InjectInbound(ipv4.ProtocolNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{
		Data: buffer.View(pkt.raw).ToVectorisedView(),
	}))
}

func (p *proxy) startUDPConn(ft fourtuple) (*udpConn, error) {
	upstreamValue := eventual.NewValue()
	downstreamIPAddr := tcpip.Address(net.ParseIP(ft.src.ip).To4())

	conn := &udpConn{
		origin: *newOrigin(p, udp.NewProtocol, ft.dst, upstreamValue, func(o *origin) error {
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

	if err := conn.init(udp.ProtocolNumber, tcpip.FullAddress{nicID, "", ft.dst.port}); err != nil {
		conn.closeNow()
		return nil, errors.New("Unable to initialize UDP connection for %v: %v", ft, err)
	}

	// to our NIC and routes packets to the downstreamIPAddr as well,
	upstreamSubnet, _ := tcpip.NewSubnet(conn.ipAddr, tcpip.AddressMask(conn.ipAddr))
	downstreamSubnet, _ := tcpip.NewSubnet(downstreamIPAddr, tcpip.AddressMask(downstreamIPAddr))
	conn.stack.SetRouteTable([]tcpip.Route{
		{
			Destination: upstreamSubnet,
			Gateway:     "",
			NIC:         nicID,
		},
		{
			Destination: downstreamSubnet,
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
