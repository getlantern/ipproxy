package ipproxy

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/google/netstack/tcpip"
	"github.com/google/netstack/tcpip/buffer"
	"github.com/google/netstack/tcpip/network/ipv4"
	"github.com/google/netstack/tcpip/transport/udp"
	"github.com/google/netstack/waiter"

	"github.com/getlantern/errors"
)

func (p *proxy) onUDP(pkt ipPacket) {
	ft := pkt.ft()
	conn := p.udpConnTrack[ft]
	if conn == nil {
		var err error
		conn, err = p.startUDPConn(ft)
		if err != nil {
			log.Error(err)
			return
		}
		p.udpConnTrack[ft] = conn
	}

	log.Debugf("Injecting packet")
	p.endpoint.Inject(ipv4.ProtocolNumber, buffer.View(pkt.raw).ToVectorisedView())
}

func (p *proxy) startUDPConn(ft fivetuple) (*udpConn, error) {
	log.Debugf("Creating udpConn for %v", ft)

	upstreamAddr := fmt.Sprintf("%v:%d", ft.dstIP, ft.dstPort)
	upstream, err := p.dialUDP(context.Background(), "udp", upstreamAddr)
	if err != nil {
		return nil, errors.New("Unable to dial upstream %v: %v", upstreamAddr, err)
	}

	conn := &udpConn{
		Conn:    upstream,
		ft:      ft,
		closeCh: make(chan struct{}),
	}

	var stackErr *tcpip.Error
	conn.ep, stackErr = p.stack.NewEndpoint(udp.ProtocolNumber, p.proto, &conn.wq)
	if stackErr != nil {
		return nil, errors.New("Unable to create UDP endpoint: %v", stackErr)
	}

	// Wait for connections to appear.
	_waitEntry, _notifyCh := waiter.NewChannelEntry(nil)
	conn.waitEntry = &_waitEntry
	conn.notifyCh = _notifyCh
	conn.wq.EventRegister(conn.waitEntry, waiter.EventIn)

	if err := conn.ep.Bind(tcpip.FullAddress{0, "", ft.dstPort}, nil); err != nil {
		conn.finalize()
		return nil, errors.New("UDP bind failed: %v", err)
	}

	go conn.copyToUpstream()

	return conn, nil
}

type udpConn struct {
	net.Conn
	ft        fivetuple
	ep        tcpip.Endpoint
	wq        waiter.Queue
	waitEntry *waiter.Entry
	notifyCh  chan struct{}
	closeCh   chan struct{}
	closeOnce sync.Once
}

func (conn *udpConn) copyToUpstream() {
	defer conn.finalize()

	for {
		select {
		case <-conn.closeCh:
			return
		case <-conn.notifyCh:
			addr := &tcpip.FullAddress{0, "", conn.ft.dstPort}
			buf, _, err := conn.ep.Read(addr)
			if err != nil {
				log.Errorf("Error reading packet from downstream, ignoring: %v", err)
				continue
			}
			log.Debugf("Got udp packet: %v", buf)
		}
	}
}

func (conn *udpConn) Close() error {
	conn.closeOnce.Do(func() {
		close(conn.closeCh)
	})
	return nil
}

func (conn *udpConn) finalize() {
	conn.wq.EventUnregister(conn.waitEntry)
	conn.ep.Close()
}
