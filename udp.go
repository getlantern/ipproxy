package ipproxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/netstack/tcpip"
	"github.com/google/netstack/tcpip/buffer"
	"github.com/google/netstack/tcpip/network/ipv4"
	"github.com/google/netstack/tcpip/transport/udp"
	"github.com/google/netstack/waiter"

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

func (p *proxy) startUDPConn(ft fivetuple) (*udpConn, error) {
	upstreamAddr := fmt.Sprintf("%v:%d", ft.dstIP, ft.dstPort)
	upstream, err := p.opts.DialUDP(context.Background(), "udp", upstreamAddr)
	if err != nil {
		return nil, errors.New("Unable to dial upstream %v: %v", upstreamAddr, err)
	}

	upstreamIPAddr := tcpip.Address(net.ParseIP(ft.dstIP).To4())
	nicID := p.nextNICID()
	if err := p.stack.CreateNIC(nicID, p.linkID); err != nil {
		return nil, errors.New("Unable to create NIC: %v", err)
	}
	if err := p.stack.AddAddress(nicID, p.proto, upstreamIPAddr); err != nil {
		return nil, errors.New("Unable to assign NIC address: %v", err)
	}

	downstreamIPAddr := tcpip.Address(net.ParseIP(ft.srcIP).To4())

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
		p:              p,
		downstreamAddr: &tcpip.FullAddress{0, downstreamIPAddr, ft.srcPort},
		upstream:       upstream,
		ft:             ft,
		closeCh:        make(chan struct{}),
	}
	conn.markActive()

	var epErr *tcpip.Error
	conn.ep, epErr = p.stack.NewEndpoint(udp.ProtocolNumber, p.proto, &conn.wq)
	if epErr != nil {
		return nil, errors.New("Unable to create UDP endpoint: %v", epErr)
	}

	// Wait for connections to appear.
	_waitEntry, _notifyCh := waiter.NewChannelEntry(nil)
	conn.waitEntry = &_waitEntry
	conn.notifyCh = _notifyCh
	conn.wq.EventRegister(conn.waitEntry, waiter.EventIn)

	if err := conn.ep.Bind(tcpip.FullAddress{nicID, upstreamIPAddr, ft.dstPort}, nil); err != nil {
		conn.finalize()
		return nil, errors.New("UDP bind failed: %v", err)
	}

	go conn.copyToUpstream()
	go conn.copyFromUpstream()
	return conn, nil
}

type udpConn struct {
	lastActive     int64
	p              *proxy
	downstreamAddr *tcpip.FullAddress
	upstream       io.ReadWriteCloser
	ft             fivetuple
	ep             tcpip.Endpoint
	wq             waiter.Queue
	waitEntry      *waiter.Entry
	notifyCh       chan struct{}
	closeCh        chan struct{}
	closeOnce      sync.Once
}

func (conn *udpConn) copyToUpstream() {
	defer conn.finalize()

	for {
		select {
		case <-conn.closeCh:
			return
		case <-conn.notifyCh:
			addr := &tcpip.FullAddress{0, "", conn.ft.dstPort}
			buf, _, readErr := conn.ep.Read(addr)
			if readErr != nil {
				log.Errorf("Unexpected error reading from downstream: %v", readErr)
				continue
			}
			_, writeErr := conn.upstream.Write(buf)
			if writeErr != nil {
				log.Errorf("Unexpected error writing to upstream: %v", writeErr)
				return
			}
			conn.markActive()
		}
	}
}

func (conn *udpConn) copyFromUpstream() {
	defer conn.Close()
	b := conn.p.pool.Get()
	for {
		n, readErr := conn.upstream.Read(b)
		if readErr != nil {
			if neterr, ok := readErr.(net.Error); ok && neterr.Temporary() {
				continue
			}
			if readErr != io.EOF && !strings.Contains(readErr.Error(), "use of closed network connection") {
				log.Errorf("Unexpected error reading from upstream: %v", readErr)
			}
			return
		}
		_, _, writeErr := conn.ep.Write(tcpip.SlicePayload(b[:n]), tcpip.WriteOptions{
			To: conn.downstreamAddr,
		})
		if writeErr != nil {
			log.Errorf("Unexpected error writing to downstream: %v", writeErr)
			return
		}
		conn.markActive()
	}
}

func (conn *udpConn) markActive() {
	atomic.StoreInt64(&conn.lastActive, time.Now().UnixNano())
}

func (conn *udpConn) timeSinceLastActive() time.Duration {
	return time.Duration(time.Now().UnixNano() - atomic.LoadInt64(&conn.lastActive))
}

func (conn *udpConn) Close() error {
	conn.closeOnce.Do(func() {
		close(conn.closeCh)
	})
	return nil
}

func (conn *udpConn) finalize() {
	conn.wq.EventUnregister(conn.waitEntry)
	if conn.ep != nil {
		conn.ep.Close()
	}
	if conn.upstream != nil {
		conn.upstream.Close()
	}
	conn.p.udpConnTrackMx.Lock()
	delete(conn.p.udpConnTrack, conn.ft)
	conn.p.udpConnTrackMx.Unlock()
}

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
				conn.Close()
			}
		}
	}
}
