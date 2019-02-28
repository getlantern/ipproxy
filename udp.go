package ipproxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
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
		baseConn:       newBaseConn(p),
		downstreamAddr: &tcpip.FullAddress{0, downstreamIPAddr, ft.src.port},
		upstream:       upstream,
		ft:             ft,
	}
	conn.markActive()

	if err := conn.init(udp.ProtocolNumber, tcpip.FullAddress{nicID, upstreamIPAddr, ft.dst.port}); err != nil {
		return nil, errors.New("Unable to initialize UDP connection: %v", err)
	}

	go conn.copyToUpstream()
	go conn.copyFromUpstream()
	return conn, nil
}

type udpConn struct {
	baseConn
	downstreamAddr *tcpip.FullAddress
	upstream       io.ReadWriteCloser
	ft             fourtuple
}

func (conn *udpConn) copyToUpstream() {
	defer func() {
		conn.closedCh <- conn.finalize()
		close(conn.closedCh)
	}()

	for {
		select {
		case <-conn.closeCh:
			return
		case <-conn.notifyCh:
			addr := &tcpip.FullAddress{0, "", conn.ft.dst.port}
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

// finalize does the actual cleaning up of the connection. It runs at the end
// of the loop that writes to upstream.
func (conn *udpConn) finalize() (err error) {
	conn.baseConn.finalize()
	if conn.upstream != nil {
		err = conn.upstream.Close()
	}
	conn.p.udpConnTrackMx.Lock()
	delete(conn.p.udpConnTrack, conn.ft)
	conn.p.udpConnTrackMx.Unlock()
	return
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
