// Package ipproxy provides a facility for proxying IP traffic. Currently it
// only supports TCP and UDP on top of IPv4.
package ipproxy

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/netstack/tcpip"
	"github.com/google/netstack/tcpip/link/channel"
	"github.com/google/netstack/tcpip/network/ipv4"
	"github.com/google/netstack/tcpip/stack"
	"github.com/google/netstack/tcpip/transport/tcp"
	"github.com/google/netstack/tcpip/transport/udp"

	"github.com/oxtoacart/bpool"

	"github.com/getlantern/errors"
	"github.com/getlantern/golog"
)

var (
	log = golog.LoggerFor("ipproxy")
)

const (
	DefaultMTU                 = 1500
	DefaultOutboundBufferDepth = 1
	DefaultBufferPoolSize      = 100
	DefaultIdleTimeout         = 65 * time.Second
	DefaultTCPConnectBacklog   = 10

	IPProtocolTCP = 6
	IPProtocolUDP = 17
)

type Opts struct {
	// MTU is the maximum transmission unit in bytes. Default of 1500 is usually
	// fine.
	MTU int

	// OutboundBufferDepth specifies the number of outbound packets to buffer.
	// The default is 1.
	OutboundBufferDepth int

	// BufferPoolSize specifies the size of the packet buffer pool. The default is
	// 100.
	BufferPoolSize int

	// IdleTimeout specifies the amount of time before idle connections are
	// automatically closed. The default is 65 seconds.
	IdleTimeout time.Duration

	// TCPConnectBacklog is the allows backlog of TCP connections to a given
	// upstream port. Defaults to 10.
	TCPConnectBacklog int

	// DialTCP specifies a function for dialing upstream TCP connections. Defaults
	// to net.Dialer.DialContext().
	DialTCP func(ctx context.Context, network, addr string) (net.Conn, error)

	// DialUDP specifies a function for dialing upstream UDP connections. Defaults
	// to net.Dialer.DialContext().
	DialUDP func(ctx context.Context, network, addr string) (*net.UDPConn, error)
}

func (opts *Opts) setDefaults() {
	if opts.MTU <= 0 {
		opts.MTU = DefaultMTU
	}
	if opts.OutboundBufferDepth <= 0 {
		opts.OutboundBufferDepth = DefaultOutboundBufferDepth
	}
	if opts.BufferPoolSize <= 0 {
		opts.BufferPoolSize = DefaultBufferPoolSize
	}
	if opts.IdleTimeout <= 0 {
		opts.IdleTimeout = DefaultIdleTimeout
	}
	if opts.TCPConnectBacklog <= 0 {
		opts.TCPConnectBacklog = DefaultTCPConnectBacklog
	}
	if opts.DialTCP == nil {
		d := &net.Dialer{}
		opts.DialTCP = d.DialContext
	}
	if opts.DialUDP == nil {
		d := &net.Dialer{}
		opts.DialUDP = func(ctx context.Context, network, addr string) (*net.UDPConn, error) {
			conn, err := d.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return conn.(*net.UDPConn), nil
		}
	}
}

type Proxy interface {
	// Serve starts proxying and blocks until finished
	Serve() error

	// ConnCounts gets current counts of connections
	ConnCounts() (numTCPDests int, numTCPConns int, numUDPConns int)

	// Close shuts down the proxy in an orderly fashion and blocks until shutdown
	// is complete.
	Close() error
}

type proxy struct {
	acceptedPackets int64
	rejectedPackets int64

	currentNICID uint32

	opts            *Opts
	proto           tcpip.NetworkProtocolNumber
	downstream      io.ReadWriter
	linkID          tcpip.LinkEndpointID
	channelEndpoint *channel.Endpoint
	stack           *stack.Stack
	pool            *bpool.BytePool

	tcpConnTrack   map[addr]*tcpDest
	tcpConnTrackMx sync.Mutex
	udpConnTrack   map[fourtuple]*udpConn
	udpConnTrackMx sync.Mutex

	closeable
}

func (p *proxy) Serve() error {
	go p.trackStats()
	go p.reapTCP()
	go p.reapUDP()
	go p.copyFromUpstream()
	return p.copyToUpstream()
}

func New(downstream io.ReadWriter, opts *Opts) (Proxy, error) {
	// Default options
	if opts == nil {
		opts = &Opts{}
	}
	opts.setDefaults()

	linkID, channelEndpoint := channel.New(opts.OutboundBufferDepth, uint32(opts.MTU), "")
	s := stack.New([]string{ipv4.ProtocolName}, []string{tcp.ProtocolName, udp.ProtocolName}, stack.Options{})

	p := &proxy{
		opts:            opts,
		proto:           ipv4.ProtocolNumber,
		downstream:      downstream,
		linkID:          linkID,
		channelEndpoint: channelEndpoint,
		stack:           s,
		pool:            bpool.NewBytePool(opts.BufferPoolSize, opts.MTU),
		tcpConnTrack:    make(map[addr]*tcpDest, 0),
		udpConnTrack:    make(map[fourtuple]*udpConn, 0),
		closeable: closeable{
			closeCh:  make(chan struct{}),
			closedCh: make(chan error),
		},
	}

	return p, nil
}

func (p *proxy) copyToUpstream() (finalErr error) {
	defer func() {
		go func() {
			err := p.finalize()
			close(p.channelEndpoint.C)
			p.closedCh <- err
			close(p.closedCh)
		}()
		finalErr = p.Close()
	}()

	for {
		b := p.pool.Get()
		n, err := p.downstream.Read(b)
		if err != nil {
			if err == io.EOF {
				return err
			}
			return errors.New("Unexpected error reading from downstream: %v", err)
		}
		raw := b[:n]
		pkt, err := parseIPPacket(raw)
		if err != nil {
			log.Debugf("Error on inbound packet, ignoring: %v", err)
			p.rejectedPacket()
			continue
		}
		switch pkt.ipProto {
		case IPProtocolTCP:
			p.acceptedPacket()
			p.onTCP(pkt)
		case IPProtocolUDP:
			p.acceptedPacket()
			p.onUDP(pkt)
		default:
			p.rejectedPacket()
			log.Debugf("Unknown IP protocol, ignoring: %v", pkt.ipProto)
			continue
		}
	}
}

func (p *proxy) copyFromUpstream() {
	for pktInfo := range p.channelEndpoint.C {
		pkt := p.pool.Get()[:0]
		pkt = append(pkt, pktInfo.Header...)
		pkt = append(pkt, pktInfo.Payload...)
		_, err := p.downstream.Write(pkt)
		if err != nil {
			log.Errorf("Unexpected error writing to downstream: %v", err)
			return
		}
		p.pool.Put(pkt)
		p.pool.Put(pktInfo.Payload)
	}
}

func (p *proxy) nextNICID() tcpip.NICID {
	return tcpip.NICID(atomic.AddUint32(&p.currentNICID, 1))
}

func (p *proxy) finalize() error {
	err := p.finalizeTCP()
	_err := p.finalizeUDP()
	if err == nil {
		err = _err
	}
	return err
}
