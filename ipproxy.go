// Packate ipproxy provides a facility for proxying IP traffic. Current it only
// supports IPv4.
package ipproxy

import (
	"context"
	"io"
	"net"
	"strings"
	"time"

	"github.com/google/netstack/tcpip"
	"github.com/google/netstack/tcpip/link/channel"
	"github.com/google/netstack/tcpip/network/arp"
	"github.com/google/netstack/tcpip/network/ipv4"
	"github.com/google/netstack/tcpip/network/ipv6"
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
	DefaultNICID               = 1

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

	// NICID is the internal id for the link-local interface. Usually the default
	// value is fine.
	NICID int

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
	if opts.NICID <= 0 {
		opts.NICID = DefaultNICID
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

	// NumTCPConns returns the current number of TCP connections being tracked
	NumTCPConns() int

	// NumUDPConns returns the current number of UDP connections being tracked
	NumUDPConns() int
}

type proxy struct {
	acceptedPackets int64
	rejectedPackets int64

	proto      tcpip.NetworkProtocolNumber
	downstream io.ReadWriter
	endpoint   *channel.Endpoint
	stack      *stack.Stack
	pool       *bpool.BytePool

	udpConnTrack map[fivetuple]*udpConn

	closeCh chan interface{}

	dialTCP func(context.Context, string, string) (net.Conn, error)
	dialUDP func(context.Context, string, string) (*net.UDPConn, error)
}

func (p *proxy) Serve() error {
	return p.copyToUpstream()
}

func New(downstream io.ReadWriter, opts *Opts) (Proxy, error) {
	// Default options
	if opts == nil {
		opts = &Opts{}
	}
	opts.setDefaults()

	s := stack.New([]string{ipv4.ProtocolName, ipv6.ProtocolName, arp.ProtocolName}, []string{tcp.ProtocolName, udp.ProtocolName}, stack.Options{})

	linkID, endpoint := channel.New(opts.OutboundBufferDepth, uint32(opts.MTU), "")
	if err := s.CreateNIC(1, linkID); err != nil {
		return nil, errors.New("Unable to create NIC: %v", err)
	}
	s.SetPromiscuousMode(1, true)

	// Add default route that routes all IPv4 packets to our interface
	s.SetRouteTable([]tcpip.Route{
		{
			Destination: tcpip.Address(strings.Repeat("\x00", 4)),
			Mask:        tcpip.AddressMask(strings.Repeat("\x00", 4)),
			Gateway:     "",
			NIC:         1,
		},
	})

	p := &proxy{
		proto:        ipv4.ProtocolNumber,
		downstream:   downstream,
		endpoint:     endpoint,
		stack:        s,
		pool:         bpool.NewBytePool(opts.BufferPoolSize, opts.MTU),
		udpConnTrack: make(map[fivetuple]*udpConn, 0),
		dialTCP:      opts.DialTCP,
		dialUDP:      opts.DialUDP,
	}

	return p, nil
}

func (p *proxy) copyToUpstream() error {
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
			// p.onTCP(pkt)
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
