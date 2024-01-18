// Package ipproxy provides a facility for proxying IP traffic. Currently it
// only supports TCP and UDP on top of IPv4.
package ipproxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"

	"github.com/getlantern/errors"
	"github.com/getlantern/golog"
)

var (
	log = golog.LoggerFor("ipproxy")
)

const (
	DefaultMTU                 = 1500
	DefaultOutboundBufferDepth = 10000
	DefaultIdleTimeout         = 65 * time.Second
	DefaultTCPConnectBacklog   = 10
	DefaultStatsInterval       = 15 * time.Second

	IPProtocolICMP = 1
	IPProtocolTCP  = 6
	IPProtocolUDP  = 17
)

type Opts struct {
	// MTU in bytes. Default of 1500 is usually fine.
	MTU int

	// OutboundBufferDepth specifies the number of outbound packets to buffer.
	// The default is 1.
	OutboundBufferDepth int

	// IdleTimeout specifies the amount of time before idle connections are
	// automatically closed. The default is 65 seconds.
	IdleTimeout time.Duration

	// TCPConnectBacklog is the allows backlog of TCP connections to a given
	// upstream port. Defaults to 10.
	TCPConnectBacklog int

	// StatsInterval controls how frequently to display stats. Defaults to 15
	// seconds.
	StatsInterval time.Duration

	// DialTCP specifies a function for dialing upstream TCP connections. Defaults
	// to net.Dialer.DialContext().
	DialTCP func(ctx context.Context, network, addr string) (net.Conn, error)

	// DialUDP specifies a function for dialing upstream UDP connections. Defaults
	// to net.Dialer.DialContext().
	DialUDP func(ctx context.Context, network, addr string) (net.Conn, error)
}

// ApplyDefaults applies the default values to the given Opts, including making
// a new Opts if opts is nil.
func (opts *Opts) ApplyDefaults() *Opts {
	if opts == nil {
		opts = &Opts{}
	}
	if opts.MTU <= 0 {
		opts.MTU = DefaultMTU
	}
	if opts.OutboundBufferDepth <= 0 {
		opts.OutboundBufferDepth = DefaultOutboundBufferDepth
	}
	if opts.IdleTimeout <= 0 {
		opts.IdleTimeout = DefaultIdleTimeout
	}
	if opts.TCPConnectBacklog <= 0 {
		opts.TCPConnectBacklog = DefaultTCPConnectBacklog
	}
	if opts.StatsInterval <= 0 {
		opts.StatsInterval = DefaultStatsInterval
	}
	if opts.DialTCP == nil {
		d := &net.Dialer{}
		opts.DialTCP = d.DialContext
	}
	if opts.DialUDP == nil {
		d := &net.Dialer{}
		opts.DialUDP = d.DialContext
	}
	return opts
}

type Proxy interface {
	// Serve starts proxying and blocks until finished
	Serve() error

	// AcceptedPackets is the count of accepted packets
	AcceptedPackets() int

	// RejectedPackets is the count of rejected packets
	RejectedPackets() int

	// NumTCPOrigins is the number of TCP origins being tracked
	NumTCPOrigins() int

	// NumTCPConns is the number of TCP connections being tracked
	NumTCPConns() int

	// NumUDPConns is the number of UDP "connections" being tracked
	NumUDPConns() int

	// Close shuts down the proxy in an orderly fashion and blocks until shutdown
	// is complete.
	Close() error
}

type proxy struct {
	acceptedPackets int64
	rejectedPackets int64
	numTcpOrigins   int64
	numTcpConns     int64
	numUdpConns     int64

	opts       *Opts
	proto      tcpip.NetworkProtocolNumber
	downstream io.ReadWriter

	pktIn      chan ipPacket
	tcpOrigins map[netip.AddrPort]*tcpOrigin

	ipstack *stack.Stack
	linkEP    *channel.Endpoint

	toDownstream chan stack.PacketBufferPtr

	atomicIsLocalIPFunc atomic.Value /*func(netip.Addr) bool]*/

	closeable
}

func (p *proxy) Serve() error {
	p.ipstack = stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6},
	})
	sackEnabledOpt := tcpip.TCPSACKEnabled(true) // TCP SACK is disabled by default
	err := p.ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &sackEnabledOpt)
	if err != nil {
		return fmt.Errorf("could not enable TCP SACK: %v", err)
	}
	p.linkEP = channel.New(512, uint32(p.opts.MTU), "")
	if err := p.ipstack.CreateNIC(nicID, p.linkEP); err != nil {
		return fmt.Errorf("could not create netstack NIC: %v", err)
	}
	if err := p.ipstack.SetPromiscuousMode(nicID, true); err != nil {
		return errors.New("Unable to set promiscuous mode: %v", err)
	}
	p.ipstack.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
	})
	const tcpReceiveBufferSize = 0
	const maxInFlightConnectionAttempts = 1024
	tcpFwd := tcp.NewForwarder(p.ipstack, tcpReceiveBufferSize, maxInFlightConnectionAttempts, p.onTCP)
	udpFwd := udp.NewForwarder(p.ipstack, p.onUDP)
	p.ipstack.SetTransportProtocolHandler(tcp.ProtocolNumber, p.wrapProtoHandler(tcpFwd.HandlePacket))
	p.ipstack.SetTransportProtocolHandler(udp.ProtocolNumber, p.wrapProtoHandler(udpFwd.HandlePacket))
	return p.inject()
	/*icmpStack, icmpEndpoint, err := p.stackForICMP()
	if err != nil {
		return err
	}

	serveCtx, cancel := context.WithCancel(context.Background())
	go func() {
		<-p.closeCh
		cancel()
	}()

	go p.trackStats()
	go p.copyToDownstream(serveCtx, icmpEndpoint)
	go p.copyFromUpstream()
	var wg sync.WaitGroup
	wg.Add(1)
	go p.copyToUpstream(icmpStack, icmpEndpoint, &wg)
	return p.readDownstreamPackets(&wg)*/
}

func New(downstream io.ReadWriter, opts *Opts) (Proxy, error) {
	// Default options
	opts = opts.ApplyDefaults()
	p := &proxy{
		opts:         opts,
		proto:        ipv4.ProtocolNumber,
		downstream:   downstream,
		pktIn:        make(chan ipPacket, 1000),
		tcpOrigins:   make(map[netip.AddrPort]*tcpOrigin),
		closeable: closeable{
			closeCh:           make(chan struct{}),
			readyToFinalizeCh: make(chan struct{}),
			closedCh:          make(chan struct{}),
		},
	}

	return p, nil
}

var PrivateIPNetworks = []net.IPNet{
	net.IPNet{
		IP:   net.ParseIP("10.0.0.0"),
		Mask: net.CIDRMask(8, 32),
	},
	net.IPNet{
		IP:   net.ParseIP("172.16.0.0"),
		Mask: net.CIDRMask(12, 32),
	},
	net.IPNet{
		IP:   net.ParseIP("192.168.0.0"),
		Mask: net.CIDRMask(16, 32),
	},
}

func isLocalIP(ip net.IP) bool {
	for _, ipNet := range PrivateIPNetworks {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return ip.IsPrivate()
}

func (p *proxy) wrapProtoHandler(h func(stack.TransportEndpointID, stack.PacketBufferPtr) bool) func(stack.TransportEndpointID, stack.PacketBufferPtr) bool {
	return func(tei stack.TransportEndpointID, pb stack.PacketBufferPtr) bool {
		addr := tei.LocalAddress
		ip, ok := netip.AddrFromSlice(addr.AsSlice())
		if !ok {
			log.Debug("netstack: could not parse local address for incoming connection")
			return false
		}
		ip = ip.Unmap()
		if !isLocalIP(net.IP(addr.AsSlice())) {
			p.addSubnetAddress(ip)
		}
		return h(tei, pb)
	}
}

func (p *proxy) addSubnetAddress(ip netip.Addr) {
	pa := tcpip.ProtocolAddress{
		AddressWithPrefix: tcpip.AddrFromSlice(ip.AsSlice()).WithPrefix(),
	}
	if ip.Is4() {
		pa.Protocol = ipv4.ProtocolNumber
	} else if ip.Is6() {
		pa.Protocol = ipv6.ProtocolNumber
	}
	p.ipstack.AddProtocolAddress(nicID, pa, stack.AddressProperties{
		PEB:        stack.CanBePrimaryEndpoint, // zero value default
		ConfigType: stack.AddressConfigStatic,  // zero value default
	})
}

func (p *proxy) inject() error {
	ctx := context.Background()
	for {
		pkt := p.linkEP.ReadContext(ctx)
		if pkt.IsNil() {
			if ctx.Err() != nil {
				// Return without logging.
				return ctx.Err()
			}
			log.Debugf("[v2] ReadContext-for-write = ok=false")
			continue
		}

		log.Debugf("[v2] packet Write out: % x", stack.PayloadSince(pkt.NetworkHeader()))

		p.linkEP.InjectInbound(ipv4.ProtocolNumber, pkt)
	}
	return nil
}


func (p *proxy) readDownstreamPackets(wg *sync.WaitGroup) (finalErr error) {
	defer wg.Wait() // wait for copyToUpstream to finish with all of its cleanup
	defer p.closeNow()

	for {
		// we can't reuse this byte slice across reads because each one is held in
		// memory by the tcpip stack.
		b := make([]byte, p.opts.MTU)
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

		p.pktIn <- pkt
	}
}

func (p *proxy) stackForICMP() (*stack.Stack, *channel.Endpoint, error) {
	channelEndpoint := channel.New(p.opts.OutboundBufferDepth, uint32(p.opts.MTU), "")
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6},
	})
	if err := s.CreateNIC(nicID, channelEndpoint); err != nil {
		s.Close()
		return nil, nil, errors.New("Unable to create ICMP NIC: %v", err)
	}

	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
	})
	if err := s.SetPromiscuousMode(nicID, true); err != nil {
		return nil, nil, errors.New("Unable to set promiscuous mode: %v", err)
	}
	return s, channelEndpoint, nil
}
