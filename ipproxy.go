// Package ipproxy provides a facility for proxying IP traffic. Currently it
// only supports TCP and UDP on top of IPv4.
package ipproxy

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
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
	"github.com/xjasonlyu/tun2socks/v2/core/device"
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

	nicID          = 1
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

	// When enabled, print extra debugging information when handling packets
	DebugPackets bool

	// the network layer device ipproxy should be configured to use
	Device device.Device

	// the name of the network layer device ipproxy should be configured to use
	DeviceName string

	// Only forward IPv4 traffic
	DisableIPv6 bool

	// Local network addresses to add to the NIC
	LocalAddresses []netip.Addr

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
	Serve(context.Context) error

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

	ipstack *stack.Stack
	linkEP  stack.LinkEndpoint

	mu sync.Mutex
}

func (p *proxy) Serve(ctx context.Context) error {
	log.Debug("ipproxy serving traffic")

	go func() {
		<-ctx.Done()
		p.Close()
	}()

	// tcpReceiveBufferSize if set to zero, the default receive window buffer size is used instead.
	const tcpReceiveBufferSize = 0
	const maxInFlightConnectionAttempts = 1024
	tcpFwd := tcp.NewForwarder(p.ipstack, tcpReceiveBufferSize, maxInFlightConnectionAttempts, p.onTCP)
	udpFwd := udp.NewForwarder(p.ipstack, p.onUDP)

	p.ipstack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)
	p.ipstack.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

	p.ipstack.Wait()

	return nil
}

func (p *proxy) Close() error {
	if p.ipstack != nil {
		p.ipstack.Close()
	}
	return nil
}

func New(opts *Opts) (Proxy, error) {
	// Default options
	opts = opts.ApplyDefaults()
	networkProtocols := []stack.NetworkProtocolFactory{ipv4.NewProtocol}
	if !opts.DisableIPv6 {
		networkProtocols = append(networkProtocols, ipv6.NewProtocol)
	}
	ipstack := stack.New(stack.Options{
		NetworkProtocols:   networkProtocols,
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6},
	})
	sackEnabledOpt := tcpip.TCPSACKEnabled(true) // TCP SACK is disabled by default
	if err := ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &sackEnabledOpt); err != nil {
		log.Errorf("could not enable TCP SACK: %v", err)
		return nil, fmt.Errorf("could not enable TCP SACK: %v", err)
	}
	var linkEndpoint stack.LinkEndpoint
	if opts.Device != nil {
		linkEndpoint = opts.Device
	} else if opts.DeviceName != "" {
		device, err := parseDevice(opts.DeviceName, uint32(opts.MTU))
		if err != nil {
			return nil, err
		}
		linkEndpoint = device
	} else {
		linkEndpoint = channel.New(512, uint32(opts.MTU), "")
	}

	if err := ipstack.CreateNIC(nicID, linkEndpoint); err != nil {
		log.Errorf("could not create netstack NIC: %v", err)
		return nil, fmt.Errorf("could not create netstack NIC: %v", err)
	}
	if err := ipstack.SetPromiscuousMode(nicID, true); err != nil {
		log.Errorf("Unable to set promiscuous mode: %v", err)
		return nil, errors.New("Unable to set promiscuous mode: %v", err)
	}
	// Enable spoofing on the interface to allow replying from addresses other than those set on the interface
	if err := ipstack.SetSpoofing(nicID, true); err != nil {
		return nil, fmt.Errorf("failed to enable spoofing on NIC: %v", err)
	}

	for _, ip := range opts.LocalAddresses {
		if err := addSubnetAddress(ipstack, ip); err != nil {
			return nil, err
		}
	}

	ipstack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: nicID})
	if !opts.DisableIPv6 {
		ipstack.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: nicID})
	}

	p := &proxy{
		opts:         opts,
		ipstack:      ipstack,
		linkEP: 	  linkEndpoint,
	}

	return p, nil
}

func addSubnetAddress(ipstack *stack.Stack, ip netip.Addr) error {
	pa := tcpip.ProtocolAddress{
		AddressWithPrefix: tcpip.AddrFromSlice(ip.AsSlice()).WithPrefix(),
	}
	if ip.Is4() {
		pa.Protocol = ipv4.ProtocolNumber
	} else if ip.Is6() {
		pa.Protocol = ipv6.ProtocolNumber
	}
	// Add the given network address to the NIC
	if err := ipstack.AddProtocolAddress(nicID, pa, stack.AddressProperties{
		PEB:        stack.CanBePrimaryEndpoint, // zero value default
		ConfigType: stack.AddressConfigStatic,  // zero value default
	}); err != nil {
		return fmt.Errorf("failed to add IPv4 address: %v", err)
	}
	return nil
}
