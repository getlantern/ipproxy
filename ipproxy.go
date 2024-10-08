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

	nicID = 1
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
	Device Device

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

	// Start starts proxying and blocks until finished
	Start(context.Context) error
	// Stop shuts down the proxy in an orderly fashion and blocks until shutdown
	// is complete.
	Stop() error
}

type proxy struct {
	acceptedPackets int64
	rejectedPackets int64
	numTcpOrigins   int64
	numTcpConns     int64
	numUdpConns     int64

	opts *Opts

	mu      sync.Mutex
	device  Device
	ipstack *stack.Stack
}

func New(opts *Opts) Proxy {
	// Default options
	return &proxy{
		// Default options
		opts: opts.ApplyDefaults(),
	}
}

func (p *proxy) Start(ctx context.Context) error {
	log.Debug("ipproxy serving traffic")
	opts := p.opts
	go func() {
		<-ctx.Done()
		p.Stop()
	}()

	networkProtocols := []stack.NetworkProtocolFactory{ipv4.NewProtocol}
	if !opts.DisableIPv6 {
		networkProtocols = append(networkProtocols, ipv6.NewProtocol)
	}

	var linkEndpoint stack.LinkEndpoint
	if opts.Device != nil {
		linkEndpoint = opts.Device.Endpoint()
	} else if opts.DeviceName != "" {
		device, err := parseDevice(opts.DeviceName, uint32(opts.MTU))
		if err != nil {
			return err
		}
		p.setDevice(device)
		linkEndpoint = device.Endpoint()
	} else {
		linkEndpoint = channel.New(512, uint32(opts.MTU), "")
	}
	ipstack := stack.New(stack.Options{
		NetworkProtocols:   networkProtocols,
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6},
	})
	p.setStack(ipstack)
	sackEnabledOpt := tcpip.TCPSACKEnabled(true) // TCP SACK is disabled by default
	if err := ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &sackEnabledOpt); err != nil {
		log.Errorf("could not enable TCP SACK: %v", err)
		return fmt.Errorf("could not enable TCP SACK: %v", err)
	}

	if err := ipstack.CreateNIC(nicID, linkEndpoint); err != nil {
		log.Errorf("could not create netstack NIC: %v", err)
		return fmt.Errorf("could not create netstack NIC: %v", err)
	}
	if err := ipstack.SetPromiscuousMode(nicID, true); err != nil {
		log.Errorf("Unable to set promiscuous mode: %v", err)
		return errors.New("Unable to set promiscuous mode: %v", err)
	}
	// Enable spoofing on the interface to allow replying from addresses other than those set on the interface
	if err := ipstack.SetSpoofing(nicID, true); err != nil {
		return fmt.Errorf("failed to enable spoofing on NIC: %v", err)
	}

	for _, ip := range opts.LocalAddresses {
		if err := addSubnetAddress(ipstack, ip); err != nil {
			return err
		}
	}

	ipstack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: nicID})
	if !opts.DisableIPv6 {
		ipstack.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: nicID})
	}

	// tcpReceiveBufferSize if set to zero, the default receive window buffer size is used instead.
	const tcpReceiveBufferSize = 0
	const maxInFlightConnectionAttempts = 1024
	tcpFwd := tcp.NewForwarder(ipstack, tcpReceiveBufferSize, maxInFlightConnectionAttempts, p.onTCP)
	udpFwd := udp.NewForwarder(ipstack, p.onUDP)

	ipstack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)
	ipstack.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

	ipstack.Wait()

	return nil
}

func (p *proxy) setDevice(device Device) {
	p.mu.Lock()
	p.device = device
	p.mu.Unlock()
}

func (p *proxy) setStack(s *stack.Stack) {
	p.mu.Lock()
	p.ipstack = s
	p.mu.Unlock()
}

// Stop shuts down the proxy in an orderly fashion and blocks until shutdown is complete.
func (p *proxy) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ipstack != nil {
		p.ipstack.Close()
		p.ipstack.Wait()
		p.ipstack = nil
	}
	if p.device != nil {
		p.device.Close()
		p.device = nil
	}
	return nil
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
