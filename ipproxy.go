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
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"

	"github.com/getlantern/dnsgrab"
	"github.com/getlantern/errors"
	"github.com/getlantern/golog"
	"github.com/getlantern/netx"

	"github.com/getlantern/ipproxy/utils"
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

	DnsGrabAddress string
	DnsGrabServer dnsgrab.Server

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

	ipstack *stack.Stack
	linkEP    *channel.Endpoint

	toDownstream chan stack.PacketBufferPtr

	mu sync.Mutex
	connsOpenBySubnetIP map[netip.Addr]int

	dnsGrabUDPAddr *net.UDPAddr

	writeHandle *channel.NotificationHandle

	closeable
}

func (p *proxy) Serve() error {
	log.Debug("ipproxy serving traffic")

	serveCtx, cancel := context.WithCancel(context.Background())
	go func() {
		<-p.closeCh
		cancel()
	}()
	// tcpReceiveBufferSize if set to zero, the default receive window buffer size is used instead.
	const tcpReceiveBufferSize = 0
	const maxInFlightConnectionAttempts = 1024
	tcpFwd := tcp.NewForwarder(p.ipstack, tcpReceiveBufferSize, maxInFlightConnectionAttempts, p.onTCP)
	udpFwd := udp.NewForwarder(p.ipstack, p.onUDP)
	p.ipstack.SetTransportProtocolHandler(tcp.ProtocolNumber, p.wrapProtoHandler(tcpFwd.HandlePacket))
	p.ipstack.SetTransportProtocolHandler(udp.ProtocolNumber, p.wrapProtoHandler(udpFwd.HandlePacket))
	go p.copyToDownstream(serveCtx)
	go p.copyFromUpstream()
	var wg sync.WaitGroup
	wg.Add(1)
	go p.copyToUpstream(&wg)
	return p.readDownstreamPackets(&wg)
}

func New(downstream io.ReadWriter, opts *Opts) (Proxy, error) {

	// Default options
	opts = opts.ApplyDefaults()
	var dnsGrabUDPAddr *net.UDPAddr
	if opts.DnsGrabAddress != "" {
		var err error
		log.Debugf("dnsgrab enabled, rerouting DNS requests to %s", opts.DnsGrabAddress)
		dnsGrabUDPAddr, err = netx.ResolveUDPAddr("udp", opts.DnsGrabAddress)
		if err != nil {
			return nil, log.Errorf("unable to resolve dnsGrabAddr: %v", err)
		}
	}
	ipstack := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6},
	})
	sackEnabledOpt := tcpip.TCPSACKEnabled(true) // TCP SACK is disabled by default
	if err := ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &sackEnabledOpt); err != nil {
		log.Errorf("could not enable TCP SACK: %v", err)
		return nil, fmt.Errorf("could not enable TCP SACK: %v", err)
	}
	linkEP := channel.New(512, uint32(opts.MTU), "")
	if err := ipstack.CreateNIC(nicID, linkEP); err != nil {
		log.Errorf("could not create netstack NIC: %v", err)
		return nil, fmt.Errorf("could not create netstack NIC: %v", err)
	}
	if err := ipstack.SetPromiscuousMode(nicID, true); err != nil {
		log.Errorf("Unable to set promiscuous mode: %v", err)
		return nil, errors.New("Unable to set promiscuous mode: %v", err)
	}
	ipstack.SetSpoofing(nicID, true) // Otherwise our TCP connection can not find the route backward
	ipstack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: nicID})

	p := &proxy{
		opts:         opts,
		proto:        ipv4.ProtocolNumber,
		downstream:   downstream,
		ipstack:      ipstack,
		linkEP: 	  linkEP,
		pktIn:        make(chan ipPacket, 1000),
		toDownstream: make(chan stack.PacketBufferPtr),
		connsOpenBySubnetIP: make(map[netip.Addr]int),
		closeable: closeable{
			closeCh:           make(chan struct{}),
			readyToFinalizeCh: make(chan struct{}),
			closedCh:          make(chan struct{}),
		},
		dnsGrabUDPAddr: dnsGrabUDPAddr,
	}

	return p, nil
}


func isLocalIP(ip net.IP) bool {
	privateIPNetworks := []net.IPNet{
	  net.IPNet{
	       IP: net.ParseIP(utils.GetLocalIP()),
	  },
	  net.IPNet{
	       IP:   net.ParseIP("10.0.0.2"),
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
	for _, ipNet := range privateIPNetworks {
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

	p.mu.Lock()
	p.connsOpenBySubnetIP[ip]++
	needAdd := p.connsOpenBySubnetIP[ip] == 1
	p.mu.Unlock()

	if !needAdd {
		return
	}

	log.Debugf("Adding subnet address %s", ip.String())

	pa := tcpip.ProtocolAddress{
		AddressWithPrefix: tcpip.AddrFromSlice(ip.AsSlice()).WithPrefix(),
	}
	if ip.Is4() {
		pa.Protocol = ipv4.ProtocolNumber
	} else if ip.Is6() {
		pa.Protocol = ipv6.ProtocolNumber
	}
	// Add the given network address to the NIC
	p.ipstack.AddProtocolAddress(nicID, pa, stack.AddressProperties{
		PEB:        stack.CanBePrimaryEndpoint, // zero value default
		ConfigType: stack.AddressConfigStatic,  // zero value default
	})
}

func (p *proxy) copyToDownstream(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			if ptr := p.linkEP.ReadContext(ctx); ptr != nil {
				select {
				case <-ctx.Done():
					return
				case p.toDownstream <- ptr.Clone():
					continue
				}
			}
		}
	}
}

func (p *proxy) copyFromUpstream() {
	defer p.Close()

	for {
		select {
		case <-p.closedCh:
			return
		case pktInfo := <-p.toDownstream:
			pkt := make([]byte, 0, p.opts.MTU)
			for _, view := range pktInfo.AsSlices() {
				pkt = append(pkt, view...)
			}

			_, err := p.downstream.Write(pkt)
			pktInfo.DecRef()
			if err != nil {
				log.Errorf("Unexpected error writing to downstream: %v", err)
				return
			}
		}
	}
}

func (p *proxy) copyToUpstream(wg *sync.WaitGroup) {
	defer wg.Done()
	defer p.closeNow()
	defer p.ipstack.Close()

	for {
		select {
		case pkt := <-p.pktIn:
			switch pkt.ipProto {
			case IPProtocolICMP:
				fallthrough
			case IPProtocolUDP:
				fallthrough
			case IPProtocolTCP:
				p.acceptedPacket()
				p.linkEP.InjectInbound(ipv4.ProtocolNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{
					Payload: buffer.MakeWithData(pkt.raw)},
				))
			default:
				p.rejectedPacket()
				log.Debugf("Unknown IP protocol, ignoring: %v", pkt.ipProto)
				continue
			}
		case <-p.closeCh:
			return
		}
	}
}

func (p *proxy) readDownstreamPackets(wg *sync.WaitGroup) (finalErr error) {
	defer wg.Wait() // wait for copyToUpstream to finish with all of its cleanup
	defer p.closeNow()
	b := make([]byte, p.opts.MTU)
	for {
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

