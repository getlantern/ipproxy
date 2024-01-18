package ipproxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"

	"github.com/getlantern/errors"
	"github.com/getlantern/eventual"
)

func netaddrIPFromNetstackIP(s tcpip.Address) netip.Addr {
	switch s.Len() {
	case 4:
		s := s.As4()
		return netip.AddrFrom4(s)
	case 16:
		s := s.As16()
		return netip.AddrFrom16(s).Unmap()
	}
	return netip.Addr{}
}

func stringifyTEI(tei stack.TransportEndpointID) string {
	localHostPort := net.JoinHostPort(tei.LocalAddress.String(), strconv.Itoa(int(tei.LocalPort)))
	remoteHostPort := net.JoinHostPort(tei.RemoteAddress.String(), strconv.Itoa(int(tei.RemotePort)))
	return fmt.Sprintf("%s -> %s", remoteHostPort, localHostPort)
}

func (p *proxy) onTCP(r *tcp.ForwarderRequest) {
	reqDetails := r.ID()
	clientRemoteIP := netaddrIPFromNetstackIP(reqDetails.RemoteAddress)

	dialIP := netaddrIPFromNetstackIP(reqDetails.LocalAddress)
	var wq waiter.Queue

	getConnOrReset := func(opts ...tcpip.SettableSocketOption) *gonet.TCPConn {
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			log.Errorf("CreateEndpoint error for %s: %v", stringifyTEI(reqDetails), err)
			r.Complete(true) // sends a RST
			return nil
		}
		r.Complete(false)
		for _, opt := range opts {
			ep.SetSockOpt(opt)
		}
		ep.SocketOptions().SetKeepAlive(true)
		return gonet.NewTCPConn(&wq, ep)
	}

	dialAddr := netip.AddrPortFrom(dialIP, uint16(reqDetails.LocalPort))

	if !p.forwardTCP(getConnOrReset, clientRemoteIP, &wq, dialAddr) {
		r.Complete(true) // sends a RST
	}

	/*o := p.tcpOrigins[dstAddr]
	if o == nil {
		var err error
		o, err = p.createTCPOrigin(dstAddr)
		if err != nil {
			log.Error(err)
			return
		}
		p.tcpOrigins[dstAddr] = o
		p.addTCPOrigin()
	}

	packetBuffer := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(pkt.raw)},
	)
	o.channelEndpoint.InjectInbound(ipv4.ProtocolNumber, packetBuffer)*/
}

func (p *proxy)  forwardTCP(getClient func(...tcpip.SettableSocketOption) *gonet.TCPConn, clientRemoteIP netip.Addr, 
	wq *waiter.Queue, dialAddr netip.AddrPort) (handled bool) {
	dialAddrStr := dialAddr.String()
	log.Debugf("[v2] netstack: forwarding incoming connection to %s", dialAddrStr)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	waitEntry, notifyCh := waiter.NewChannelEntry(waiter.EventHUp) // TODO(bradfitz): right EventMask?
	wq.EventRegister(&waitEntry)
	defer wq.EventUnregister(&waitEntry)
	done := make(chan bool)
	// netstack doesn't close the notification channel automatically if there was no
	// hup signal, so we close done after we're done to not leak the goroutine below.
	defer close(done)
	go func() {
		select {
		case <-notifyCh:
			log.Debugf("netstack: forwardTCP notifyCh fired; canceling context for %s", dialAddrStr)
		case <-done:
		}
		cancel()
	}()

	// Attempt to dial the outbound connection before we accept the inbound one.
	server, err := p.opts.DialTCP(ctx, "tcp", dialAddrStr)
	if err != nil {
		log.Errorf("netstack: could not connect to local server at %s: %v", dialAddr.String(), err)
		return
	}
	defer server.Close()

	handled = true

	// We dialed the connection; we can complete the client's TCP handshake.
	client := getClient()
	if client == nil {
		return
	}
	defer client.Close()

	connClosed := make(chan error, 2)
	go func() {
		_, err := io.Copy(server, client)
		connClosed <- err
	}()
	go func() {
		_, err := io.Copy(client, server)
		connClosed <- err
	}()
	err = <-connClosed
	if err != nil {
		log.Errorf("proxy connection closed with error: %v", err)
	}
	log.Debugf("netstack: forwarder connection to %s closed", dialAddrStr)
	return
}

func (p *proxy) createTCPOrigin(dstAddr netip.AddrPort) (*tcpOrigin, error) {
	o := &tcpOrigin{
		conns: make(map[tcpip.FullAddress]*baseConn),
	}
	o.origin = *newOrigin(p, tcp.NewProtocol, dstAddr, nil, func(_o *origin) error {
		o.closeAllConns()
		return nil
	})

	if err := o.init(tcp.ProtocolNumber, tcpip.FullAddress{NIC: nicID, Addr: o.ipAddr, Port: dstAddr.Port()}); err != nil {
		o.closeNow()
		return nil, errors.New("Unable to initialize TCP origin: %v", err)
	}

	o.stack.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
	})

	if err := o.ep.Listen(p.opts.TCPConnectBacklog); err != nil {
		o.closeNow()
		return nil, errors.New("Unable to listen for TCP connections: %v", err)
	}

	go acceptTCP(o)
	return o, nil
}

func acceptTCP(o *tcpOrigin) {
	defer o.closeNow()

	for {
		acceptedEp, wq, err := o.ep.Accept(nil)
		if err != nil {
			if _, ok := err.(*tcpip.ErrWouldBlock); ok {
				select {
				case <-o.closeCh:
					return
				case <-o.notifyCh:
					continue
				}
			}
			log.Errorf("Accept() failed: %v", err)
			return
		}

		go o.onAccept(acceptedEp, wq)
	}
}

func (o *tcpOrigin) onAccept(acceptedEp tcpip.Endpoint, wq *waiter.Queue) {
	upstream, dialErr := o.p.opts.DialTCP(context.Background(), "tcp", o.addr.String())
	if dialErr != nil {
		log.Errorf("Unexpected error dialing upstream to %v: %v", o.addr, dialErr)
		return
	}

	upstreamValue := eventual.NewValue()
	upstreamValue.Set(upstream)

	downstreamAddr, _ := acceptedEp.GetRemoteAddress()
	tcpConn := newBaseConn(o.p, upstreamValue, wq, func() error {
		o.removeConn(downstreamAddr)
		return nil
	})
	tcpConn.ep = acceptedEp
	go tcpConn.copyToUpstream()
	go tcpConn.copyFromUpstream(tcpip.WriteOptions{})
	o.addConn(downstreamAddr, tcpConn)
}

type tcpOrigin struct {
	origin
	conns   map[tcpip.FullAddress]*baseConn
	connsMx sync.Mutex
}

func (o *tcpOrigin) addConn(addr tcpip.FullAddress, conn *baseConn) {
	o.connsMx.Lock()
	o.conns[addr] = conn
	o.connsMx.Unlock()
	o.p.addTCPConn()
}

func (o *tcpOrigin) removeConn(addr tcpip.FullAddress) {
	o.connsMx.Lock()
	_, found := o.conns[addr]
	if found {
		delete(o.conns, addr)
	}
	o.connsMx.Unlock()
	if found {
		o.p.removeTCPConn()
	}
}

func (o *tcpOrigin) closeAllConns() {
	o.connsMx.Lock()
	conns := make([]*baseConn, 0, len(o.conns))
	for _, conn := range o.conns {
		conns = append(conns, conn)
	}
	o.connsMx.Unlock()
	for _, conn := range conns {
		conn.closeNow()
	}
}

func (p *proxy) reapTCP() {
	for a, o := range p.tcpOrigins {
		o.connsMx.Lock()
		conns := make([]*baseConn, 0, len(o.conns))
		for _, conn := range o.conns {
			conns = append(conns, conn)
		}
		o.connsMx.Unlock()
		timeSinceOriginLastActive := o.timeSinceLastActive()
		if len(conns) > 0 {
			for _, conn := range conns {
				timeSinceConnLastActive := conn.timeSinceLastActive()
				if timeSinceConnLastActive > p.opts.IdleTimeout {
					log.Debug("Reaping TCP conn")
					go conn.closeNow()
				}
				if timeSinceConnLastActive < timeSinceOriginLastActive {
					timeSinceOriginLastActive = timeSinceConnLastActive
				}
			}
		}
		if timeSinceOriginLastActive > p.opts.IdleTimeout {
			go o.closeNow()
			delete(p.tcpOrigins, a)
			p.removeTCPOrigin()
		}
	}
}

func (p *proxy) closeTCP() {
	for a, o := range p.tcpOrigins {
		log.Debug("Closing all conns")
		o.closeAllConns()
		log.Debug("Closing origin")
		o.closeNow()
		delete(p.tcpOrigins, a)
		p.removeTCPOrigin()
		log.Debug("Removed origin")
	}
}
