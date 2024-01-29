package ipproxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
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
	if p.opts.DebugPackets {
		log.Debugf("onTCP: %s", stringifyTEI(reqDetails))
	}
	clientRemoteIP := netaddrIPFromNetstackIP(reqDetails.RemoteAddress)

	dialIP := netaddrIPFromNetstackIP(reqDetails.LocalAddress)
	var wq waiter.Queue

	defer p.removeSubnetAddress(dialIP)

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
}

func (p *proxy) removeSubnetAddress(ip netip.Addr) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.connsOpenBySubnetIP[ip]--
	if p.connsOpenBySubnetIP[ip] == 0 {
		p.ipstack.RemoveAddress(nicID, tcpip.AddrFromSlice(ip.AsSlice()))
		delete(p.connsOpenBySubnetIP, ip)
	}
}

func (p *proxy)  forwardTCP(getClient func(...tcpip.SettableSocketOption) *gonet.TCPConn, clientRemoteIP netip.Addr, 
	wq *waiter.Queue, dialAddr netip.AddrPort) (handled bool) {
	dialAddrStr := dialAddr.String()
	if p.opts.DebugPackets {
		log.Debugf("forwarding incoming connection to %s", dialAddrStr)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	waitEntry, notifyCh := waiter.NewChannelEntry(waiter.EventHUp)
	wq.EventRegister(&waitEntry)
	defer wq.EventUnregister(&waitEntry)
	done := make(chan bool)
	defer close(done)
	go func() {
		select {
		case <-notifyCh:
			if p.opts.DebugPackets {
				log.Debugf("netstack: forwardTCP notifyCh fired; canceling context for %s", dialAddrStr)
			}
		case <-done:
		}
		cancel()
	}()

	// Attempt to dial the outbound connection before we accept the inbound one.
	if p.opts.DebugPackets {
		log.Debugf("Dialing outbound connection to %s", dialAddrStr)
	}
	server, err := p.opts.DialTCP(ctx, "tcp", dialAddrStr)
	if err != nil {
		log.Errorf("netstack: could not connect to local server at %s: %v", dialAddr.String(), err)
		return
	}
	defer server.Close()

	handled = true

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
	if err != nil && p.opts.DebugPackets {
		log.Errorf("proxy connection closed with error: %v", err)
	}
	if p.opts.DebugPackets {
		log.Debugf("tcp forwarder connection to %s closed", dialAddrStr)
	}
	return
}

