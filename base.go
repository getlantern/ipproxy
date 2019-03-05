package ipproxy

import (
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/netstack/tcpip"
	"github.com/google/netstack/tcpip/link/channel"
	"github.com/google/netstack/tcpip/network/ipv4"
	"github.com/google/netstack/tcpip/stack"
	"github.com/google/netstack/tcpip/transport/tcp"
	"github.com/google/netstack/tcpip/transport/udp"
	"github.com/google/netstack/waiter"

	"github.com/getlantern/errors"
)

const (
	nicID = 1
)

type baseConn struct {
	lastActive int64
	p          *proxy
	upstream   io.ReadWriteCloser
	finalizer  func() error
	ep         tcpip.Endpoint
	wq         *waiter.Queue
	waitEntry  *waiter.Entry
	notifyCh   chan struct{}

	closeable
}

func newBaseConn(p *proxy, upstream io.ReadWriteCloser, wq *waiter.Queue, finalizer func() error) baseConn {
	if finalizer == nil {
		finalizer = func() error { return nil }
	}

	waitEntry, notifyCh := waiter.NewChannelEntry(nil)
	wq.EventRegister(&waitEntry, waiter.EventIn)

	return baseConn{
		p:         p,
		upstream:  upstream,
		finalizer: finalizer,
		wq:        wq,
		waitEntry: &waitEntry,
		notifyCh:  notifyCh,
		closeable: closeable{
			closeCh:  make(chan struct{}),
			closedCh: make(chan error),
		},
	}
}

func (conn *baseConn) copyToUpstream(readAddr *tcpip.FullAddress) {
	defer func() {
		conn.closedCh <- conn.finalize()
		close(conn.closedCh)
	}()

	for {
		buf, _, readErr := conn.ep.Read(readAddr)
		if readErr != nil {
			if readErr == tcpip.ErrWouldBlock {
				select {
				case <-conn.closeCh:
					return
				case <-conn.notifyCh:
					continue
				}
			}
			if !strings.Contains(readErr.String(), "endpoint is closed for receive") {
				log.Errorf("Unexpected error reading from downstream: %v", readErr)
			}
			return
		}
		if _, writeErr := conn.upstream.Write(buf); writeErr != nil {
			log.Errorf("Unexpected error writing to upstream: %v", writeErr)
			return
		}
		conn.markActive()
	}
}

func (conn *baseConn) copyFromUpstream(responseOptions tcpip.WriteOptions) {
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

		writeErr := conn.writeToDownstream(b[:n], responseOptions)
		if writeErr != nil {
			log.Errorf("Unexpected error writing to downstream: %v", writeErr)
			return
		}
		conn.markActive()
	}
}

func (conn *baseConn) writeToDownstream(b []byte, responseOptions tcpip.WriteOptions) *tcpip.Error {
	// write in a loop since partial writes are a possibility
	for {
		n, notifyCh, writeErr := conn.ep.Write(tcpip.SlicePayload(b), responseOptions)
		if writeErr != nil {
			if writeErr == tcpip.ErrWouldBlock {
				<-notifyCh
				continue
			}
			return writeErr
		}
		b = b[n:]
		if len(b) == 0 {
			// done writing
			return nil
		}
	}
}

func (conn *baseConn) markActive() {
	atomic.StoreInt64(&conn.lastActive, time.Now().UnixNano())
}

func (conn *baseConn) timeSinceLastActive() time.Duration {
	return time.Duration(time.Now().UnixNano() - atomic.LoadInt64(&conn.lastActive))
}

func (conn *baseConn) finalize() error {
	err := conn.finalizer()
	if conn.upstream != nil {
		_err := conn.upstream.Close()
		if err == nil {
			err = _err
		}
	}

	conn.wq.EventUnregister(conn.waitEntry)
	if conn.ep != nil {
		conn.ep.Close()
	}

	return err
}

func newOrigin(p *proxy, addr addr, finalizer func() error) *origin {
	linkID, channelEndpoint := channel.New(p.opts.OutboundBufferDepth, uint32(p.opts.MTU), "")
	s := stack.New([]string{ipv4.ProtocolName}, []string{tcp.ProtocolName, udp.ProtocolName}, stack.Options{})

	o := &origin{
		baseConn:        newBaseConn(p, nil, &waiter.Queue{}, finalizer),
		addr:            addr.String(),
		stack:           s,
		linkID:          linkID,
		channelEndpoint: channelEndpoint,
		clients:         make(map[tcpip.FullAddress]*baseConn),
	}
	go o.copyToDownstream()
	return o
}

type origin struct {
	baseConn
	addr            string
	stack           *stack.Stack
	linkID          tcpip.LinkEndpointID
	channelEndpoint *channel.Endpoint
	clients         map[tcpip.FullAddress]*baseConn
	clientsMx       sync.Mutex
}

func (o *origin) copyToDownstream() {
	for {
		select {
		case <-o.closedCh:
			return
		case pktInfo := <-o.channelEndpoint.C:
			o.p.toDownstream <- pktInfo
		}
	}
}

func (o *origin) init(transportProtocol tcpip.TransportProtocolNumber, ipAddr tcpip.Address, bindAddr tcpip.FullAddress) error {
	if err := o.stack.CreateNIC(nicID, o.linkID); err != nil {
		return errors.New("Unable to create TCP NIC: %v", err)
	}
	if aErr := o.stack.AddAddress(nicID, o.p.proto, ipAddr); aErr != nil {
		return errors.New("Unable to assign NIC IP address: %v", aErr)
	}

	var epErr *tcpip.Error
	if o.ep, epErr = o.stack.NewEndpoint(transportProtocol, o.p.proto, o.wq); epErr != nil {
		return errors.New("Unable to create endpoint: %v", epErr)
	}

	if err := o.ep.Bind(bindAddr, nil); err != nil {
		o.finalize()
		return errors.New("Bind failed: %v", err)
	}

	return nil
}

func (o *origin) addClient(addr tcpip.FullAddress, client *baseConn) {
	o.clientsMx.Lock()
	o.clients[addr] = client
	o.clientsMx.Unlock()
}

func (o *origin) removeClient(addr tcpip.FullAddress) {
	o.clientsMx.Lock()
	delete(o.clients, addr)
	o.clientsMx.Unlock()
}

func (o *origin) numClients() int {
	o.clientsMx.Lock()
	numClients := len(o.clients)
	o.clientsMx.Unlock()
	return numClients
}
