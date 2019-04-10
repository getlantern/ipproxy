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
	"github.com/google/netstack/waiter"

	"github.com/getlantern/errors"
	"github.com/getlantern/eventual"
)

const (
	nicID            = 1
	maxWriteWait     = 30 * time.Millisecond
	tcpipHeaderBytes = 40
)

type baseConn struct {
	lastActive int64
	p          *proxy
	upstream   eventual.Value
	ep         tcpip.Endpoint
	wq         *waiter.Queue
	waitEntry  *waiter.Entry
	notifyCh   chan struct{}

	closeable
}

func newBaseConn(p *proxy, upstream eventual.Value, wq *waiter.Queue, finalizer func() error) *baseConn {
	waitEntry, notifyCh := waiter.NewChannelEntry(nil)
	wq.EventRegister(&waitEntry, waiter.EventIn)

	conn := &baseConn{
		p:         p,
		upstream:  upstream,
		wq:        wq,
		waitEntry: &waitEntry,
		notifyCh:  notifyCh,
		closeable: closeable{
			closeCh:           make(chan struct{}),
			readyToFinalizeCh: make(chan struct{}),
			closedCh:          make(chan struct{}),
		},
	}

	conn.finalizer = func() (err error) {
		if finalizer != nil {
			err = finalizer()
		}

		upstream := conn.getUpstream(0)
		if upstream != nil {
			_err := upstream.Close()
			if err == nil {
				err = _err
			}
		}

		conn.wq.EventUnregister(conn.waitEntry)
		if conn.ep != nil {
			conn.ep.Close()
		}

		return
	}

	conn.markActive()

	return conn
}

func (conn *baseConn) getUpstream(timeout time.Duration) io.ReadWriteCloser {
	if conn.upstream == nil {
		return nil
	}
	upstream, ok := conn.upstream.Get(timeout)
	if !ok {
		return nil
	}
	return upstream.(io.ReadWriteCloser)
}

func (conn *baseConn) copyToUpstream(readAddr *tcpip.FullAddress) {
	defer conn.closeNow()

	upstream := conn.getUpstream(conn.p.opts.IdleTimeout)
	if upstream == nil {
		return
	}

	for {
		buf, _, readErr := conn.ep.Read(readAddr)
		if len(buf) > 0 {
			if _, writeErr := upstream.Write(buf); writeErr != nil {
				log.Errorf("Unexpected error writing to upstream: %v", writeErr)
				return
			}
		}

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

		conn.markActive()

		select {
		case <-conn.closeCh:
			return
		default:
			// keep processing
		}
	}
}

func (conn *baseConn) copyFromUpstream(responseOptions tcpip.WriteOptions) {
	defer conn.Close()

	upstream := conn.getUpstream(conn.p.opts.IdleTimeout)
	if upstream == nil {
		return
	}

	for {
		// we can't reuse this byte slice across reads because each one is held in
		// memory by the tcpip stack.
		b := make([]byte, conn.p.opts.MTU-tcpipHeaderBytes) // leave room for tcpip header that gets added later
		n, readErr := upstream.Read(b)

		if n > 0 {
			writeErr := conn.writeToDownstream(b[:n], responseOptions)
			if writeErr != nil {
				log.Errorf("Unexpected error writing to downstream: %v", writeErr)
				return
			}
		}

		if readErr != nil {
			if readErr != io.EOF && !strings.Contains(readErr.Error(), "use of closed network connection") {
				log.Errorf("Unexpected error reading from upstream: %v", readErr)
			}
			return
		}

		conn.markActive()
	}
}

func (conn *baseConn) writeToDownstream(b []byte, responseOptions tcpip.WriteOptions) *tcpip.Error {
	// write in a loop since partial writes are a possibility
	for i := time.Duration(0); true; i++ {
		n, _, writeErr := conn.ep.Write(tcpip.SlicePayload(b), responseOptions)
		if writeErr != nil {
			if writeErr == tcpip.ErrWouldBlock {
				// back off and retry
				waitTime := i * 1 * time.Millisecond
				if waitTime > maxWriteWait {
					waitTime = maxWriteWait
				}
				if waitTime > 0 {
					time.Sleep(waitTime)
				}
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
	return nil
}

func (conn *baseConn) markActive() {
	atomic.StoreInt64(&conn.lastActive, time.Now().UnixNano())
}

func (conn *baseConn) timeSinceLastActive() time.Duration {
	return time.Duration(time.Now().UnixNano() - atomic.LoadInt64(&conn.lastActive))
}

func newOrigin(p *proxy, transportProtocolName string, addr addr, upstream eventual.Value, finalizer func(o *origin) error) *origin {
	linkID, channelEndpoint := channel.New(p.opts.OutboundBufferDepth, uint32(p.opts.MTU), "")
	s := stack.New([]string{ipv4.ProtocolName}, []string{transportProtocolName}, stack.Options{})

	ipAddr := tcpip.Address(net.ParseIP(addr.ip).To4())

	o := &origin{
		addr:            addr,
		ipAddr:          ipAddr,
		stack:           s,
		linkID:          linkID,
		channelEndpoint: channelEndpoint,
		clients:         make(map[tcpip.FullAddress]*baseConn),
	}
	o.baseConn = newBaseConn(p, upstream, &waiter.Queue{}, func() (err error) {
		if finalizer != nil {
			err = finalizer(o)
		}
		s.Close()
		for _, ep := range tcpip.GetDanglingEndpoints() {
			ep.Close()
			tcpip.DeleteDanglingEndpoint(ep)
		}
		return
	})

	go o.copyToDownstream()
	return o
}

type origin struct {
	*baseConn
	addr            addr
	ipAddr          tcpip.Address
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
			select {
			case <-o.closedCh:
				return
			case o.p.toDownstream <- pktInfo:
			}
		}
	}
}

func (o *origin) init(transportProtocol tcpip.TransportProtocolNumber, bindAddr tcpip.FullAddress) error {
	if err := o.stack.CreateNIC(nicID, o.linkID); err != nil {
		return errors.New("Unable to create TCP NIC: %v", err)
	}
	if aErr := o.stack.AddAddress(nicID, o.p.proto, o.ipAddr); aErr != nil {
		return errors.New("Unable to assign NIC IP address: %v", aErr)
	}

	var epErr *tcpip.Error
	if o.ep, epErr = o.stack.NewEndpoint(transportProtocol, o.p.proto, o.wq); epErr != nil {
		return errors.New("Unable to create endpoint: %v", epErr)
	}

	if err := o.ep.Bind(bindAddr); err != nil {
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
