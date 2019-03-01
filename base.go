package ipproxy

import (
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/netstack/tcpip"
	"github.com/google/netstack/waiter"

	"github.com/getlantern/errors"
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

func newBaseConn(p *proxy, upstream io.ReadWriteCloser, finalizer func() error) baseConn {
	return newBaseConnWithQueue(p, upstream, &waiter.Queue{}, finalizer)
}

func newBaseConnWithQueue(p *proxy, upstream io.ReadWriteCloser, wq *waiter.Queue, finalizer func() error) baseConn {
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

func (conn *baseConn) init(transportProtocol tcpip.TransportProtocolNumber, bindAddr tcpip.FullAddress) error {
	var epErr *tcpip.Error
	if conn.ep, epErr = conn.p.stack.NewEndpoint(transportProtocol, conn.p.proto, conn.wq); epErr != nil {
		return errors.New("Unable to create endpoint: %v", epErr)
	}

	if err := conn.ep.Bind(bindAddr, nil); err != nil {
		conn.finalize()
		return errors.New("Bind failed: %v", err)
	}

	return nil
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

		_, _, writeErr := conn.ep.Write(tcpip.SlicePayload(b[:n]), responseOptions)
		if writeErr != nil {
			log.Errorf("Unexpected error writing to downstream: %v", writeErr)
			return
		}
		conn.markActive()
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

func newOrigin(p *proxy, addr string, finalizer func() error) *origin {
	return &origin{
		baseConn: newBaseConnWithQueue(p, nil, &waiter.Queue{}, finalizer),
		addr:     addr,
		clients:  make(map[tcpip.FullAddress]*baseConn),
	}
}

type origin struct {
	baseConn
	addr      string
	clients   map[tcpip.FullAddress]*baseConn
	clientsMx sync.Mutex
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
