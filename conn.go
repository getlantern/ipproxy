package ipproxy

import (
	"sync/atomic"
	"time"

	"github.com/google/netstack/tcpip"
	"github.com/google/netstack/waiter"

	"github.com/getlantern/errors"
)

type baseConn struct {
	lastActive int64
	p          *proxy
	ep         tcpip.Endpoint
	wq         waiter.Queue
	waitEntry  *waiter.Entry
	notifyCh   chan struct{}

	closeable
}

func newBaseConn(p *proxy) baseConn {
	return baseConn{
		p: p,
		closeable: closeable{
			closeCh:  make(chan struct{}),
			closedCh: make(chan error),
		},
	}
}

func (conn *baseConn) init(transportProtocol tcpip.TransportProtocolNumber, bindAddr tcpip.FullAddress) error {
	var epErr *tcpip.Error
	if conn.ep, epErr = conn.p.stack.NewEndpoint(transportProtocol, conn.p.proto, &conn.wq); epErr != nil {
		return errors.New("Unable to create endpoint: %v", epErr)
	}

	// Wait for connections to appear.
	_waitEntry, _notifyCh := waiter.NewChannelEntry(nil)
	conn.waitEntry = &_waitEntry
	conn.notifyCh = _notifyCh
	conn.wq.EventRegister(conn.waitEntry, waiter.EventIn)

	if err := conn.ep.Bind(bindAddr, nil); err != nil {
		conn.finalize()
		return errors.New("Bind failed: %v", err)
	}

	return nil
}

func (conn *baseConn) markActive() {
	atomic.StoreInt64(&conn.lastActive, time.Now().UnixNano())
}

func (conn *baseConn) timeSinceLastActive() time.Duration {
	return time.Duration(time.Now().UnixNano() - atomic.LoadInt64(&conn.lastActive))
}

func (conn *baseConn) finalize() {
	conn.wq.EventUnregister(conn.waitEntry)
	if conn.ep != nil {
		conn.ep.Close()
	}
}
