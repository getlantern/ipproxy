package ipproxy

import (
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/waiter"

	"github.com/getlantern/errors"
	"github.com/getlantern/eventual"
)

const (
	nicID            = 1
	maxWriteWait     = 30 * time.Millisecond
	tcpipHeaderBytes = 40
)

type baseConn struct {
	lastActive    int64
	p             *proxy
	upstream      eventual.Value
	ep            tcpip.Endpoint
	wq            *waiter.Queue
	waitEntry     *waiter.Entry
	notifyCh      chan struct{}
	context       context.Context
	cancelContext context.CancelFunc

	closeable
}

func newBaseConn(p *proxy, upstream eventual.Value, wq *waiter.Queue, finalizer func() error) *baseConn {
	waitEntry, notifyCh := waiter.NewChannelEntry(waiter.EventIn)
	wq.EventRegister(&waitEntry)
	ctx, cancelContext := context.WithCancel(context.Background())
	conn := &baseConn{
		p:             p,
		upstream:      upstream,
		wq:            wq,
		waitEntry:     &waitEntry,
		notifyCh:      notifyCh,
		context:       ctx,
		cancelContext: cancelContext,
		closeable: closeable{
			closeCh:           make(chan struct{}),
			readyToFinalizeCh: make(chan struct{}),
			closedCh:          make(chan struct{}),
		},
	}

	conn.finalizer = func() (err error) {
		defer func() {
			p := recover()
			if p != nil {
				log.Errorf("panic in finalizer: %v", p)
			}
		}()

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
		conn.cancelContext()

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

func (conn *baseConn) copyToUpstream() {
	defer conn.closeNow()

	upstream := conn.getUpstream(conn.p.opts.IdleTimeout)
	if upstream == nil {
		return
	}

	var b bytes.Buffer
	for {
		_, readErr := conn.ep.Read(&b, tcpip.ReadOptions{})
		if b.Len() > 0 {
			if _, writeErr := upstream.Write(b.Bytes()); writeErr != nil {
				log.Errorf("Unexpected error writing to upstream: %v", writeErr)
				return
			}
		}

		if readErr != nil {
			if _, ok := readErr.(*tcpip.ErrWouldBlock); ok {
				select {
				case <-conn.closeCh:
					return
				case <-conn.notifyCh:
					continue
				}
			}
			errString := readErr.String()
			if !strings.Contains(errString, "endpoint is closed for receive") &&
				!strings.Contains(errString, "connection reset") {
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
		n, writeErr := conn.ep.Write(bytes.NewBuffer(b), responseOptions)
		if writeErr != nil {
			if _, ok := writeErr.(*tcpip.ErrWouldBlock); ok {
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
			return &writeErr
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

func newOrigin(p *proxy, transportProtocol stack.TransportProtocolFactory, addr addr, upstream eventual.Value, finalizer func(o *origin) error) *origin {
	channelEndpoint := channel.New(p.opts.OutboundBufferDepth, uint32(p.opts.MTU), "")
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{transportProtocol},
	})

	o := &origin{
		addr:            addr,
		ipAddr:          tcpip.AddrFrom4([4]byte(net.ParseIP(addr.ip).To4())),
		stack:           s,
		channelEndpoint: channelEndpoint,
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
	channelEndpoint *channel.Endpoint
}

func (o *origin) copyToDownstream() {
	for {
		select {
		case <-o.closedCh:
			return
		default:
			if ptr := o.channelEndpoint.ReadContext(o.context); ptr != nil {
				select {
				case o.p.toDownstream <- ptr.Clone():
					continue
				default:
					return
				}
			}

		}
	}
}

func (o *origin) init(transportProtocol tcpip.TransportProtocolNumber, bindAddr tcpip.FullAddress) error {
	if err := o.stack.CreateNIC(nicID, o.channelEndpoint); err != nil {
		return errors.New("Unable to create TCP NIC: %v", err)
	}

	if aErr := o.stack.AddProtocolAddress(nicID, tcpip.ProtocolAddress{Protocol: o.p.proto, AddressWithPrefix: o.ipAddr.WithPrefix()}, stack.AddressProperties{}); aErr != nil {
		return errors.New("Unable to assign NIC IP address: %v", aErr)
	}

	var epErr tcpip.Error
	if o.ep, epErr = o.stack.NewEndpoint(transportProtocol, o.p.proto, o.wq); epErr != nil {
		o.ep = nil
		return errors.New("Unable to create endpoint: %v", epErr)
	}

	if err := o.ep.Bind(bindAddr); err != nil {
		return errors.New("Bind failed: %v", err)
	}

	return nil
}
