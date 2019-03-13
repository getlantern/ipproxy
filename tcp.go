package ipproxy

import (
	"context"
	"time"

	"github.com/google/netstack/tcpip"
	"github.com/google/netstack/tcpip/buffer"
	"github.com/google/netstack/tcpip/network/ipv4"
	"github.com/google/netstack/tcpip/transport/tcp"
	"github.com/google/netstack/waiter"

	"github.com/getlantern/errors"
)

func (p *proxy) onTCP(pkt ipPacket) {
	dstAddr := pkt.ft().dst
	p.tcpOriginsMx.Lock()
	o := p.tcpOrigins[dstAddr]
	p.tcpOriginsMx.Unlock()
	if o == nil {
		var err error
		o, err = p.createTCPOrigin(dstAddr)
		if err != nil {
			log.Error(err)
			return
		}
		p.tcpOriginsMx.Lock()
		p.tcpOrigins[dstAddr] = o
		p.tcpOriginsMx.Unlock()
	}

	o.channelEndpoint.Inject(ipv4.ProtocolNumber, buffer.View(pkt.raw).ToVectorisedView())
}

func (p *proxy) createTCPOrigin(dstAddr addr) (*origin, error) {
	o := newOrigin(p, dstAddr, func() error {
		p.removeTCPOrigin(dstAddr)
		return nil
	})
	o.markActive()

	if err := o.init(tcp.ProtocolNumber, tcpip.FullAddress{nicID, o.ipAddr, dstAddr.port}); err != nil {
		return nil, errors.New("Unable to initialize TCP origin: %v", err)
	}
	if pErr := o.stack.SetPromiscuousMode(nicID, true); pErr != nil {
		return nil, errors.New("Unable to set NIC to promiscuous mode: %v", pErr)
	}

	if err := o.ep.Listen(p.opts.TCPConnectBacklog); err != nil {
		o.finalize()
		return nil, errors.New("Unable to listen for TCP connections: %v", err)
	}

	go acceptTCP(o)
	return o, nil
}

func acceptTCP(o *origin) {
	defer func() {
		o.closedCh <- o.finalize()
		close(o.closedCh)
	}()

	for {
		acceptedEp, wq, err := o.ep.Accept()
		if err != nil {
			if err == tcpip.ErrWouldBlock {
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

func (o *origin) onAccept(acceptedEp tcpip.Endpoint, wq *waiter.Queue) {
	upstream, dialErr := o.p.opts.DialTCP(context.Background(), "tcp", o.addr.String())
	if dialErr != nil {
		log.Errorf("Unexpected error dialing upstream to %v: %v", o.addr, dialErr)
		o.Close()
		return
	}

	downstreamAddr, _ := acceptedEp.GetRemoteAddress()
	tcpConn := newBaseConn(o.p, upstream, wq, func() error {
		o.removeClient(downstreamAddr)
		return nil
	})
	tcpConn.ep = acceptedEp
	go tcpConn.copyToUpstream(nil)
	go tcpConn.copyFromUpstream(tcpip.WriteOptions{})
	tcpConn.markActive()
	o.addClient(downstreamAddr, &tcpConn)
}

func (p *proxy) removeTCPOrigin(dstAddr addr) {
	p.tcpOriginsMx.Lock()
	delete(p.tcpOrigins, dstAddr)
	p.tcpOriginsMx.Unlock()
}

// reapUDP reaps idled TCP connections and origins. We do this on a single
// goroutine to avoid creating a bunch of timers for each connection
// (which is expensive).
func (p *proxy) reapTCP() {
	ticker := time.NewTicker(1 * time.Second)
	for {
		select {
		case <-p.closeCh:
			return
		case <-ticker.C:
			p.tcpOriginsMx.Lock()
			origins := make(map[addr]*origin, len(p.tcpOrigins))
			for a, o := range p.tcpOrigins {
				origins[a] = o
			}
			p.tcpOriginsMx.Unlock()

			for a, o := range origins {
				o.clientsMx.Lock()
				conns := make([]*baseConn, 0, len(o.clients))
				for _, conn := range o.clients {
					conns = append(conns, conn)
				}
				o.clientsMx.Unlock()
				if len(conns) > 0 {
					for _, conn := range conns {
						if conn.timeSinceLastActive() > p.opts.IdleTimeout {
							go conn.Close()
						}
					}
				} else if o.timeSinceLastActive() > p.opts.IdleTimeout {
					o.p.removeTCPOrigin(a)
					go o.Close()
				}
			}
		}
	}
}

func (p *proxy) finalizeTCP() (err error) {
	p.tcpOriginsMx.Lock()
	origins := make(map[addr]*origin, len(p.tcpOrigins))
	for a, o := range p.tcpOrigins {
		origins[a] = o
	}
	p.tcpOriginsMx.Unlock()

	for _, o := range origins {
		o.clientsMx.Lock()
		conns := make([]*baseConn, 0, len(o.clients))
		for _, conn := range o.clients {
			conns = append(conns, conn)
		}
		o.clientsMx.Unlock()

		for _, conn := range conns {
			if conn.timeSinceLastActive() > p.opts.IdleTimeout {
				_err := conn.Close()
				if err == nil {
					err = _err
				}
			}
		}

		_err := o.Close()
		if err == nil {
			err = _err
		}
	}

	return
}
