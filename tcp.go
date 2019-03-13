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
	if o == nil {
		var err error
		o, err = p.createTCPOrigin(dstAddr)
		if err != nil {
			log.Error(err)
			return
		}
		p.tcpOrigins[dstAddr] = o
	}
	p.tcpOriginsMx.Unlock()

	o.channelEndpoint.Inject(ipv4.ProtocolNumber, buffer.View(pkt.raw).ToVectorisedView())
}

func (p *proxy) createTCPOrigin(dstAddr addr) (*origin, error) {
	o := newOrigin(p, dstAddr, nil, func(o *origin) error {
		p.tcpOriginsMx.Lock()
		delete(p.tcpOrigins, dstAddr)
		o.clientsMx.Lock()
		clients := make([]*baseConn, 0, len(o.clients))
		for _, client := range o.clients {
			clients = append(clients, client)
		}
		o.clientsMx.Unlock()
		for _, client := range o.clients {
			client.closeNow()
		}
		p.tcpOriginsMx.Unlock()
		return nil
	})

	if err := o.init(tcp.ProtocolNumber, tcpip.FullAddress{nicID, o.ipAddr, dstAddr.port}); err != nil {
		o.closeNow()
		return nil, errors.New("Unable to initialize TCP origin: %v", err)
	}
	if pErr := o.stack.SetPromiscuousMode(nicID, true); pErr != nil {
		o.closeNow()
		return nil, errors.New("Unable to set NIC to promiscuous mode: %v", pErr)
	}

	if err := o.ep.Listen(p.opts.TCPConnectBacklog); err != nil {
		o.closeNow()
		return nil, errors.New("Unable to listen for TCP connections: %v", err)
	}

	go acceptTCP(o)
	return o, nil
}

func acceptTCP(o *origin) {
	defer o.closeNow()

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
	o.addClient(downstreamAddr, tcpConn)
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

			for _, o := range origins {
				o.clientsMx.Lock()
				conns := make([]*baseConn, 0, len(o.clients))
				for _, conn := range o.clients {
					conns = append(conns, conn)
				}
				o.clientsMx.Unlock()
				if len(conns) > 0 {
					for _, conn := range conns {
						if conn.timeSinceLastActive() > p.opts.IdleTimeout {
							go conn.closeNow()
						}
					}
				} else if o.timeSinceLastActive() > p.opts.IdleTimeout {
					go o.closeNow()
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
		_err := o.closeNow()
		if err == nil {
			err = _err
		}
	}

	return
}
