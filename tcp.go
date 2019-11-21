package ipproxy

import (
	"context"
	"sync"

	"github.com/google/netstack/tcpip"
	"github.com/google/netstack/tcpip/buffer"
	"github.com/google/netstack/tcpip/network/ipv4"
	"github.com/google/netstack/tcpip/transport/tcp"
	"github.com/google/netstack/waiter"

	"github.com/getlantern/errors"
	"github.com/getlantern/eventual"
)

func (p *proxy) onTCP(pkt ipPacket) {
	dstAddr := pkt.ft().dst
	o := p.tcpOrigins[dstAddr]
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
	o.channelEndpoint.InjectInbound(ipv4.ProtocolNumber, tcpip.PacketBuffer{
		Data: buffer.View(pkt.raw).ToVectorisedView(),
	})
}

func (p *proxy) createTCPOrigin(dstAddr addr) (*tcpOrigin, error) {
	o := &tcpOrigin{
		conns: make(map[tcpip.FullAddress]*baseConn),
	}
	o.origin = *newOrigin(p, tcp.NewProtocol(), dstAddr, nil, func(_o *origin) error {
		o.closeAllConns()
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

func acceptTCP(o *tcpOrigin) {
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
	go tcpConn.copyToUpstream(nil)
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
					p.removeTCPConn()
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
