package ipproxy

import (
	"context"
	"net"
	"time"

	"github.com/google/netstack/tcpip"
	"github.com/google/netstack/tcpip/buffer"
	"github.com/google/netstack/tcpip/network/ipv4"
	"github.com/google/netstack/tcpip/transport/tcp"

	"github.com/getlantern/errors"
)

func (p *proxy) onTCP(pkt ipPacket) {
	dstAddr := pkt.ft().dst
	p.tcpConnTrackMx.Lock()
	dest := p.tcpConnTrack[dstAddr]
	p.tcpConnTrackMx.Unlock()
	if dest == nil {
		var err error
		dest, err = p.startTCPDest(dstAddr)
		if err != nil {
			log.Error(err)
			return
		}
		p.tcpConnTrackMx.Lock()
		p.tcpConnTrack[dstAddr] = dest
		p.tcpConnTrackMx.Unlock()
	}

	p.channelEndpoint.Inject(ipv4.ProtocolNumber, buffer.View(pkt.raw).ToVectorisedView())
}

func (p *proxy) startTCPDest(dstAddr addr) (*origin, error) {
	nicID := p.nextNICID()
	if err := p.stack.CreateNIC(nicID, p.linkID); err != nil {
		return nil, errors.New("Unable to create TCP NIC: %v", err)
	}
	ipAddr := tcpip.Address(net.ParseIP(dstAddr.ip).To4())
	if err := p.stack.AddAddress(nicID, p.proto, ipAddr); err != nil {
		return nil, errors.New("Unable to add IP addr for TCP dest: %v", err)
	}

	dest := newOrigin(p, dstAddr.String(), func() error {
		p.removeTCPDest(dstAddr)
		return nil
	})
	dest.markActive()

	if err := dest.init(tcp.ProtocolNumber, tcpip.FullAddress{nicID, ipAddr, dstAddr.port}); err != nil {
		return nil, errors.New("Unable to initialize TCP dest: %v", err)
	}

	if err := dest.ep.Listen(p.opts.TCPConnectBacklog); err != nil {
		dest.finalize()
		return nil, errors.New("Unable to listen for TCP connections: %v", err)
	}

	go acceptTCP(dest)
	return dest, nil
}

func acceptTCP(dest *origin) {
	defer func() {
		dest.closedCh <- dest.finalize()
		close(dest.closedCh)
	}()

	for {
		acceptedEp, wq, err := dest.ep.Accept()
		if err != nil {
			if err == tcpip.ErrWouldBlock {
				select {
				case <-dest.closeCh:
					return
				case <-dest.notifyCh:
					continue
				}
			}
			log.Errorf("Accept() failed: %v", err)
			return
		}

		upstream, dialErr := dest.p.opts.DialTCP(context.Background(), "tcp", dest.addr)
		if dialErr != nil {
			log.Errorf("Unexpected error dialing upstream to %v: %v", dest.addr, err)
			return
		}

		downstreamAddr, _ := acceptedEp.GetRemoteAddress()
		tcpConn := newBaseConnWithQueue(dest.p, upstream, wq, func() error {
			dest.removeClient(downstreamAddr)
			return nil
		})
		tcpConn.ep = acceptedEp
		go tcpConn.copyToUpstream(nil)
		go tcpConn.copyFromUpstream(tcpip.WriteOptions{})
		tcpConn.markActive()
		dest.addClient(downstreamAddr, &tcpConn)
	}
}

func (p *proxy) removeTCPDest(dstAddr addr) {
	p.tcpConnTrackMx.Lock()
	delete(p.tcpConnTrack, dstAddr)
	p.tcpConnTrackMx.Unlock()
}

// reapUDP reaps idled TCP connections and destinations. We do this on a single
// goroutine to avoid creating a bunch of timers for each connection
// (which is expensive).
func (p *proxy) reapTCP() {
	for {
		time.Sleep(1 * time.Second)
		p.tcpConnTrackMx.Lock()
		dests := make(map[addr]*origin, len(p.tcpConnTrack))
		for a, dest := range p.tcpConnTrack {
			dests[a] = dest
		}
		p.tcpConnTrackMx.Unlock()

		for a, dest := range dests {
			dest.clientsMx.Lock()
			conns := make([]*baseConn, 0, len(dest.clients))
			for _, conn := range dest.clients {
				conns = append(conns, conn)
			}
			dest.clientsMx.Unlock()
			if len(conns) > 0 {
				for _, conn := range dest.clients {
					if conn.timeSinceLastActive() > p.opts.IdleTimeout {
						go conn.Close()
					}
				}
			} else if dest.timeSinceLastActive() > p.opts.IdleTimeout {
				dest.p.removeTCPDest(a)
				go dest.Close()
			}
		}
	}
}

func (p *proxy) finalizeTCP() (err error) {
	p.tcpConnTrackMx.Lock()
	dests := make(map[addr]*origin, len(p.tcpConnTrack))
	for a, dest := range p.tcpConnTrack {
		dests[a] = dest
	}
	p.tcpConnTrackMx.Unlock()

	for _, dest := range dests {
		dest.clientsMx.Lock()
		conns := make([]*baseConn, 0, len(dest.clients))
		for _, conn := range dest.clients {
			conns = append(conns, conn)
		}
		dest.clientsMx.Unlock()

		for _, conn := range dest.clients {
			if conn.timeSinceLastActive() > p.opts.IdleTimeout {
				_err := conn.Close()
				if err == nil {
					err = _err
				}
			}
		}

		_err := dest.Close()
		if err == nil {
			err = _err
		}
	}

	return
}
