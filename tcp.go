package ipproxy

import (
	"net"

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

func (p *proxy) startTCPDest(dstAddr addr) (*tcpDest, error) {
	nicID := p.nextNICID()
	if err := p.stack.CreateNIC(nicID, p.linkID); err != nil {
		return nil, errors.New("Unable to create TCP NIC: %v", err)
	}
	ipAddr := tcpip.Address(net.ParseIP(dstAddr.ip).To4())
	if err := p.stack.AddAddress(nicID, p.proto, ipAddr); err != nil {
		return nil, errors.New("Unable to add IP addr for TCP dest: %v", err)
	}

	dest := &tcpDest{
		baseConn: newBaseConn(p),
		dstAddr:  dstAddr,
	}
	dest.markActive()

	if err := dest.init(tcp.ProtocolNumber, tcpip.FullAddress{nicID, ipAddr, dstAddr.port}); err != nil {
		return nil, errors.New("Unable to initialize TCP dest: %v", err)
	}

	if err := dest.ep.Listen(p.opts.TCPConnectBacklog); err != nil {
		dest.finalize()
		return nil, errors.New("Unable to listen for TCP connections: %v", err)
	}

	go dest.accept()
	return dest, nil
}

type tcpDest struct {
	baseConn
	dstAddr addr
}

func (dest *tcpDest) accept() {
	for {
		n, wq, err := dest.ep.Accept()
		if err != nil {
			log.Debug(err)
			if err == tcpip.ErrWouldBlock {
				<-dest.notifyCh
				continue
			}
			log.Errorf("Accept() failed: %v", err)
			return
		}

		log.Debugf("Accepted: %v %v", n, wq)
		// go echo(wq, n)
	}
}

type tcpConn struct {
	baseConn
}
