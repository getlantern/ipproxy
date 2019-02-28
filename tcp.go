package ipproxy

import (
	"github.com/google/netstack/tcpip"
	"github.com/google/netstack/tcpip/buffer"
	"github.com/google/netstack/tcpip/network/ipv4"
	"github.com/google/netstack/tcpip/transport/tcp"

	"github.com/getlantern/errors"
)

func (p *proxy) onTCP(pkt ipPacket) {
	dstPort := pkt.ft().dst.port
	p.tcpConnTrackMx.Lock()
	client := p.tcpConnTrack[dstPort]
	p.tcpConnTrackMx.Unlock()
	if client == nil {
		var err error
		client, err = p.startTCPClient(dstPort)
		if err != nil {
			log.Error(err)
			return
		}
		p.tcpConnTrackMx.Lock()
		p.tcpConnTrack[dstPort] = client
		p.tcpConnTrackMx.Unlock()
	}

	p.channelEndpoint.Inject(ipv4.ProtocolNumber, buffer.View(pkt.raw).ToVectorisedView())
}

func (p *proxy) startTCPClient(dstPort uint16) (*tcpClient, error) {
	nicID := p.nextNICID()
	if err := p.stack.CreateNIC(nicID, p.linkID); err != nil {
		return nil, errors.New("Unable to create TCP NIC: %v", err)
	}
	if err := p.stack.SetPromiscuousMode(nicID, true); err != nil {
		return nil, errors.New("Unable to set TCP NIC to promiscuous mode: %v", err)
	}

	client := &tcpClient{
		baseConn: newBaseConn(p),
		dstPort:  dstPort,
	}
	client.markActive()

	if err := client.init(tcp.ProtocolNumber, tcpip.FullAddress{nicID, "", dstPort}); err != nil {
		return nil, errors.New("Unable to initialize TCP client: %v", err)
	}

	if err := client.ep.Listen(p.opts.TCPConnectBacklog); err != nil {
		client.finalize()
		return nil, errors.New("Unable to listen for TCP connections: %v", err)
	}

	go client.accept()
	return client, nil
}

type tcpClient struct {
	baseConn
	dstPort uint16
}

func (client *tcpClient) accept() {
	for {
		n, wq, err := client.ep.Accept()
		if err != nil {
			log.Debug(err)
			if err == tcpip.ErrWouldBlock {
				<-client.notifyCh
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
