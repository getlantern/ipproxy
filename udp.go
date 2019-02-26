package ipproxy

import (
	"github.com/google/netstack/tcpip"
	"github.com/google/netstack/tcpip/buffer"
	"github.com/google/netstack/tcpip/network/ipv4"
	"github.com/google/netstack/tcpip/transport/udp"
	"github.com/google/netstack/waiter"
)

type udpConn struct {
	ep tcpip.Endpoint
}

func (conn *udpConn) Close() error {
	// TODO: figure out close sequence
	return nil
}

func (p *proxy) onUDP(pkt ipPacket) {
	ft := pkt.fourtuple()
	conn := p.udpConnTrack[ft]
	if conn == nil {
		dstPort := pkt.dstPort()
		log.Debugf("Creating udpConn for %v", dstPort)
		var wq waiter.Queue
		ep, err := p.stack.NewEndpoint(udp.ProtocolNumber, p.proto, &wq)
		if err != nil {
			log.Errorf("Unable to create UDP endpoint: %v", err)
			return
		}

		// Wait for connections to appear.
		waitEntry, notifyCh := waiter.NewChannelEntry(nil)
		wq.EventRegister(&waitEntry, waiter.EventIn)
		// defer wq.EventUnregister(&waitEntry)

		finalize := func() {
			wq.EventUnregister(&waitEntry)
			ep.Close()
		}

		if err := ep.Bind(tcpip.FullAddress{0, "", dstPort}, nil); err != nil {
			log.Errorf("UDP bind failed: %v", err)
			finalize()
			return
		}

		go func() {
			defer finalize()
			for range notifyCh {
				addr := &tcpip.FullAddress{0, "", dstPort}
				buf, _, err := ep.Read(addr)
				if err != nil {
					log.Errorf("Error reading packet from downstream, ignoring: %v", err)
					continue
				}
				log.Debugf("Got udp packet: %v", buf)
			}
		}()

		conn = &udpConn{ep: ep}
		p.udpConnTrack[ft] = conn
	}

	log.Debugf("Injecting packet")
	p.endpoint.Inject(ipv4.ProtocolNumber, buffer.View(pkt.raw).ToVectorisedView())
}
