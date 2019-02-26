package ipproxy

import (
	"sync/atomic"
	"time"
)

func (p *proxy) trackStats() {
	ticker := time.NewTicker(15 * time.Second)
	for {
		select {
		case <-p.closeCh:
			return
		case <-ticker.C:
			// log.Debugf("TCP Conns: %v    UDP Conns: %v", p.NumTCPConns(), p.NumUDPConns())
			log.Debugf("Accepted Packets: %d    Rejected Packets: %d", p.AcceptedPackets(), p.RejectedPackets())
		}
	}
}

func (p *proxy) NumTCPConns() int {
	// p.tcpConnTrackMx.Lock()
	// tcpConns := len(p.tcpConnTrack)
	// p.tcpConnTrackMx.Unlock()
	// return tcpConns
	return 0
	// TODO: implement
}

func (p *proxy) NumUDPConns() int {
	// p.udpConnTrackMx.Lock()
	// udpConns := len(p.udpConnTrack)
	// p.udpConnTrackMx.Unlock()
	// return udpConns
	return 0
	// TODO: implement
}

func (p *proxy) acceptedPacket() {
	atomic.AddInt64(&p.acceptedPackets, 1)
}

func (p *proxy) AcceptedPackets() int {
	return int(atomic.LoadInt64(&p.acceptedPackets))
}

func (p *proxy) rejectedPacket() {
	atomic.AddInt64(&p.rejectedPackets, 1)
}

func (p *proxy) RejectedPackets() int {
	return int(atomic.LoadInt64(&p.rejectedPackets))
}
