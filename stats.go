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
			numTCPDests, numTCPConns, numUDPConns := p.ConnCounts()
			log.Debugf("TCP Dests: %v   TCP Conns: %v    UDP Conns: %v", numTCPDests, numTCPConns, numUDPConns)
			log.Debugf("Accepted Packets: %d    Rejected Packets: %d", p.AcceptedPackets(), p.RejectedPackets())
		}
	}
}

func (p *proxy) ConnCounts() (numTCPDests int, numTCPConns int, numUDPConns int) {
	p.tcpConnTrackMx.Lock()
	dests := make([]*tcpDest, 0, len(p.tcpConnTrack))
	for _, dest := range p.tcpConnTrack {
		dests = append(dests, dest)
	}
	p.tcpConnTrackMx.Unlock()
	numTCPDests = len(dests)
	for _, dest := range dests {
		numTCPConns += dest.numConns()
	}

	p.udpConnTrackMx.Lock()
	numUDPConns = len(p.udpConnTrack)
	p.udpConnTrackMx.Unlock()

	return
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
