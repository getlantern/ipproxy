package ipproxy

import (
	"context"
	"sync/atomic"
	"time"
)

func (p *proxy) trackStats(ctx context.Context) {
	ticker := time.NewTicker(p.opts.StatsInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			log.Debugf("TCP Origins: %v   TCP Clients: %v    UDP Conns: %v", p.NumTCPOrigins(), p.NumTCPConns(), p.NumUDPConns())
			log.Debugf("Accepted Packets: %d    Rejected Packets: %d", p.AcceptedPackets(), p.RejectedPackets())
		}
	}
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

func (p *proxy) addTCPOrigin() {
	atomic.AddInt64(&p.numTcpOrigins, 1)
}

func (p *proxy) removeTCPOrigin() {
	atomic.AddInt64(&p.numTcpOrigins, -1)
}

func (p *proxy) NumTCPOrigins() int {
	return int(atomic.LoadInt64(&p.numTcpOrigins))
}

func (p *proxy) addTCPConn() {
	atomic.AddInt64(&p.numTcpConns, 1)
}

func (p *proxy) removeTCPConn() {
	atomic.AddInt64(&p.numTcpConns, -1)
}

func (p *proxy) NumTCPConns() int {
	return int(atomic.LoadInt64(&p.numTcpConns))
}

func (p *proxy) addUDPConn() {
	atomic.AddInt64(&p.numUdpConns, 1)
}

func (p *proxy) removeUDPConn() {
	atomic.AddInt64(&p.numUdpConns, -1)
}

func (p *proxy) NumUDPConns() int {
	return int(atomic.LoadInt64(&p.numUdpConns))
}
