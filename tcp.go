package ipproxy

import (
	"context"
	"io"
	"net"
	"strings"

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
		addr:     dstAddr.String(),
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
	addr string
}

func (dest *tcpDest) accept() {
	for {
		acceptedEp, wq, err := dest.ep.Accept()
		if err != nil {
			if err == tcpip.ErrWouldBlock {
				<-dest.notifyCh
				continue
			}
			log.Errorf("Accept() failed: %v", err)
			return
		}

		// remote, _ := acceptedEp.GetRemoteAddress()
		// local, _ := acceptedEp.GetLocalAddress()
		// dest.p.stack.SetRouteTable([]tcpip.Route{
		// 	{
		// 		Destination: remote.Addr,
		// 		Mask:        tcpip.AddressMask(remote.Addr),
		// 		Gateway:     "",
		// 		NIC:         1,
		// 	},
		// 	{
		// 		Destination: local.Addr,
		// 		Mask:        tcpip.AddressMask(local.Addr),
		// 		Gateway:     "",
		// 		NIC:         1,
		// 	},
		// })
		upstream, dialErr := dest.p.opts.DialTCP(context.Background(), "tcp", dest.addr)
		if dialErr != nil {
			log.Errorf("Unexpected error dialing upstream to %v: %v", dest.addr, err)
			return
		}

		tcpConn := &tcpConn{
			baseConn: newBaseConnWithQueue(dest.p, wq),
			upstream: upstream,
		}
		tcpConn.ep = acceptedEp
		go tcpConn.copyToUpstream()
		go tcpConn.copyFromUpstream()
	}
}

type tcpConn struct {
	baseConn
	upstream io.ReadWriteCloser
}

func (conn *tcpConn) copyToUpstream() {
	defer func() {
		conn.closedCh <- conn.finalize()
		close(conn.closedCh)
	}()

	for {
		buf, _, readErr := conn.ep.Read(nil)
		if readErr != nil {
			if readErr == tcpip.ErrWouldBlock {
				select {
				case <-conn.closeCh:
					return
				case <-conn.notifyCh:
					continue
				}
			}
			if !strings.Contains(readErr.String(), "endpoint is closed for receive") {
				log.Errorf("Unexpected error reading from downstream: %v", readErr)
			}
			return
		}
		if _, writeErr := conn.upstream.Write(buf); writeErr != nil {
			log.Errorf("Unexpected error writing to upstream: %v", writeErr)
			return
		}
		conn.markActive()
	}
}

func (conn *tcpConn) copyFromUpstream() {
	defer conn.Close()

	b := conn.p.pool.Get()
	for {
		n, readErr := conn.upstream.Read(b)
		if readErr != nil {
			if neterr, ok := readErr.(net.Error); ok && neterr.Temporary() {
				continue
			}
			if readErr != io.EOF && !strings.Contains(readErr.Error(), "use of closed network connection") {
				log.Errorf("Unexpected error reading from upstream: %v", readErr)
			}
			return
		}

		_, _, writeErr := conn.ep.Write(tcpip.SlicePayload(b[:n]), tcpip.WriteOptions{})
		if writeErr != nil {
			log.Errorf("Unexpected error writing to downstream: %v", writeErr)
			return
		}
		conn.markActive()
	}
}

func (conn *tcpConn) finalize() error {
	err := conn.baseConn.finalize()
	if conn.upstream != nil {
		_err := conn.upstream.Close()
		if err == nil {
			err = _err
		}
	}
	// conn.p.udpConnTrackMx.Lock()
	// delete(conn.p.udpConnTrack, conn.ft)
	// conn.p.udpConnTrackMx.Unlock()
	return err
}
