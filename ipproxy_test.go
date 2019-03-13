package ipproxy

import (
	"bytes"
	"context"
	"io"
	"net"
	"runtime"
	"runtime/pprof"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/netstack/tcpip"

	"github.com/getlantern/fdcount"
	"github.com/getlantern/gotun"

	"github.com/stretchr/testify/assert"
)

const (
	shortIdleTimeout = 1 * time.Second
	longIdleTimeout  = 1000 * time.Minute
)

var (
	serverTCPConnections int64
)

// Note - this test has to be run with root permissions to allow setting up the
// TUN device.
func TestTCPandUDP(t *testing.T) {
	doTest(
		t,
		2,
		shortIdleTimeout,
		"10.0.0.4", "10.0.0.3",
		func(p Proxy, uconn net.Conn, b []byte) {
			assert.Equal(t, "helloudp", string(b))
		},
		func(p Proxy, conn net.Conn, b []byte) {
			assert.Equal(t, "hellotcp", string(b))
			conn.Close()
			time.Sleep(50 * time.Millisecond)
			_, numTCPOrigins, _ := p.ConnCounts()
			assert.Zero(t, numTCPOrigins, "TCP client should be quickly purged from connection tracking")
			assert.Zero(t, atomic.LoadInt64(&serverTCPConnections), "Server-side TCP connection should have been closed")
		},
		func(p Proxy, dev io.Closer) {
			time.Sleep(2 * shortIdleTimeout)
			numTCPOrigins, _, numUDPConns := p.ConnCounts()
			assert.Zero(t, numTCPOrigins, "TCP origin should be purged after idle timeout")
			assert.Zero(t, numUDPConns, "UDP conn should be purged after idle timeout")
		})
}

// TestCloseCleanup is a lot like TestTCPandUDP but it relies on calling
// p.Close() for connection cleanup
func TestCloseCleanup(t *testing.T) {
	doTest(
		t,
		1,
		longIdleTimeout,
		"10.0.0.6", "10.0.0.5",
		func(p Proxy, uconn net.Conn, b []byte) {
			assert.Equal(t, "helloudp", string(b))
		},
		func(p Proxy, conn net.Conn, b []byte) {
			assert.Equal(t, "hellotcp", string(b))
		},
		func(p Proxy, dev io.Closer) {
			time.Sleep(2 * shortIdleTimeout)
			numTCPOrigins, numTCPClients, numUDPConns := p.ConnCounts()
			assert.Equal(t, 1, numTCPOrigins, "TCP origin should not be purged before idle timeout")
			assert.Equal(t, 1, numTCPClients, "TCP client should not be purged before idle timeout")
			assert.Equal(t, 1, numUDPConns, "UDP conns should not be purged before idle timeout")
			log.Debug("Closing device")
			err := dev.Close()
			if assert.NoError(t, err) {
				log.Debug("Closing proxy")
				err = p.Close()
				if assert.NoError(t, err) {
					log.Debug("Checking")
					numTCPOrigins, numTCPClients, numUDPConns = p.ConnCounts()
					log.Debug("Got counts")
					assert.Zero(t, numTCPOrigins, "TCP origin should be purged after close")
					assert.Zero(t, numTCPClients, "TCP client should be purged after close")
					assert.Zero(t, numUDPConns, "UDP conns should be purged after close")
					log.Debug("Done checking")
				}
			}
		})
}

func doTest(t *testing.T, loops int, idleTimeout time.Duration, addr string, gw string, afterUDP func(Proxy, net.Conn, []byte), afterTCP func(Proxy, net.Conn, []byte), finish func(Proxy, io.Closer)) {
	defer func() {
		time.Sleep(2 * time.Second)

		buf := make([]byte, 1<<20)
		stacklen := runtime.Stack(buf, true)
		goroutines := string(buf[:stacklen])
		assert.NotContains(t, goroutines, "tcp.(*endpoint).Listen", "tcp listeners should have stopped")
		assert.NotContains(t, goroutines, "echoReplier", "all echo repliers should have stopped")
		assert.NotContains(t, goroutines, "copyTo", "all copyTo goroutines should have stopped")
		assert.NotContains(t, goroutines, "copyFrom", "all copyFrom goroutines should have stopped")

		runtime.GC()
		prof := pprof.Lookup("heap")
		profBuf := bytes.NewBuffer(nil)
		prof.WriteTo(profBuf, 2)
		profString := profBuf.String()
		if !assert.NotContains(t, profString, "netstack", "no netstack objects should remain in use") {
			log.Debugf("Number of dangling endpoints: %d", len(tcpip.GetDanglingEndpoints()))
		}
	}()

	atomic.StoreInt64(&serverTCPConnections, 0)
	ip := "127.0.0.1"

	dev, err := tun.OpenTunDevice("tun0", addr, gw, "255.255.255.0")
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		dev.Close()
	}()

	d := &net.Dialer{}
	p, err := New(dev, &Opts{
		IdleTimeout: idleTimeout,
		DialTCP: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Send everything to local echo server
			_, port, _ := net.SplitHostPort(addr)
			return d.DialContext(ctx, network, ip+":"+port)
		},
		DialUDP: func(ctx context.Context, network, addr string) (*net.UDPConn, error) {
			// Send everything to local echo server
			_, port, _ := net.SplitHostPort(addr)
			conn, dialErr := net.Dial(network, ip+":"+port)
			if dialErr != nil {
				return nil, dialErr
			}
			return conn.(*net.UDPConn), nil
		},
	})
	if !assert.NoError(t, err) {
		return
	}
	go p.Serve()

	closeCh := make(chan interface{})
	echoAddr := tcpEcho(t, closeCh, ip)
	udpEcho(t, closeCh, echoAddr)

	// point at TUN device rather than echo server directly
	_, port, _ := net.SplitHostPort(echoAddr)
	echoAddr = gw + ":" + port

	_, tcpConnCount, err := fdcount.Matching("TCP")
	if !assert.NoError(t, err, "unable to get initial TCP socket count") {
		return
	}
	_, udpConnCount, err := fdcount.Matching("UDP")
	if !assert.NoError(t, err, "unable to get initial UDP socket count") {
		return
	}

	for i := 0; i < loops; i++ {
		log.Debugf("Loop %d", i)
		b := make([]byte, 8)
		log.Debugf("UDP dialing echo server at: %v", echoAddr)
		uconn, err := net.Dial("udp", echoAddr)
		if !assert.NoError(t, err, "Unable to get UDP connection to TUN device") {
			return
		}
		defer uconn.Close()

		_, err = uconn.Write([]byte("helloudp"))
		if !assert.NoError(t, err) {
			return
		}

		uconn.SetDeadline(time.Now().Add(250 * time.Millisecond))
		_, err = io.ReadFull(uconn, b)
		if !assert.NoError(t, err) {
			return
		}
		afterUDP(p, uconn, b)

		log.Debugf("TCP dialing echo server at: %v", echoAddr)
		conn, err := net.DialTimeout("tcp4", echoAddr, 5*time.Second)
		if !assert.NoError(t, err) {
			return
		}
		defer conn.Close()

		_, err = conn.Write([]byte("hellotcp"))
		if !assert.NoError(t, err) {
			return
		}

		_, err = io.ReadFull(conn, b)
		if !assert.NoError(t, err) {
			return
		}
		afterTCP(p, conn, b)
		finish(p, dev)
	}

	close(closeCh)
	tcpConnCount.AssertDelta(0)
	udpConnCount.AssertDelta(0)
}

func tcpEcho(t *testing.T, closeCh <-chan interface{}, ip string) string {
	l, err := net.Listen("tcp", ip+":0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		<-closeCh
		l.Close()
	}()

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				log.Debug("Copying TCP")
				atomic.AddInt64(&serverTCPConnections, 1)
				n, err := io.Copy(conn, conn)
				log.Debugf("Finished copying TCP: %d: %v", n, err)
				atomic.AddInt64(&serverTCPConnections, -1)
			}()
		}
	}()

	return l.Addr().String()
}

func udpEcho(t *testing.T, closeCh <-chan interface{}, echoAddr string) {
	conn, err := net.ListenPacket("udp", echoAddr)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		<-closeCh
		conn.Close()
	}()

	go func() {
		b := make([]byte, 20480)
		for {
			n, addr, err := conn.ReadFrom(b)
			if err != nil {
				return
			}
			log.Debugf("Got UDP packet! Addr: %v", addr)
			conn.WriteTo(b[:n], addr)
		}
	}()
}
