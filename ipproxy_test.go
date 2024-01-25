package ipproxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/stretchr/testify/require"
	"io"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/getlantern/fdcount"
	"github.com/stretchr/testify/assert"
)

const (
	shortIdleTimeout = 1 * time.Second
	longIdleTimeout  = 1000 * time.Minute
)

var (
	serverTCPConnections int64
)

func TestRoundtrip(t *testing.T) {

	dev, err := TUNDevice("tun5", "10.0.1.2", "255.255.255.0", 1500)
	require.NoError(t, err)
	t.Cleanup(func() { dev.Close() })

	outIF, err := net.InterfaceByName("eno2")
	require.NoError(t, err)
	outIFAddrs, err := outIF.Addrs()
	require.NoError(t, err)
	var laddrTCP *net.TCPAddr
	var laddrUDP *net.UDPAddr
	for _, outIFAddr := range outIFAddrs {
		switch t := outIFAddr.(type) {
		case *net.IPNet:
			ipv4 := t.IP.To4()
			if ipv4 != nil {
				laddrTCP = &net.TCPAddr{IP: ipv4, Port: 0}
				laddrUDP = &net.UDPAddr{IP: ipv4, Port: 0}
				break
			}
		}
	}
	require.NotNil(t, laddrTCP)
	log.Debugf("Outbound TCP will use %v", laddrTCP)
	log.Debugf("Outbound UDP will use %v", laddrUDP)

	var d net.Dialer
	p, err := New(dev, &Opts{
		IdleTimeout:   70 * time.Second,
		StatsInterval: 3 * time.Second,
		DialTCP: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := d.DialContext(ctx, network, "localhost:9876")
			log.Debugf("Dialed %v", conn.RemoteAddr())
			return conn, err
		},
		DialUDP: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return nil, errors.New("not implemented")
		},
	})
	require.NoError(t, err)
	// Listen for incoming connections on port 8080
	ln, err := net.Listen("tcp", ":9876")
	t.Cleanup(func() { ln.Close() })
	require.NoError(t, err)
	result := bytes.Buffer{}
	go func() {
		t.Log("Accepting connections")
		conn, err := ln.Accept()
		require.NoError(t, err)
		t.Log("Connection accepted")
		// read in loop
		for {
			buf := make([]byte, 1024)
			n, err := conn.Read(buf)
			if errors.Is(err, io.EOF) {
				t.Log("EOF")
				conn.Close()
				break
			}
			t.Log(fmt.Sprintf("read %d bytes: %v", n, string(buf[:n])))
			require.NoError(t, err)
			result.Write(buf[:n])
		}
	}()
	go p.Serve()

	// execute: `sudo route add -host 185.85.17.95 dev tun5`
	// Add a route to the host 185.85.17.95 using the tun5 device
	cmd := exec.Command("sudo", "route", "add", "-host", "185.85.17.95", "dev", "tun5")
	err = cmd.Run()
	require.NoError(t, err)

	go func() {
		// connect to 185.85.17.95 on any port and write hello\nhello!
		conn, err := net.Dial("tcp", "185.85.17.95:9876")
		require.NoError(t, err)
		_, err = conn.Write([]byte("hello my baby, hello my darling\n"))
		require.NoError(t, err)
		time.Sleep(1 * time.Second)
		_, err = conn.Write([]byte("bye!"))
		require.NoError(t, err)
		conn.Close()
	}()

	time.Sleep(2 * time.Second)
	p.Close()
	require.Equal(t, "hello my baby, hello my darling\nbye!", result.String())
}

// Note - this test has to be run with root permissions to allow setting up the
// TUN device.
func TestTCPAndUDP(t *testing.T) {
	doTest(
		t,
		2,
		shortIdleTimeout,
		"10.0.1.2", "10.0.1.1",
		func(p Proxy, uconn net.Conn, b []byte) {
			assert.Equal(t, "helloudp", string(b))
		},
		func(p Proxy, conn net.Conn, b []byte) {
			assert.Equal(t, "hellotcp", string(b))
			conn.Close()
			time.Sleep(50 * time.Millisecond)
			log.Debug("checking")
			assert.Zero(t, p.NumTCPConns(), "TCP client should be quickly purged from connection tracking")
			assert.Zero(t, atomic.LoadInt64(&serverTCPConnections), "Server-side TCP connection should have been closed")
		},
		func(p Proxy, dev io.Closer) {
			time.Sleep(10 * shortIdleTimeout)
			log.Debug("checking")
			assert.Zero(t, p.NumTCPOrigins(), "TCP origin should be purged after idle timeout")
			assert.Zero(t, p.NumUDPConns(), "UDP conn should be purged after idle timeout")
		})
}

// TestCloseCleanup is a lot like TestTCPandUDP but it relies on calling
// p.Close() for connection cleanup
func TestCloseCleanup(t *testing.T) {
	doTest(
		t,
		1,
		longIdleTimeout,
		"10.0.2.2", "10.0.2.1",
		func(p Proxy, uconn net.Conn, b []byte) {
			assert.Equal(t, "helloudp", string(b))
		},
		func(p Proxy, conn net.Conn, b []byte) {
			assert.Equal(t, "hellotcp", string(b))
		},
		func(p Proxy, dev io.Closer) {
			time.Sleep(2 * shortIdleTimeout)
			// assert.Equal(t, 1, p.NumTCPOrigins(), "TCP origin should not be purged before idle timeout")
			assert.True(t, p.NumTCPConns() > 0, "TCP client should not be purged before idle timeout")
			assert.True(t, p.NumUDPConns() > 0, "UDP conns should not be purged before idle timeout")
			log.Debug("Closing device")
			err := dev.Close()
			if assert.NoError(t, err) {
				log.Debug("Closing proxy")
				err = p.Close()
				if assert.NoError(t, err) {
					time.Sleep(1 * time.Second)
					log.Debug("Checking")
					assert.Zero(t, p.NumTCPOrigins(), "TCP origin should be purged after close")
					assert.Zero(t, p.NumTCPConns(), "TCP client should be purged after close")
					assert.Zero(t, p.NumUDPConns(), "UDP conns should be purged after close")
					log.Debug("Done checking")
				}
			}
		})
}

func doTest(t *testing.T, loops int, idleTimeout time.Duration, addr string, gw string, afterUDP func(Proxy, net.Conn, []byte), afterTCP func(Proxy, net.Conn, []byte), finish func(Proxy, io.Closer)) {
	var wg sync.WaitGroup
	defer func() {
		wg.Wait()
		buf := make([]byte, 1<<20)
		stacklen := runtime.Stack(buf, true)
		goroutines := string(buf[:stacklen])
		assert.NotContains(t, goroutines, "tcp.(*endpoint).Listen", "tcp listeners should have stopped")
		assert.NotContains(t, goroutines, "echoReplier", "all echo repliers should have stopped")
		assert.NotContains(t, goroutines, "copyTo", "all copyTo goroutines should have stopped")
		assert.NotContains(t, goroutines, "copyFrom", "all copyFrom goroutines should have stopped")
	}()

	atomic.StoreInt64(&serverTCPConnections, 0)
	ip := "127.0.0.1"

	dev, err := TUNDevice("", addr, "255.255.255.0", 1500)
	if err != nil {
		if strings.HasSuffix(err.Error(), "operation not permitted") {
			t.Log("This test requires root access. Compile, then run with root privileges. See the README for more details.")
		}
		t.Fatal(err)
	}
	defer dev.Close()

	d := &net.Dialer{}
	p, err := New(dev, &Opts{
		IdleTimeout:   idleTimeout,
		StatsInterval: 1 * time.Second,
		DialTCP: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Send everything to local echo server
			_, port, _ := net.SplitHostPort(addr)
			return d.DialContext(ctx, network, ip+":"+port)
		},
		DialUDP: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Send everything to local echo server
			_, port, _ := net.SplitHostPort(addr)
			return net.Dial(network, ip+":"+port)
		},
	})
	if !assert.NoError(t, err) {
		return
	}
	defer p.Close()

	wg.Add(1)
	go func() {
		if err := p.Serve(); err != nil {
			log.Error(err)
		}
		wg.Done()
	}()

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
