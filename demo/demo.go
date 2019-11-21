package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/getlantern/golog"
	tun "github.com/getlantern/gotun"
	"github.com/getlantern/ipproxy"
)

var (
	log = golog.LoggerFor("gotun-demo")
)

var (
	tunDevice = flag.String("tun-device", "tun0", "tun device name")
	tunAddr   = flag.String("tun-address", "10.0.0.2", "tun device address")
	tunMask   = flag.String("tun-mask", "255.255.255.0", "tun device netmask")
	tunGW     = flag.String("tun-gw", "10.0.0.1", "tun device gateway")
	ifOut     = flag.String("ifout", "en0", "name of interface to use for outbound connections")
	tcpDest   = flag.String("tcpdest", "speedtest-ny.turnkeyinternet.net", "destination to which to connect all TCP traffic")
	udpDest   = flag.String("udpdest", "8.8.8.8", "destination to which to connect all UDP traffic")
	pprofAddr = flag.String("pprofaddr", "", "pprof address to listen on, not activate pprof if empty")
)

type fivetuple struct {
	proto            string
	srcIP, dstIP     string
	srcPort, dstPort int
}

func (ft fivetuple) String() string {
	return fmt.Sprintf("[%v] %v:%v -> %v:%v", ft.proto, ft.srcIP, ft.srcPort, ft.dstIP, ft.dstPort)
}

func main() {
	flag.Parse()

	if *pprofAddr != "" {
		go func() {
			log.Debugf("Starting pprof page at http://%s/debug/pprof", *pprofAddr)
			srv := &http.Server{
				Addr: *pprofAddr,
			}
			if err := srv.ListenAndServe(); err != nil {
				log.Error(err)
			}
		}()
	}

	dev, err := tun.OpenTunDevice(*tunDevice, *tunAddr, *tunGW, *tunMask)
	if err != nil {
		log.Fatal(err)
	}
	defer dev.Close()

	outIF, err := net.InterfaceByName(*ifOut)
	if err != nil {
		log.Fatal(err)
	}
	outIFAddrs, err := outIF.Addrs()
	if err != nil {
		log.Fatal(err)
	}
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
	if laddrTCP == nil {
		log.Fatalf("Unable to get IPv4 address for interface %v", *ifOut)
	}
	log.Debugf("Outbound TCP will use %v", laddrTCP)
	log.Debugf("Outbound UDP will use %v", laddrUDP)

	var d net.Dialer
	p, err := ipproxy.New(dev, &ipproxy.Opts{
		IdleTimeout:   70 * time.Second,
		StatsInterval: 3 * time.Second,
		DialTCP: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Send everything to tcpDest
			_, port, _ := net.SplitHostPort(addr)
			conn, err := d.DialContext(ctx, network, *tcpDest+":"+port)
			log.Debugf("Dialed %v", conn.RemoteAddr())
			return conn, err
		},
		DialUDP: func(ctx context.Context, network, addr string) (*net.UDPConn, error) {
			// Send everything to udpDest
			_, port, _ := net.SplitHostPort(addr)
			conn, dialErr := net.Dial(network, *udpDest+":"+port)
			if dialErr != nil {
				return nil, dialErr
			}
			return conn.(*net.UDPConn), nil
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	ch := make(chan os.Signal, 1)
	signal.Notify(ch,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT)
	go func() {
		<-ch
		log.Debug("Closing TUN device")
		dev.Close()
		log.Debug("Closed TUN device")
		p.Close()
		log.Debug("Closed ipproxy")
	}()

	defer p.Close()
	log.Debugf("Final result: %v", p.Serve())
}
