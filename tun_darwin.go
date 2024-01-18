package ipproxy

import (
	"io"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"

	"github.com/getlantern/errors"
	"github.com/songgao/water"
)

func isIPv4(ip net.IP) bool {
	if ip.To4() != nil {
		return true
	}
	return false
}

func isIPv6(ip net.IP) bool {
	// To16() also valid for ipv4, ensure it's not an ipv4 address
	if ip.To4() != nil {
		return false
	}
	if ip.To16() != nil {
		return true
	}
	return false
}

// TUNDevice creates a TUN device with the given name and configures an interface for that TUN device
func TUNDevice(name, addr, gw, netmask string, mtu int) (io.ReadWriteCloser, error) {
	tun, err := water.New(water.Config{
		DeviceType: water.TUN,
	})
	if err != nil {
		return nil, err
	}
	name = tun.Name()
	ip := net.ParseIP(addr)
	if ip == nil {
		return nil, errors.New("invalid IP address")
	}

	var params string
	if isIPv4(ip) {
		params = fmt.Sprintf("%s inet %s netmask %s %s", name, addr, netmask, gw)
	} else if isIPv6(ip) {
		prefixlen, err := strconv.Atoi(netmask)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("parse IPv6 prefixlen failed: %v", err))
		}
		params = fmt.Sprintf("%s inet6 %s/%d", name, addr, prefixlen)
	} else {
		return nil, errors.New("invalid IP address")
	}

	out, err := exec.Command("ifconfig", strings.Split(params, " ")...).Output()
	if err != nil {
		if len(out) != 0 {
			return nil, errors.New(fmt.Sprintf("%v, output: %s", err, out))
		}
		return nil, err
	}
	log.Debugf("Created TUN device named %v", name)
	return tun, nil
}
