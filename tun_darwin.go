package ipproxy

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"

	"github.com/getlantern/errors"
	"github.com/xjasonlyu/tun2socks/v2/core/device"
)

const (
	offset     = 4 /* 4 bytes TUN_PI */
)

func isIPv4(ip net.IP) bool {
	return ip.To4() != nil
}

func isIPv6(ip net.IP) bool {
	return ip.To4() == nil && ip.To16() != nil
}

// TUNDevice creates a TUN device with the given name and configures an interface for that TUN device
func TUNDevice(name, addr, gw, netmask string, mtu int) (device.Device, error) {
	device, err := parseDevice(name, uint32(mtu))
	if err != nil {
		return nil, fmt.Errorf("create tun: %w", err)
	}

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
	return device, nil
}
