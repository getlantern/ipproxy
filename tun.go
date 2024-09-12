package ipproxy

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

const (
	defaultMTU    = 1500
	fdbasedDriver = "fd"
)

func parseDevice(name string, mtu uint32) (Device, error) {
	u, err := url.Parse(name)
	if err == nil {
		name = u.Scheme
	}
	fd, err := strconv.Atoi(strings.ToLower(name))
	if err != nil {
		return nil, fmt.Errorf("cannot open fd: %s", name)
	}
	if mtu == 0 {
		mtu = defaultMTU
	}
	return open(fd, mtu, 0)
}
