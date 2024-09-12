package ipproxy

import (
	"strconv"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

var _ Device = (*device)(nil)

type device struct {
	stack.LinkEndpoint
	fd   int
	mtu  uint32
	name string
}

// Device is a stack.LinkEndpoint implemented by network layer devices (e.g. tun)
type Device interface {
	stack.LinkEndpoint
	Name() string
}

func (d *device) Name() string {
	if d.fd != 0 {
		return strconv.Itoa(d.fd)
	}
	return d.name
}

func (d *device) Close() {
	defer d.LinkEndpoint.Close()
	_ = unix.Close(d.fd)
}
