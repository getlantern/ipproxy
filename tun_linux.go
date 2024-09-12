package ipproxy

import (
	"fmt"
	"os/exec"
	"strconv"

	"github.com/getlantern/errors"

	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
)

// TUNDevice creates a TUN device with the given name and configures an interface for that TUN
// device at the given address and netmask and given mtu (should usually be 1500).
func TUNDevice(name, addr, gw, netmask string, mtu int) (Device, error) {
	dev, err := parseDevice(name, uint32(mtu))
	if err != nil {
		return nil, errors.New("error opening TUN device: %v", err)
	}
	log.Debugf("Created TUN device named %v", name)

	if out, configErr := exec.Command("ifconfig", name, addr, "netmask", netmask, "mtu", strconv.Itoa(mtu)).CombinedOutput(); configErr != nil {
		dev.Close()
		return nil, errors.New("failed to configure tun device address: %v", string(out))
	}

	return dev, nil
}

func open(fd int, mtu uint32, offset int) (Device, error) {
	f := &device{fd: fd, mtu: mtu}
	ep, err := fdbased.New(&fdbased.Options{
		FDs:            []int{fd},
		MTU:            mtu,
		EthernetHeader: false,
	})
	if err != nil {
		return nil, fmt.Errorf("create endpoint: %w", err)
	}
	f.LinkEndpoint = ep

	return f, nil
}
