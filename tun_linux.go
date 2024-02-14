package ipproxy

import (
	"os/exec"
	"strconv"

	"github.com/xjasonlyu/tun2socks/v2/core/device"
	"github.com/getlantern/errors"
)

// TUNDevice creates a TUN device with the given name and configures an interface for that TUN
// device at the given address and netmask and given mtu (should usually be 1500).
func TUNDevice(name, addr, gw, netmask string, mtu int) (device.Device, error) {
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
