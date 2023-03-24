package asa

import "github.com/hknutzen/Netspoc-Approve/go/pkg/device"

type ASAConfig struct {
}

func (s *State) ParseConfig(data []byte) (device.DeviceConfig, error) {
	if len(data) == 0 {
		var n *ASAConfig
		return n, nil
	}
	config := &ASAConfig{}
	return config, nil
}
