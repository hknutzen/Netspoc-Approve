package asa

import "github.com/hknutzen/Netspoc-Approve/go/pkg/device"

func (n1 *ASAConfig) MergeSpoc(c2 device.DeviceConfig) device.DeviceConfig {
	n2 := c2.(*ASAConfig)
	if n2 == nil {
		return n1
	}
	return n1
}

func (c *ASAConfig) SetExpectedDeviceName(name string) {}
func (n *ASAConfig) CheckDeviceName() error            { return nil }

func (n *ASAConfig) CheckRulesFromRaw() error {
	if n == nil {
		return nil
	}
	return nil
}
