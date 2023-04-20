package asa

import "github.com/hknutzen/Netspoc-Approve/go/pkg/device"

func (n1 *ASAConfig) MergeSpoc(c2 device.DeviceConfig) device.DeviceConfig {
	n2 := c2.(*ASAConfig)
	lookup := n1.lookup
	if lookup == nil {
		lookup = make(map[string]map[string][]*cmd)
		n1.lookup = lookup
	}
	for prefix, m2 := range n2.lookup {
		m1 := lookup[prefix]
		if m1 == nil {
			m1 = make(map[string][]*cmd)
			lookup[prefix] = m1
		}
		for name, l := range m2 {
			m1[name] = append(m1[name], l...)
		}
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
