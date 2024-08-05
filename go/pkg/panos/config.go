package panos

import (
	"fmt"

	"github.com/hknutzen/Netspoc-Approve/go/pkg/device"
)

func (c *PanConfig) CheckRulesFromRaw() error { return nil }

// MergeSpoc merges two configurations read from Netspoc.
// c2 is either read from a raw file or it is a IPv6 configuration.
func (p1 *PanConfig) MergeSpoc(c2 device.DeviceConfig) device.DeviceConfig {
	p2 := c2.(*PanConfig)
	processVsysPairs(p1, p2, func(v1, v2 *panVsys) error {
		// Create empty vsys in p1 to add complete vsys from p2 below.
		if v1 == nil {
			if p1 == nil || p1.Devices == nil {
				p1 = &PanConfig{
					Devices: &panDevices{
						Entries: []*panDevice{&panDevice{}},
					},
				}
			}
			d1 := p1.Devices.Entries[0]
			v1 = &panVsys{Name: v2.Name}
			d1.Vsys = append(d1.Vsys, v1)
		}
		if v2 != nil {
			// Add elements of vsys from raw/IPv6.
			v1.Addresses = append(v1.Addresses, v2.Addresses...)
			v1.AddressGroups = append(v1.AddressGroups, v2.AddressGroups...)
			v1.Services = append(v1.Services, v2.Services...)
			// Add rules.
			// Rules are prepended per default.
			// Rules with attribute <APPEND> are appended.
			var top []*panRule
			for _, r := range v2.Rules {
				if r.Append == nil {
					top = append(top, r)
				} else {
					r.Append = nil
					v1.Rules = append(v1.Rules, r)
				}
			}
			v1.Rules = append(top, v1.Rules...)
		}
		return nil
	})
	return p1
}

func processVsysPairs(c1, c2 *PanConfig, f func(v1, v2 *panVsys) error) error {
	getDevVsysMap :=
		func(c *PanConfig) (*panDevice, map[string]*panVsys) {
			if c == nil || c.Devices == nil || len(c.Devices.Entries) == 0 {
				return &panDevice{}, nil
			}
			d := c.Devices.Entries[0]
			m := make(map[string]*panVsys)
			for _, v := range d.Vsys {
				m[v.Name] = v
			}
			return d, m
		}
	d1, m1 := getDevVsysMap(c1)
	d2, m2 := getDevVsysMap(c2)
	if d1.Name != "" && d2.Name != "" && d1.Name != d2.Name {
		return fmt.Errorf("Different names in <device> of XML: %s='%s', %s='%s'",
			c1.origin, d1.Name, c2.origin, d2.Name)
	}
	for _, v1 := range d1.Vsys {
		v2 := m2[v1.Name]
		if err := f(v1, v2); err != nil {
			return err
		}
	}
	for _, v2 := range d2.Vsys {
		if m1[v2.Name] == nil {
			if err := f(nil, v2); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *PanConfig) getDevName() string {
	return c.Devices.Entries[0].Hostname
}

func (c *PanConfig) checkDeviceName(expected string) error {
	name := c.getDevName()
	if name != expected {
		return fmt.Errorf("Wrong device name: %s, expected: %s", name, expected)
	}
	return nil
}
