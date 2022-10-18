package panos

import (
	"fmt"
	"regexp"

	"github.com/hknutzen/Netspoc-Approve/go/pkg/device"
)

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
		func(c *PanConfig) (*panDevice, map[string]*panVsys, error) {
			if c == nil || c.Devices == nil {
				return &panDevice{}, nil, nil
			}
			l := c.Devices.Entries
			if len(l) != 1 {
				return nil, nil, fmt.Errorf(
					"Expected exactly one device entry in '%s' configuration",
					c.origin)
			}
			d := l[0]
			m := make(map[string]*panVsys)
			for i, v := range d.Vsys {
				name := v.Name
				if name == "" {
					return nil, nil, fmt.Errorf(
						"Missing name in %d. VSYS of '%s' configuration",
						i+1, c.origin)
				}
				if _, ok := m[name]; ok {
					return nil, nil, fmt.Errorf(
						"Duplicate name '%s' in VSYS of '%s' configuration",
						c.origin, name)
				}
				m[name] = v
			}
			return d, m, nil
		}
	d1, m1, err := getDevVsysMap(c1)
	if err != nil {
		return err
	}
	d2, m2, err := getDevVsysMap(c2)
	if err != nil {
		return err
	}
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

func (c *PanConfig) GetDevName() string {
	return c.Devices.Entries[0].Hostname
}

func (c *PanConfig) CheckRulesFromRaw() error {
	if c == nil || c.Devices == nil {
		return nil
	}
	re := regexp.MustCompile(`^r\d`)
	for _, d := range c.Devices.Entries {
		for _, v := range d.Vsys {
			for _, r := range v.Rules {
				if re.MatchString(r.Name) {
					return fmt.Errorf(
						"Must not use rule name starting with 'r<NUM>' in raw: %s",
						r.Name)
				}
			}
		}
	}
	return nil
}
