package asa

import (
	"strings"

	"github.com/hknutzen/Netspoc-Approve/go/pkg/device"
)

func (n1 *ASAConfig) MergeSpoc(c2 device.DeviceConfig) device.DeviceConfig {
	n2 := c2.(*ASAConfig)
	lookup := n1.lookup
	if lookup == nil {
		lookup = make(objLookup)
		n1.lookup = lookup
	}
	mergeACLs(n1, n2)
	for prefix, m2 := range n2.lookup {
		m1 := lookup[prefix]
		if m1 == nil {
			m1 = make(map[string][]*cmd)
			lookup[prefix] = m1
		}
		for name, l2 := range m2 {
			l1 := m1[name]
			switch prefix {
			case "access-list":
			case "access-group":
			default:
				l1 = append(l1, l2...)
			}
			m1[name] = l1
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

func mergeACLs(n1, n2 *ASAConfig) {
	set := func(prefix, name string, l []*cmd) {
		m := n1.lookup[prefix]
		if m == nil {
			m = make(map[string][]*cmd)
			n1.lookup[prefix] = m
		}
		m[name] = l
	}
	l1 := n1.lookup["access-group"][""]
	l2 := n2.lookup["access-group"][""]
	m := make(map[string]*cmd)
	for _, c := range l1 {
		m[c.parsed] = c
	}
	for _, c2 := range l2 {
		name2 := c2.ref[0]
		acl2 := n2.lookup["access-list"][name2]
		if c1, found := m[c2.parsed]; found {
			// Modify existing ACL
			name1 := c1.ref[0]
			acl1 := n1.lookup["access-list"][name1]
			if c2.append {
				// Append mode adds entries behind last permit line.
				// Find last permit line within entries from Netspoc.
				i := len(acl1) - 1
				for ; i >= 0; i-- {
					if strings.Contains(acl1[i].parsed, "$NAME extended permit") {
						i++
						break
					}
				}
				acl1 = append(acl1[:i], append(acl2, acl1[i:]...)...)
			} else {
				acl1 = append(acl2, acl1...)
			}
			set("access-list", name1, acl1)
		} else {
			// Insert new ACL
			if n1.lookup["access-list"][name2] != nil {
				device.Abort("Name clash for 'access-list %s'", name2)
			}
			set("access-list", name2, acl2)
			l1 = append(l1, c2)
			set("access-group", "", l1)
		}
	}
}
