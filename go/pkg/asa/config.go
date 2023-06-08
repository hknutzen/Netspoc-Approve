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
		aclName2 := c2.ref[0]
		aclList2 := n2.lookup["access-list"][aclName2]
		if c1, found := m[c2.parsed]; found {
			// Modify existing ACL
			aclName1 := c1.ref[0]
			aclList1 := n1.lookup["access-list"][aclName1]

			// Append mode adds entries behind last permit line.
			// Find last permit line within entries from Netspoc.
			i := len(aclList1) - 1
			for ; i >= 0; i-- {
				if strings.Contains(aclList1[i].parsed, "$NAME extended permit") {
					i++
					break
				}
			}
			set("access-list", aclName1,
				append(aclList1[:i], append(aclList2, aclList1[i:]...)...))
		} else {
			// Insert new ACL
			if n1.lookup["access-list"][aclName2] != nil {
				device.Abort("Name clash for 'access-list %s'", aclName2)
			}
			set("access-list", aclName2, aclList2)
			set("access-group", "", append(l1, c2))
		}
	}
}
