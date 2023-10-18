package nsx

import (
	"fmt"
	"regexp"

	"github.com/hknutzen/Netspoc-Approve/go/pkg/device"
)

func (n1 *NsxConfig) MergeSpoc(c2 device.DeviceConfig) device.DeviceConfig {
	n2 := c2.(*NsxConfig)
	n1.Groups = append(n1.Groups, n2.Groups...)
	n1.Services = append(n1.Services, n2.Services...)

POLICY:
	for _, p2 := range n2.Policies {
		for _, p1 := range n1.Policies {
			if p2.Id == p1.Id {
				p1.Rules = append(p1.Rules, p2.Rules...)
				continue POLICY
			}
		}
		n1.Policies = append(n1.Policies, p2)
	}
	return n1
}

func (n *NsxConfig) CheckRulesFromRaw() error {
	if n == nil || n.Policies == nil {
		return nil
	}
	re := regexp.MustCompile(`^r\d`)
	for _, p := range n.Policies {
		for _, r := range p.Rules {
			if re.MatchString(r.Id) {
				return fmt.Errorf(
					"Must not use rule name starting with 'r<NUM>' in raw: %s",
					r.Id)
			}
		}
	}
	return nil
}
