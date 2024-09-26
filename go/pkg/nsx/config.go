package nsx

import "github.com/hknutzen/Netspoc-Approve/go/pkg/deviceconf"

func (n1 *NsxConfig) MergeSpoc(c2 deviceconf.Config) deviceconf.Config {
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
