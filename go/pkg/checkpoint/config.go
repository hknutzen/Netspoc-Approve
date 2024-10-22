package checkpoint

import (
	"slices"

	"github.com/hknutzen/Netspoc-Approve/go/pkg/deviceconf"
)

func (a *chkpConfig) MergeSpoc(d deviceconf.Config) deviceconf.Config {
	b := d.(*chkpConfig)
	a.Networks = append(a.Networks, b.Networks...)
	a.Hosts = append(a.Hosts, b.Hosts...)
	a.Groups = append(a.Groups, b.Groups...)
	a.TCP = append(a.TCP, b.TCP...)
	a.UDP = append(a.UDP, b.UDP...)
	a.ICMP = append(a.ICMP, b.ICMP...)
	a.ICMP6 = append(a.ICMP6, b.ICMP6...)
	a.SvOther = append(a.SvOther, b.SvOther...)
	// Add rules.
	// Rules are prepended per default.
	// Rules with attribute .Append are appended after last non Drop line.
	var prependACL, appendACL []*chkpRule
	for _, ru := range b.Rules {
		if ru.Append {
			ru.Append = false
			appendACL = append(appendACL, ru)
		} else {
			prependACL = append(prependACL, ru)
		}
	}
	if len(prependACL) > 0 {
		a.Rules = append(prependACL, a.Rules...)
	}
	if len(appendACL) > 0 {
		// Find last non Drop line.
		i := len(a.Rules) - 1
		for ; i >= 0; i-- {
			if a.Rules[i].Action != "Drop" {
				i++
				break
			}
		}
		a.Rules = slices.Insert(a.Rules, i, appendACL...)
	}
	for gw, lb := range b.GatewayRoutes {
		a.GatewayRoutes[gw] = append(a.GatewayRoutes[gw], lb...)
	}
	return a
}
