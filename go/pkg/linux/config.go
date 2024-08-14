package linux

import (
	"slices"

	"github.com/hknutzen/Netspoc-Approve/go/pkg/device"
)

func (a *config) MergeSpoc(d device.DeviceConfig) device.DeviceConfig {
	b := d.(*config)
	a.routes = append(a.routes, b.routes...)
	for tName, bChains := range b.iptables {
		aChains := a.iptables[tName]
		if aChains == nil {
			device.Info("Adding all chains of table %q", tName)
			a.iptables[tName] = bChains
			continue
		}
		for cName, bChain := range bChains {
			aChain := aChains[cName]
			if aChain == nil {
				device.Info("Adding chain %q of table %q", cName, tName)
				aChains[cName] = bChain
				continue
			}
			switch aChain.policy {
			case "-", "":
				device.Abort("Must not redefine chain %q of table %q from rawdata",
					cName, tName)
			}
			for _, ru := range bChain.rules {
				i := 0
				if ru.append {
					// Append before last non DROP line.
					i = len(aChain.rules)
					for i > 0 {
						if aChain.rules[i-1].pairs["-j"] == "DROP" {
							i--
						} else {
							break
						}
					}
				}
				aChain.rules = slices.Insert(aChain.rules, i, ru)
			}
		}
	}
	return a
}
