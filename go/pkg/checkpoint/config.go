package checkpoint

import "github.com/hknutzen/Netspoc-Approve/go/pkg/device"

func (n1 *chkpConfig) MergeSpoc(c2 device.DeviceConfig) device.DeviceConfig {
	return n1
}

func (n *chkpConfig) CheckRulesFromRaw() error { return nil }
