package nsx

import "github.com/hknutzen/Netspoc-Approve/go/pkg/device"

func (n NsxConfig) MergeSpoc(config device.DeviceConfig) device.DeviceConfig {
	//TODO implement me
	return config
}

func (n NsxConfig) GetDevName() string {
	return ""
}

func (n NsxConfig) CheckRulesFromRaw() error {
	//TODO implement me
	return nil
}
