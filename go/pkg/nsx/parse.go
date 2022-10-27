package nsx

import (
	"bytes"
	"encoding/json"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/device"
)

type nsxPolicy struct {
	Id    string
	Rules []*nsxRule
}

type nsxRule struct {
	Id                   string
	Action               string
	SequenceNumber       int      `json:"sequence_number"`
	SourcesExcluded      bool     `json:"sources_excluded"`
	DestinationsExcluded bool     `json:"destinations_excluded"`
	SourceGroups         []string `json:"source_groups"`
	DestinationGroups    []string `json:"destination_groups"`
	Services             []string
	ServiceEntries       []json.RawMessage `json:"service_entries"`
	Profiles             []string
	Scope                []string
	Disabled             bool
	Logged               bool
	Direction            string
	IPProtocol           string `json:"ip_protocol"`
	Revision             int    `json:"_revision"`
}

type nsxGroup struct {
	Id           string
	Expression   []*nsxGroupExpression
	needed       bool
	nameOnDevice string
}

type nsxGroupExpression struct {
	RessourceType string   `json:"ressource_type"`
	IPAddresses   []string `json:"ip_addresses"`
}

type nsxService struct {
	Id             string
	ServiceEntries []*nsxServiceEntry `json:"service_entries"`
	needed         bool
}

type nsxServiceEntry struct {
	ResourceType     string   `json:"resource_type"`
	L4Protocol       string   `json:"l4_protocol"`
	SourcePorts      []string `json:"source_ports"`
	DestinationPorts []string `json:"destination_ports"`
	ICMPProtocol     string   `json:"protocol"`
	ICMPType         int      `json:"icmp_type"`
	ICMPCode         int      `json:"icmp_code"`
	ProtocolNumber   int      `json:"protocol_number"`
}

type NsxConfig struct {
	Policies []*nsxPolicy
	Groups   []*nsxGroup
	Services []*nsxService
}

func (s *State) ParseConfig(data []byte) (device.DeviceConfig, error) {
	if len(data) == 0 {
		var n *NsxConfig
		return n, nil
	}
	config := &NsxConfig{}
	err := json.Unmarshal(removeHeader(data), config)
	return config, err
}

func removeHeader(data []byte) []byte {
	if bytes.HasPrefix(data, []byte("http")) {
		i := bytes.IndexByte(data, byte('\n'))
		return data[i+1:]
	}
	if bytes.HasPrefix(data, []byte("Generated")) {
		i := bytes.IndexByte(data, byte('{'))
		return data[i:]
	}
	return data
}
