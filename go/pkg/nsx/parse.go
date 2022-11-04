package nsx

import (
	"bytes"
	"encoding/json"

	"github.com/hknutzen/Netspoc-Approve/go/pkg/device"
)

type nsxPolicy struct {
	Id    string     `json:"id"`
	Rules []*nsxRule `json:"rules"`
}

type nsxRule struct {
	Id                   string            `json:"id,omitempty"`
	Action               string            `json:"action"`
	SequenceNumber       int               `json:"sequence_number"`
	SourcesExcluded      bool              `json:"sources_excluded,omitempty"`
	DestinationsExcluded bool              `json:"destinations_excluded,omitempty"`
	SourceGroups         []string          `json:"source_groups"`
	DestinationGroups    []string          `json:"destination_groups"`
	Services             []string          `json:"services"`
	ServiceEntries       []json.RawMessage `json:"service_entries,omitempty"`
	Profiles             []string          `json:"profiles,omitempty"`
	Scope                []string          `json:"scope"`
	Disabled             bool              `json:"disabled,omitempty"`
	Logged               bool              `json:"logged,omitempty"`
	Direction            string            `json:"direction"`
	IPProtocol           string            `json:"ip_protocol,omitempty"`
	Revision             int               `json:"_revision,omitempty"`
}

type nsxGroup struct {
	Id           string                `json:"id"`
	Expression   []*nsxGroupExpression `json:"expression"`
	needed       bool
	nameOnDevice string
}

type nsxGroupExpression struct {
	Id            string   `json:"id"`
	RessourceType string   `json:"ressource_type"`
	IPAddresses   []string `json:"ip_addresses"`
}

type nsxService struct {
	Id             string             `json:"id,omitempty"`
	ServiceEntries []*nsxServiceEntry `json:"service_entries"`
	needed         bool
}

type nsxServiceEntry struct {
	DisplayName      string   `json:"display_name"`
	ResourceType     string   `json:"resource_type"`
	L4Protocol       string   `json:"l4_protocol"`
	SourcePorts      []string `json:"source_ports,omitempty"`
	DestinationPorts []string `json:"destination_ports,omitempty"`
	ICMPProtocol     string   `json:"protocol"`
	ICMPType         int      `json:"icmp_type"`
	ICMPCode         int      `json:"icmp_code"`
	ProtocolNumber   int      `json:"protocol_number"`
}

type jsonMap map[string]interface{}

func (e *nsxServiceEntry) MarshalJSON() ([]byte, error) {
	var result jsonMap
	switch e.ResourceType {
	case "IpProtocolServiceEntry":
		result = jsonMap{
			"display_name":    e.DisplayName,
			"resource_type":   e.ResourceType,
			"protocol_number": e.ProtocolNumber,
		}
	case "L4PortSetServiceEntry":
		result = jsonMap{
			"display_name":      e.DisplayName,
			"resource_type":     e.ResourceType,
			"l4_protocol":       e.L4Protocol,
			"source_ports":      e.SourcePorts,
			"destination_ports": e.DestinationPorts,
		}
	case "IcmpTypeServiceEntry":
		result = jsonMap{
			"display_name":  e.DisplayName,
			"resource_type": e.ResourceType,
			"icmp_type":     e.ICMPType,
			"icmp_code":     e.ICMPCode,
		}

	}
	return json.Marshal(result)
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
