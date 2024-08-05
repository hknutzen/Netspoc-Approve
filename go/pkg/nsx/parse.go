package nsx

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path"
	"regexp"

	"github.com/hknutzen/Netspoc-Approve/go/pkg/device"
)

type nsxPolicy struct {
	Id    string     `json:"id"`
	Rules []*nsxRule `json:"rules"`
}

type nsxRule struct {
	Id                   string          `json:"id,omitempty"`
	Action               string          `json:"action"`
	SequenceNumber       int             `json:"sequence_number"`
	SourcesExcluded      bool            `json:"sources_excluded,omitempty"`
	DestinationsExcluded bool            `json:"destinations_excluded,omitempty"`
	SourceGroups         []string        `json:"source_groups"`
	DestinationGroups    []string        `json:"destination_groups"`
	Services             []string        `json:"services"`
	ServiceEntries       json.RawMessage `json:"service_entries,omitempty"`
	Profiles             []string        `json:"profiles,omitempty"`
	Scope                []string        `json:"scope"`
	Disabled             bool            `json:"disabled,omitempty"`
	Logged               bool            `json:"logged,omitempty"`
	Tag                  string          `json:"tag,omitempty"`
	Direction            string          `json:"direction"`
	IPProtocol           string          `json:"ip_protocol,omitempty"`
	Revision             int             `json:"_revision,omitempty"`
}

type nsxGroup struct {
	Id           string                `json:"id,omitempty"`
	Expression   []*nsxGroupExpression `json:"expression"`
	needed       bool
	nameOnDevice string
}

type nsxGroupExpression struct {
	Id           string   `json:"id,omitempty"`
	ResourceType string   `json:"resource_type"`
	IPAddresses  []string `json:"ip_addresses"`
}

type nsxService struct {
	Id             string             `json:"id,omitempty"`
	ServiceEntries []*nsxServiceEntry `json:"service_entries"`
	needed         bool
}

type nsxServiceEntry struct {
	Id               string   `json:"id"`
	ResourceType     string   `json:"resource_type"`
	L4Protocol       string   `json:"l4_protocol"`
	SourcePorts      []string `json:"source_ports"`
	DestinationPorts []string `json:"destination_ports"`
	ICMPProtocol     string   `json:"protocol"`
	ICMPType         *int     `json:"icmp_type"`
	ICMPCode         *int     `json:"icmp_code"`
	ProtocolNumber   int      `json:"protocol_number"`
}

type jsonMap map[string]interface{}

func (e *nsxServiceEntry) MarshalJSON() ([]byte, error) {
	var result jsonMap
	switch e.ResourceType {
	case "IPProtocolServiceEntry":
		result = jsonMap{
			"id":              e.Id,
			"resource_type":   e.ResourceType,
			"protocol_number": e.ProtocolNumber,
		}
	case "L4PortSetServiceEntry":
		result = jsonMap{
			"id":                e.Id,
			"resource_type":     e.ResourceType,
			"l4_protocol":       e.L4Protocol,
			"source_ports":      e.SourcePorts,
			"destination_ports": e.DestinationPorts,
		}
	case "ICMPTypeServiceEntry":
		result = jsonMap{
			"id":            e.Id,
			"resource_type": e.ResourceType,
			"protocol":      e.ICMPProtocol,
		}
		if e.ICMPType != nil {
			result["icmp_type"] = *e.ICMPType
		}
		if e.ICMPCode != nil {
			result["icmp_code"] = *e.ICMPCode
		}

	}
	return json.Marshal(result)
}

type NsxConfig struct {
	Policies []*nsxPolicy
	Groups   []*nsxGroup
	Services []*nsxService
}

func (s *State) ParseConfig(data []byte, fName string) (
	device.DeviceConfig, error) {

	config := &NsxConfig{}
	if len(data) == 0 {
		return config, nil
	}
	err := json.Unmarshal(removeHeader(data), config)
	if err != nil {
		return nil, err
	}
	if path.Ext(fName) == ".raw" {
		if err := checkRaw(config); err != nil {
			return nil, err
		}
	}
	err = checkConfigValidity(config)
	return config, err
}

func checkRaw(c *NsxConfig) error {
	re := regexp.MustCompile(`^r\d`)
	for _, p := range c.Policies {
		for _, r := range p.Rules {
			if re.MatchString(r.Id) {
				return fmt.Errorf(
					"Must not use rule name starting with 'r<NUM>': %s",
					r.Id)
			}
		}
	}
	return nil
}
func checkConfigValidity(c *NsxConfig) error {
	for _, p := range c.Policies {
		for _, r := range p.Rules {
			if len(r.SourceGroups) != 1 || len(r.DestinationGroups) != 1 || len(r.Services) != 1 {
				return fmt.Errorf(
					"Expecting exactly one element in source/destination/service of rule %s", r.Id)
			}
		}
	}
	for _, g := range c.Groups {
		if len(g.Expression) != 1 {
			return fmt.Errorf("Expecting exactly one expression in group %s", g.Id)
		}
	}
	return nil
}

func removeHeader(data []byte) []byte {
	for {
		if bytes.HasPrefix(data, []byte("#")) {
			i := bytes.IndexByte(data, byte('\n'))
			if i == -1 {
				return data[len(data):]
			}
			data = data[i+1:]
		} else {
			return data
		}
	}
}
