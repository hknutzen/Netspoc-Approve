package checkpoint

import (
	"bytes"
	"encoding/json"

	"github.com/hknutzen/Netspoc-Approve/go/pkg/device"
)

type chkpConfig struct {
	Rules    []chkpRule
	Networks []chkpNetwork
	Hosts    []chkpHost
	Tcp      []chkpTCP
	Udp      []chkpUDP
	Icmp     []chkpICMP
	Icmp6    []chkpICMP6
	SvOther  []chkpSvOther
	Routes   []chkpRoute
}

type chkpRule struct {
	Name        string
	Comments    string
	Action      chkpName
	Source      []chkpName
	Destination []chkpName
	Service     []chkpName
	Track       chkpTrack
	InstallOn   []chkpName `json:"install-on"`
	RuleNumber  int        `json:"rule-number"`
	//Layer       string
}

type chkpName string

// Read name directly as string from Netspoc or
// use attribute "name" from device.
func (n *chkpName) UnmarshalJSON(b []byte) error {
	var name string
	if err := json.Unmarshal(b, &name); err != nil {
		var obj struct{ Name string }
		if err := json.Unmarshal(b, &obj); err != nil {
			return err
		}
		name = obj.Name
	}
	*n = chkpName(name)
	return nil
}

type chkpTrack struct {
	Accounting            bool   `json:",omitempty"`
	Alert                 string `json:",omitempty"`
	EnableFirewallSession bool   `json:"enable-firewall-session,omitempty"`
	PerConnection         bool   `json:"per-connection,omitempty"`
	PerSession            bool   `json:"per-session,omitempty"`
	Type                  chkpName
}

type chkpNetwork struct {
	Name        string
	Comments    string
	Subnet4     string `json:",omitempty"`
	Subnet6     string `json:",omitempty"`
	MaskLength4 int    `json:"mask-length4,omitempty"`
	MaskLength6 int    `json:"mask-length6,omitempty"`
}

type chkpHost struct {
	Name        string
	Comments    string
	IPv4Address string `json:"ipv4-address,omitempty"`
	IPv6Address string `json:"ipv6-address,omitempty"`
}

type chkpTCP struct {
	Name       string
	Comments   string
	Port       string
	SourcePort string `json:"source-port,omitempty"`
	Protocol   string `json:",omitempty"`
}

type chkpUDP struct {
	Name       string
	Comments   string
	Port       string
	SourcePort string `json:"source-port,omitempty"`
	Protocol   string `json:",omitempty"`
}

type chkpICMP struct {
	Name     string
	Comments string
	IcmpType *int `json:"icmp-type"`
	IcmpCode *int `json:"icmp-code,omitempty"`
}

type chkpICMP6 struct {
	Name     string
	Comments string
	IcmpType *int `json:"icmp-type"`
	IcmpCode *int `json:"icmp-code,omitempty"`
}

type chkpSvOther struct {
	Name       string
	Comments   string
	IpProtocol int    `json:"ip-protocol"`
	Match      string `json:",omitempty"`
}

type chkpRoute struct {
	Comment    string
	Address    string
	MaskLenght int `json:"mask-lenght"`
	Type       string
	NextHop    []chkpGateway
}

type chkpGateway struct {
	Gateway string
}

func (s *State) ParseConfig(data []byte, fName string) (
	device.DeviceConfig, error) {

	config := &chkpConfig{}
	if len(data) == 0 {
		return config, nil
	}
	err := json.Unmarshal(removeHeader(data), config)
	return config, err
}

func removeHeader(data []byte) []byte {
	if bytes.HasPrefix(data, []byte("Generated")) {
		i := bytes.IndexByte(data, byte('{'))
		return data[i:]
	}
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
