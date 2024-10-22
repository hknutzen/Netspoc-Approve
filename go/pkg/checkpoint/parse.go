package checkpoint

import (
	"encoding/json"
	"fmt"
	"path"
	"strings"

	"github.com/hknutzen/Netspoc-Approve/go/pkg/deviceconf"
)

type chkpConfig struct {
	Rules         []*chkpRule
	Networks      []*chkpNetwork
	Hosts         []*chkpHost
	Groups        []*chkpGroup
	TCP           []*chkpTCP
	UDP           []*chkpUDP
	ICMP          []*chkpICMP
	ICMP6         []*chkpICMP6
	SvOther       []*chkpSvOther
	GatewayRoutes map[string][]*chkpRoute
	GatewayIP     map[string]string
}

type chkpRule struct {
	Name        string      `json:"name"`
	Layer       string      `json:"layer,omitempty"`
	Comments    string      `json:"comments,omitempty"`
	Action      chkpName    `json:"action"`
	Source      []chkpName  `json:"source"`
	Destination []chkpName  `json:"destination"`
	Service     []chkpName  `json:"service"`
	Track       *chkpTrack  `json:"track,omitempty"`
	InstallOn   []chkpName  `json:"install-on"`
	Position    interface{} `json:"position,omitempty"`
	Append      bool        `json:"append,omitempty"` // From raw file.
	needed      bool
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
	Accounting            bool     `json:"accounting,omitempty"`
	Alert                 string   `json:"alert,omitempty"`
	EnableFirewallSession bool     `json:"enable-firewall-session,omitempty"`
	PerConnection         bool     `json:"per-connection,omitempty"`
	PerSession            bool     `json:"per-session,omitempty"`
	Type                  chkpName `json:"type,omitempty"`
}

type object interface {
	getAPIObject() string
	getName() string
	getComments() string
	getReadOnly() bool
	getNeeded() bool
	setNeeded()
	getDeletable() bool
	setDeletable()
}

type chkpObject struct {
	Name      string `json:"name"`
	Comments  string `json:"comments,omitempty"`
	ReadOnly  bool   `json:"read-only,omitempty"`
	needed    bool
	deletable bool
}

func (o *chkpObject) getName() string     { return o.Name }
func (o *chkpObject) getComments() string { return o.Comments }
func (o *chkpObject) getReadOnly() bool   { return o.ReadOnly }
func (o *chkpObject) getNeeded() bool     { return o.needed }
func (o *chkpObject) setNeeded()          { o.needed = true }
func (o *chkpObject) getDeletable() bool  { return o.deletable }
func (o *chkpObject) setDeletable()       { o.deletable = true }

func (o *chkpNetwork) getAPIObject() string { return "network" }
func (o *chkpHost) getAPIObject() string    { return "host" }
func (o *chkpGroup) getAPIObject() string   { return "group" }
func (o *chkpTCP) getAPIObject() string     { return "service-tcp" }
func (o *chkpUDP) getAPIObject() string     { return "service-udp" }
func (o *chkpICMP) getAPIObject() string    { return "service-icmp" }
func (o *chkpICMP6) getAPIObject() string   { return "service-icmp6" }
func (o *chkpSvOther) getAPIObject() string { return "service-other" }

type chkpNetwork struct {
	chkpObject
	Subnet4     string `json:"subnet4,omitempty"`
	Subnet6     string `json:"subnet6,omitempty"`
	MaskLength4 int    `json:"mask-length4,omitempty"`
	MaskLength6 int    `json:"mask-length6,omitempty"`
}

type chkpHost struct {
	chkpObject
	IPv4Address string `json:"ipv4-address,omitempty"`
	IPv6Address string `json:"ipv6-address,omitempty"`
}

type chkpGroup struct {
	chkpObject
	Members []chkpName `json:"members"`
}

type chkpTCP struct {
	chkpObject
	Port       string `json:"port"`
	SourcePort string `json:"source-port,omitempty"`
	Protocol   string `json:"protocol,omitempty"`
}

type chkpUDP struct {
	chkpObject
	Port       string `json:"port"`
	SourcePort string `json:"source-port,omitempty"`
	Protocol   string `json:"protocol,omitempty"`
}

type chkpICMP struct {
	chkpObject
	IcmpType *int `json:"icmp-type"`
	IcmpCode *int `json:"icmp-code,omitempty"`
}

type chkpICMP6 struct {
	chkpObject
	IcmpType *int `json:"icmp-type"`
	IcmpCode *int `json:"icmp-code,omitempty"`
}

type chkpSvOther struct {
	chkpObject
	IpProtocol int    `json:"ip-protocol"`
	Match      string `json:"match,omitempty"`
}

type chkpRoute struct {
	Address    string        `json:"address"`
	MaskLength int           `json:"mask-length"`
	Type       string        `json:"type"`
	NextHop    []chkpGateway `json:"next-hop"`
}

type chkpGateway struct {
	Gateway string `json:"gateway"`
}

func (s *State) ParseConfig(data []byte, fName string,
) (deviceconf.Config, error) {
	cf := &chkpConfig{}
	if len(data) == 0 {
		return cf, nil
	}
	err := json.Unmarshal(data, cf)
	if err != nil {
		return nil, err
	}
	for _, r := range cf.Rules {
		r.Layer = "network"
	}
	if path.Ext(fName) == ".raw" {
		if err := checkRaw(cf); err != nil {
			return nil, err
		}
	}
	return cf, nil
}

func checkRaw(cf *chkpConfig) error {
	checkName := func(n string) error {
		if !strings.HasPrefix(n, "Raw ") {
			return fmt.Errorf(
				"Must only define name starting with 'Raw ': %s", n)
		}
		return nil
	}
	// Raw file is allowed to reference
	// - other objects from raw file, having name starting with "Raw ",
	// - or system defined names like "Any" or "echo-request".
	// Names with "_" or " " are assumed to be defined by Netspoc.
	checkRef := func(from string, l []chkpName) error {
		for _, n := range l {
			s := string(n)
			if !strings.HasPrefix(s, "Raw ") && strings.ContainsAny(s, " _") {
				return fmt.Errorf(
					"Must not reference name from Netspoc in %q: %s", from, s)
			}
		}
		return nil
	}
	for _, r := range cf.Rules {
		if err := checkName(r.Name); err != nil {
			return err
		}
		for _, l := range [][]chkpName{r.Source, r.Destination, r.Service} {
			if err := checkRef(r.Name, l); err != nil {
				return err
			}
		}
	}
	for _, g := range cf.Groups {
		if err := checkRef(g.Name, g.Members); err != nil {
			return err
		}
	}
	for _, o := range getObjList(cf) {
		if err := checkName(o.getName()); err != nil {
			return err
		}
	}
	return nil
}
