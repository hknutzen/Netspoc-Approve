package checkpoint

import (
	"cmp"
	"encoding/json/v2"
	"fmt"
	"path"
	"strings"
)

type chkpConfig struct {
	TargetPolicy  map[string]*chkpPolicy
	TargetRules   map[string][]*chkpRule
	Networks      []*chkpNetwork
	Hosts         []*chkpHost
	Groups        []*chkpGroup
	TCP           []*chkpTCP
	UDP           []*chkpUDP
	ICMP          []*chkpICMP
	ICMP6         []*chkpICMP6
	SvOther       []*chkpSvOther
	GatewayRoutes map[string][]*chkpRoute
	GatewayIPs    map[string][]string
}

type chkpPolicy struct {
	Name    string
	Layer   string
	Comment string `json:",omitzero"`
}

type chkpRule struct {
	Name              string       `json:"name"`
	UID               string       `json:"uid,omitzero"`
	Layer             string       `json:"layer,omitzero"`
	Comments          string       `json:"comments,omitzero"`
	Action            chkpName     `json:"action"`
	Source            []chkpName   `json:"source"`
	Destination       []chkpName   `json:"destination"`
	Service           []chkpName   `json:"service"`
	Disabled          invertedBool `json:"enabled,omitzero"`
	SourceNegate      bool         `json:"source-negate,omitzero"`
	DestinationNegate bool         `json:"destination-negate,omitzero"`
	ServiceNegate     bool         `json:"service-negate,omitzero"`
	Track             *chkpTrack   `json:"track,omitzero"`
	InstallOn         []chkpName   `json:"install-on"`
	Position          any          `json:"position,omitzero"`
	Append            bool         `json:"append,omitzero"` // From raw file.
	needed            bool
}

type chkpName string

// Read name directly as string from Netspoc or
// use attribute "name" from device.
func (n *chkpName) UnmarshalJSON(b []byte) error {
	var name string
	if err := json.Unmarshal(b, &name); err != nil {
		var obj struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(b, &obj); err != nil {
			return err
		}
		name = obj.Name
	}
	*n = chkpName(name)
	return nil
}

// Default value of attribute 'enabled' is true.
// But zero value of bool is false in Go.
// Hence we store the inverted value in attribute 'disabled'.
type invertedBool bool

func (b *invertedBool) UnmarshalJSON(in []byte) error {
	var v bool
	if err := json.Unmarshal(in, &v); err != nil {
		return err
	}
	*b = invertedBool(!v)
	return nil
}
func (b *invertedBool) MarshalJSON() ([]byte, error) {
	return json.Marshal(!bool(*b))
}

type chkpTrack struct {
	Accounting            bool     `json:"accounting,omitzero"`
	Alert                 string   `json:"alert,omitzero"`
	EnableFirewallSession bool     `json:"enable-firewall-session,omitzero"`
	PerConnection         bool     `json:"per-connection,omitzero"`
	PerSession            bool     `json:"per-session,omitzero"`
	Type                  chkpName `json:"type,omitzero"`
}

type object interface {
	getAPIObject() string
	getName() string
	clearName()
	getUID() string
	setUID(string)
	getComments() string
	setIgnoreWarnings()
	getReadOnly() bool
	getNeeded() bool
	setNeeded()
	getDeletable() bool
	setDeletable()
	getChanged() bool
	setChanged()
}

type chkpObject struct {
	Name           string `json:"name,omitzero"`
	UID            string `json:"uid,omitzero"`
	Comments       string `json:"comments,omitzero"`
	IgnoreWarnings bool   `json:"ignore-warnings,omitzero"`
	ReadOnly       bool   `json:"read-only,omitzero"`
	needed         bool
	deletable      bool
	changed        bool
}

func (o *chkpObject) getName() string     { return o.Name }
func (o *chkpObject) clearName()          { o.Name = "" }
func (o *chkpObject) getUID() string      { return o.UID }
func (o *chkpObject) setUID(uid string)   { o.UID = uid }
func (o *chkpObject) getComments() string { return o.Comments }
func (o *chkpObject) setIgnoreWarnings()  { o.IgnoreWarnings = true }
func (o *chkpObject) getReadOnly() bool   { return o.ReadOnly }
func (o *chkpObject) getNeeded() bool     { return o.needed }
func (o *chkpObject) setNeeded()          { o.needed = true }
func (o *chkpObject) getDeletable() bool  { return o.deletable }
func (o *chkpObject) setDeletable()       { o.deletable = true }
func (o *chkpObject) getChanged() bool    { return o.changed }
func (o *chkpObject) setChanged()         { o.changed = true }

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
	Subnet4     string `json:"subnet4,omitzero"`
	Subnet6     string `json:"subnet6,omitzero"`
	MaskLength4 int    `json:"mask-length4,omitzero"`
	MaskLength6 int    `json:"mask-length6,omitzero"`
}

type chkpHost struct {
	chkpObject
	IPv4Address string `json:"ipv4-address,omitzero"`
	IPv6Address string `json:"ipv6-address,omitzero"`
}

type chkpGroup struct {
	chkpObject
	Members []chkpName `json:"members"`
}

type chkpTCP struct {
	chkpObject
	Port       string `json:"port"`
	SourcePort string `json:"source-port,omitzero"`
	Protocol   string `json:"protocol,omitzero"`
}

type chkpUDP struct {
	chkpObject
	Port       string `json:"port"`
	SourcePort string `json:"source-port,omitzero"`
	Protocol   string `json:"protocol,omitzero"`
}

type chkpICMP struct {
	chkpObject
	IcmpType *int `json:"icmp-type"`
	IcmpCode *int `json:"icmp-code,omitzero"`
}

type chkpICMP6 struct {
	chkpObject
	IcmpType *int `json:"icmp-type"`
	IcmpCode *int `json:"icmp-code,omitzero"`
}

type chkpSvOther struct {
	chkpObject
	IpProtocol int    `json:"ip-protocol"`
	Match      string `json:"match,omitzero"`
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

func (s *State) parseConfig(data []byte, fName string,
) (*chkpConfig, error) {
	cf := &chkpConfig{}
	if len(data) == 0 {
		return cf, nil
	}
	err := json.Unmarshal(data, cf)
	if err != nil {
		return nil, err
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
	for target, rules := range cf.TargetRules {
		for _, r := range rules {
			if err := checkName(r.Name); err != nil {
				return err
			}
			for _, l := range [][]chkpName{r.Source, r.Destination, r.Service} {
				if err := checkRef(r.Name, l); err != nil {
					return err
				}
			}
		}
		if err := checkInstallOn(rules, target); err != nil {
			return err
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

func checkInstallOn(l []*chkpRule, target string) error {
	for _, r := range l {
		if l := r.InstallOn; len(l) == 1 {
			if equalFold(string(l[0]), "Policy Targets") {
				continue
			}
			if equalFold(string(l[0]), target) {
				r.InstallOn[0] = chkpName("Policy Targets")
				continue
			}
		}
		return fmt.Errorf(
			`Must use "install-on": ["Policy Targets"] in rule %q of %q`,
			cmp.Or(r.Name, r.UID), target)
	}
	return nil
}
