package panos

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"strings"
)

func parseXML(data []byte) (*PanConfig, error) {
	v := new(PanConfig)
	err := xml.Unmarshal(data, v)
	if err != nil {
		return nil, err
	}
	return v, nil
}

type PanConfig struct {
	XMLName xml.Name     `xml:"config"`
	Entries []*panDevice `xml:"devices>entry"`
	source  string
}

type panDevice struct {
	Name string     `xml:"name,attr"`
	Vsys []*panVsys `xml:"vsys>entry"`
}

type panVsys struct {
	Name          string             `xml:"name,attr"`
	Rules         []*panRule         `xml:"rulebase>security>rules>entry"`
	Addresses     []*panAddress      `xml:"address>entry"`
	AddressGroups []*panAddressGroup `xml:"address-group>entry"`
	Services      []*panService      `xml:"service>entry"`
}

type panRule struct {
	XMLName     xml.Name    `xml:"entry"`
	Name        string      `xml:"name,attr"`
	Action      string      `xml:"action"`
	From        []string    `xml:"from>member"`
	To          []string    `xml:"to>member"`
	Source      []string    `xml:"source>member"`
	Destination []string    `xml:"destination>member"`
	Service     []string    `xml:"service>member"`
	Application []string    `xml:"application>member"`
	LogStart    string      `xml:"log-start"`
	LogEnd      string      `xml:"log-end"`
	LogSetting  string      `xml:"log-setting,omitempty"`
	RuleType    string      `xml:"rule-type"`
	Unknown     []AnyHolder `xml:",any"`
	// Artifical attribute in raw files
	Append *struct{} `xml:"APPEND,omitempty"`
}

type panMembers struct {
	Member []string `xml:"member"`
}

type panAddress struct {
	XMLName   xml.Name `xml:"entry"`
	Name      string   `xml:"name,attr"`
	IpNetmask string   `xml:"ip-netmask,omitempty"`
	//IpRange   string      `xml:"ip-range,omitempty"`
	Tag     string      `xml:"tag,omitempty"`
	Unknown []AnyHolder `xml:",any"`
	invalid bool
	needed  bool
}

type panAddressGroup struct {
	XMLName      xml.Name    `xml:"entry"`
	Name         string      `xml:"name,attr"`
	Members      []string    `xml:"static>member"`
	Unknown      []AnyHolder `xml:",any"`
	needed       bool
	nameOnDevice string
}

type panService struct {
	XMLName xml.Name `xml:"entry"`
	Name    string   `xml:"name,attr"`
	Value   string
	Unknown []AnyHolder
	invalid bool
	needed  bool
}

type rawService struct {
	Name     string       `xml:"name,attr"`
	Protocol *rawProtocol `xml:"protocol"`
	Unknown  []AnyHolder  `xml:",any"`
}

type rawProtocol struct {
	TCP     *rawPort    `xml:"tcp"`
	UDP     *rawPort    `xml:"udp"`
	Unknown []AnyHolder `xml:",any"`
}
type rawPort struct {
	Port string `xml:"port"`
	//Override struct{}    `xml:"override,omitempty"`
	Unknown []AnyHolder `xml:",any"`
}

type AnyHolder struct {
	XMLName xml.Name
	XML     string `xml:",innerxml"`
}

func (v *panService) UnmarshalXML(
	d *xml.Decoder, start xml.StartElement) error {

	s := new(rawService)
	if err := d.DecodeElement(s, &start); err != nil {
		return err
	}

	value := ""
	unknown := s.Unknown
	p := s.Protocol
	unknown = append(unknown, p.Unknown...)
	if t := p.TCP; t != nil {
		unknown = append(unknown, t.Unknown...)
		if port := t.Port; port != "" {
			value = "tcp " + port
		}
	}
	if u := p.UDP; u != nil {
		unknown = append(unknown, u.Unknown...)
		if port := u.Port; port != "" {
			if value != "" {
				return fmt.Errorf("Must not use both tcp and udp in %s", start)
			}
			value = "udp " + port
		}
	}
	if value == "" && unknown == nil {
		return fmt.Errorf("Expected tcp or udp in %v", start)
	}
	*v = panService{Name: s.Name, Value: value, Unknown: unknown}

	return nil
}

func (v *panService) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	s := new(rawService)
	s.Name = v.Name
	p := new(rawProtocol)
	s.Protocol = p
	val := v.Value
	i := strings.Index(val, " ")
	proto := val[:i]
	port := val[i+1:]
	pr := &rawPort{Port: port}
	switch proto {
	case "tcp":
		p.TCP = pr
	case "udp":
		p.UDP = pr
	}
	return e.EncodeElement(s, start)
}

// Print only value of object as XML, strip outer opening and closing tags.
// Example:
// <a><b>v</b><c>w</c></a>
// => <b>v</b><c>w</c>
func printXMLValue(v interface{}) string {
	b, err := xml.Marshal(v)
	if err != nil {
		panic(err)
	}
	i := bytes.Index(b, []byte(">"))
	j := bytes.LastIndex(b, []byte("<"))
	b = b[i+1 : j]
	return string(bytes.TrimSpace(b))
}
