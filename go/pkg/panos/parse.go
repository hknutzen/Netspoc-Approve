package panos

import (
	"bytes"
	"encoding/xml"
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
	XMLName     xml.Name `xml:"entry"`
	Name        string   `xml:"name,attr"`
	Action      string   `xml:"action"`
	From        []string `xml:"from>member"`
	To          []string `xml:"to>member"`
	Source      []string `xml:"source>member"`
	Destination []string `xml:"destination>member"`
	Service     []string `xml:"service>member"`
	Application []string `xml:"application>member"`
	LogStart    string   `xml:"log-start"`
	LogEnd      string   `xml:"log-end"`
	LogSetting  string   `xml:"log-setting,omitempty"`
	RuleType    string   `xml:"rule-type"`
	Unknown     RuleAttr `xml:",any"`
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
	//Tag     string      `xml:"tag,omitempty"`
	Unknown []AnyHolder `xml:",any"`
	//invalid bool
	needed bool
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
	XMLName  xml.Name    `xml:"entry"`
	Name     string      `xml:"name,attr"`
	Protocol panProtocol `xml:"protocol"`
	Unknown  []AnyHolder `xml:",any"`
	//invalid  bool
	needed bool
}

type panProtocol struct {
	TCP     *panPort    `xml:"tcp"`
	UDP     *panPort    `xml:"udp"`
	Unknown []AnyHolder `xml:",any"`
}
type panPort struct {
	Port    string      `xml:"port"`
	Unknown []AnyHolder `xml:",any"`
}

type AnyHolder struct {
	XMLName xml.Name
	XML     string `xml:",innerxml"`
}

type RuleAttr []AnyHolder

// Ignore attributes <source-user>, <category>, <source-hip>, <destination-hip>
// if value is <member>any</member>.
func (s *RuleAttr) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var x []AnyHolder
	d.DecodeElement(&x, &start)
	for _, attr := range x {
		switch attr.XMLName.Local {
		case "source-user", "category", "source-hip", "destination-hip":
			if attr.XML == "<member>any</member>" {
				continue
			}
		}
		*s = append(*s, attr)
	}
	return nil
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
