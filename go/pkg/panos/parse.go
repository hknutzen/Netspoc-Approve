package panos

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"net/url"
	"regexp"
)

func parseResponse(data []byte) ([]byte, error) {
	v := new(PanResponse)
	err := xml.Unmarshal(data, v)
	if err != nil {
		return nil, fmt.Errorf("Parsing response: %v", err)
	}
	if v.Status != "success" {
		return nil, fmt.Errorf(
			"Request failed with response status: %s and\n body %s",
			v.Status, string(data))
	}
	return v.Result.XML, nil
}

func parseConfig(data []byte) (*PanConfig, error) {
	v := new(PanConfig)
	err := xml.Unmarshal(data, v)
	return v, err
}

type PanResponse struct {
	XMLName xml.Name  `xml:"response"`
	Status  string    `xml:"status,attr"`
	Result  panResult `xml:"result"`
}

type panResult struct {
	XML []byte `xml:",innerxml"`
}

type PanConfig struct {
	XMLName xml.Name    `xml:"config"`
	Devices *PanDevices `xml:"devices"`
	origin  string
}

type PanDevices struct {
	XMLName xml.Name     `xml:"devices"`
	Entries []*panDevice `xml:"entry"`
}

type panDevice struct {
	Name     string     `xml:"name,attr"`
	Hostname string     `xml:"deviceconfig>system>hostname"`
	Vsys     []*panVsys `xml:"vsys>entry"`
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
	LogStart    string   `xml:"log-start,omitempty"`
	LogEnd      string   `xml:"log-end,omitempty"`
	LogSetting  string   `xml:"log-setting,omitempty"`
	RuleType    string   `xml:"rule-type,omitempty"`
	Unknown     RuleAttr `xml:",any"`
	// Artifical attribute in raw files
	Append *struct{} `xml:"APPEND,omitempty"`
}

type panMembers struct {
	Member []string `xml:"member"`
}

type panAddress struct {
	XMLName   xml.Name  `xml:"entry"`
	Name      string    `xml:"name,attr"`
	IpNetmask string    `xml:"ip-netmask,omitempty"`
	Unknown   OtherAttr `xml:",any"`
	needed    bool
}

type panAddressGroup struct {
	XMLName      xml.Name  `xml:"entry"`
	Name         string    `xml:"name,attr"`
	Members      []string  `xml:"static>member"`
	Unknown      OtherAttr `xml:",any"`
	needed       bool
	nameOnDevice string
}

type panService struct {
	XMLName  xml.Name    `xml:"entry"`
	Name     string      `xml:"name,attr"`
	Protocol panProtocol `xml:"protocol"`
	Unknown  OtherAttr   `xml:",any"`
	needed   bool
}

type panProtocol struct {
	TCP     *panPort  `xml:"tcp"`
	UDP     *panPort  `xml:"udp"`
	Unknown OtherAttr `xml:",any"`
}
type panPort struct {
	Port    string    `xml:"port"`
	Unknown OtherAttr `xml:",any"`
}

type AnyHolder struct {
	XMLName xml.Name
	XML     string `xml:",innerxml"`
}

type OtherAttr []AnyHolder

func (s *OtherAttr) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var x []AnyHolder
	d.DecodeElement(&x, &start)
	for _, attr := range x {
		attr.XML = stripWhitespace(attr.XML)
		*s = append(*s, attr)
	}
	return nil
}

type RuleAttr []AnyHolder

// Ignore attributes <source-user>, <category>, <source-hip>, <destination-hip>
// if value is <member>any</member>.
func (s *RuleAttr) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var x OtherAttr
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

func stripWhitespace(s string) string {
	re1 := regexp.MustCompile(`>\s+`)
	re2 := regexp.MustCompile(`\s+<`)
	s = re1.ReplaceAllString(s, ">")
	s = re2.ReplaceAllString(s, "<")
	return s
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
	return url.QueryEscape(string(bytes.TrimSpace(b)))
}
