package panos

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"net/url"
	"path"
	"regexp"

	"github.com/hknutzen/Netspoc-Approve/go/pkg/deviceconf"
)

func parseAPIKey(body []byte) (string, error) {
	_, data, err := parseResponse(body)
	if err != nil {
		return "", err
	}
	k := new(panKey)
	err = xml.Unmarshal(data, k)
	return k.Key, err
}

func parseResponse(data []byte) (string, []byte, error) {
	v := new(PanResponse)
	err := xml.Unmarshal(data, v)
	if err != nil {
		return "", nil, fmt.Errorf("Parsing response: %v", err)
	}
	if v.Status != "success" {
		return "", nil, fmt.Errorf("No success: %s", v.Msg)
	}
	var b []byte
	if r := v.Result; r != nil {
		b, _ = xml.Marshal(r)
	}
	return v.Msg, b, nil
}

func (s *State) ParseConfig(data []byte, fName string) (
	deviceconf.Config, error) {

	config := &PanConfig{}
	if len(data) == 0 {
		return config, nil
	}
	// Also handle saved config of device:
	// - starting with http address and
	// - with config stored as <response><result><devices>...
	if bytes.HasPrefix(data, []byte("http")) {
		i := bytes.IndexByte(data, byte('\n'))
		return parseResponseConfig(data[i+1:])
	}
	err := xml.Unmarshal(data, config)
	config.origin = "netspoc"
	if err == nil && path.Ext(fName) == ".raw" {
		err = checkRaw(config)
	}
	return config, err
}

func checkRaw(c *PanConfig) error {
	re := regexp.MustCompile(`^r\d`)
	for _, d := range c.Devices.Entries {
		for _, v := range d.Vsys {
			for _, r := range v.Rules {
				if re.MatchString(r.Name) {
					return fmt.Errorf(
						"Must not use rule name starting with 'r<NUM>': %s",
						r.Name)
				}
			}
		}
	}
	return nil
}

func parseResponseConfig(body []byte) (*PanConfig, error) {
	_, data, err := parseResponse(body)
	if err != nil {
		return nil, err
	}
	d := new(PanResultDevices)
	err = xml.Unmarshal(data, d)
	if err != nil {
		return nil, err
	}
	return &PanConfig{Devices: d.Devices, origin: "device"}, nil
}

type PanResponse struct {
	XMLName xml.Name   `xml:"response"`
	Status  string     `xml:"status,attr"`
	Msg     string     `xml:"msg"`
	Result  *panResult `xml:"result"`
}

type panResult struct {
	XMLName xml.Name
	XML     []byte `xml:",innerxml"`
}

type panKey struct {
	Key string `xml:"key"`
}

type PanResultDevices struct {
	Devices *panDevices `xml:"devices"`
}

type PanConfig struct {
	XMLName xml.Name    `xml:"config"`
	Devices *panDevices `xml:"devices"`
	origin  string
}

type panDevices struct {
	XMLName xml.Name     `xml:"devices"`
	Entries []*panDevice `xml:"entry"`
}

type panDevice struct {
	Name     string     `xml:"name,attr"`
	Hostname string     `xml:"deviceconfig>system>hostname"`
	Banner   string     `xml:"deviceconfig>system>login-banner"`
	Vsys     []*panVsys `xml:"vsys>entry"`
}

type panVsys struct {
	Name          string             `xml:"name,attr"`
	DisplayName   string             `xml:"display-name"`
	Rules         []*panRule         `xml:"rulebase>security>rules>entry"`
	Addresses     []*panAddress      `xml:"address>entry"`
	AddressGroups []*panAddressGroup `xml:"address-group>entry"`
	Services      []*panService      `xml:"service>entry"`
	ServiceGroups []*panServiceGroup `xml:"service-group>entry"`
}

type panRule struct {
	XMLName xml.Name `xml:"entry"`
	Name    string   `xml:"name,attr"`
	Action  string   `xml:"action"`
	From    []string `xml:"from>member"`
	To      []string `xml:"to>member"`
	panRuleSrc
	panRuleDst
	panRuleSrv
	Application []string `xml:"application>member"`
	LogStart    string   `xml:"log-start,omitempty"`
	LogEnd      string   `xml:"log-end,omitempty"`
	LogSetting  string   `xml:"log-setting,omitempty"`
	RuleType    string   `xml:"rule-type,omitempty"`
	Unknown     RuleAttr `xml:",any"`
	// Artifical attribute in raw files
	Append *struct{} `xml:"APPEND,omitempty"`
}

type panList interface {
	getList() []string
}
type panRuleSrc struct {
	Source []string `xml:"source>member"`
}

func (el panRuleSrc) getList() []string {
	return el.Source
}

type panRuleDst struct {
	Destination []string `xml:"destination>member"`
}

func (el panRuleDst) getList() []string {
	return el.Destination
}

type panRuleSrv struct {
	Service []string `xml:"service>member"`
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
	edit      bool
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
	edit     bool
}

type panServiceGroup struct {
	XMLName xml.Name  `xml:"entry"`
	Name    string    `xml:"name,attr"`
	Members []string  `xml:"members>member"`
	Unknown OtherAttr `xml:",any"`
	needed  bool
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
func printXMLValue(v any) string {
	b, err := xml.Marshal(v)
	if err != nil {
		panic(err)
	}
	i := bytes.Index(b, []byte(">"))
	j := bytes.LastIndex(b, []byte("<"))
	b = b[i+1 : j]
	return url.QueryEscape(string(b))
}

func printXML(v any) string {
	b, err := xml.Marshal(v)
	if err != nil {
		panic(err)
	}
	return url.QueryEscape(string(b))
}
