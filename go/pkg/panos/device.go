package panos

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/hknutzen/Netspoc-Approve/go/pkg/device"
)

type State struct {
	client    *http.Client
	devUser   string
	urlPrefix string
	changes   []change
}

type change struct {
	Cmds []string
}

func (s *State) LoadDevice(
	path string, cfg *device.Config, logLogin, logConfig *os.File) (
	device.DeviceConfig, error) {

	devName := ""
	err := device.TryReachableHTTPLogin(path, cfg,
		func(name, ip, user, pass string) error {
			s.client = device.GetHTTPClient(cfg)
			s.devUser = user
			key, err := s.getAPIKey(ip, user, pass, logLogin)
			if err != nil {
				return err
			}
			prefix := fmt.Sprintf("https://%s/api/?key=%s&", ip, key)
			s.urlPrefix = prefix
			if !s.checkHA(logLogin) {
				return fmt.Errorf("not in active state: %s (%s)", ip, name)
			}
			devName = name
			return nil
		})
	if err != nil {
		return nil, err
	}

	// Use "get", not "show", to get candidate configuration.
	// Must not use active configuration, since candidate may have
	// been changed already by other user or by interrupted previous
	// run of this program.
	// Don't request full "config", but only "devices" part, since
	// config contains very large predefined application data.
	uri := "type=config&action=get&xpath=/config/devices"
	body, err := s.httpPrefixGetLog(uri, logConfig)
	if err != nil {
		return nil, err
	}
	config, err := parseResponseConfig(body)
	if err != nil {
		err = fmt.Errorf("While reading device: %v", err)
	}
	config.SetExpectedDeviceName(devName)
	return config, err
}

func (s *State) getAPIKey(ip, user, pass string, logFH *os.File) (
	string, error) {

	base, err := url.Parse("https://" + string(ip))
	if err != nil {
		return "", err
	}
	base.Path += "api"
	params := url.Values{}
	params.Set("type", "keygen")
	params.Set("user", user)
	params.Set("password", pass)
	base.RawQuery = params.Encode()
	uri := base.String()
	passRE := regexp.MustCompile(`(password=).*?(&|$)`)
	loggedURI := passRE.ReplaceAllString(uri, "${1}xxx$2")
	device.DoLog(logFH, loggedURI)
	body, err := s.httpGet(uri)
	keyRE := regexp.MustCompile(`<key>.*</key>`)
	loggedBody := keyRE.ReplaceAllString(string(body), "<key>xxx</key>")
	device.DoLog(logFH, loggedBody)
	if err != nil {
		msg := err.Error()
		msg = passRE.ReplaceAllString(msg, "${1}xxx$2")
		return "", fmt.Errorf("API key %s", msg)
	}
	return parseAPIKey(body)
}

// Check if high-availability is enabled and device is in <state>
// - "active" for <mode>Active-Passive</mode>
// - "active-primary" for <mode>Active-Active</mode>
/*
// <response status="success">
//	 <result>
//	  <enabled>yes</enabled>
//	  <group>
//	   <mode>Active-Passive</mode>
//	   <local-info>
//	    <state>active</state>
//	   </local-info>
//	  </group>
//	 </result>
// </response>
*/
// Result is true if HA not enabled or if enabled and active.
func (s *State) checkHA(logFH *os.File) bool {
	uri :=
		"type=op&cmd=<show><high-availability><state/></high-availability></show>"
	body, err := s.httpPrefixGetLog(uri, logFH)
	if err != nil {
		return false
	}
	_, data, err := parseResponse(body)
	if err != nil {
		return false
	}
	type haState struct {
		Enabled string `xml:"enabled"`
		Mode    string `xml:"group>mode"`
		State   string `xml:"group>local-info>state"`
	}
	ha := new(haState)
	err = xml.Unmarshal(data, ha)
	if err != nil {
		return false
	}
	if ha.Enabled != "yes" {
		return true
	}
	switch ha.Mode {
	case "Active-Passive":
		return ha.State == "active"
	case "Active-Active":
		return ha.State == "active-primary"
	}
	return false
}

func (s *State) GetChanges(
	c1, c2 device.DeviceConfig) ([]error, error) {

	p1 := c1.(*PanConfig)
	p2 := c2.(*PanConfig)
	isRealDev := p1.getDevName() != ""
	var warnings []error
	err := processVsysPairs(p1, p2, func(v1, v2 *panVsys) error {
		if v1 == nil {
			return fmt.Errorf(
				"Unknown name '%s' in VSYS of device configuration", v2.Name)
		}
		if v2 == nil {
			return nil
		}
		if isRealDev {
			if w := vsysOK(v1); w != nil {
				warnings = append(warnings, w)
			}
		}
		dev := p1.Devices.Entries[0].Name
		devPath := "/config/devices/entry" + nameAttr(dev)
		xPath := devPath + "/vsys/entry" + nameAttr(v2.Name)
		l := diffConfig(v1, v2, xPath)
		if len(l) != 0 {
			s.changes = append(s.changes, change{l})
		}
		return nil
	})
	return warnings, err
}

func vsysOK(v *panVsys) error {
	name := strings.ToLower(v.DisplayName)
	if !strings.Contains(name, "netspoc") {
		return fmt.Errorf("Missing NetSPoC in name of %s", v.Name)
	}
	return nil
}

func (s *State) ApplyCommands(logFH *os.File) error {
	doCmd := func(cmd string) (string, []byte, error) {
		body, err := s.httpPrefixGetLog(cmd, logFH)
		if err != nil {
			return "", nil, err
		}
		return parseResponse(body)
	}
	commit := func() error {
		cmd := s.urlPrefix +
			"type=commit&action=partial&cmd=<commit><partial><admin><member>" +
			s.devUser + "</member></admin></partial></commit>"
		msg, data, err := doCmd(cmd)
		if err != nil {
			return err
		}
		if strings.Contains(msg, "There are no changes to commit") ||
			strings.Contains(msg, "The result of this commit would be the same") {
			return nil
		}
		if msg != "" {
			return fmt.Errorf("Unexpected message: %s", msg)
		}
		type enqueued struct {
			Job string `xml:"job"`
		}
		j := new(enqueued)
		err = xml.Unmarshal(data, j)
		if err != nil {
			return err
		}
		id := j.Job
		for {
			time.Sleep(10 * time.Second)
			cmd := s.urlPrefix +
				"type=op&cmd=<show><jobs><id>" + id + "</id></jobs></show>"
			_, data, err := doCmd(cmd)
			if err != nil {
				return err
			}
			type status struct {
				Result string `xml:"job>result"`
			}
			s := new(status)
			err = xml.Unmarshal(data, s)
			if err != nil {
				return err
			}
			switch s.Result {
			case "PEND":
				continue
			case "OK":
				return nil
			default:
				return fmt.Errorf("Unexpected job result: %q", s.Result)
			}
		}
	}
	for _, chg := range s.changes {
		for _, cmd := range chg.Cmds {
			_, _, err := doCmd(cmd)
			if err != nil {
				return fmt.Errorf("Command failed with %v", err)
			}
		}
	}
	if err := commit(); err != nil {
		return fmt.Errorf("Commit failed: %v", err)
	}
	return nil
}

var apiRE = regexp.MustCompile(`[?]key=.*?&`)

func (s *State) httpPrefixGetLog(uri string, logFH *os.File) ([]byte, error) {
	uri = s.urlPrefix + uri
	loggedURI := apiRE.ReplaceAllString(uri, "?key=xxx&")
	device.DoLog(logFH, loggedURI)
	body, err := s.httpGet(uri)
	device.DoLog(logFH, string(body))
	return body, err
}

func (s *State) httpGet(uri string) ([]byte, error) {
	resp, err := s.client.Get(uri)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg := fmt.Sprintf("status code: %d", resp.StatusCode)
		if len(body) != 0 {
			msg += "\n" + string(body)
		}
		return body, errors.New(msg)
	}
	return body, err
}

func nameAttr(n string) string {
	return "[@name='" + url.QueryEscape(n) + "']"
}

func textAttr(n string) string {
	return "[text()='" + url.QueryEscape(n) + "']"
}

func (s *State) HasChanges() bool {
	return len(s.changes) != 0
}

func (s *State) ShowChanges() string {
	var collect strings.Builder
	for _, chg := range s.changes {
		for _, c := range chg.Cmds {
			c, _ = url.QueryUnescape(c)
			fmt.Fprintln(&collect, c)
		}
	}
	return collect.String()
}

func (s *State) CloseConnection() {}
