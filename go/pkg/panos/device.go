package panos

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
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

func getAPIKey(ip, user, pass string, client *http.Client) (string, error) {
	base, err := url.Parse("https://" + string(ip))
	if err != nil {
		return "", err
	}
	base.Path += "api"
	params := url.Values{}
	params.Add("type", "keygen")
	params.Add("user", user)
	params.Add("password", pass)
	base.RawQuery = params.Encode()
	uri := base.String()
	resp, err := client.Get(uri)
	if err != nil {
		return "", err
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg := fmt.Sprintf("API key status code: %d", resp.StatusCode)
		if len(body) != 0 {
			msg += "\n" + string(body)
		}
		return "", errors.New(msg)
	}
	if err != nil {
		return "", err
	}
	return parseAPIKey(body)
}

func (s *State) LoadDevice(
	name, ip, user, pass string,
	client *http.Client,
	logFH *os.File,
) (device.DeviceConfig, error) {

	key, err := getAPIKey(ip, user, pass, client)
	if err != nil {
		return nil, err
	}
	prefix := fmt.Sprintf("https://%s/api/?key=%s&", ip, key)
	s.client = client
	s.devUser = user
	s.urlPrefix = prefix
	// Use "get", not "show", to get candidate configuration.
	// Must not use active configuration, since candidate may have
	// been changed already by other user or by interrupted previous
	// run of this program.
	// Don't request full "config", but only "devices" part, since
	// config contains very large predefined application data.
	uri := prefix + "type=config&action=get&xpath=/config/devices"
	device.DoLog(logFH, uri)
	resp, err := client.Get(uri)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	device.DoLog(logFH, string(body))

	if resp.StatusCode != http.StatusOK {
		msg := fmt.Sprintf("status code: %d", resp.StatusCode)
		if len(body) != 0 {
			msg += "\n" + string(body)
		}
		return nil, errors.New(msg)
	}
	if err != nil {
		return nil, err
	}
	return parseResponseConfig(body)
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
		uri := s.urlPrefix + cmd
		device.DoLog(logFH, cmd)
		resp, err := s.client.Get(uri)
		if err != nil {
			return "", nil, err
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		device.DoLog(logFH, string(body))

		if resp.StatusCode != http.StatusOK {
			return "", nil, fmt.Errorf("status code: %d", resp.StatusCode)
		}
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
