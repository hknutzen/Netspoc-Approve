package nsx

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"

	"github.com/hknutzen/Netspoc-Approve/go/pkg/device"
)

type State struct {
	client  *http.Client
	prefix  string
	token   string
	changes []change
}
type change struct {
	method   string
	url      string
	postData []byte
}

func (s *State) LoadDevice(
	name, ip, user, pass string,
	client *http.Client,
	logFH *os.File,
) (device.DeviceConfig, error) {

	prefix := fmt.Sprintf("https://%s", ip)
	device.DoLog(logFH, "#"+prefix)
	s.client = client
	s.prefix = prefix
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	client.Jar = jar

	uri := prefix + "/api/session/create"
	v := url.Values{}
	v.Set("j_username", user)
	v.Set("j_password", pass)
	resp, err := client.PostForm(uri, v)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status code: %d", resp.StatusCode)
	}
	s.token = resp.Header.Get("x-xsrf-token")

	path := "/policy/api/v1/infra/domains/default/gateway-policies"
	data, err := s.sendRequest("GET", path, nil)
	if err != nil {
		return nil, err
	}

	type rawConfig struct {
		Groups   []json.RawMessage
		Services []json.RawMessage
		Policies []json.RawMessage
	}

	var rawConf rawConfig
	var resultStruct struct{ Results []struct{ Id string } }
	err = json.Unmarshal(data, &resultStruct)
	if err != nil {
		return nil, err
	}
	for _, result := range resultStruct.Results {
		// Ignore all policies not created by Netspoc.
		if !strings.HasPrefix(result.Id, "Netspoc") {
			continue
		}
		data, err := s.sendRequest("GET", path+"/"+result.Id, nil)
		if err != nil {
			return nil, err
		}
		rawConf.Policies = append(rawConf.Policies, data)
	}

	path = "/policy/api/v1/infra/services"
	rawConf.Services, err = s.getRawJSON(path, logFH)
	if err != nil {
		return nil, err
	}

	path = "/policy/api/v1/infra/domains/default/groups"
	rawConf.Groups, err = s.getRawJSON(path, logFH)
	if err != nil {
		return nil, err
	}

	out, err := json.Marshal(rawConf)
	if err != nil {
		return nil, err
	}
	device.DoLog(logFH, string(out))

	config, err := s.ParseConfig(out)
	if err != nil {
		err = fmt.Errorf("While reading device: %v", err)
	}
	return config, err
}

func (s *State) getRawJSON(path string, logFH *os.File) ([]json.RawMessage, error) {
	var data []json.RawMessage
	var cursor string
	for {
		var results struct {
			Cursor  string
			Results []json.RawMessage
		}
		var id struct{ Id string }
		out, err := s.sendRequest("GET", path+"?cursor="+cursor, nil)
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal(out, &results)
		if err != nil {
			return nil, err
		}
		for _, result := range results.Results {
			err = json.Unmarshal(result, &id)
			if err != nil {
				return nil, err
			}
			if strings.HasPrefix(id.Id, "Netspoc") {
				data = append(data, result)
			}
		}
		cursor = results.Cursor
		if cursor == "" {
			break
		}
	}
	return data, nil
}

func (s *State) sendRequest(method string, path string, body io.Reader) ([]byte, error) {
	req, err := http.NewRequest(method, s.prefix+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-xsrf-token", s.token)
	if body != nil {
		req.Header.Set("content-type", "application/json")
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg := fmt.Sprintf("status code: %d, method: %s, uri: %s", resp.StatusCode, method, path)
		if body, _ := io.ReadAll(resp.Body); len(body) != 0 {
			msg += "\n" + string(body)
		}
		return nil, errors.New(msg)
	}
	return io.ReadAll(resp.Body)

}

func (s *State) GetChanges(c1, c2 device.DeviceConfig) ([]error, error) {
	p1 := c1.(*NsxConfig)
	p2 := c2.(*NsxConfig)
	s.changes = diffConfig(p1, p2)
	return nil, nil
}

func (s *State) HasChanges() bool {
	return len(s.changes) != 0
}

func (s *State) ShowChanges() string {
	var collect strings.Builder
	for _, chg := range s.changes {
		fmt.Fprintf(&collect, "%s %s\n", chg.method, chg.url)
		fmt.Fprintln(&collect, string(chg.postData))
	}
	return collect.String()
}

func (s *State) ApplyCommands(logFh *os.File) error {
	for _, c := range s.changes {
		device.DoLog(logFh, fmt.Sprintf("URI: %s %s", c.method, c.url))
		device.DoLog(logFh, "DATA: "+string(c.postData))
		resp, err := s.sendRequest(c.method, c.url, bytes.NewReader(c.postData))
		if err != nil {
			return err
		}
		device.DoLog(logFh, "RESP: "+string(resp))
	}
	return nil
}
