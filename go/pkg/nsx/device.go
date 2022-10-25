package nsx

import (
	"encoding/json"
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
	token  string
	client *http.Client
}

func (s *State) LoadDevice(
	name, ip, user, pass string,
	client *http.Client,
	logFH *os.File,
) (device.DeviceConfig, error) {

	prefix := fmt.Sprintf("https://%s/", ip)
	device.DoLog(logFH, prefix)
	s.client = client
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	client.Jar = jar

	uri := prefix + "api/session/create"
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

	uri = prefix + "policy/api/v1/infra/domains/default/gateway-policies"
	data, err := s.sendRequest("GET", uri, nil)
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
		//Ignore all policies not created by NetSpoc
		if !strings.HasPrefix(result.Id, "NetSpoc") {
			continue
		}
		data, err := s.sendRequest("GET", uri+"/"+result.Id, nil)
		if err != nil {
			return nil, err
		}
		rawConf.Policies = append(rawConf.Policies, data)
	}

	uri = prefix + "policy/api/v1/infra/services"
	rawConf.Services, err = s.getRawJSON(uri, logFH)
	if err != nil {
		return nil, err
	}

	uri = prefix + "policy/api/v1/infra/domains/default/groups"
	rawConf.Groups, err = s.getRawJSON(uri, logFH)
	if err != nil {
		return nil, err
	}

	out, err := json.Marshal(rawConf)
	if err != nil {
		return nil, err
	}
	device.DoLog(logFH, string(out))

	//return nil, fmt.Errorf("token: %s", s.token)
	return s.ParseConfig(out)
}

func (s *State) getRawJSON(uri string, logFH *os.File) ([]json.RawMessage, error) {
	var results struct{ Results []json.RawMessage }
	var id struct{ Id string }
	var data []json.RawMessage
	out, err := s.sendRequest("GET", uri, nil)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(out, &results)
	for _, result := range results.Results {
		err = json.Unmarshal(result, &id)
		if err != nil {
			return nil, err
		}
		if strings.HasPrefix(id.Id, "Netspoc") {
			data = append(data, result)
		}
	}
	return data, nil
}

func (s *State) sendRequest(method string, url string, body io.Reader) ([]byte, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-xsrf-token", s.token)
	resp, err := s.client.Do(req)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status code: %d, %s", resp.StatusCode, url)
	}
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)

}

func (s *State) GetChanges(c1, c2 device.DeviceConfig) ([]device.Change, []error, error) {
	return nil, nil, nil
}
func (s *State) ApplyCommands(c []device.Change, cl *http.Client, fh *os.File) error { return nil }
