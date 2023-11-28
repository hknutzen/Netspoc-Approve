package checkpoint

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strings"

	"github.com/hknutzen/Netspoc-Approve/go/pkg/device"
)

type State struct {
	client  *http.Client
	prefix  string
	sid     string
	changes []change
}
type change struct {
	method   string
	url      string
	postData []byte
}

func (s *State) LoadDevice(
	spocFile string, cfg *device.Config, logLogin, logConfig *os.File) (
	device.DeviceConfig, error) {

	err := device.TryReachableHTTPLogin(spocFile, cfg,
		func(name, ip, user, pass string) error {
			s.prefix = fmt.Sprintf("https://%s", ip)
			s.client = device.GetHTTPClient(cfg)
			jar, err := cookiejar.New(nil)
			if err != nil {
				return err
			}
			s.client.Jar = jar

			uri := s.prefix + "/web_api/login"
			device.DoLog(logLogin, "POST "+uri)
			v := fmt.Sprintf(`{"user":"%s","password":"%s"}`, user, "xxx")
			device.DoLog(logLogin, v)
			v = fmt.Sprintf(`{"user":"%s","password":"%s"}`, user, pass)
			resp, err :=
				s.client.Post(uri, "application/json", strings.NewReader(v))
			device.DoLog(logLogin, resp.Status)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("status code: %d", resp.StatusCode)
			}
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return err
			}
			var result struct{ Sid string }
			err = json.Unmarshal(body, &result)
			if err != nil {
				return err
			}
			s.sid = result.Sid
			return nil
		})
	if err != nil {
		return nil, err
	}

	device.DoLog(logConfig, "#"+s.prefix)

	rawConf := make(map[string][]json.RawMessage)
	var addErr error
	type apiArgs map[string]interface{}
	add := func(attr, endPoint string, args apiArgs) {
		if addErr != nil {
			return
		}
		if _, found := args["limit"]; !found {
			args["limit"] = 500
		}
		// Read partial result until 'total' is reached.
		for {
			apiPath := s.prefix + "/web_api/" + endPoint
			body, _ := json.Marshal(args)
			req, err := http.NewRequest("POST", apiPath, bytes.NewReader(body))
			if err != nil {
				addErr = err
				return
			}
			req.Header.Set("X-chkp-sid", s.sid)
			req.Header.Set("content-type", "application/json")
			resp, err := s.client.Do(req)
			if err != nil {
				addErr = err
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				msg := fmt.Sprintf("status code: %d, method: POST, uri: %s",
					resp.StatusCode, apiPath)
				if body, _ := io.ReadAll(resp.Body); len(body) != 0 {
					msg += "\n" + string(body)
				}
				addErr = errors.New(msg)
				return
			}
			partJSON, err := io.ReadAll(resp.Body)
			if err != nil {
				addErr = err
				return
			}
			var part struct {
				To       int
				Total    int
				Objects  []json.RawMessage
				Rulebase []json.RawMessage
			}
			err = json.Unmarshal(partJSON, &part)
			if err != nil {
				addErr = err
				return
			}
			if part.Rulebase != nil {
				part.Objects = part.Rulebase
			}
			rawConf[attr] = append(rawConf[attr], part.Objects...)
			if part.To >= part.Total {
				return
			}
			args["offset"] = part.To
		}

	}
	add("rules", "show-access-rulebase",
		apiArgs{
			"name":                  "network",
			"details-level":         "standard",
			"use-object-dictionary": false,
		})
	add("networks", "show-networks", apiArgs{})
	add("hosts", "show-hosts", apiArgs{})
	add("tcp", "show-services-tcp", apiArgs{})
	add("udp", "show-services-udp", apiArgs{})
	add("icmp", "show-services-icmp", apiArgs{"details-level": "full"})
	add("icmp6", "show-services-icmp6", apiArgs{"details-level": "full"})
	add("svOther", "show-services-other", apiArgs{"details-level": "full"})
	// Collect static routes for all managed gateways
	/* add("routes", "gaia_api/v1.7/show-static-routes",
	apiArgs{"target": fwName, "limit": 200})
	*/
	if addErr != nil {
		return nil, fmt.Errorf("While reading device: %v", addErr)
	}
	out, _ := json.Marshal(rawConf)
	device.DoLog(logConfig, string(out))
	config, err := s.ParseConfig(out, "<device>")
	if err != nil {
		return nil, fmt.Errorf("While parsing device config: %v", err)
	}
	return config, nil
}

func (s *State) getRawJSON(path string) ([]json.RawMessage, error) {
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
	req.Header.Set("X-chkp-sid", s.sid)
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

func (s *State) GetChanges(c1, c2 device.DeviceConfig) error {
	p1 := c1.(*chkpConfig)
	p2 := c2.(*chkpConfig)
	s.changes = diffConfig(p1, p2)
	return nil
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

func (s *State) CloseConnection()         {}
func (s *State) GetErrUnmanaged() []error { return nil }
