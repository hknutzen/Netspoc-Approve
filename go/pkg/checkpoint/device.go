package checkpoint

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
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
			uri := s.prefix + "/web_api/login"
			device.DoLog(logLogin, uri)
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
		// Read partial results until 'total' is reached.
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
				msg := fmt.Sprintf("status code: %d, uri: %s",
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
	add("networks", "show-networks", apiArgs{"details-level": "full"})
	add("hosts", "show-hosts", apiArgs{"details-level": "full"})
	add("tcp", "show-services-tcp", apiArgs{"details-level": "full"})
	add("udp", "show-services-udp", apiArgs{"details-level": "full"})
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
	cf, err := s.ParseConfig(out, "<device>")
	for _, r := range cf.(*chkpConfig).Rules {
		if r.Layer == "" {
			r.Layer = "network"
		}
	}
	if err != nil {
		return nil, fmt.Errorf("While parsing device config: %v", err)
	}
	return cf, nil
}

func (s *State) sendRequest(path string, body io.Reader) ([]byte, error) {
	req, err := http.NewRequest("POST", s.prefix+path, body)
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
		msg := fmt.Sprintf("status code: %d, uri: %s", resp.StatusCode, path)
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
		fmt.Fprintln(&collect, chg.url)
		fmt.Fprintln(&collect, string(chg.postData))
	}
	return collect.String()
}

func (s *State) ApplyCommands(logFh *os.File) error {
	for _, c := range s.changes {
		device.DoLog(logFh, c.url)
		device.DoLog(logFh, string(c.postData))
		resp, err := s.sendRequest(c.url, bytes.NewReader(c.postData))
		if err != nil {
			return err
		}
		device.DoLog(logFh, string(resp))
	}
	return nil
}

func (s *State) CloseConnection()         {}
func (s *State) GetErrUnmanaged() []error { return nil }
