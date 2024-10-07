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
	"time"

	"github.com/hknutzen/Netspoc-Approve/go/pkg/deviceconf"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/errlog"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/httpdevice"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/program"
)

type State struct {
	client    *http.Client
	prefix    string
	sid       string
	changes   []change
	installOn []string
}
type change struct {
	endpoint string
	postData interface{}
}

type jsonMap map[string]interface{}

func (s *State) LoadDevice(
	spocFile string, cfg *program.Config, logLogin, logConfig *os.File) (
	deviceconf.Config, error) {

	// Login to device and get session ID.
	err := httpdevice.TryReachableHTTPLogin(spocFile, cfg,
		func(name, ip, user, pass string) error {
			s.prefix = fmt.Sprintf("https://%s", ip)
			s.client = httpdevice.GetHTTPClient(cfg)
			uri := s.prefix + "/web_api/login"
			errlog.DoLog(logLogin, uri)
			v := fmt.Sprintf(`{"user":"%s","password":"%s"}`, user, "xxx")
			errlog.DoLog(logLogin, v)
			v = fmt.Sprintf(`{"user":"%s","password":"%s"}`, user, pass)
			resp, err :=
				s.client.Post(uri, "application/json", strings.NewReader(v))
			errlog.DoLog(logLogin, resp.Status)
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

	// Discard uncommited changes from previous run.
	_, err = s.sendRequest("/web_api/discard", bytes.NewReader([]byte("{}")))
	if err != nil {
		return nil, err
	}
	// Collect configuration of device.
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
	errlog.DoLog(logConfig, string(out))
	cf, err := s.ParseConfig(out, "<device>")
	//out, _ = json.Marshal(cf)
	//errlog.DoLog(logConfig, string(out))
	if err != nil {
		err = fmt.Errorf("While parsing device config: %v", err)
	}
	return cf, err
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

func (s *State) GetChanges(c1, c2 deviceconf.Config) error {
	p1 := c1.(*chkpConfig)
	p2 := c2.(*chkpConfig)
	s.changes, s.installOn = diffConfig(p1, p2)
	return nil
}

func (s *State) HasChanges() bool {
	return len(s.changes) != 0
}

func (s *State) ShowChanges() string {
	var collect strings.Builder
	for _, chg := range s.changes {
		postData, _ := json.Marshal(chg.postData)
		fmt.Fprintln(&collect, chg.endpoint)
		fmt.Fprintln(&collect, string(postData))
	}
	return collect.String()
}

func (s *State) ApplyCommands(logFh *os.File) error {
	sendCmd := func(endpoint string, args interface{}) ([]byte, error) {
		url := "/web_api/" + endpoint
		postData, _ := json.Marshal(args)
		errlog.DoLog(logFh, url)
		errlog.DoLog(logFh, string(postData))
		resp, err := s.sendRequest(url, bytes.NewReader(postData))
		errlog.DoLog(logFh, string(resp))
		return resp, err
	}
	waitTask := func(id string) error {
		for {
			time.Sleep(1 * time.Second)
			resp, err := sendCmd("show-task", jsonMap{"task-id": id})
			if err != nil {
				return err
			}
			var result struct {
				Tasks []struct {
					Status   string
					TaskName string `json:"task-name"`
				}
			}
			err = json.Unmarshal(resp, &result)
			if err != nil {
				return err
			}
			task := result.Tasks[0]
			cmd := task.TaskName
			status := task.Status
			switch status {
			case "in progress", "pending":
				continue
			case "succeeded":
				return nil
			case "succeeded with warnings":
				errlog.Warning("command %q succeeded with warnings", cmd)
				return nil
			default:
				return fmt.Errorf("Unexpected status of command %q: %q",
					cmd, status)
			}
		}
	}
	waitCmd := func(endpoint string, args interface{}) error {
		resp, err := sendCmd(endpoint, args)
		if err != nil {
			return err
		}
		var result struct {
			TaskID string `json:"task-id"`
		}
		err = json.Unmarshal(resp, &result)
		if err != nil {
			return err
		}
		return waitTask(result.TaskID)
	}
	for _, c := range s.changes {
		if _, err := sendCmd(c.endpoint, c.postData); err != nil {
			return err
		}
	}
	if err := waitCmd("publish", jsonMap{}); err != nil {
		return err
	}
	return waitCmd("install-policy",
		jsonMap{"policy-package": "standard", "targets": s.installOn})
}

func (s *State) CloseConnection()         {}
func (s *State) GetErrUnmanaged() []error { return nil }
