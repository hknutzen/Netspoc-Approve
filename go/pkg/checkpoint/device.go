package checkpoint

import (
	"bytes"
	"cmp"
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
			s.client, s.prefix = httpdevice.GetHTTPClient(cfg, ip)
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
	// Collect unparsed configuration of device.
	rawConf := make(jsonMap)
	// Parts of configuration read from checkpoint device.
	type rawPart struct {
		To      int
		Total   int
		Objects []json.RawMessage
	}
	// Functions that extract configuration parts from response data.
	type extractFunc func([]byte) (*rawPart, error)
	extractObject := func(data []byte) (*rawPart, error) {
		part := &rawPart{}
		err := json.Unmarshal(data, part)
		return part, err
	}
	extractRulebase := func(data []byte) (*rawPart, error) {
		part := struct {
			To      int
			Total   int
			Objects []json.RawMessage `json:"rulebase"`
		}{}
		err := json.Unmarshal(data, &part)
		part2 := rawPart(part)
		return &part2, err
	}
	extractRoute := func(data []byte) (*rawPart, error) {
		part := &struct {
			response *rawPart `json:"response-message"`
		}{}
		err := json.Unmarshal(data, part)
		return part.response, err
	}
	// Collect JSON data from different API endpoints.
	var collectErr error
	collect0 := func(extract extractFunc, endPoint string, args jsonMap,
	) (result []json.RawMessage) {
		if collectErr != nil {
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
				collectErr = err
				return
			}
			req.Header.Set("X-chkp-sid", s.sid)
			req.Header.Set("content-type", "application/json")
			resp, err := s.client.Do(req)
			if err != nil {
				collectErr = err
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				msg := fmt.Sprintf("status code: %d, uri: %s",
					resp.StatusCode, apiPath)
				if body, _ := io.ReadAll(resp.Body); len(body) != 0 {
					msg += "\n" + string(body)
				}
				collectErr = errors.New(msg)
				return
			}
			partJSON, err := io.ReadAll(resp.Body)
			if err != nil {
				collectErr = err
				return
			}
			part, err := extract(partJSON)
			if err != nil {
				collectErr = err
				return
			}
			result = append(result, part.Objects...)
			if part.To >= part.Total {
				return
			}
			args["offset"] = part.To
		}
	}
	rawConf["rules"] = collect0(extractRulebase, "show-access-rulebase",
		jsonMap{
			"name":                  "network",
			"details-level":         "standard",
			"use-object-dictionary": false,
		})
	collect := func(attr, endPoint string, args jsonMap) {
		rawConf[attr] = collect0(extractObject, endPoint, args)
	}
	collect("networks", "show-networks", jsonMap{"details-level": "full"})
	collect("hosts", "show-hosts", jsonMap{"details-level": "full"})
	collect("tcp", "show-services-tcp", jsonMap{"details-level": "full"})
	collect("udp", "show-services-udp", jsonMap{"details-level": "full"})
	collect("icmp", "show-services-icmp", jsonMap{"details-level": "full"})
	collect("icmp6", "show-services-icmp6", jsonMap{"details-level": "full"})
	collect("svOther", "show-services-other", jsonMap{"details-level": "full"})
	// Collect static routes of all gateways.
	getGatewayUIDs := func() []string {
		url := "/web_api/show-simple-gateways"
		postData, _ := json.Marshal(jsonMap{"details-level": "uid"})
		resp, err := s.sendRequest(url, bytes.NewReader(postData))
		collectErr = cmp.Or(collectErr, err)
		var result struct {
			Objects []string
		}
		json.Unmarshal(resp, &result)
		return result.Objects
	}
	getGatewayNameIP := func(uid string) (name, ip string) {
		url := "/web_api/show-simple-gateway"
		postData, _ := json.Marshal(jsonMap{"uid": uid})
		resp, err := s.sendRequest(url, bytes.NewReader(postData))
		collectErr = cmp.Or(collectErr, err)
		var result struct {
			name string
			ip   string `json:"ipv4-address"`
		}
		json.Unmarshal(resp, &result)
		return result.name, result.ip
	}
	routeMap := make(map[string][]json.RawMessage)
	ipMap := make(map[string]string)
	for _, uid := range getGatewayUIDs() {
		name, ip := getGatewayNameIP(uid)
		ipMap[name] = ip
		routeMap[name] = collect0(extractRoute, "gaia_api/v1.7/show-static-routes",
			jsonMap{"target": ip, "limit": 200})
	}
	rawConf["GatewayRoutes"] = routeMap
	if collectErr != nil {
		return nil, fmt.Errorf("While reading device: %v", collectErr)
	}
	out, _ := json.Marshal(rawConf)
	errlog.DoLog(logConfig, string(out))
	cf, err := s.ParseConfig(out, "<device>")
	if err != nil {
		err = fmt.Errorf("While parsing device config: %v", err)
	}
	cf.(*chkpConfig).GatewayIP = ipMap
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
	s.changes = append(s.changes, diffRoutes(p1, p2)...)
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
