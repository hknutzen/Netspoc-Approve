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
	"strconv"
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
	user      string
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
			if err != nil {
				return err
			}
			errlog.DoLog(logLogin, resp.Status)
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
			s.user = user
			b := strings.ReplaceAll(string(body), s.sid, "xxx")
			errlog.DoLog(logLogin, b)
			return nil
		})
	if err != nil {
		return nil, err
	}

	if err := s.discardSessions(logLogin); err != nil {
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
			Response *rawPart `json:"response-message"`
		}{}
		err := json.Unmarshal(data, part)
		return part.Response, err
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
			body, _ := json.Marshal(args)
			partJSON, err := s.sendRequest("/web_api/"+endPoint, body, logLogin)
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
	rawConf["Rules"] = collect0(extractRulebase, "show-access-rulebase",
		jsonMap{
			"name":                  "network",
			"details-level":         "standard",
			"use-object-dictionary": false,
		})
	collect := func(attr, endPoint string, args jsonMap) {
		rawConf[attr] = collect0(extractObject, endPoint, args)
	}
	collect("Networks", "show-networks", jsonMap{"details-level": "full"})
	collect("Hosts", "show-hosts", jsonMap{"details-level": "full"})
	collect("Groups", "show-groups", jsonMap{"details-level": "full",
		"dereference-group-members": true})
	collect("TCP", "show-services-tcp", jsonMap{"details-level": "full"})
	collect("UDP", "show-services-udp", jsonMap{"details-level": "full"})
	collect("ICMP", "show-services-icmp", jsonMap{"details-level": "full"})
	collect("ICMP6", "show-services-icmp6", jsonMap{"details-level": "full"})
	collect("SvOther", "show-services-other", jsonMap{"details-level": "full"})
	// Collect static routes of all gateways.
	//
	// We need IP address of each simple gateway,
	// because call "gaia_api/v1.7/show-static-routes"
	// currently only works with IP and not with name as argument.
	getGatewayNameIP := func(uid string) (name, ip string) {
		url := "/web_api/show-simple-gateway"
		postData, _ := json.Marshal(jsonMap{"uid": uid})
		resp, err := s.sendRequest(url, postData, logLogin)
		collectErr = cmp.Or(collectErr, err)
		var result struct {
			Name string
			IP   string `json:"ipv4-address"`
		}
		json.Unmarshal(resp, &result)
		return result.Name, result.IP
	}
	uids, err := s.getUIDs("show-simple-gateways", logLogin)
	collectErr = cmp.Or(collectErr, err)
	routeMap := make(map[string][]json.RawMessage)
	ipMap := make(map[string]string)
	for _, uid := range uids {
		name, ip := getGatewayNameIP(uid)
		if collectErr != nil {
			return nil, fmt.Errorf("While reading device: %v", collectErr)
		}
		ipMap[name] = ip
		routeMap[name] = collect0(extractRoute, "gaia-api/v1.7/show-static-routes",
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

func (s *State) sendRequest(path string, body []byte, logFh *os.File,
) ([]byte, error) {
	errlog.DoLog(logFh, path)
	req, err := http.NewRequest("POST", s.prefix+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-chkp-sid", s.sid)
	if body != nil {
		req.Header.Set("content-type", "application/json")
		errlog.DoLog(logFh, string(body))
	}
	resp, err := s.client.Do(req)
	if err != nil {
		errlog.DoLog(logFh, err.Error())
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		errlog.DoLog(logFh, strconv.Itoa(resp.StatusCode))
		msg := fmt.Sprintf("status code: %d, uri: %s", resp.StatusCode, path)
		if body, _ := io.ReadAll(resp.Body); len(body) != 0 {
			msg += "\n" + string(body)
			errlog.DoLog(logFh, string(body))
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
	simulated := os.Getenv("SIMULATE_ROUTER") != ""
	sendCmd := func(endpoint string, args interface{}) ([]byte, error) {
		url := "/web_api/" + endpoint
		postData, _ := json.Marshal(args)
		resp, err := s.sendRequest(url, postData, logFh)
		errlog.DoLog(logFh, string(resp))
		return resp, err
	}
	waitTask := func(id string) error {
		for {
			if !simulated {
				time.Sleep(10 * time.Second)
			}
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

// Discard uncommited changes from previous runs.
func (s *State) discardSessions(logFh *os.File) error {
	l, err := s.getUIDs("show-sessions", logFh)
	if err != nil {
		return err
	}
	for _, uid := range l {
		postData, _ := json.Marshal(jsonMap{"uid": uid})
		body, err := s.sendRequest("/web_api/show-session", postData, logFh)
		errlog.DoLog(logFh, string(body))
		if err != nil {
			return err
		}
		var v struct {
			UID         string
			UserName    string `json:"user-name"`
			Application string
		}
		json.Unmarshal(body, &v)
		if v.UserName == s.user && v.Application == "WEB_API" {
			postData, _ := json.Marshal(jsonMap{"uid": v.UID})
			body, err := s.sendRequest("/web_api/discard", postData, logFh)
			errlog.DoLog(logFh, string(body))
			if err != nil {
				// Ignore error and continue with next session.
				continue
			}
		}
	}
	return nil
}

func (s *State) getUIDs(call string, logFh *os.File) ([]string, error) {
	url := "/web_api/" + call
	args := []byte(`{"details-level": "uid"}`)
	resp, err := s.sendRequest(url, args, logFh)
	if err != nil {
		return nil, err
	}
	var result struct {
		Objects []string
	}
	json.Unmarshal(resp, &result)
	return result.Objects, nil
}

func (s *State) CloseConnection() {
	if s.sid != "" {
		s.sendRequest("/web_api/logout", []byte(`{}`), nil)
	}
}

func (s *State) GetErrUnmanaged() []error { return nil }
