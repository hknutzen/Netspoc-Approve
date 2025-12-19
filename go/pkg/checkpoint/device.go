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
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/hknutzen/Netspoc-Approve/go/pkg/errlog"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/httpdevice"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/program"
)

type State struct {
	client         *http.Client
	prefix         string
	user           string
	sid            string
	deviceCfg      *chkpConfig
	spocCfg        *chkpConfig
	changes        []change
	installTargets []string
	routeChanges   []change
}
type change struct {
	endpoint string
	postData any
}

type jsonMap map[string]any

func (s *State) LoadDevice(
	spocFile string, cfg *program.Config, logLogin, logConfig *os.File) error {

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
		return err
	}

	if err := s.discardSessions(logLogin); err != nil {
		return err
	}

	// Collect unparsed configuration of device.
	deviceConf := make(jsonMap)
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
	targetPolicy, err := s.getTargetPolicy(logLogin)
	if err != nil {
		collectErr = err
	}
	deviceConf["TargetPolicy"] = targetPolicy
	targetRules := make(jsonMap)
	for target, p := range targetPolicy {
		targetRules[target] = collect0(extractRulebase, "show-access-rulebase",
			jsonMap{
				"name":                  p.Layer,
				"details-level":         "standard",
				"use-object-dictionary": false,
			})
	}
	deviceConf["TargetRules"] = targetRules
	collect := func(attr, endPoint string, args jsonMap) {
		deviceConf[attr] = collect0(extractObject, endPoint, args)
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
	// Collect static routes of all simple gateways and clusters.
	getGatewayUIDs := func(kind string) []string {
		if collectErr != nil {
			return nil
		}
		uids, err := s.getUIDs("show-simple-"+kind+"s", logLogin)
		collectErr = cmp.Or(collectErr, err)
		return uids
	}
	// Get IP address of each simple gateway|cluster.
	// Only for cluster, collect list of IP addresses of cluster members.
	getNameIPList := func(kind, uid string) (string, string, []string) {
		url := "/web_api/show-simple-" + kind
		postData, _ := json.Marshal(jsonMap{"uid": uid})
		resp, err := s.sendRequest(url, postData, logLogin)
		collectErr = cmp.Or(collectErr, err)
		type member struct {
			IP string `json:"ip-address"`
		}
		var result struct {
			Name           string
			ClusterMembers []member `json:"cluster-members"`
			IP             string   `json:"ipv4-address"`
		}
		err = json.Unmarshal(resp, &result)
		collectErr = cmp.Or(collectErr, err)
		var ips []string
		if kind == "gateway" {
			ips = []string{result.IP}
		} else {
			ips = make([]string, len(result.ClusterMembers))
			for i, m := range result.ClusterMembers {
				ips[i] = m.IP
			}
		}
		return result.Name, result.IP, ips
	}
	routeMap := make(map[string][]json.RawMessage)
	ipMap := make(map[string][]string)
	for _, kind := range []string{"gateway", "cluster"} {
		for _, uid := range getGatewayUIDs(kind) {
			name, ip, ips := getNameIPList(kind, uid)
			if collectErr != nil {
				break
			}
			ipMap[name] = ips
			// Collect routes only if Netspoc has generated routes.
			if len(s.spocCfg.GatewayRoutes[name]) > 0 {
				routeMap[name] = collect0(extractRoute,
					"gaia-api/v1.8/show-static-routes",
					jsonMap{"target": ip, "limit": 200})
			}
		}
	}
	deviceConf["GatewayRoutes"] = routeMap
	deviceConf["GatewayIPs"] = ipMap
	if collectErr != nil {
		return fmt.Errorf("While reading device: %v", collectErr)
	}
	out, _ := json.Marshal(deviceConf)
	errlog.DoLog(logConfig, string(out))
	s.deviceCfg, err = s.ParseConfig(out, "<device>")
	if err != nil {
		return fmt.Errorf("While parsing device config: %v", err)
	}
	return nil
}

func (s *State) sendRequest(path string, body []byte, logFh *os.File,
) ([]byte, error) {
	errlog.DoLog(logFh, path)
	req, _ := http.NewRequest("POST", s.prefix+path, bytes.NewReader(body))
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

func (s *State) GetChanges() error {
	// Check for errors, before starting compare.
	for t := range s.spocCfg.TargetRules {
		if s.deviceCfg.TargetPolicy[t] == nil {
			return fmt.Errorf("Missing policy package for target %q", t)
		}
		if err := checkInstallOn(s.deviceCfg.TargetRules[t], t); err != nil {
			return err
		}
	}
	s.changes, s.installTargets = diffConfig(s.deviceCfg, s.spocCfg)
	s.routeChanges = diffRoutes(s.deviceCfg, s.spocCfg)
	return nil
}

func (s *State) HasChanges() bool {
	return len(s.changes) != 0 || len(s.routeChanges) != 0
}

func (s *State) ShowChanges() string {
	var collect strings.Builder
	for _, chg := range slices.Concat(s.changes, s.routeChanges) {
		postData, _ := json.Marshal(chg.postData)
		fmt.Fprintln(&collect, chg.endpoint)
		fmt.Fprintln(&collect, string(postData))
	}
	return collect.String()
}

func (s *State) ApplyCommands(logFh *os.File) error {
	simulated := os.Getenv("SIMULATE_ROUTER") != ""
	sendCmd := func(endpoint string, args any) ([]byte, error) {
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
				errlog.Warning("task %q succeeded with warnings", cmd)
				return nil
			default:
				return fmt.Errorf("Unexpected status of task %q: %q",
					cmd, status)
			}
		}
	}
	waitCmd := func(endpoint string, args any) error {
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
	if len(s.changes) > 0 {
		for _, c := range s.changes {
			if _, err := sendCmd(c.endpoint, c.postData); err != nil {
				return err
			}
		}
		if err := waitCmd("publish", jsonMap{}); err != nil {
			return err
		}
		for _, target := range s.installTargets {
			pName := s.deviceCfg.TargetPolicy[target].Name
			err := waitCmd("install-policy", jsonMap{
				"policy-package": pName,
				"targets":        []string{target}})
			if err != nil {
				return err
			}
		}
	}
	for _, c := range s.routeChanges {
		if _, err := sendCmd(c.endpoint, c.postData); err != nil {
			return err
		}
	}
	return nil
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
			// Ignore error and continue with next session.
			body, _ := s.sendRequest("/web_api/discard", postData, logFh)
			errlog.DoLog(logFh, string(body))
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
	err = json.Unmarshal(resp, &result)
	return result.Objects, err
}

func (s *State) getTargetPolicy(logFh *os.File) (map[string]*chkpPolicy, error) {
	url := "/web_api/show-packages"
	args := []byte(`{"details-level": "full"}`)
	resp, err := s.sendRequest(url, args, logFh)
	if err != nil {
		return nil, err
	}
	var result struct {
		Packages []*struct {
			Name                string
			Access              bool
			Comment             string
			AccessLayers        []chkpName `json:"access-layers"`
			InstallationTargets []chkpName `json:"installation-targets"`
		}
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		return nil, err
	}
	targetPolicy := make(map[string]*chkpPolicy)
	for _, p := range result.Packages {
		if p.Access {
			if len(p.InstallationTargets) != 1 {
				return nil, fmt.Errorf(
					"Policy package %q must use exactly one installation-target",
					p.Name)
			}
			target := string(p.InstallationTargets[0])
			if len(p.AccessLayers) != 1 {
				return nil, fmt.Errorf(
					"Policy package %q must use exactly one access-layer", p.Name)
			}
			layer := string(p.AccessLayers[0])
			targetPolicy[target] = &chkpPolicy{
				Name:    p.Name,
				Comment: p.Comment,
				Layer:   layer,
			}
		}
	}
	return targetPolicy, nil
}

func (s *State) CloseConnection() {
	if s.sid != "" {
		s.sendRequest("/web_api/logout", []byte(`{}`), nil)
	}
}

func (s *State) GetErrUnmanaged() []error {
	var errors []error
	for _, target := range s.installTargets {
		p := s.deviceCfg.TargetPolicy[target]
		if !strings.Contains(p.Comment, "NetSPoC") {
			errors = append(errors,
				fmt.Errorf(`Missing "NetSPoC" in comment of policy %q`, p.Name))
		}
	}
	return errors
}
