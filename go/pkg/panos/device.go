package panos

import (
	"crypto/tls"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func (s *state) loadDevice(path string) (*PanConfig, error) {
	nameList, ipList, err := getHostnameIPList(path)
	if err != nil {
		return nil, err
	}

	logFH, err := s.getLogFH(".config")
	if err != nil {
		return nil, err
	}
	defer closeLogFH(logFH)
	var client = &http.Client{
		Timeout: time.Duration(s.config.Timeout) * time.Second,
		Transport: &http.Transport{
			Dial: (&net.Dialer{
				// Set low connection timeout, so we can better switch to
				// backup device.
				Timeout: time.Duration(s.config.LoginTimeout) * time.Second,
			}).Dial,
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	s.httpClient = client
	for i, name := range nameList {
		s.devName = name
		key, err := s.getAPIKey()
		if err != nil {
			return nil, err
		}
		ip := ipList[i]
		prefix := fmt.Sprintf("https://%s/api/?key=%s&", ip, key)
		s.urlPrefix = prefix
		// Use "get", not "show", to get candidate configuration.
		// Must not use active configuration, since candidate may have
		// been changed already by other user or by interrupted previous
		// run of this program.
		// Don't request full "config", but only "devices" part, since
		// config contains very large predefined application data.
		uri := prefix + "type=config&action=get&xpath=/config/devices"
		doLog(logFH, uri)
		resp, err := client.Get(uri)
		if err != nil {
			var urlErr *url.Error
			if errors.As(err, &urlErr) {
				if urlErr.Timeout() {
					continue
				}
			}
			return nil, err
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		doLog(logFH, string(body))

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf(
				"Request failed with status code: %d and\nbody: %s\n",
				resp.StatusCode, body)
		}
		if err != nil {
			return nil, err
		}
		_, data, err := parseResponse(body)
		if err != nil {
			return nil, err
		}
		d := new(PanResultDevices)
		err = xml.Unmarshal(data, d)
		if err != nil {
			return nil, err
		}
		return &PanConfig{Devices: d.Devices, origin: "device"}, nil
	}
	return nil, fmt.Errorf(
		"Devices unreachable: %s", strings.Join(nameList, ", "))
}

func (s *state) deviceCommands(l []string) error {
	logFH, err := s.getLogFH(".change")
	if err != nil {
		return err
	}
	defer closeLogFH(logFH)
	if len(l) == 0 {
		doLog(logFH, "No changes applied")
	}
	client := s.httpClient
	doCmd := func(cmd string) (string, []byte, error) {
		uri := s.urlPrefix + cmd
		doLog(logFH, cmd)
		resp, err := client.Get(uri)
		if err != nil {
			return "", nil, err
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		doLog(logFH, string(body))

		if resp.StatusCode != http.StatusOK {
			return "", nil, fmt.Errorf(
				"status code: %d and\nbody: %s\n",
				resp.StatusCode, body)
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
	for _, cmd := range l {
		_, _, err := doCmd(cmd)
		if err != nil {
			return fmt.Errorf("Request %s failed with %v", cmd, err)
		}
	}
	if err := commit(); err != nil {
		return fmt.Errorf("Commit failed: %v", err)
	}
	return nil
}

func (s *state) getAPIKey() (string, error) {
	user, pass, err := s.config.GetAAAPassword(s.devName)
	s.devUser = user
	return pass, err
}
