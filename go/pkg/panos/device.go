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
		data, err := parseResponse(body)
		if err != nil {
			return nil, err
		}
		d := new(PanDevices)
		err = xml.Unmarshal(data, d)
		if err != nil {
			return nil, err
		}
		return &PanConfig{Devices: d, origin: "device"}, nil
	}
	return nil, fmt.Errorf(
		"Devices unreachable: %s", strings.Join(nameList, ", "))
}

func (s *state) deviceCommands(l []string) error {
	client := s.httpClient
	prefix := s.urlPrefix
	logFH, err := s.getLogFH(".change")
	if err != nil {
		return err
	}
	defer closeLogFH(logFH)
	if len(l) == 0 {
		doLog(logFH, "No changes")
	}
	for _, cmd := range l {
		uri := prefix + cmd
		doLog(logFH, uri)
		resp, err := client.Get(uri)
		if err != nil {
			return err
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		doLog(logFH, string(body))

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf(
				"Request failed with status code: %d and\nbody: %s\n",
				resp.StatusCode, body)
		}
		if err != nil {
			return err
		}
		_, err = parseResponse(body)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *state) getAPIKey() (string, error) {
	user, pass, err := s.config.GetAAAPassword(s.devName)
	if err != nil {
		return "", err
	}
	if user != "api-key" {
		return "",
			fmt.Errorf(
				"Expected user 'api-key' not '%s' for device '%s'"+
					" in aaa_credentials",
				user, s.devName)
	}
	return pass, nil
}
