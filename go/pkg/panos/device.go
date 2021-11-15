package panos

import (
	"crypto/tls"
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
		key, err := s.getAPIKey(name)
		if err != nil {
			return nil, err
		}
		ip := ipList[i]
		prefix := fmt.Sprintf("https://%s/api/?key=%s", ip, key)
		s.urlPrefix = prefix
		resp, err := client.Get(prefix + "&type=config&action=show&xpath=/")
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

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf(
				"Request failed with status code: %d and\nbody: %s\n",
				resp.StatusCode, body)
		}
		if err != nil {
			return nil, err
		}
		s.devName = name
		return parseResponse(body)
	}
	return nil, fmt.Errorf(
		"Devices are unreachable: %s", strings.Join(nameList, ", "))
}

func (s *state) getAPIKey(device string) (string, error) {
	user, pass, err := s.config.GetAAAPassword(device)
	if err != nil {
		return "", err
	}
	if user != "api-key" {
		return "",
			fmt.Errorf(
				"Expected user 'api-key' not '%s' for device '%s'"+
					" in aaa_credentials",
				user, device)
	}
	return pass, nil
}
