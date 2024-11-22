package httpdevice

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/hknutzen/Netspoc-Approve/go/pkg/codefiles"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/errlog"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/program"
)

func GetHTTPClient(cfg *program.Config, ip string) (*http.Client, string) {
	addr := fmt.Sprintf("https://%s", ip)
	if simul := os.Getenv("SIMULATE_ROUTER"); simul != "" {
		addr = simul
	}
	return &http.Client{
		Timeout: time.Duration(cfg.Timeout) * time.Second,
		Transport: &http.Transport{
			Dial: (&net.Dialer{
				// Set low connection timeout, so we can better switch to
				// backup device.
				Timeout: time.Duration(cfg.LoginTimeout) * time.Second,
			}).Dial,
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}, addr
}

func TryReachableHTTPLogin(
	fname string,
	cfg *program.Config,
	login func(name, ip, user, pass string) error,
) error {

	nameList, ipList, err := getHostnameIPList(fname)
	if err != nil {
		return err
	}
	for i, name := range nameList {
		ip := ipList[i]
		user, pass, err := cfg.GetUserPass(name)
		if err != nil {
			return err
		}
		if err := login(name, ip, user, pass); err != nil {
			errlog.Warning("%v", err)
			continue
		}
		return nil
	}
	return fmt.Errorf(
		"Devices unreachable: %s", strings.Join(nameList, ", "))
}

func getHostnameIPList(path string) ([]string, []string, error) {
	info, checked := codefiles.LoadInfoFile(path)
	nameList := info.NameList
	ipList := info.IPList
	if len(nameList) == 0 {
		return nil, nil, fmt.Errorf("Missing device name in %v", checked)
	}
	if len(ipList) == 0 {
		return nil, nil, fmt.Errorf("Missing IP address in %v", checked)
	}
	if len(nameList) != len(ipList) {
		return nil, nil, fmt.Errorf(
			"Number of device names and IP addresses don't match in %v", checked)
	}
	return nameList, ipList, nil
}
