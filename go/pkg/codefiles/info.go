package codefiles

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

type codeInfo struct {
	GeneratedBy             string   `json:"generated_by"`
	Model                   string   `json:"model"`
	IPList                  []string `json:"ip_list,omitempty"`
	NameList                []string `json:"name_list,omitempty"`
	PolicyDistributionPoint string   `json:"policy_distribution_point,omitempty"`
}

func LoadInfoFile(path string) (*codeInfo, []string) {
	path6 := GetIPv6Fname(path)
	info := &codeInfo{}
	var checked []string
	for _, file := range []string{path, path6} {
		file += ".info"
		fd, err := os.Open(file)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			panic(err)
		}
		checked = append(checked, file)
		defer fd.Close()
		if err := json.NewDecoder(fd).Decode(&info); err != nil {
			panic(err)
		}
		// Must also read IPv6 file if v4 file has no IP.
		if len(info.IPList) > 0 {
			break
		}
	}
	return info, checked
}

func GetIPPDP(fName string) (string, string, error) {
	info, checked := LoadInfoFile(fName)
	ipList := info.IPList
	if len(ipList) == 0 {
		return "", "", fmt.Errorf("Missing IP address in %v", checked)
	}
	return ipList[0], info.PolicyDistributionPoint, nil
}
