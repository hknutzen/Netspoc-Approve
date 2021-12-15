package device

import (
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
)

// Format of aaa_credentials file
// - multiple lines
// - three fields, separated by whitespace: pattern username password
// - If current device name matches pattern, then return username and password.
// - Pattern may contain shell wildcard characters
//   * matches zero or more characters
//   ? matches one character
// - First matching line is taken.
func (c *Config) GetAAAPassword(name string) (string, string, error) {
	file := c.aaaCredentials
	if file == "" {
		return "", "",
			errors.New("Must configure AAA_CREDENTIALS together with SYSTEMUSER")
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return "", "", fmt.Errorf("Can't %v", err)
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) != 3 {
			return "", "", fmt.Errorf("Expected 3 fields in lines of %s", file)
		}
		matched, err := path.Match(parts[0], name)
		if err != nil {
			return "", "", fmt.Errorf("Invalid pattern '%s' in %s", parts[0], file)
		}
		if matched {
			return parts[1], parts[2], nil
		}
	}
	return "", "", fmt.Errorf("No matching entry found in %s", file)
}
