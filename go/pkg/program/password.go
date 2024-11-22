package program

import (
	"fmt"
	"os"
	"path"
	"strings"

	"golang.org/x/term"
)

func (c *Config) GetUserPass(hostName string) (string, string, error) {
	if c.User != "" {
		var err error
		if c.Password == "" {
			c.Password, err = c.askPassword()
		}
		return c.User, c.Password, err
	}
	return c.getSystemPassword(hostName)
}

// Read password from user.
func (c *Config) askPassword() (string, error) {
	fmt.Printf("Enter password for %q: ", c.User)
	pass, err := term.ReadPassword(int(os.Stdin.Fd()))
	return string(pass), err
}

// Format of credentials file
// - multiple lines
// - three fields, separated by whitespace: pattern username password
// - If current device name matches pattern, then return username and password.
// - Pattern may contain shell wildcard characters
//   - * matches zero or more characters
//   - ? matches one character
//
// - First matching line is taken.
func (c *Config) getSystemPassword(name string) (string, string, error) {
	file := path.Join(c.BaseDir, "credentials")
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
