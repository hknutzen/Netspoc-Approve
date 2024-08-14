package device

import (
	"fmt"
	"os"
	"path"
	"strings"

	"golang.org/x/term"
)

func (c *Config) GetUserPass(hostName string) (string, string) {
	if c.User != "" {
		if c.Password == "" {
			c.Password = c.askPassword()
		}
		return c.User, c.Password
	}
	return c.getAAAPassword(hostName)
}

// Read password from user.
// Write directly to tty, because STDOUT may be redirected.
func (c *Config) askPassword() string {
	fd, err := os.OpenFile("/dev/tty", os.O_WRONLY, 0)
	if err != nil {
		Abort("%v", err)
	}
	defer fd.Close()
	fmt.Fprintf(fd, "Enter password for %q: ", c.User)
	pass, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		Abort("%v", err)
	}
	return string(pass)
}

// Format of aaa_credentials file
// - multiple lines
// - three fields, separated by whitespace: pattern username password
// - If current device name matches pattern, then return username and password.
// - Pattern may contain shell wildcard characters
//   - * matches zero or more characters
//   - ? matches one character
//
// - First matching line is taken.
func (c *Config) getAAAPassword(name string) (string, string) {
	file := c.aaaCredentials
	if file == "" {
		Abort("Must configure attribute 'aaa_credentials'")
	}
	data, err := os.ReadFile(file)
	if err != nil {
		Abort("Can't %v", err)
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) != 3 {
			Abort("Expected 3 fields in lines of %s", file)
		}
		matched, err := path.Match(parts[0], name)
		if err != nil {
			Abort("Invalid pattern '%s' in %s", parts[0], file)
		}
		if matched {
			return parts[1], parts[2]
		}
	}
	Abort("No matching entry found in %s", file)
	return "", ""
}
