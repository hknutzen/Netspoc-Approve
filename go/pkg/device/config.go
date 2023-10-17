package device

import (
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
)

var defaultVals = map[string]string{
	"timeout":       "60",
	"login_timeout": "3",
	"keep_history":  "365", // delete history older than this (in days)
	"compress_at":   "7",   // compress netspocdir after that many days
}

var home, _ = os.UserHomeDir()
var confPaths = []string{
	path.Join(home, ".netspoc-approve"),
	"/usr/local/etc/netspoc-approve",
	"/etc/netspoc-approve",
}

type Config struct {
	netspocDir     string
	lockfileDir    string
	historyDir     string
	statusDir      string
	CheckBanner    *regexp.Regexp
	aaaCredentials string
	systemUser     string
	ServerIPList   []netip.Addr
	Timeout        int
	LoginTimeout   int
	keepHistory    int
	compressAt     int
}

// Use most specific config file; ignore others.
func LoadConfig() (*Config, error) {
	var data []byte
	var file string
	for _, p := range confPaths {
		var err error
		data, err = os.ReadFile(p)
		if err == nil {
			file = p
			break
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("Can't %v", err)
		}
	}
	if data == nil {
		return nil, fmt.Errorf("No config file found in %v", confPaths)
	}

	var c Config
	seen := make(map[string]bool)

	insert := func(key, val string) error {
		getInt := func() (int, error) {
			i, err := strconv.Atoi(val)
			if err != nil {
				return i, fmt.Errorf("Expected integer value for '%s' in %s: %v",
					key, file, err)
			}
			if i < 0 {
				return 0, fmt.Errorf(
					"Expected positive integer for '%s' in %s: %v", key, file, err)
			}
			return i, nil
		}
		getIPList := func() ([]netip.Addr, error) {
			var result []netip.Addr
			for _, s := range strings.Fields(val) {
				ip, err := netip.ParseAddr(s)
				if err != nil {
					return nil, fmt.Errorf("Expected IP address in '%s' of %s: %v",
						key, file, err)
				}
				result = append(result, ip)
			}
			return result, nil
		}
		var err error
		switch key {
		case "netspocdir":
			c.netspocDir = val
		case "lockfiledir":
			c.lockfileDir = val
		case "historydir":
			c.historyDir = val
		case "statusdir":
			c.statusDir = val
		case "checkbanner":
			c.CheckBanner, err = regexp.Compile(val)
			if err != nil {
				err = fmt.Errorf("Invalid regexp in '%s' of %s: %v", key, file, err)
			}
		case "aaa_credentials":
			c.aaaCredentials = val
		case "systemuser":
			c.systemUser = val
		case "server_ip_list":
			c.ServerIPList, err = getIPList()
		case "timeout":
			c.Timeout, err = getInt()
		case "login_timeout":
			c.LoginTimeout, err = getInt()
		case "keep_history":
			c.keepHistory, err = getInt()
		case "compress_at":
			c.compressAt, err = getInt()
		default:
			warn("Ignoring key '%s' in %s", key, file)
		}
		return err
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		words := strings.Fields(line)
		if len(words) == 0 || words[0][0] == '#' {
			continue
		}
		if len(words) != 3 || words[1] != "=" {
			warn("Ignoring line '%s' in %s", line, file)
			continue
		}
		key, val := words[0], words[2]
		if seen[key] {
			warn("Ignoring '%s' in %s", key, file)
			continue
		}
		seen[key] = true
		if err := insert(key, val); err != nil {
			return nil, err
		}
	}
	for key, val := range defaultVals {
		if !seen[key] {
			if err := insert(key, val); err != nil {
				return nil, err
			}
		}
	}
	for _, k := range []string{"netspocdir", "lockfiledir"} {
		if !seen[k] {
			return nil, fmt.Errorf("Missing '%s' in %s", k, file)
		}
	}
	return &c, nil
}

func warn(f string, l ...interface{}) {
	fmt.Fprintf(os.Stderr, "WARNING>>> "+f+"\n", l...)
}
