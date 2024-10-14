package program

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

type Config struct {
	NetspocDir     string
	LockfileDir    string
	netspocGit     string
	HistoryDir     string
	StatusDir      string
	CheckBanner    *regexp.Regexp
	aaaCredentials string
	systemUser     string
	ServerIPList   []netip.Addr
	Timeout        int
	LoginTimeout   int
	keepHistory    int
	compressAt     int
	// Is only set by command line option -u.
	User     string
	Password string
}

// Use most specific config file; ignore others.
func LoadConfig() (*Config, error) {
	home, _ := os.UserHomeDir()
	confPaths := []string{
		path.Join(home, ".netspoc-approve"),
		"/usr/local/etc/netspoc-approve",
		"/etc/netspoc-approve",
	}
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

	insert := func(key string, values ...string) error {
		val := values[0]
		getInt := func() (int, error) {
			i, err := strconv.Atoi(val)
			if err != nil {
				return i, fmt.Errorf("Expected integer value for '%s' in %s: %v",
					key, file, err)
			}
			if i < 0 {
				return 0, fmt.Errorf(
					"Expected positive integer for '%s' in %s: %v", key, file, i)
			}
			return i, nil
		}
		getIPList := func() ([]netip.Addr, error) {
			var result []netip.Addr
			for _, s := range values {
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
		case "server_ip_list":
			c.ServerIPList, err = getIPList()
			return err
		}
		if len(values) != 1 {
			return fmt.Errorf("Expected exactly one value for %q in %s: %v",
				key, file, values)
		}
		switch key {
		case "netspocdir":
			c.NetspocDir = val
		case "lockfiledir":
			c.LockfileDir = val
		case "netspoc_git":
			c.netspocGit = val
		case "historydir":
			c.HistoryDir = val
		case "statusdir":
			c.StatusDir = val
		case "checkbanner":
			c.CheckBanner, err = regexp.Compile(val)
			if err != nil {
				err = fmt.Errorf("Invalid regexp in '%s' of %s: %v", key, file, err)
			}
		case "aaa_credentials":
			c.aaaCredentials = val
		case "systemuser":
			c.systemUser = val
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
		if len(words) < 3 || words[1] != "=" {
			warn("Ignoring line '%s' in %s", line, file)
			continue
		}
		key := words[0]
		if seen[key] {
			warn("Ignoring duplicate key '%s' in %s", key, file)
			continue
		}
		seen[key] = true
		if err := insert(key, words[2:]...); err != nil {
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

func (c *Config) GetVal(key string) string {
	switch key {
	case "netspocdir":
		return c.NetspocDir
	case "lockfiledir":
		return c.LockfileDir
	case "netspoc_git":
		return c.netspocGit
	case "historydir":
		return c.HistoryDir
	case "statusdir":
		return c.StatusDir
	case "checkbanner":
		if re := c.CheckBanner; re != nil {
			return re.String()
		}
		return ""
	case "aaa_credentials":
		return c.aaaCredentials
	case "systemuser":
		return c.systemUser
	case "server_ip_list":
		var l []string
		for _, ip := range c.ServerIPList {
			l = append(l, ip.String())
		}
		return strings.Join(l, " ")
	case "timeout":
		return strconv.Itoa(c.Timeout)
	case "login_timeout":
		return strconv.Itoa(c.LoginTimeout)
	case "keep_history":
		return strconv.Itoa(c.keepHistory)
	case "compress_at":
		return strconv.Itoa(c.compressAt)
	}
	return ""
}

func warn(f string, l ...interface{}) {
	fmt.Fprintf(os.Stderr, "WARNING>>> "+f+"\n", l...)
}
