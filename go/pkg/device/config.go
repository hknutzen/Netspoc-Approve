package device

import (
	"errors"
	"io/fs"
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
	checkBanner    *regexp.Regexp
	aaaCredentials string
	systemUser     string
	timeout        int
	loginTimeout   int
	keepHistory    int
	compressAt     int
}

// Use most specific config file; ignore others.
func LoadConfig() *Config {
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
			abort("Can't %v", err)
		}
	}
	if data == nil {
		abort("No config file found in\n %v", confPaths)
	}

	var c Config
	seen := make(map[string]bool)

	insert := func(key, val string) {
		getInt := func() int {
			i, err := strconv.Atoi(val)
			if err != nil {
				abort("Expected integer value for '%s' in %s: %v", key, file, err)
			}
			if i < 0 {
				abort("Expected positive integer for '%s' in %s: %v",
					key, file, err)
			}
			return i
		}
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
			re, err := regexp.Compile(val)
			if err != nil {
				abort("Invalid regexp in '%s' of %s: %v", key, file, err)
			}
			c.checkBanner = re
		case "aaa_credentials":
			c.aaaCredentials = val
		case "systemuser":
			c.systemUser = val
		case "timeout":
			c.timeout = getInt()
		case "login_timeout":
			c.loginTimeout = getInt()
		case "keep_history":
			c.keepHistory = getInt()
		case "compress_at":
			c.compressAt = getInt()
		default:
			warn("Ignoring key '%s' in %s", key, file)
		}
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
		insert(key, val)
	}
	for key, val := range defaultVals {
		if !seen[key] {
			insert(key, val)
		}
	}
	check := func(k string) {
		if !seen[k] {
			abort("Missing '%s' in %s", k, file)
		}
	}
	check("netspocdir")
	check("lockfiledir")
	return &c
}
