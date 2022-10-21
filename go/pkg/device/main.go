package device

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/pflag"
)

type RealDevice interface {
	LoadDevice(n, i, u, p string, c *http.Client, l *os.File) (DeviceConfig, error)
	ParseConfig(data []byte) (DeviceConfig, error)
	GetChanges(c1, c2 DeviceConfig) ([]Change, []error, error)
	ApplyCommands([]Change, *http.Client, *os.File) error
}

type DeviceConfig interface {
	MergeSpoc(DeviceConfig) DeviceConfig
	GetDevName() string
	CheckRulesFromRaw() error
}

type state struct {
	RealDevice
	config     *Config
	httpClient *http.Client
	logPath    string
	quiet      bool
	devName    string
}

type Change struct {
	Vsys string
	Cmds []string
}

func Main(device RealDevice) int {
	fs := pflag.NewFlagSet(os.Args[0], pflag.ContinueOnError)

	// Setup custom usage function.
	fs.Usage = func() {
		prog := path.Base(os.Args[0])
		fmt.Fprintf(os.Stderr,
			"Usage: %s [options] FILE1\n"+
				"     : %s FILE1 FILE2\n", prog, prog)
		fs.PrintDefaults()
	}

	// Command line flags
	quiet := fs.BoolP("quiet", "q", false, "No info messages")
	compare := fs.BoolP("compare", "C", false, "Compare only")
	logDir := fs.StringP("logdir", "L", "", "Path for saving session logs")
	//user := fs.StringP("user", "u", "", "Username for login to remote device")
	if err := fs.Parse(os.Args[1:]); err != nil {
		if err == pflag.ErrHelp {
			return 1
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		fs.Usage()
		return 1
	}

	var err error
	s := &state{RealDevice: device}
	s.quiet = *quiet

	// Argument processing
	args := fs.Args()
	switch len(args) {
	case 0:
		fallthrough
	default:
		fs.Usage()
		return 1
	case 2:
		if *logDir != "" {
			fs.Usage()
			return 1
		}
		err = s.compareFiles(args[0], args[1])
	case 1:
		s.config, err = LoadConfig()
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR>>> %v\n", err)
			return 1
		}
		path := args[0]
		s.setLogDir(*logDir, path)
		if *compare {
			err = s.compare(path)
		} else {
			err = s.approve(path)
		}
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR>>> %v\n", err)
		return 1
	}
	return 0
}

func (s *state) compareFiles(path1, path2 string) error {
	conf1, err := s.loadSpoc(path1)
	if err != nil {
		return err
	}
	return s.showCompare(conf1, path2)
}

func (s *state) compare(path string) error {
	conf1, err := s.loadDevice(path)
	if err != nil {
		return err
	}
	if err := s.showCompare(conf1, path); err != nil {
		return err
	}
	return nil
}

func (s *state) approve(path string) error {
	conf1, err := s.loadDevice(path)
	if err != nil {
		return err
	}
	changed, err := s.getCompare(conf1, path, errT)
	if err != nil {
		return err
	}
	return s.applyCommands(changed)
}

func (s *state) loadDevice(path string) (DeviceConfig, error) {
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
		ip := ipList[i]
		user, pass, err := s.config.GetAAAPassword(name)
		if err != nil {
			return nil, err
		}
		conf, err := s.LoadDevice(name, ip, user, pass, client, logFH)
		if err != nil {
			var urlErr *url.Error
			if errors.As(err, &urlErr) {
				if urlErr.Timeout() {
					continue
				}
			}
			return nil, err
		}
		return conf, nil
	}
	return nil, fmt.Errorf(
		"Devices unreachable: %s", strings.Join(nameList, ", "))
}

func (s *state) applyCommands(l []Change) error {
	logFH, err := s.getLogFH(".change")
	if err != nil {
		return err
	}
	defer closeLogFH(logFH)
	if len(l) == 0 {
		DoLog(logFH, "No changes applied")
	}
	client := s.httpClient
	return s.ApplyCommands(l, client, logFH)
}

func (s *state) showCompare(conf1 DeviceConfig, path string) error {
	changes, err := s.getCompare(conf1, path, warnT)
	if err != nil {
		return err
	}
	for _, chg := range changes {
		if chg.Cmds == nil {
			s.info("comp: %s unchanged\n", chg.Vsys)
		} else {
			s.info("comp: *** %s changed ***\n", chg.Vsys)
			for _, c := range chg.Cmds {
				c, _ = url.QueryUnescape(c)
				fmt.Println(c)
			}
		}
	}
	return nil
}

func (s *state) info(format string, args ...interface{}) {
	if !s.quiet {
		fmt.Fprintf(os.Stderr, format, args...)
	}
}

type warnOrErr int

const (
	errT = iota
	warnT
)

func (s *state) getCompare(
	c1 DeviceConfig, path string, chk warnOrErr) ([]Change, error) {

	c2, err := s.loadSpoc(path)
	if err != nil {
		return nil, err
	}
	changes, warnings, err := s.GetChanges(c1, c2)
	if err != nil {
		return nil, err
	}
	if warnings != nil {
		if chk == errT {
			return nil, warnings[0]
		}
		for _, w := range warnings {
			fmt.Fprintf(os.Stderr, "WARNING>>> %v\n", w)
		}
	}
	// Check hostname only after config has been validated in GetChanges.
	if s.devName != "" {
		name := c1.GetDevName()
		if name != s.devName {
			err := fmt.Errorf("Wrong device name: %s, expected: %s",
				name, s.devName)
			if chk == errT {
				return nil, err
			}
			fmt.Fprintf(os.Stderr, "WARNING>>> %v\n", err)
		}
	}
	return changes, nil
}

func (s *state) loadSpoc(v4Path string) (DeviceConfig, error) {
	v6Path := getIPv6Path(v4Path)
	conf4, err := s.loadSpocWithRaw(v4Path)
	if err != nil {
		return nil, err
	}
	conf6, err := s.loadSpocWithRaw(v6Path)
	if err != nil {
		return nil, err
	}
	return merge(conf4, conf6), nil
}

func (s *state) loadSpocWithRaw(pathName string) (DeviceConfig, error) {
	conf, err := s.loadSpocFile(pathName)
	if err != nil {
		return nil, err
	}
	rawPath := pathName + ".raw"
	raw, err := s.loadSpocFile(rawPath)
	if err != nil {
		return nil, err
	}
	if raw != nil {
		if err := raw.CheckRulesFromRaw(); err != nil {
			return nil, err
		}
	}
	return merge(conf, raw), nil
}

func merge(c1, c2 DeviceConfig) DeviceConfig {
	if c1 == nil {
		return c2
	}
	return c1.MergeSpoc(c2)
}

func (s *state) loadSpocFile(path string) (DeviceConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("Can't %v", err)
	}
	c, err := s.ParseConfig(data)
	//c.origin = "Netspoc"
	if err != nil {
		return nil, fmt.Errorf("Can't parse %s: %v", path, err)
	}
	return c, nil
}

func getIPv6Path(p string) string {
	dir := path.Dir(p)
	base := path.Base(p)
	return dir + "/ipv6/" + base
}

func getHostnameIPList(path string) ([]string, []string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("Can't %v", err)
	}
	reName := regexp.MustCompile(`\[ BEGIN (.+) \]`)
	reIP := regexp.MustCompile(`\[ IP = (.+) \]`)
	header := data[:1000]
	find := func(re *regexp.Regexp) string {
		if l := re.FindSubmatch(header); l != nil {
			return string(l[1])
		}
		return ""
	}
	names := find(reName)
	ips := find(reIP)
	if names == "" {
		return nil, nil, fmt.Errorf("Missing device name in %s", path)
	}
	if ips == "" {
		return nil, nil, fmt.Errorf("Missing IP address in %s", path)
	}
	ipList := strings.Split(ips, ", ")
	nameList := strings.Split(names, ", ")
	if len(nameList) != len(ipList) {
		return nil, nil, fmt.Errorf(
			"Number of device names and IP addresses don't match in %s", path)
	}
	return nameList, ipList, nil
}

func (s *state) setLogDir(logDir, file string) {
	if logDir != "" {
		s.logPath = path.Join(logDir, path.Base(file))
	}
}

func (s *state) getLogFH(ext string) (*os.File, error) {
	if s.logPath == "" {
		return nil, nil
	}
	file := s.logPath + ext
	return os.Create(file)
}

func closeLogFH(fh *os.File) {
	if fh != nil {
		fh.Close()
	}
}

var apiRE = regexp.MustCompile(`^(.*[?&]key=).*?(&.*)$`)

func DoLog(fh *os.File, t string) {
	if fh != nil {
		if strings.HasPrefix(t, "http") {
			t = apiRE.ReplaceAllString(t, "$1***$2")
			t, _ = url.QueryUnescape(t)
		} else if strings.HasPrefix(t, "action=") {
			t, _ = url.QueryUnescape(t)
		}
		fmt.Fprintln(fh, t)
	}
}
