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
	LoadDevice(path string, c *Config, l1, l2 *os.File) (DeviceConfig, error)
	ParseConfig(data []byte) (DeviceConfig, error)
	GetChanges(c1, c2 DeviceConfig) ([]error, error)
	ApplyCommands(*os.File) error
	HasChanges() bool
	ShowChanges() string
	CloseConnection()
}

type DeviceConfig interface {
	MergeSpoc(DeviceConfig) DeviceConfig
	SetExpectedDeviceName(string)
	CheckDeviceName() error
	CheckRulesFromRaw() error
}

type state struct {
	RealDevice
	config  *Config
	logPath string
	quiet   bool
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
	s.CloseConnection()
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
	err = s.getCompare(conf1, path, errT)
	if err != nil {
		return err
	}
	return s.applyCommands()
}

func (s *state) loadDevice(path string) (DeviceConfig, error) {
	logConfig, err := s.getLogFH(".config")
	if err != nil {
		return nil, err
	}
	defer closeLogFH(logConfig)
	logLogin, err := s.getLogFH(".login")
	if err != nil {
		return nil, err
	}
	defer closeLogFH(logLogin)
	return s.LoadDevice(path, s.config, logLogin, logConfig)
}

func (s *state) applyCommands() error {
	logFH, err := s.getLogFH(".change")
	if err != nil {
		return err
	}
	defer closeLogFH(logFH)
	if !s.HasChanges() {
		DoLog(logFH, "No changes applied")
	}
	return s.ApplyCommands(logFH)
}

func (s *state) showCompare(conf1 DeviceConfig, path string) error {
	err := s.getCompare(conf1, path, warnT)
	if err != nil {
		return err
	}
	if !s.HasChanges() {
		s.info("comp: device unchanged\n")
	} else {
		s.info("comp: *** device changed ***\n")
		fmt.Print(s.ShowChanges())
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

func (s *state) getCompare(c1 DeviceConfig, path string, chk warnOrErr) error {
	c2, err := s.loadSpoc(path)
	if err != nil {
		return err
	}
	warnings, err := s.GetChanges(c1, c2)
	if err != nil {
		return err
	}
	if warnings != nil {
		if chk == errT {
			return warnings[0]
		}
		for _, w := range warnings {
			warning("%v", w)
		}
	}
	// Check hostname only after config has been validated in GetChanges.
	if err := c1.CheckDeviceName(); err != nil {
		if chk == errT {
			return err
		}
		warning("%v", err)
	}
	return nil
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
	return conf4.MergeSpoc(conf6), nil
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
	return conf.MergeSpoc(raw), nil
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

func getRawHostnameIP(path string) ([]string, []string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("Can't %v", err)
	}
	reName := regexp.MustCompile(`\[ BEGIN (.+) \]`)
	reIP := regexp.MustCompile(`\[ IP = (.+) \]`)
	find := func(re *regexp.Regexp) string {
		if l := re.FindSubmatch(data); l != nil {
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
	return nameList, ipList, nil
}

func GetHostnameIP(path string) (string, string, error) {
	nameList, ipList, err := getRawHostnameIP(path)
	if err != nil {
		return "", "", err
	}
	return nameList[0], ipList[0], nil
}

func getHostnameIPList(path string) ([]string, []string, error) {
	nameList, ipList, err := getRawHostnameIP(path)
	if err != nil {
		return nil, nil, err
	}
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

func DoLog(fh *os.File, s string) {
	if fh != nil {
		if strings.HasPrefix(s, "http") || strings.HasPrefix(s, "action=") {
			s, _ = url.QueryUnescape(s)
		}
		fmt.Fprintln(fh, s)
	}
}

func GetHTTPClient(cfg *Config) *http.Client {
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
	}
}

func TryReachableHTTPLogin(
	path string,
	cfg *Config,
	login func(name, ip, user, pass string) error,
) error {

	nameList, ipList, err := getHostnameIPList(path)
	if err != nil {
		return err
	}
	for i, name := range nameList {
		ip := ipList[i]
		user, pass, err := cfg.GetAAAPassword(name)
		if err != nil {
			return err
		}
		if err := login(name, ip, user, pass); err != nil {
			warning("%v", err)
			continue
		}
		return nil
	}
	return fmt.Errorf(
		"Devices unreachable: %s", strings.Join(nameList, ", "))
}

func Info(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}

func warning(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "WARNING>>> "+format+"\n", args...)
}

func Abort(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "Error>>> "+format+"\n", args...)
	os.Exit(1)
}
