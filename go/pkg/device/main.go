package device

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/spf13/pflag"
)

type RealDevice interface {
	LoadDevice(fname string, c *Config, l1, l2 *os.File) (DeviceConfig, error)
	ParseConfig(data []byte, fName string) (DeviceConfig, error)
	GetChanges(c1, c2 DeviceConfig) error
	GetErrUnmanaged() []error
	ApplyCommands(*os.File) error
	HasChanges() bool
	ShowChanges() string
	CloseConnection()
}

type DeviceConfig interface {
	MergeSpoc(DeviceConfig) DeviceConfig
	CheckRulesFromRaw() error
}

type state struct {
	RealDevice
	config   *Config
	logFname string
}

var quiet bool

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
	fs.BoolVarP(&quiet, "quiet", "q", false, "No info messages")
	compare := fs.BoolP("compare", "C", false, "Compare only")
	logDir := fs.StringP("logdir", "L", "", "Path for saving session logs")
	user := fs.StringP("user", "u", "", "Username for login to remote device")
	if err := fs.Parse(os.Args[1:]); err != nil {
		if err == pflag.ErrHelp {
			return 1
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		fs.Usage()
		return 1
	}

	return handleBailout(func() int {
		var err error
		s := &state{RealDevice: device}

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
			s.config.User = *user
			fname := args[0]
			s.setLogDir(*logDir, fname)
			if *compare {
				err = s.compare(fname)
			} else {
				err = s.approve(fname)
			}
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR>>> %v\n", err)
			return 1
		}
		s.CloseConnection()
		return 0
	})
}

func (s *state) compareFiles(fname1, fname2 string) error {
	conf1, err := s.loadSpoc(fname1)
	if err != nil {
		return err
	}
	err = s.getCompare(conf1, fname2)
	if err != nil {
		return err
	}
	s.showCompare()
	return nil
}

func (s *state) compare(fname string) error {
	err := s.compareDevice(fname)
	if err != nil {
		return err
	}
	for _, w := range s.GetErrUnmanaged() {
		Warning("%v", w)
	}
	s.showCompare()
	return nil
}

func (s *state) approve(fname string) error {
	err := s.compareDevice(fname)
	if err != nil {
		return err
	}
	if l := s.GetErrUnmanaged(); l != nil {
		return l[0]
	}
	return s.applyCommands()
}

func (s *state) compareDevice(fname string) error {
	conf1, err := s.loadDevice(fname)
	if err != nil {
		return err
	}
	return s.getCompare(conf1, fname)
}

func (s *state) loadDevice(fname string) (DeviceConfig, error) {
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
	return s.LoadDevice(fname, s.config, logLogin, logConfig)
}

func (s *state) applyCommands() error {
	logFH, err := s.getLogFH(".change")
	if err != nil {
		return err
	}
	defer closeLogFH(logFH)
	if !s.HasChanges() {
		DoLog(logFH, "No changes applied")
		return nil
	}
	return s.ApplyCommands(logFH)
}

func (s *state) showCompare() {
	if !s.HasChanges() {
		Info("comp: device unchanged")
	} else {
		Info("comp: *** device changed ***")
		fmt.Print(s.ShowChanges())
	}
}

func (s *state) getCompare(c1 DeviceConfig, fname string) error {
	c2, err := s.loadSpoc(fname)
	if err != nil {
		return err
	}
	return s.GetChanges(c1, c2)
}

func (s *state) loadSpoc(v4Path string) (DeviceConfig, error) {
	v6Path := getIPv6Fname(v4Path)
	conf4, err := s.loadSpocFile(v4Path)
	if err != nil {
		return nil, err
	}
	conf6, err := s.loadSpocFile(v6Path)
	if err != nil {
		return nil, err
	}
	conf := conf4.MergeSpoc(conf6)
	return s.addRaw(conf, v4Path)
}

func (s *state) addRaw(conf DeviceConfig, v4Path string) (DeviceConfig, error) {
	rawPath := v4Path + ".raw"
	raw, err := s.loadSpocFile(rawPath)
	if err != nil {
		return nil, err
	}
	if raw != nil {
		if err := raw.CheckRulesFromRaw(); err != nil {
			return nil, err
		}
	}
	conf = conf.MergeSpoc(raw)
	return conf, nil
}

func (s *state) loadSpocFile(fname string) (DeviceConfig, error) {
	data, err := os.ReadFile(fname)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("Can't %v", err)
	}
	c, err := s.ParseConfig(data, fname)
	if err != nil {
		b := path.Base(fname)
		return nil, fmt.Errorf("While reading %s: %v", b, err)
	}
	return c, nil
}

func getIPv6Fname(p string) string {
	dir := path.Dir(p)
	base := path.Base(p)
	return dir + "/ipv6/" + base
}

type codeInfo struct {
	GeneratedBy             string   `json:"generated_by"`
	Model                   string   `json:"model"`
	IPList                  []string `json:"ip_list,omitempty"`
	NameList                []string `json:"name_list,omitempty"`
	PolicyDistributionPoint string   `json:"policy_distribution_point,omitempty"`
}

func getHostnameIPList(path string) ([]string, []string, error) {
	info, checked := loadInfoFile(path)
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

func GetIPPDP(fName string) (string, string, error) {
	info, checked := loadInfoFile(fName)
	ipList := info.IPList
	if len(ipList) == 0 {
		return "", "", fmt.Errorf("Missing IP address in %v", checked)
	}
	return ipList[0], info.PolicyDistributionPoint, nil
}

func GetHostname(fName string) string {
	return path.Base(fName)
}

func loadInfoFile(path string) (*codeInfo, []string) {
	path6 := getIPv6Fname(path)
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

func (s *state) setLogDir(logDir, file string) {
	if logDir != "" {
		s.logFname = path.Join(logDir, path.Base(file))
	}
}

func (s *state) getLogFH(ext string) (*os.File, error) {
	if s.logFname == "" {
		return nil, nil
	}
	fname := s.logFname + ext
	return os.Create(fname)
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
	fname string,
	cfg *Config,
	login func(name, ip, user, pass string) error,
) error {

	nameList, ipList, err := getHostnameIPList(fname)
	if err != nil {
		return err
	}
	for i, name := range nameList {
		ip := ipList[i]
		user, pass := cfg.GetUserPass(name)
		if err := login(name, ip, user, pass); err != nil {
			Warning("%v", err)
			continue
		}
		return nil
	}
	return fmt.Errorf(
		"Devices unreachable: %s", strings.Join(nameList, ", "))
}

func Info(format string, args ...interface{}) {
	if !quiet {
		fmt.Fprintf(os.Stderr, format+"\n", args...)
	}
}

func Warning(format string, args ...interface{}) {
	printWithMarker("WARNING>>> ", format, args...)
}

type bailout struct{}

func handleBailout(f func() int) (exitCode int) {
	defer func() {
		if e := recover(); e != nil {
			if _, ok := e.(bailout); !ok {
				panic(e) // Resume same panic if it's not a bailout.
			}
			exitCode = 1
		}
	}()
	return f()
}

func Abort(format string, args ...interface{}) {
	printWithMarker("ERROR>>> ", format, args...)
	panic(bailout{})
}

func printWithMarker(m string, format string, args ...interface{}) {
	out := fmt.Sprintf(format, args...)
	out = strings.TrimSuffix(out, "\n")
	out = strings.ReplaceAll(out, "\n", "\n"+m)
	fmt.Fprintln(os.Stderr, m+out)
}
