package panos

import (
	"bytes"
	"fmt"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/device"
	"github.com/spf13/pflag"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"
)

type state struct {
	config     *device.Config
	devName    string
	httpClient *http.Client
	logPath    string
	urlPrefix  string
	devUser    string
	quiet      bool
}

type change struct {
	vsys string
	cmds []string
}

func Main() int {
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

	s := new(state)
	s.config = device.LoadConfig()
	s.quiet = *quiet

	// Argument processing
	args := fs.Args()
	var err error
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
	conf1, err := loadSpoc(path1)
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
	return s.deviceCommands(changed)
}

func (s *state) showCompare(conf1 *PanConfig, path string) error {
	changes, err := s.getCompare(conf1, path, warnT)
	if err != nil {
		return err
	}
	for _, chg := range changes {
		if chg.cmds == nil {
			s.info("comp: %s unchanged\n", chg.vsys)
		} else {
			s.info("comp: *** %s changed ***\n", chg.vsys)
			for _, c := range chg.cmds {
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
	c1 *PanConfig, path string, chk warnOrErr) ([]change, error) {

	c2, err := loadSpoc(path)
	if err != nil {
		return nil, err
	}
	var changes []change
	err = processVsysPairs(c1, c2, func(v1, v2 *panVsys) error {
		if v1 == nil {
			return fmt.Errorf(
				"Unknown name '%s' in VSYS of device configuration", v2.Name)
		}
		if v2 == nil {
			return nil
		}
		if err := s.vsysOK(v1, chk); err != nil {
			return err
		}
		device := c1.Devices.Entries[0].Name
		devicePath := "/config/devices/entry" + nameAttr(device)
		xPath := devicePath + "/vsys/entry" + nameAttr(v2.Name)
		l, err := diffConfig(v1, v2, xPath)
		if err != nil {
			return fmt.Errorf("%v of vsys '%s'", err, v2.Name)
		}
		changes = append(changes, change{v2.Name, l})
		return nil
	})
	// Check hostname only after config has been validated above.
	if err := s.devNameOK(c1, chk); err != nil {
		return nil, err
	}
	return changes, err
}

func loadSpoc(path string) (*PanConfig, error) {
	conf, err := loadSpocFile(path)
	if err != nil {
		return nil, err
	}
	rawPath := path + ".raw"
	if _, err := os.Stat(rawPath); err == nil {
		raw, err := loadSpocFile(rawPath)
		if err != nil {
			return nil, err
		}
		return conf, mergeRaw(conf, raw)
	}
	return conf, nil
}

func loadSpocFile(path string) (*PanConfig, error) {
	data, err := os.ReadFile(path)
	// Also handle saved config of device:
	// - starting with http address and
	// - with config stored as <response><result><devices>...
	if bytes.HasPrefix(data, []byte("http")) {
		i := bytes.IndexByte(data, byte('\n'))
		return parseResponseConfig(data[i+1:])
	}
	if err != nil {
		return nil, fmt.Errorf("Can't %v", err)
	}
	c, err := parseConfig(data)
	c.origin = "Netspoc"
	if err != nil {
		return nil, fmt.Errorf("Can't parse %s: %v", path, err)
	}
	return c, nil
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

func mergeRaw(c, r *PanConfig) error {
	return processVsysPairs(c, r, func(v1, v2 *panVsys) error {
		// Add complete vsys from raw.
		if v1 == nil {
			d1 := c.Devices.Entries[0]
			d1.Vsys = append(d1.Vsys, v2)
			return nil
		}
		// Vsys isn't changed from raw.
		if v2 == nil {
			return nil
		}
		// Add elements of vsys from raw.
		v1.Addresses = append(v1.Addresses, v2.Addresses...)
		v1.AddressGroups = append(v1.AddressGroups, v2.AddressGroups...)
		v1.Services = append(v1.Services, v2.Services...)
		// Add rules.
		// Rules are prepended per default.
		// Rules with attribute <APPEND> are appended.
		var top []*panRule
		for _, r := range v2.Rules {
			re := regexp.MustCompile(`^r\d`)
			if re.MatchString(r.Name) {
				return fmt.Errorf(
					"Must not use rule name starting with 'r<NUM>' in raw: %s",
					r.Name)
			}
			if r.Append == nil {
				top = append(top, r)
			} else {
				r.Append = nil
				v1.Rules = append(v1.Rules, r)
			}
		}
		v1.Rules = append(top, v1.Rules...)
		return nil
	})
}

func processVsysPairs(c1, c2 *PanConfig, f func(v1, v2 *panVsys) error) error {
	getDevVsysMap := func(c *PanConfig) (*panDevice, map[string]*panVsys, error) {
		l := c.Devices.Entries
		if len(l) != 1 {
			return nil, nil, fmt.Errorf(
				"Expected exactly one device entry in '%s' configuration", c.origin)
		}
		d := l[0]
		m := make(map[string]*panVsys)
		for i, v := range d.Vsys {
			name := v.Name
			if name == "" {
				return nil, nil, fmt.Errorf(
					"Missing name in %d. VSYS of '%s' configuration", c.origin, i+1)
			}
			if _, ok := m[name]; ok {
				return nil, nil, fmt.Errorf(
					"Duplicate name '%s' in VSYS of '%s' configuration",
					c.origin, name)
			}
			m[name] = v
		}
		return d, m, nil
	}
	d1, m1, err := getDevVsysMap(c1)
	if err != nil {
		return err
	}
	d2, m2, err := getDevVsysMap(c2)
	if err != nil {
		return err
	}
	if d1.Name != "" && d2.Name != "" && d1.Name != d2.Name {
		return fmt.Errorf("Different names in <device> of XML: %s='%s', %s='%s'",
			c1.origin, d1.Name, c2.origin, d2.Name)
	}
	for _, v1 := range d1.Vsys {
		v2 := m2[v1.Name]
		if err := f(v1, v2); err != nil {
			return err
		}
	}
	for _, v2 := range d2.Vsys {
		if m1[v2.Name] == nil {
			if err := f(nil, v2); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *state) devNameOK(conf *PanConfig, check warnOrErr) error {
	if s.devName != "" {
		name := conf.Devices.Entries[0].Hostname
		if name != s.devName {
			err := fmt.Errorf("Wrong device name: %s, expected: %s",
				name, s.devName)
			if check == errT {
				return err
			}
			fmt.Fprintf(os.Stderr, "WARNING>>> %v\n", err)
		}
	}
	return nil
}

func (s *state) vsysOK(v *panVsys, check warnOrErr) error {
	if s.devName != "" {
		name := strings.ToLower(v.DisplayName)
		if !strings.Contains(name, "netspoc") {
			err := fmt.Errorf("Missing NetSPoC in name of %s", v.Name)
			if check == errT {
				return err
			}
			fmt.Fprintf(os.Stderr, "WARNING>>> %v\n", err)
		}
	}
	return nil
}

func nameAttr(n string) string {
	return "[@name='" + url.QueryEscape(n) + "']"
}

func textAttr(n string) string {
	return "[text()='" + url.QueryEscape(n) + "']"
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

func doLog(fh *os.File, t string) {
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
