package asa

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/hknutzen/Netspoc-Approve/go/pkg/console"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/device"
	"golang.org/x/exp/maps"
)

type State struct {
	conn     *console.Conn
	a        *ASAConfig
	b        *ASAConfig
	changes  changeList
	subCmdOf string
}
type change struct {
	cmd string
}
type changeList []string

func (l *changeList) push(chg ...string) {
	*l = append(*l, chg...)
}

func (s *State) LoadDevice(
	spocFile string, cfg *device.Config, logLogin, logConfig *os.File) (
	device.DeviceConfig, error) {

	hostName, ip, err := device.GetHostnameIP(spocFile)
	if err != nil {
		return nil, err
	}
	user, pass, err := cfg.GetAAAPassword(hostName)
	if err != nil {
		return nil, err
	}
	s.conn, err = console.ConnectSSH(user, ip, cfg, logLogin)
	if err != nil {
		return nil, err
	}
	s.loginEnable(pass)
	s.setTerminal()

	s.conn.SetLogFH(logConfig)
	device.Info("Parsing device config")
	out := s.conn.GetCmdOutput("write term")
	device.Info("Got device config")
	config, err := s.ParseConfig([]byte(out), "<device>")
	device.Info("Parsed device config")
	if err != nil {
		err = fmt.Errorf("While reading device: %v", err)
	}
	return config, err
}

func (s *State) loginEnable(pass string) {
	conn := s.conn
	match := conn.ShortWait(`(?i)password:|\(yes/no.*\)\?`)
	if strings.HasSuffix(match, "?") {
		match = conn.IssueCmd("yes", `(?i)password:`)
		device.Info("SSH key permanently added to known hosts")
	}
	match = conn.IssueCmd(pass, `[>#]`)
	if strings.HasSuffix(match, ">") {
		// Enter enable mode.
		match = conn.IssueCmd("enable", `(?i)password:|#`)
		if !strings.HasSuffix(match, "#") {
			// Enable password required.
			// Use login password as enable password.
			match = conn.IssueCmd(pass, `(?i)password:|#`)
			if !strings.HasSuffix(match, "#") {
				device.Abort("Authentication for enable mode failed")
			}
		}
	} else if !strings.HasSuffix(match, "#") {
		device.Abort("Authentication failed")
	}
	// Force new prompt by issuing empty command.
	// Use this prompt because of performance impact of standard prompt.
	match = conn.IssueCmd("", `#[ ]?`)
	i := strings.LastIndex(match, "\r\n")
	conn.SetStdPrompt(match[i:])
}

func (s *State) setTerminal() {
	conn := s.conn
	out := conn.GetCmdOutput("sh pager")
	if !strings.Contains(out, "no pager") {
		conn.SendCmd("terminal pager 0")
	}
	out = conn.GetCmdOutput("sh term")
	if !strings.Contains(out, "511") {
		conn.SendCmd("configure terminal")
		conn.SendCmd("terminal width 511")
		conn.SendCmd("end")
	}
}

func (s *State) GetChanges(c1, c2 device.DeviceConfig) ([]error, error) {
	s.a = c1.(*ASAConfig)
	s.b = c2.(*ASAConfig)
	if err := s.checkInterfaces(); err != nil {
		return nil, err
	}
	s.diffConfig()
	return nil, nil
}

func (s *State) HasChanges() bool {
	return len(s.changes) != 0
}

func (s *State) ShowChanges() string {
	var collect strings.Builder
	for _, chg := range s.changes {
		fmt.Fprintln(&collect, chg)
	}
	return collect.String()
}

func (s *State) ApplyCommands(logFh *os.File) error {
	return nil
}

func (s *State) showCmd(c string) string {
	return s.conn.GetCmdOutput(c)
}

func (s *State) cmd(c string) {
}

func (s *State) CloseConnection() {
	if c := s.conn; c != nil {
		s.conn.Close()
	}
}

func (s *State) checkInterfaces() error {

	// Collect named interfaces from Netspoc.
	// These are defined implicitly by commands
	// "access-group $access-list in|out interface INTF".
	// Ignore "access-group $access-list global".
	bIntf := make(map[string]bool)
	for _, l := range s.b.lookup["access-group"] {
		for _, c := range l {
			tokens := strings.Fields(c.parsed)
			if len(tokens) == 5 {
				bIntf[tokens[4]] = true
			}
		}
	}

	// Collect and check named interfaces from device.
	aIntf := make(map[string]bool)
	for _, l := range s.a.lookup["interface"] {
		for _, c := range l {
			name := ""
			shutdown := false
			for _, sc := range c.sub {
				tokens := strings.Fields(sc.parsed)
				switch tokens[0] {
				case "shutdown":
					shutdown = true
				case "nameif":
					name = tokens[1]
				}
			}
			if name != "" {
				aIntf[name] = true
				if !shutdown && !bIntf[name] {
					device.Warning(
						"Interface '%s' on device is not known by Netspoc", name)
				}
			}
		}
	}

	// Check interfaces from Netspoc
	bNames := maps.Keys(bIntf)
	sort.Strings(bNames)
	for _, name := range bNames {
		if !aIntf[name] {
			return fmt.Errorf(
				"Interface '%s' from Netspoc not known on device", name)
		}
	}
	return nil
}
