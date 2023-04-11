package asa

import (
	"fmt"
	"os"
	"strings"

	"github.com/hknutzen/Netspoc-Approve/go/pkg/console"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/device"
)

type State struct {
	conn    *console.Conn
	changes []change
}
type change struct {
	cmd string
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
	config, err := s.ParseConfig([]byte(out))
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
	p1 := c1.(*ASAConfig)
	p2 := c2.(*ASAConfig)
	s.changes = diffConfig(p1, p2)
	return nil, nil
}

func (s *State) HasChanges() bool {
	return len(s.changes) != 0
}

func (s *State) ShowChanges() string {
	var collect strings.Builder
	for _, chg := range s.changes {
		fmt.Fprintln(&collect, chg.cmd)
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
