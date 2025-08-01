package asa

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/hknutzen/Netspoc-Approve/go/pkg/cisco"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/codefiles"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/console"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/errlog"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/program"
)

type State struct {
	cisco.State
}

func Setup() *State {
	s := &State{}
	s.SetupParser(cmdInfo)
	s.Model = "ASA"
	return s
}

func (s *State) LoadDevice(
	spocFile string, cfg *program.Config, logLogin, logConfig *os.File) error {

	user, pass, err := cfg.GetUserPass(codefiles.GetHostname(spocFile))
	if err != nil {
		return err
	}
	s.Conn, err = console.GetSSHConn(spocFile, user, cfg, logLogin)
	if err != nil {
		return err
	}
	hostName := codefiles.GetHostname(spocFile)
	s.LoginEnable(pass, cfg)
	s.setTerminal()
	s.logVersion()
	s.checkDeviceName(hostName)

	s.Conn.SetLogFH(logConfig)
	errlog.Info("Requesting device config")
	out := s.Conn.GetCmdOutput("write term")
	errlog.Info("Got device config")
	s.DeviceCfg, err = s.ParseConfig([]byte(out), "<device>")
	errlog.Info("Parsed device config")
	if err != nil {
		err = fmt.Errorf("While reading device: %v", err)
	}
	return err
}

func (s *State) setTerminal() {
	conn := s.Conn
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

func (s *State) logVersion() {
	s.Conn.GetCmdOutput("sh ver")
}

func (s *State) checkDeviceName(name string) {
	out := s.Conn.GetCmdOutput("show hostname")
	out = strings.TrimSuffix(out, "\n")
	if name != out {
		errlog.Abort("Wrong device name: %q, expected: %q", out, name)
	}
}

func (s *State) ApplyCommands(logFh *os.File) error {
	s.Conn.SetLogFH(logFh)
	s.cmd("configure terminal")
	for _, chg := range s.Changes {
		s.cmd(chg)
	}
	s.cmd("end")
	out := s.Conn.GetCmdOutput("write memory")
	if !strings.Contains(out, "[OK]") {
		errlog.Abort("Command 'write memory' failed, missing [OK] in output:\n%s",
			out)
	}
	return nil
}

// Send 1 or 2 commands in one data packet to device.
// No output expected from commands.
// Exceptions are given in map validOutput
func (s *State) cmd(cmd string) {
	c1, c2, _ := strings.Cut(cmd, "\n")
	s.Conn.Send(cmd)
	check := func(ci string) {
		out := s.Conn.GetOutput()
		out = s.Conn.StripEcho(ci, out)
		if out != "" {
			if !isValidOutput(ci, out) {
				errlog.Abort("Got unexpected output from '%s':\n%s", ci, out)
			}
		}
	}
	check(c1)
	if c2 != "" {
		check(c2)
	}
}

var sameGroupRegex = regexp.MustCompile(
	`^WARNING: Same object-group is used more than once in one config line`)
var cryptoMapIncompleteRegex = regexp.MustCompile(
	`WARNING: The crypto map entry (?:is|will be) incomplete!`)

var validOutput = map[string]*regexp.Regexp{
	"access-list":    sameGroupRegex,
	"no access-list": sameGroupRegex,
	"crypto map":     cryptoMapIncompleteRegex,
	"no crypto map":  cryptoMapIncompleteRegex,
	// Expected multi line warning.
	"tunnel-group": regexp.MustCompile(
		`^WARNING: (For IKEv1, )?L2L tunnel-groups that have names which are not an IP|^address may only be used if the tunnel authentication|^method is Digital Certificates and/or The peer is|^configured to use Aggressive Mode`),
}

func isValidOutput(cmd, out string) bool {
LINE:
	for _, line := range strings.Split(out, "\n") {
		if line == "" {
			continue
		}
		for prefix, re := range validOutput {
			if strings.HasPrefix(cmd, prefix) && re.MatchString(line) {
				continue LINE
			}
		}
		if strings.HasPrefix(line, "INFO:") {
			continue
		}
		if strings.HasPrefix(line, "WARNING:") {
			errlog.Warning("Got unexpected output from '%s':\n%s", cmd, line)
			continue
		}
		return false
	}
	return true
}

func (s *State) CloseConnection() {
	if c := s.Conn; c != nil {
		s.Conn.Close()
	}
}
