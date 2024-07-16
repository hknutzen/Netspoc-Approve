package asa

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/hknutzen/Netspoc-Approve/go/pkg/cisco"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/console"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/device"
)

type State struct {
	cisco.State
	conn         *console.Conn
	errUnmanaged []error
}

func Setup() *State {
	s := &State{}
	s.SetupParser(cmdInfo)
	s.Model = "ASA"
	return s
}

func (s *State) LoadDevice(
	spocFile string, cfg *device.Config, logLogin, logConfig *os.File) (
	device.DeviceConfig, error) {

	user, pass := cfg.GetUserPass(device.GetHostname(spocFile))
	var err error
	s.conn, err = console.GetSSHConn(spocFile, user, cfg, logLogin)
	if err != nil {
		return nil, err
	}
	hostName := device.GetHostname(spocFile)
	s.loginEnable(pass, cfg)
	s.setTerminal()
	s.logVersion()
	s.checkDeviceName(hostName)

	s.conn.SetLogFH(logConfig)
	device.Info("Requesting device config")
	out := s.conn.GetCmdOutput("write term")
	device.Info("Got device config")
	config, err := s.ParseConfig([]byte(out), "<device>")
	device.Info("Parsed device config")
	if err != nil {
		err = fmt.Errorf("While reading device: %v", err)
	}
	return config, err
}

func (s *State) loginEnable(pass string, cfg *device.Config) {
	var bannerLines string
	conn := s.conn
	out := conn.ShortWait(`(?i)password:|\(yes/no.*\)\?`)
	if strings.HasSuffix(out, "?") {
		out = conn.IssueCmd("yes", `(?i)password:`)
	}
	bannerLines += out
	out = conn.IssueCmd(pass, `[>#]`)
	bannerLines += out
	if strings.HasSuffix(out, ">") {
		// Enter enable mode.
		out = conn.IssueCmd("enable", `(?i)password:|#`)
		bannerLines += out
		if !strings.HasSuffix(out, "#") {
			// Enable password required.
			// Use login password as enable password.
			out = conn.IssueCmd(pass, `(?i)password:|#`)
			bannerLines += out
			if !strings.HasSuffix(out, "#") {
				device.Abort("Authentication for enable mode failed")
			}
		}
	}
	// Force new prompt by issuing empty command.
	// Use this prompt because of performance impact of standard prompt.
	out = conn.IssueCmd("", `#[ ]?`)
	i := strings.LastIndex(out, "\n")
	// Current prompt: "\n\rHOSTNAME# "
	p := out[i:]
	// Prompt of ASA may vary before terminating "# "
	i = strings.LastIndex(p, "#")
	rx := regexp.MustCompile(
		regexp.QuoteMeta(p[:i]) + `\S*` + regexp.QuoteMeta(p[i:]))
	conn.SetStdPrompt(rx)
	s.checkBanner(bannerLines, cfg)
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

func (s *State) logVersion() {
	s.conn.GetCmdOutput("sh ver")
}

func (s *State) checkDeviceName(name string) {
	out := s.conn.GetCmdOutput("show hostname")
	out = strings.TrimSuffix(out, "\n")
	if name != out {
		device.Abort("Wrong device name: %q, expected: %q", out, name)
	}
}

func (s *State) checkBanner(lines string, cfg *device.Config) {
	if rx := cfg.CheckBanner; rx != nil && rx.FindStringIndex(lines) == nil {
		s.errUnmanaged =
			[]error{errors.New("Missing banner at NetSPoC managed device")}
	}
}

func (s *State) GetErrUnmanaged() []error {
	return s.errUnmanaged
}

func (s *State) ApplyCommands(logFh *os.File) error {
	s.conn.SetLogFH(logFh)
	s.cmd("configure terminal")
	for _, chg := range s.Changes {
		s.cmd(chg)
	}
	s.cmd("end")
	out := s.conn.GetCmdOutput("write memory")
	if !strings.Contains(out, "[OK]") {
		device.Abort("Command 'write memory' failed, missing [OK] in output:\n%s",
			out)
	}
	return nil
}

// Send 1 or 2 commands in one data packet to device.
// No output expected from commands.
// Exceptions are given in map cmd2validOutput
func (s *State) cmd(cmd string) {
	c1, c2, _ := strings.Cut(cmd, "\n")
	s.conn.Send(cmd)
	check := func(ci string) {
		out := s.conn.GetOutput()
		out = s.conn.StripEcho(ci, out)
		if out != "" {
			if !isValidOutput(ci, out) {
				device.Abort("Got unexpected output from '%s':\n%s", ci, out)
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
var validOutput = map[string]*regexp.Regexp{
	"access-list":    sameGroupRegex,
	"no access-list": sameGroupRegex,
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
			device.Warning("Got unexpected output from '%s':\n%s", cmd, line)
			continue
		}
		return false
	}
	return true
}

func (s *State) CloseConnection() {
	if c := s.conn; c != nil {
		s.conn.Close()
	}
}
