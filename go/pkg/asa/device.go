package asa

import (
	"regexp"
	"strings"

	"github.com/hknutzen/Netspoc-Approve/go/pkg/console"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/errlog"
)

type State struct{}

func (s *State) SetTerminal(conn *console.Conn) {
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

func (s *State) CheckDeviceName(name string, conn *console.Conn) {
	out := conn.GetCmdOutput("show hostname")
	out = strings.TrimSuffix(out, "\n")
	if name != out {
		errlog.Abort("Wrong device name: %q, expected: %q", out, name)
	}
}

func (s *State) PrepareDevice(conn *console.Conn)  {}
func (s *State) ScheduleReload(conn *console.Conn) {}
func (s *State) ExtendReload(conn *console.Conn)   {}
func (s *State) CancelReload(conn *console.Conn)   {}
func (s *State) RemoveBanner(data []byte) []byte   { return data }
func (s *State) StripReloadBanner(out string, conn *console.Conn,
) (string, bool) {
	return out, false
}

func (s *State) WriteMem(conn *console.Conn) {
	out := conn.GetCmdOutput("write memory")
	if !strings.Contains(out, "[OK]") {
		errlog.Abort("Command 'write memory' failed, missing [OK] in output:\n%s",
			out)
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

func (s *State) IsValidOutput(cmd, out string) bool {
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
