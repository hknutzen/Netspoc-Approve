package ios

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/hknutzen/Netspoc-Approve/go/pkg/cisco"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/codefiles"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/console"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/errlog"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/program"
)

type State struct {
	cisco.State
	reloadActive bool
}

func Setup() *State {
	s := &State{}
	s.SetupParser(cmdInfo)
	s.Model = "IOS"
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
	out := s.Conn.GetCmdOutput("sh run")
	errlog.Info("Got device config")
	s.DeviceCfg, err = s.ParseConfig([]byte(out), "<device>")
	errlog.Info("Parsed device config")
	if err != nil {
		err = fmt.Errorf("While reading device: %v", err)
	}
	return err
}

func (s *State) setTerminal() {
	s.Conn.SendCmd("term len 0")
	s.Conn.SendCmd("term width 512")
}

func (s *State) logVersion() {
	s.Conn.GetCmdOutput("sh ver")
}

func (s *State) checkDeviceName(name string) {
	// Force new prompt by issuing empty command.
	// Output is: \r\n\s*NAME#\s?
	out := strings.TrimSpace(s.Conn.IssueCmd("", `#[ ]?`))
	out = strings.TrimSuffix(out, "#")
	if name != out {
		errlog.Abort("Wrong device name: %q, expected: %q", out, name)
	}
}

func (s *State) prepareDevice() {
	s.Conn.SendCmd("configure terminal")
	// Don't slow down the system by logging to console.
	s.Conn.SendCmd("no logging console")
	// Enable logging synchronous to get a fresh prompt after
	// a reload banner is shown.
	s.Conn.SendCmd("line vty 0 15")
	s.Conn.SendCmd("logging synchronous level all")
	// Needed for default route to work as expected.
	s.Conn.SendCmd("ip subnet-zero")
	s.Conn.SendCmd("ip classless")
	s.Conn.SendCmd("end")
}

func (s *State) ApplyCommands(logFh *os.File) error {
	s.Conn.SetLogFH(logFh)
	s.prepareDevice()
	func() {
		s.scheduleReload()
		defer s.cancelReload()
		s.Conn.SendCmd("configure terminal")
		defer s.Conn.SendCmd("end")
		for _, chg := range s.Changes {
			s.cmd(chg)
		}
	}()
	s.writeMem()
	return nil
}

// Output of "write mem":
// 1.
// Building configuration...
// Compressed configuration from 22772 bytes to 7054 bytes[OK]
// 2.
// Building configuration...
// [OK]
// 3.
// Warning: Attempting to overwrite an NVRAM configuration previously written
// by a different version of the system image.
// Overwrite the previous NVRAM configuration?[confirm]
// Building configuration...
// Compressed configuration from 10194 bytes to 5372 bytes[OK]
// 4.
// startup-config file open failed (Device or resource busy)
// In this case we retry the command up to three times.

func (s *State) writeMem() {
	retries := 2
	for {
		out := s.Conn.IssueCmd("write memory", `#[ ]?|\[confirm\]`)
		if strings.Contains(out, "Overwrite the previous NVRAM configuration") {
			out = s.Conn.GetCmdOutput("")
		}
		if strings.Contains(out, "[OK]") {
			return
		}
		if strings.Contains(out, "startup-config file open failed") {
			if retries > 0 {
				retries--
				time.Sleep(3 * time.Second)
				continue
			}
			errlog.Abort("write mem: startup-config open failed - giving up")
		}
		errlog.Abort("write mem: unexpected result: %s", out)
	}
}

// Send 1 or 2 commands in one data packet to device.
// No output expected from commands.
func (s *State) cmd(cmd string) {
	c1, c2, _ := strings.Cut(cmd, "\n")
	s.Conn.Send(cmd)
	needReload := false
	check := func(ci string) {
		out := s.Conn.GetOutput()
		out, needReload = s.stripReloadBanner(out)
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
	if needReload {
		s.extendReload()
	}
}

func isValidOutput(cmd, out string) bool {
	for _, line := range strings.Split(out, "\n") {
		if line == "" {
			continue
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

const reloadMinutes = 2

func (s *State) scheduleReload() {
	s.sendReloadCmd(false)
}

func (s *State) extendReload() {
	s.sendReloadCmd(true)
}

func (s *State) sendReloadCmd(withDo bool) {
	cmd := fmt.Sprintf("reload in %d", reloadMinutes)
	if withDo {
		cmd = "do " + cmd
	}
	out := s.Conn.IssueCmd(cmd, `\[yes\/no\]:\ |\[confirm\]`)
	// System configuration has been modified. Save? [yes/no]:
	if strings.Contains(out, "[yes/no]") {
		// Leave our changes unsaved, to be sure that a reload
		// gets last good configuration.
		s.Conn.IssueCmd("n", `\[confirm\]`)
	}
	// Confirm the reload with empty command, wait for the standard prompt.
	s.reloadActive = true
	s.Conn.SendCmd("")
}

func (s *State) cancelReload() {
	// Don't wait for standard prompt, but for banner message, which is
	// sent asynchronously.
	s.Conn.IssueCmd("reload cancel", `--- SHUTDOWN ABORTED ---`)
	// Because of 'logging synchronous' we are sure to get another prompt.
	s.Conn.WaitShort(`[#] ?$`)
	// Synchronize expect buffers with empty command.
	s.Conn.SendCmd("")
	s.reloadActive = false
}

/*
Remove banner message from command output and
check if a renewal of running reload process is needed.

If a reload is scheduled or aborted, a banner message will be inserted into
the expected command output:
<three empty lines>
<BELL>
***
*** --- <message> ---
***
This message is schown some time before the actual reload takes place:
  - SHUTDOWN in 0:05:00
  - SHUTDOWN in 0:01:00
*/

// End of line has already been converted from \r\n to \n.
var bannerRe = regexp.MustCompile(`\n\n\n\x07[*]{3}\n[*]{3}([^\n]+)\n[*]{3}\n`)

func (s *State) stripReloadBanner(out string) (string, bool) {
	if s.reloadActive {
		// Find message inside banner.
		if l := bannerRe.FindStringSubmatchIndex(out); l != nil {
			msg := out[l[2]:l[3]]
			prefix := out[:l[0]]
			postfix := out[l[1]:]
			out = prefix + postfix
			if strings.TrimSpace(prefix+postfix) == "" {
				// Because of 'logging synchronous' we are sure to get another prompt
				// if the banner is the only output before current prompt.
				// Read next prompt.
				errlog.Info("Found banner before output, expecting another prompt")
				out = s.Conn.WaitShort(`[#] ?$`)
				out = s.Conn.StripStdPrompt(out)
			} else if prefix != "" && strings.TrimSpace(postfix) == "" {
				// Try to read another prompt if banner is shown directly
				// behind current output.
				errlog.Info("Found banner after output, checking another prompt")
				if s.Conn.TryPrompt() {
					errlog.Info("- Found prompt")
				}
			}
			matched, _ := regexp.MatchString(`SHUTDOWN in 0?0:01:00`, msg)
			return out, matched
		}
	}
	return out, false
}
