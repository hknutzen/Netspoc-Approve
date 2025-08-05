package ios

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/hknutzen/Netspoc-Approve/go/pkg/console"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/errlog"
)

type State struct {
	reloadActive bool
}

func (s *State) SetTerminal(conn *console.Conn) {
	conn.SendCmd("term len 0")
	conn.SendCmd("term width 512")
}

func (s *State) CheckDeviceName(name string, conn *console.Conn) {
	// Force new prompt by issuing empty command.
	// Output is: \r\n\s*NAME#\s?
	out := strings.TrimSpace(conn.IssueCmd("", `#[ ]?`))
	out = strings.TrimSuffix(out, "#")
	if name != out {
		errlog.Abort("Wrong device name: %q, expected: %q", out, name)
	}
}

func (s *State) PrepareDevice(conn *console.Conn) {
	conn.SendCmd("configure terminal")
	// Don't slow down the system by logging to console.
	conn.SendCmd("no logging console")
	// Enable logging synchronous to get a fresh prompt after
	// a reload banner is shown.
	conn.SendCmd("line vty 0 15")
	conn.SendCmd("logging synchronous level all")
	// Needed for default route to work as expected.
	conn.SendCmd("ip subnet-zero")
	conn.SendCmd("ip classless")
	conn.SendCmd("end")
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

func (s *State) WriteMem(conn *console.Conn) {
	retries := 2
	for {
		out := conn.IssueCmd("write memory", `#[ ]?|\[confirm\]`)
		if strings.Contains(out, "Overwrite the previous NVRAM configuration") {
			out = conn.GetCmdOutput("")
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

func (s *State) IsValidOutput(cmd, out string) bool {
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

const reloadMinutes = 2

func (s *State) ScheduleReload(conn *console.Conn) {
	s.sendReloadCmd(false, conn)
}

func (s *State) ExtendReload(conn *console.Conn) {
	s.sendReloadCmd(true, conn)
}

func (s *State) sendReloadCmd(withDo bool, conn *console.Conn) {
	cmd := fmt.Sprintf("reload in %d", reloadMinutes)
	if withDo {
		cmd = "do " + cmd
	}
	out := conn.IssueCmd(cmd, `\[yes\/no\]:\ |\[confirm\]`)
	// System configuration has been modified. Save? [yes/no]:
	if strings.Contains(out, "[yes/no]") {
		// Leave our changes unsaved, to be sure that a reload
		// gets last good configuration.
		conn.IssueCmd("n", `\[confirm\]`)
	}
	// Confirm the reload with empty command, wait for the standard prompt.
	s.reloadActive = true
	conn.SendCmd("")
}

func (s *State) CancelReload(conn *console.Conn) {
	// Don't wait for standard prompt, but for banner message, which is
	// sent asynchronously.
	conn.IssueCmd("reload cancel", `--- SHUTDOWN ABORTED ---`)
	// Because of 'logging synchronous' we are sure to get another prompt.
	conn.WaitShort(`[#] ?$`)
	// Synchronize expect buffers with empty command.
	conn.SendCmd("")
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

func (s *State) StripReloadBanner(out string, conn *console.Conn,
) (string, bool) {
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
				out = conn.WaitShort(`[#] ?$`)
				out = conn.StripStdPrompt(out)
			} else if prefix != "" && strings.TrimSpace(postfix) == "" {
				// Try to read another prompt if banner is shown directly
				// behind current output.
				errlog.Info("Found banner after output, checking another prompt")
				if conn.TryPrompt() {
					errlog.Info("- Found prompt")
				}
			}
			matched, _ := regexp.MatchString(`SHUTDOWN in 0?0:01:00`, msg)
			return out, matched
		}
	}
	return out, false
}

// Remove definitions of banner lines from IOS config.
// banner xxx ^CC
// <lines>
// ^C
func (s *State) RemoveBanner(data []byte) []byte {
	rx := regexp.MustCompile(`^banner\s\S+\s+(.)\S`)
	i := 0
	j := 0
	var endBanner []byte = nil
	for {
		e := bytes.Index(data[i:], []byte("\n"))
		if e == -1 {
			j += copy(data[j:], data[i:])
			break
		}
		e++
		e += i
		line := data[i:e]
		i = e
		if endBanner != nil {
			if bytes.HasPrefix(line, endBanner) {
				endBanner = nil
			}
			continue
		}
		if m := rx.FindSubmatch(line); m != nil {
			endBanner = m[1]
			continue
		}
		j += copy(data[j:], line)
	}
	return data[:j]
}
