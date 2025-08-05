package cisco

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/hknutzen/Netspoc-Approve/go/pkg/codefiles"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/console"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/errlog"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/program"
)

type state struct {
	realCisco
	parser
	conn         *console.Conn
	errUnmanaged []error
	deviceCfg    *config
	spocCfg      *config
	changes      []string
	subCmdOf     string
}

type realCisco interface {
	GetCmdInfo() string
	RemoveBanner(data []byte) []byte
	SetTerminal(*console.Conn)
	CheckDeviceName(string, *console.Conn)
	PrepareDevice(*console.Conn)
	ScheduleReload(*console.Conn)
	ExtendReload(*console.Conn)
	CancelReload(*console.Conn)
	StripReloadBanner(string, *console.Conn) (string, bool)
	IsValidOutput(string, string) bool
	WriteMem(*console.Conn)
}

func Setup(d realCisco) *state {
	s := &state{realCisco: d}
	s.setupParser(s.GetCmdInfo())
	return s
}

func (s *state) LoadDevice(
	spocFile string, cfg *program.Config, logLogin, logConfig *os.File) error {

	user, pass, err := cfg.GetUserPass(codefiles.GetHostname(spocFile))
	if err != nil {
		return err
	}
	s.conn, err = console.GetSSHConn(spocFile, user, cfg, logLogin)
	if err != nil {
		return err
	}
	hostName := codefiles.GetHostname(spocFile)
	s.loginEnable(pass, cfg)
	s.SetTerminal(s.conn)
	s.logVersion()
	s.CheckDeviceName(hostName, s.conn)

	s.conn.SetLogFH(logConfig)
	errlog.Info("Requesting device config")
	out := s.conn.GetCmdOutput("sh run")
	errlog.Info("Got device config")
	s.deviceCfg, err = s.parseConfig([]byte(out), "<device>")
	errlog.Info("Parsed device config")
	if err != nil {
		err = fmt.Errorf("While reading device: %v", err)
	}
	return err
}

func (s *state) loginEnable(pass string, cfg *program.Config) {
	var bannerLines string
	conn := s.conn
	out := conn.WaitLogin(`(?i)password:|\(yes/no.*\)\?`)
	if strings.HasSuffix(out, "?") {
		out = conn.IssueCmd("yes", `(?i)password:`)
	}
	bannerLines += out
	// Look for prompt. Ignore prompt lines with whitespace or multiple
	// hash that may occur in lines of banner.
	waitPrompt := func(enter, suffix string) bool {
		stdPrompt := `\n\r?[^#> ]+[>#] ?$`
		out = conn.IssueCmd(enter, `(?i)password:|`+stdPrompt)
		bannerLines += out
		out = strings.TrimSuffix(out, " ")
		return strings.HasSuffix(out, suffix)
	}
	if waitPrompt(pass, ">") {
		// Enter enable mode.
		if !waitPrompt("enable", "#") {
			// Enable password required.
			// Use login password as enable password.
			if !waitPrompt(pass, "#") {
				errlog.Abort("Authentication for enable mode failed")
			}
		}
	} else if !strings.HasSuffix(out, "#") {
		errlog.Abort("Authentication failed")
	}

	// Force new prompt by issuing empty command.
	// Use this prompt because of performance impact of standard prompt.
	out = conn.IssueCmd("", `#[ ]?`)
	i := strings.LastIndex(out, "\n")
	// Current prompt: "\n\rHOSTNAME# "
	p := out[i:]
	// Prompt may vary before terminating "# "
	i = strings.LastIndex(p, "#")
	rx := regexp.MustCompile(
		regexp.QuoteMeta(p[:i]) + `\S*` + regexp.QuoteMeta(p[i:]))
	conn.SetStdPrompt(rx)
	s.checkBanner(bannerLines, cfg)
}

func (s *state) logVersion() {
	s.conn.GetCmdOutput("sh ver")
}

func (s *state) checkBanner(lines string, cfg *program.Config) {
	if rx := cfg.CheckBanner; rx != nil && rx.FindStringIndex(lines) == nil {
		s.errUnmanaged =
			[]error{errors.New("Missing banner at NetSPoC managed device")}
	}
}

func (s *state) GetErrUnmanaged() []error {
	return s.errUnmanaged
}

func (s *state) ApplyCommands(logFh *os.File) error {
	s.conn.SetLogFH(logFh)
	s.PrepareDevice(s.conn)
	func() {
		s.ScheduleReload(s.conn)
		defer s.CancelReload(s.conn)
		s.conn.SendCmd("configure terminal")
		defer s.conn.SendCmd("end")
		for _, chg := range s.changes {
			s.cmd(chg)
		}
	}()
	s.WriteMem(s.conn)
	return nil
}

// Send 1 or 2 commands in one data packet to device.
// No output expected from commands.
func (s *state) cmd(cmd string) {
	c1, c2, _ := strings.Cut(cmd, "\n")
	s.conn.Send(cmd)
	needReload := false
	check := func(ci string) {
		out := s.conn.GetOutput()
		out, needReload = s.StripReloadBanner(out, s.conn)
		out = s.conn.StripEcho(ci, out)
		if out != "" {
			if !s.IsValidOutput(ci, out) {
				errlog.Abort("Got unexpected output from '%s':\n%s", ci, out)
			}
		}
	}
	check(c1)
	if c2 != "" {
		check(c2)
	}
	if needReload {
		s.ExtendReload(s.conn)
	}
}

func (s *state) CloseConnection() {
	if c := s.conn; c != nil {
		s.conn.Close()
	}
}
