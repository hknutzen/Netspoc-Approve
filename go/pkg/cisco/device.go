package cisco

import (
	"errors"
	"regexp"
	"strings"

	"github.com/hknutzen/Netspoc-Approve/go/pkg/device"
)

func (s *State) LoginEnable(pass string, cfg *device.Config) {
	var bannerLines string
	conn := s.Conn
	out := conn.WaitLogin(`(?i)password:|\(yes/no.*\)\?`)
	if strings.HasSuffix(out, "?") {
		out = conn.IssueCmd("yes", `(?i)password:`)
	}
	bannerLines += out
	// Look for prompt. Ignore prompt lines with whitespace or multiple
	// hash that may occur in lines of banner.
	waitPrompt := func(enter, suffix string) bool {
		stdPrompt := `\r\n\r?[^#> ]+[>#] ?$`
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
				device.Abort("Authentication for enable mode failed")
			}
		}
	} else if !strings.HasSuffix(out, "#") {
		device.Abort("Authentication failed")
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

func (s *State) checkBanner(lines string, cfg *device.Config) {
	if rx := cfg.CheckBanner; rx != nil && rx.FindStringIndex(lines) == nil {
		s.errUnmanaged =
			[]error{errors.New("Missing banner at NetSPoC managed device")}
	}
}

func (s *State) GetErrUnmanaged() []error {
	return s.errUnmanaged
}
