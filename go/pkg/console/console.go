package console

import (
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/hknutzen/Netspoc-Approve/go/pkg/codefiles"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/device"
	expect "github.com/tailscale/goexpect"
)

type Conn struct {
	con          *expect.GExpect
	promptRE     *regexp.Regexp
	Timeout      time.Duration
	ShortTimeout time.Duration
	log          *os.File
}

func GetSSHConn(spocFile, user string, cfg *device.Config, logLogin *os.File) (
	*Conn, error) {

	ip, pdp, err := codefiles.GetIPPDP(spocFile)
	if err != nil {
		return nil, err
	}
	cmd := []string{"ssh", "-l", user, ip}
	if pdp != "" && !isThisServer(pdp, cfg) {
		cmd = append(cmd,
			[]string{"-o", "ProxyCommand ssh " + pdp + " -W %h:%p"}...)
	}
	if simul := os.Getenv("SIMULATE_ROUTER"); simul != "" {
		cmd = strings.Fields(simul)
	}
	short := time.Duration(cfg.LoginTimeout) * time.Second
	con, _, err := expect.SpawnWithArgs(cmd, short, expect.PartialMatch(true))
	if err != nil {
		return nil, err
	}
	return &Conn{
		con:          con,
		log:          logLogin,
		Timeout:      time.Duration(cfg.Timeout) * time.Second,
		ShortTimeout: short,
	}, nil
}

// Check if ip is located on this server. Otherwise ip is used as proxy server.
func isThisServer(ip string, cfg *device.Config) bool {
	// If ServerIPList isn't configured, never use a proxy server.
	if len(cfg.ServerIPList) == 0 {
		return true
	}
	for _, serverIP := range cfg.ServerIPList {
		if ip == serverIP.String() {
			return true
		}
	}
	return false
}

func (c *Conn) SetLogFH(fh *os.File) {
	c.log = fh
}

func (c *Conn) logString(s string) {
	if fh := c.log; fh != nil {
		fh.Write([]byte(s))
	}
}

func (c *Conn) Close() {
	if c.con != nil {
		c.SetLogFH(nil)
		c.con.Send("exit\n")
	}
}

// Wait for prompt.
// Remove all "\r" characters in output for simplicity.
func (c *Conn) expectLog(prompt *regexp.Regexp, t time.Duration,
) (string, error) {
	out, _, err := c.con.Expect(prompt, t)
	out = strings.ReplaceAll(out, "\r\n", "\n")
	c.logString(out)
	return out, err
}

func (c *Conn) WaitLogin(prompt string) string {
	out, err := c.expectLog(regexp.MustCompile(prompt), c.ShortTimeout)
	if err != nil {
		device.Abort("while waiting for login prompt '%s': %v", prompt, err)
	}
	return out
}

func (c *Conn) WaitShort(prompt string) string {
	out, err := c.expectLog(regexp.MustCompile(prompt), c.ShortTimeout)
	if err != nil {
		device.Abort("while waiting for prompt '%s': %v", prompt, err)
	}
	return out
}

func (c *Conn) waitPrompt(re *regexp.Regexp) string {
	out, err := c.expectLog(re, c.Timeout)
	if err != nil {
		device.Abort("while waiting for prompt '%s': %v", re, err)
	}
	return out
}

func (c *Conn) TryPrompt() bool {
	// timeout == 0 => Just dump the buffer and exit.
	out, _, err := c.con.Expect(c.promptRE, 0)
	out = strings.ReplaceAll(out, "\r\n", "\n")
	c.logString(out)
	return err == nil
}

func (c *Conn) Send(cmd string) {
	c.con.Send(cmd + "\n")
}

func (c *Conn) IssueCmd(cmd, re string) string {
	c.Send(cmd)
	return c.waitPrompt(regexp.MustCompile(re))
}

func (c *Conn) SendCmd(cmd string) {
	c.Send(cmd)
	c.waitPrompt(c.promptRE)
}

func (c *Conn) GetCmdOutput(cmd string) string {
	c.Send(cmd)
	return c.StripEcho(cmd, c.GetOutput())
}

func (c *Conn) GetOutput() string {
	out := c.waitPrompt(c.promptRE)
	out = c.StripStdPrompt(out)
	return out
}

func (c *Conn) SetStdPrompt(p *regexp.Regexp) {
	c.promptRE = p
}

func (c *Conn) StripStdPrompt(s string) string {
	loc := c.promptRE.FindStringIndex(s)
	if loc == nil {
		device.Abort("Missing prompt '%s' in response:\n'%v'", c.promptRE, s)
	}
	i := loc[0]
	// Don't remove trailing "\n".
	return s[:i+1]
}

func (c *Conn) StripEcho(cmd, s string) string {
	cShort := cmd
	cmd += "\n"
	if len(s) < len(cmd) || s[:len(cmd)] != cmd {
		device.Abort("Got unexpected echo in response to '%s':\n%v", cShort, s)
	}
	return s[len(cmd):]
}
