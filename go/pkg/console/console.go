package console

import (
	"os"
	"regexp"
	"strings"
	"time"

	expect "github.com/google/goexpect"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/device"
)

type Conn struct {
	con          *expect.GExpect
	prompt       string
	promptRE     *regexp.Regexp
	Timeout      time.Duration
	ShortTimeout time.Duration
	log          *os.File
}

func ConnectSSH(user, ip string, cfg *device.Config, logFH *os.File) (
	*Conn, error) {

	short := time.Duration(cfg.LoginTimeout) * time.Second
	con, _, err := expect.SpawnWithArgs([]string{"ssh", "-l", user, ip}, short,
		expect.PartialMatch(true))
	if err != nil {
		return nil, err
	}
	return &Conn{
		con:          con,
		log:          logFH,
		Timeout:      time.Duration(cfg.Timeout) * time.Second,
		ShortTimeout: short,
	}, nil
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

func (c *Conn) expectLog(re *regexp.Regexp, t time.Duration) string {
	out, _, err := c.con.Expect(re, t)
	c.logString(out)
	if err != nil {
		device.Abort("while waiting for %s: %v", re, err)
	}
	return out
}

func (c *Conn) ShortWait(re string) string {
	return c.expectLog(regexp.MustCompile(re), c.ShortTimeout)
}

func (c *Conn) IssueCmd(cmd, re string) string {
	c.con.Send(cmd + "\n")
	return c.expectLog(regexp.MustCompile(re), c.Timeout)
}

func (c *Conn) SendCmd(cmd string) {
	c.con.Send(cmd + "\n")
	c.expectLog(c.promptRE, c.Timeout)
}

func (c *Conn) GetCmdOutput(cmd string) string {
	cmd += "\n"
	c.con.Send(cmd)
	out := c.expectLog(c.promptRE, c.Timeout)
	out = strings.TrimPrefix(out, cmd)
	return strings.TrimSuffix(out, c.prompt)
}

func (c *Conn) SetStdPrompt(p string) {
	c.prompt = p
	c.promptRE = regexp.MustCompile(regexp.QuoteMeta(p))
}
