package console

import (
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/Netflix/go-expect"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/device"
)

type Conn struct {
	con          *expect.Console
	Prompt       string
	ShortTimeout time.Duration
	cmd          *exec.Cmd
	log          *logWriter
}

type logWriter struct {
	fh *os.File
}

func (w *logWriter) Write(p []byte) (n int, err error) {
	if fh := w.fh; fh != nil {
		return w.fh.Write(p)
	}
	return len(p), nil
}

func ConnectSSH(user, ip string, cfg *device.Config, logFH *os.File) (
	*Conn, error) {

	log := &logWriter{fh: logFH}
	con, err := expect.NewConsole(
		expect.WithStdout(log),
		expect.WithDefaultTimeout(time.Duration(cfg.Timeout)*time.Second),
	)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command("ssh", "-l", user, ip)
	cmd.Stdin = con.Tty()
	cmd.Stdout = con.Tty()
	cmd.Stderr = con.Tty()
	// New process needs to be the process leader and control of a tty
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid:  true,
		Setctty: true,
	}
	err = cmd.Start()
	if err != nil {
		return nil, err
	}
	return &Conn{
		con:          con,
		cmd:          cmd,
		log:          log,
		ShortTimeout: time.Duration(cfg.LoginTimeout) * time.Second,
	}, nil
}

func (c *Conn) SetLogFH(fh *os.File) {
	c.log.fh = fh
}

func (c *Conn) Close() {
	c.SetLogFH(nil)
	c.con.Send("exit\n")
	c.cmd.Wait()
	c.con.Close()
}

func (c *Conn) ShortWait(re string) string {
	out, err := c.con.Expect(
		expect.RegexpPattern(re),
		expect.WithTimeout(c.ShortTimeout))
	if err != nil {
		device.Abort("while waiting for %s: %v", re, err)
	}
	return out
}

func (c *Conn) IssueCmd(cmd, re string) string {
	c.con.Send(cmd + "\n")
	out, err := c.con.Expect(expect.RegexpPattern(re))
	if err != nil {
		device.Abort("%v", err)
	}
	return out
}

func (c *Conn) SendCmd(cmd string) {
	c.con.Send(cmd + "\n")
	_, err := c.con.Expect(expect.String(c.Prompt))
	if err != nil {
		device.Abort("%v", err)
	}
}

func (c *Conn) GetCmdOutput(cmd string) string {
	cmd += "\n"
	c.con.Send(cmd)
	out, err := c.con.Expect(expect.String(c.Prompt))
	if err != nil {
		device.Abort("%v", err)
	}
	out = strings.TrimPrefix(out, cmd)
	return strings.TrimSuffix(out, c.Prompt)
}
