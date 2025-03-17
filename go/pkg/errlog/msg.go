package errlog

import (
	"fmt"
	"net/url"
	"os"
	"path"
	"strings"

	"github.com/hknutzen/Netspoc-Approve/go/pkg/mytime"
)

var Quiet bool

func Info(format string, args ...any) {
	if !Quiet {
		fmt.Fprintf(stderrLog, format+"\n", args...)
	}
}

func Warning(format string, args ...any) {
	PrintWithMarker("WARNING>>> ", format, args...)
}

func DoLog(fh *os.File, s string) {
	if fh != nil {
		if strings.HasPrefix(s, "http") || strings.HasPrefix(s, "action=") {
			s, _ = url.QueryUnescape(s)
		}
		fmt.Fprintln(fh, s)
	}
}

var stderrLog *os.File

func SetStderrLog(fname string) {
	stderrLog = os.Stderr
	if fname != "" {
		MoveLogFile(fname)
		fh, err := CreateWithPath(fname)
		if err != nil {
			Abort("Can't %v", err)
		}
		stderrLog = fh
	}
}

func PrintWithMarker(m string, format string, args ...any) {
	out := fmt.Sprintf(format, args...)
	out = strings.TrimSuffix(out, "\n")
	out = strings.ReplaceAll(out, "\n", "\n"+m)
	fmt.Fprintln(stderrLog, m+out)
}

// Rename existing logfile.
func MoveLogFile(fname string) {
	if _, err := os.Stat(fname); err == nil {
		os.Rename(fname, fmt.Sprintf("%s.%d", fname, mytime.Now().Unix()))
	}
}

func CreateWithPath(fname string) (*os.File, error) {
	dir := path.Dir(fname)
	err := os.MkdirAll(dir, 0755)
	if err != nil {
		return nil, err
	}
	return os.OpenFile(fname, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
}
