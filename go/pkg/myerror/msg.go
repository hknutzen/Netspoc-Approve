package myerror

import (
	"fmt"
	"os"
	"path"
	"strings"
	"time"
)

var Quiet bool

func Info(format string, args ...interface{}) {
	if !Quiet {
		fmt.Fprintf(StderrLog, format+"\n", args...)
	}
}

func Warning(format string, args ...interface{}) {
	PrintWithMarker("WARNING>>> ", format, args...)
}

var StderrLog *os.File

func SetStderrLog(fname string) {
	StderrLog = os.Stderr
	if fname != "" {
		MoveLogFile(fname)
		fh, err := CreateWithPath(fname)
		if err != nil {
			Abort("Can't %v", err)
		}
		StderrLog = fh
	}
}

func PrintWithMarker(m string, format string, args ...interface{}) {
	out := fmt.Sprintf(format, args...)
	out = strings.TrimSuffix(out, "\n")
	out = strings.ReplaceAll(out, "\n", "\n"+m)
	fmt.Fprintln(StderrLog, m+out)
}

// Rename existing logfile.
func MoveLogFile(fname string) {
	if _, err := os.Stat(fname); err == nil {
		os.Rename(fname, fmt.Sprintf("%s.%d", fname, time.Now().Unix()))
	}
}

func CreateWithPath(fname string) (*os.File, error) {
	dir := path.Dir(fname)
	err := os.MkdirAll(dir, 0755)
	if err != nil {
		return nil, err
	}
	return os.Create(fname)
}
