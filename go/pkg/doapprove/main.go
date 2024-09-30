package doapprove

import (
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"strings"
	"time"

	"github.com/hknutzen/Netspoc-Approve/go/pkg/device"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/program"
	"github.com/spf13/pflag"
)

func Main() int {
	fs := pflag.NewFlagSet(os.Args[0], pflag.ContinueOnError)
	// Setup custom usage function.
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr,
			"Usage: %s [options] approve|compare DEVICE\n%s",
			os.Args[0], fs.FlagUsages())
	}
	brief := fs.BoolP("brief", "b", false,
		"Suppress message about unreachable device")
	if err := fs.Parse(os.Args[1:]); err != nil {
		if err == pflag.ErrHelp {
			return 1
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		fs.Usage()
		return 1
	}
	args := fs.Args()
	if len(args) != 2 {
		fs.Usage()
		return 1
	}
	action := args[0]
	devName := args[1]

	// Load config file 'netspoc-approve'.
	cfg, err := program.LoadConfig()
	if err != nil {
		return abort("%v", err)
	}
	// Get directory of current policy.
	base := cfg.NetspocDir
	policy, err := os.Readlink(path.Join(base, "current"))
	if err != nil {
		return abort("Can't get 'current' policy directory: %v", err)
	}
	dir := path.Join(base, policy)

	codeFile := path.Join(dir, "code", devName)
	code6File := path.Join(dir, "code/ipv6", devName)
	if !(fileExists(codeFile) || fileExists(code6File)) {
		return abort("unknown device %q", devName)
	}

	// Get arguments and run approve / compare.
	logDir := path.Join(dir, "log")
	logFile := path.Join(logDir, devName)
	isCompare := action == "compare"
	switch action {
	case "compare":
		logFile += ".compare"
	case "approve":
		logFile += ".drc"
	default:
		fs.Usage()
		return 1
	}
	lockFH, err := device.SetLock(devName, cfg.LockfileDir)
	if lockFH != nil {
		defer lockFH.Close()
	}
	if err != nil {
		return abort("%v", err)
	}
	hLog, err := getHistoryLogger(cfg, devName)
	if err != nil {
		return abort("can't %v", err)
	}
	hLog.Println("START:", strings.Join(os.Args[1:], " "))
	hLog.Println("POLICY:", policy)
	var warnings, errors, changed, failed bool
	stat := device.ApproveOrCompare(
		isCompare, codeFile, cfg, logDir, logFile, false)
	if stat != 0 {
		failed = true
		errors = true
	}

	// Check result and print errors messages.
	data, err := os.ReadFile(logFile)
	if err != nil {
		return abort("can't %v", err)
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "ERROR>>>") {
			errors = true
			if *brief &&
				strings.HasPrefix(line, "ERROR>>> while waiting for login prompt") {
				continue
			}
		} else if strings.HasPrefix(line, "WARNING>>>") {
			warnings = true
		} else if strings.HasPrefix(line, "comp: ***") {
			changed = true
		} else {
			continue
		}
		if *brief {
			fmt.Printf("%s:%s\n", devName, line)
		} else {
			fmt.Println(line)
		}
		hLog.Println("RES:", line)
	}

	// Update status file.
	if dir := cfg.StatusDir; dir != "" {
		if isCompare {
			if !errors {
				setCompareStatus(dir, devName, policy, changed)
			}
		} else {
			result := "OK"
			if errors {
				result = "***ERRORS***"
			} else if warnings {
				result = "***WARNINGS***"
			}
			setApproveStatus(dir, devName, policy, result)
		}
	}

	okMsg := "OK"
	if failed {
		okMsg = "FAILED"
	}
	if !*brief && (failed || warnings || errors || changed) {
		fmt.Fprintf(os.Stderr, "%s, details in %s\n", okMsg, logFile)
	}

	hLog.Println("END:", okMsg)

	if failed {
		return 1
	} else {
		return 0
	}
}

func getHistoryLogger(cfg *program.Config, devName string) (*log.Logger, error) {
	logFH := io.Discard
	if dir := cfg.HistoryDir; dir != "" {
		fname := path.Join(dir, devName)
		fh, err := os.OpenFile(fname, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, err
		}
		logFH = fh
	}
	prefix := myTimeNow().Format("2006 01 02 15:04:05 ")
	return log.New(logFH, prefix, 0), nil
}

func myTimeNow() time.Time {
	if v := os.Getenv("TEST_TIME"); v != "" {
		t, err := time.Parse("2006-Jan-02 15:04:05", v)
		if err != nil {
			panic(err)
		}
		return t
	}
	return time.Now()
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func abort(format string, args ...interface{}) int {
	fmt.Fprintf(os.Stderr, "Error: "+format+"\n", args...)
	return 1
}
