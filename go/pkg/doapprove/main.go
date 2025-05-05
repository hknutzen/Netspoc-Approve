package doapprove

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/hknutzen/Netspoc-Approve/go/pkg/device"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/mytime"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/program"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/status"
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
	policies := path.Join(cfg.BaseDir, "policies")
	dir, err := filepath.EvalSymlinks(path.Join(policies, "current"))
	if err != nil {
		return abort("Can't get 'current' policy directory: %v", err)
	}
	policy := filepath.Base(dir)

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
	lockFH, err := device.SetLock(devName, cfg)
	if lockFH != nil {
		defer lockFH.Close()
	}
	if err != nil {
		return abort("%v", err)
	}
	hLog, err := openHistoryLog(cfg, devName)
	if err != nil {
		return abort("can't %v", err)
	}
	logHistory(hLog, "START:", strings.Join(os.Args[1:], " "))
	logHistory(hLog, "POLICY:", policy)
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
	for _, ln := range lines {
		if strings.HasPrefix(ln, "ERROR>>>") {
			errors = true
		} else if strings.HasPrefix(ln, "WARNING>>>") {
			warnings = true
		} else if strings.HasPrefix(ln, "comp: ***") {
			changed = true
		} else {
			continue
		}
		if *brief {
			isTimeout :=
				strings.HasPrefix(ln, "ERROR>>> while waiting for login prompt") &&
					strings.Contains(ln, "timer expired")
			if !isTimeout {
				fmt.Printf("%s:%s\n", devName, ln)
			}
		} else {
			fmt.Println(ln)
		}
		logHistory(hLog, "RES:", ln)
	}

	// Update status file.
	if isCompare {
		status.SetCompare(cfg, devName, policy, changed || errors)
	} else {
		status.SetApprove(cfg, devName, policy, failed)
	}

	okMsg := "OK"
	if failed {
		okMsg = "FAILED"
	}
	if !*brief && (failed || warnings || errors || changed) {
		fmt.Fprintf(os.Stderr, "%s, details in %s\n", okMsg, logFile)
	}

	logHistory(hLog, "END:", okMsg)

	if failed {
		return 1
	} else {
		return 0
	}
}

func openHistoryLog(cfg *program.Config, devName string) (*os.File, error) {
	historyDir := path.Join(cfg.BaseDir, "history")
	os.MkdirAll(historyDir, 0755)
	fname := path.Join(historyDir, devName)
	fh, err := os.OpenFile(fname, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	return fh, nil
}

func logHistory(fh *os.File, args ...any) {
	prefix := mytime.Now().Format("2006 01 02 15:04:05")
	fmt.Fprintln(fh, slices.Concat([]any{prefix}, args)...)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func abort(format string, args ...any) int {
	fmt.Fprintf(os.Stderr, "Error: "+format+"\n", args...)
	return 1
}
