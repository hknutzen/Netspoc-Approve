package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"slices"
	"strings"

	"github.com/hknutzen/Netspoc-Approve/go/pkg/device"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/program"
	"github.com/spf13/pflag"
)

/*
do-approve

Description:
Wrapper to approve and compare current policy.
Locks current device, does history logging and writes status file.

https://github.com/hknutzen/Netspoc-Approve
(c) 2024 by Heinz Knutzen <heinz.knutzen@gmail.com>

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

func main() {
	os.Exit(Main())
}

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

	// Change to directory of current policy.
	cfg, err := program.LoadConfig()
	if err != nil {
		return abort("%v", err)
	}
	base := cfg.NetspocDir
	policy, err := os.Readlink(path.Join(base, "current"))
	if err != nil {
		return abort("Can't get 'current' policy directory: %v", err)
	}
	dir := path.Join(base, policy)
	if err := os.Chdir(dir); err != nil {
		return abort("Can't cd to %s: %v", dir, err)
	}

	codeFile := path.Join("code", devName)
	code6File := path.Join("code/ipv6", devName)
	if !(fileExists(codeFile) || fileExists(code6File)) {
		return abort("unknown device %s", devName)
	}

	// Get arguments and run approve / compare.
	logDir := "log"
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
	device.SetLock(devName, cfg.LockfileDir)
	hLog, err := getHistoryLogger(cfg, devName)
	if err != nil {
		return abort("can't %v", err)
	}
	hLog.Println("ARGS:", strings.Join(os.Args[1:], " "))
	hLog.Println("START:", action)
	hLog.Println("POLICY:", policy)
	var warnings, errors, changed, failed bool
	stat := device.ApproveOrCompare(isCompare, codeFile, cfg, logDir, logFile)
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
	silent := *brief && slices.ContainsFunc(lines, func(line string) bool {
		return strings.HasPrefix(line, "ERROR>>> while waiting for login prompt")
	})
	for _, line := range lines {
		if strings.HasPrefix(line, "WARNING>>>") {
			warnings = true
		} else if strings.HasPrefix(line, "ERROR>>>") {
			errors = true
		} else if strings.HasPrefix(line, "comp: ***") {
			changed = true
		} else {
			continue
		}
		if !silent {
			if *brief {
				fmt.Printf("%s:%s\n", devName, line)
			} else {
				fmt.Println(line)
			}
			hLog.Println("RES:", line)
		}
	}

	// Update status file.
	if dir := cfg.StatusDir; dir != "" {
		if isCompare {
			setCompareStatus(dir, devName, policy, changed)
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
		fmt.Fprintf(os.Stderr, "%s, details in %s",
			okMsg, path.Join(base, policy, logFile))
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
		f, err := os.OpenFile(fname, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, err
		}
		logFH = f
	}
	return log.New(logFH, "", log.LstdFlags), nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func abort(format string, args ...interface{}) int {
	fmt.Fprintf(os.Stderr, "Error: "+format+"\n", args...)
	return 1
}
