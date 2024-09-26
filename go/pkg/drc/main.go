package drc

import (
	"fmt"
	"os"
	"path"

	"github.com/hknutzen/Netspoc-Approve/go/pkg/device"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/myerror"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/program"
	"github.com/spf13/pflag"
)

var version = "devel"

func Main() int {
	fs := pflag.NewFlagSet(os.Args[0], pflag.ContinueOnError)

	// Setup custom usage function.
	fs.Usage = func() {
		prog := path.Base(os.Args[0])
		fmt.Fprintf(os.Stderr,
			"Usage: %s [options] FILE1\n"+
				"     : %s [-q] FILE1 FILE2\n", prog, prog)
		fs.PrintDefaults()
	}

	// Command line flags
	isCompare := fs.BoolP("compare", "C", false, "Compare only")
	logDir := fs.StringP("logdir", "L", "", "Path for saving session logs")
	logFile := fs.StringP("LOGFILE", "", "", "Path to redirect STDERR")
	user := fs.StringP("user", "u", "", "Username for login to remote device")
	quiet := fs.BoolP("quiet", "q", false, "No info messages")
	showVer := fs.BoolP("version", "v", false, "Show version")
	if err := fs.Parse(os.Args[1:]); err != nil {
		if err == pflag.ErrHelp {
			return 1
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		fs.Usage()
		return 1
	}
	if *showVer {
		fmt.Fprintf(os.Stderr, "version %s\n", version)
		return 0
	}
	myerror.Quiet = *quiet

	// Argument processing
	args := fs.Args()
	switch len(args) {
	case 0:
		fallthrough
	default:
		fs.Usage()
		return 1
	case 1:
		cfg, err := program.LoadConfig()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return 1
		}
		cfg.User = *user
		fname := args[0]
		device.SetLock(fname, cfg.LockfileDir)
		return device.ApproveOrCompare(*isCompare, fname, cfg, *logDir, *logFile)
	case 2:
		q := fs.Changed("quiet")
		n := fs.NFlag()
		if q && n > 1 || !q && n > 0 {
			fs.Usage()
			return 1
		}
		return device.CompareFiles(args[0], args[1])
	}
}
