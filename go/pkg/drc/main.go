package drc

import (
	"fmt"
	"os"
	"path"

	"github.com/hknutzen/Netspoc-Approve/go/pkg/asa"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/device"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/ios"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/linux"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/nsx"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/panos"
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
	fs.BoolP("quiet", "q", false, "No info messages")
	fs.BoolP("compare", "C", false, "Compare only")
	fs.StringP("logdir", "L", "", "Path for saving session logs")
	fs.StringP("LOGFILE", "", "", "Path to redirect STDERR")
	fs.StringP("user", "u", "", "Username for login to remote device")
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

	// Argument processing
	var netspocFile string
	args := fs.Args()
	switch len(args) {
	case 0:
		fallthrough
	default:
		fs.Usage()
		return 1
	case 2:
		netspocFile = args[1]
	case 1:
		netspocFile = args[0]
	}
	r := getRealDevice(netspocFile)
	if r == nil {
		return 1
	}
	return device.Main(r, fs)
}

// This function had to be separated from package "device" into this package,
// to prevent import loop in package "device".
func getRealDevice(fname string) device.RealDevice {
	info, _ := device.LoadInfoFile(fname)
	switch info.Model {
	case "ASA":
		return asa.Setup()
	case "IOS":
		return ios.Setup()
	case "Linux":
		return &linux.State{}
	case "NSX":
		return &nsx.State{}
	case "PAN-OS":
		return &panos.State{}
	default:
		fmt.Fprintf(os.Stderr, "ERROR>>> Unexpected model %q in file %s.info\n",
			info.Model, fname)
	}
	return nil
}
