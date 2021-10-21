package panos

import (
	"fmt"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/device"
	"github.com/spf13/pflag"
	"os"
)

type state struct {
	compare bool
	config  *device.Config
}

func Main() int {
	fs := pflag.NewFlagSet(os.Args[0], pflag.ContinueOnError)

	// Setup custom usage function.
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr,
			"Usage: %s [options] FILE1 FILE2\n", os.Args[0])
		fs.PrintDefaults()
	}

	// Command line flags
	//quiet := fs.BoolP("quiet", "q", false, "No info messages")
	compare := fs.BoolP("compare", "C", false, "Compare only")
	//user := fs.StringP("user", "u", "", "Username for login to remote device")
	if err := fs.Parse(os.Args[1:]); err != nil {
		if err == pflag.ErrHelp {
			return 1
		}
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		fs.Usage()
		return 1
	}

	s := new(state)
	s.config = device.LoadConfig()
	s.compare = *compare

	// Argument processing
	args := fs.Args()
	switch len(args) {
	case 0:
		fallthrough
	default:
		fs.Usage()
		return 1
	case 2:
		return s.compareFiles(args[0], args[1])
		/*case 1:
		if *compare {
			return s.compare(args[0])
		} else {
			return s.approve(args[0])
		}*/
	}
}

func (s *state) compareFiles(path1, path2 string) int {
	conf1, err := loadSpoc(path1)
	if err != nil {
		showErr("%v", err)
		return 1
	}
	conf2, err := loadSpoc(path2)
	if err != nil {
		showErr("%v", err)
		return 1
	}
	cmds, err := s.compareCommon(conf1, conf2)
	if err != nil {
		showErr("%v", err)
		return 1
	}
	for _, c := range cmds {
		fmt.Println(c)
	}
	return 0
}

func loadSpoc(path string) (*PanConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("Can't %v", err)
	}
	c, err := parseXML(data)
	if err != nil {
		return nil, fmt.Errorf("Can't parse %s: %v", path, err)
	}
	return c, nil
}

func (s *state) compareCommon(conf1, conf2 *PanConfig) ([]string, error) {
	l1 := conf1.Entries
	if len(l1) != 1 {
		return nil, fmt.Errorf(
			"Expected exactly one device entry in device configuration")
	}
	l2 := conf2.Entries
	if len(l2) != 1 {
		return nil, fmt.Errorf(
			"Expected exactly one device entry in netspoc configuration")
	}
	d1 := l1[0]
	d2 := l2[0]
	device := d1.Name
	if device != d2.Name {
		return nil, fmt.Errorf(
			"Different device names: device='%s', netspoc='%s'", device, d2.Name)
	}
	devicePath := "/config/devices/entry" + nameAttr(device)
	m := make(map[string]*panVsys)
	for i, v := range d1.Vsys {
		name := v.Name
		if name == "" {
			return nil, fmt.Errorf(
				"Missing name in %d. VSYS of device configuration", i+1)
		}
		if _, ok := m[name]; ok {
			return nil, fmt.Errorf(
				"Duplicate name '%s' in VSYS of device configuration", name)
		}
		m[name] = v
	}
	var cmds []string
	for _, v2 := range d2.Vsys {
		name := v2.Name
		v1 := m[name]
		if v1 == nil {
			return nil, fmt.Errorf(
				"Unknown name '%s' in VSYS of device configuration", name)
		}
		xPath := devicePath + "/vsys/entry" + nameAttr(name)
		l := diffConfig(v1, v2, xPath)
		cmds = append(cmds, l...)
	}
	return cmds, nil
}

func nameAttr(n string) string {
	return "[@name='" + n + "']"
}

func showErr(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "Error: "+format+"\n", args...)
}
