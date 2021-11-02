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
	conf, err := getConfig(path)
	if err != nil {
		return nil, err
	}
	rawPath := path + ".raw"
	if _, err := os.Stat(rawPath); err == nil {
		raw, err := getConfig(rawPath)
		if err != nil {
			return nil, err
		}
		return conf, mergeRaw(conf, raw)
	} else {
		return conf, nil
	}
}

func getConfig(path string) (*PanConfig, error) {
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

func mergeRaw(c, r *PanConfig) error {
	return processVsysPairs(c, r, func(v1, v2 *panVsys) error {
		// Add complete vsys from raw.
		if v1 == nil {
			d1 := c.Entries[0]
			d1.Vsys = append(d1.Vsys, v2)
			return nil
		}
		// Vsys isn't changed from raw.
		if v2 == nil {
			return nil
		}
		// Add elements of vsys from raw.
		v1.Addresses = append(v1.Addresses, v2.Addresses...)
		v1.AddressGroups = append(v1.AddressGroups, v2.AddressGroups...)
		v1.Services = append(v1.Services, v2.Services...)
		// Add rules.
		// Rules are prepended per default.
		// Rules with attribute <APPEND> are appended,
		// but before last "drop" rule with same From/to pair.
		// Analyze From/To pairs.
		var top []*panRule
		type zones struct {
			from string
			to   string
		}
		bot := make(map[zones][]*panRule)
		for _, r := range v2.Rules {
			if r.Append == nil {
				top = append(top, r)
			} else {
				if len(r.From) != 1 || len(r.To) != 1 {
					return fmt.Errorf(
						"Must not use rule '%s' with multiple zones in From/To in raw",
						r.Name)
				}
				z := zones{r.From[0], r.To[0]}
				bot[z] = append(bot[z], r)
			}
		}
		v1.Rules = append(top, v1.Rules...)
		for z, l := range bot {
			var last *panRule
			idx := -1
			for i, r := range v1.Rules {
				if len(r.From) == 1 && r.From[0] == z.from &&
					len(r.To) == 1 && r.To[0] == z.to {

					idx = i
					last = r
				}
				if idx == -1 {
					return fmt.Errorf(
						"Can't APPEND to unknown rule with From=%s, To=%s",
						z.from, z.to)
				}
				if last.Action == "drop" {
					v1.Rules = append(v1.Rules[:idx], append(l, v1.Rules[idx:]...)...)
				} else {
					v1.Rules = append(v1.Rules, l...)
				}
			}
		}
		return nil
	})
}

func (s *state) compareCommon(c1, c2 *PanConfig) ([]string, error) {
	var cmds []string
	err := processVsysPairs(c1, c2, func(v1, v2 *panVsys) error {
		if v1 == nil {
			return fmt.Errorf(
				"Unknown name '%s' in VSYS of device configuration", v2.Name)
		}
		if v2 == nil {
			return nil
		}
		device := c1.Entries[0].Name
		devicePath := "/config/devices/entry" + nameAttr(device)
		xPath := devicePath + "/vsys/entry" + nameAttr(v2.Name)
		l, err := diffConfig(v1, v2, xPath)
		if err != nil {
			return fmt.Errorf("%v of vsys '%s'", err, v2.Name)
		}
		cmds = append(cmds, l...)
		return nil
	})
	return cmds, err
}

func processVsysPairs(c1, c2 *PanConfig, f func(v1, v2 *panVsys) error) error {
	getDevVsysMap := func(c *PanConfig) (*panDevice, map[string]*panVsys, error) {
		l := c.Entries
		if len(l) != 1 {
			return nil, nil, fmt.Errorf(
				"Expected exactly one device entry in '%s' configuration", c.source)
		}
		d := l[0]
		m := make(map[string]*panVsys)
		for i, v := range d.Vsys {
			name := v.Name
			if name == "" {
				return nil, nil, fmt.Errorf(
					"Missing name in %d. VSYS of '%s' configuration", c.source, i+1)
			}
			if _, ok := m[name]; ok {
				return nil, nil, fmt.Errorf(
					"Duplicate name '%s' in VSYS of '%s' configuration",
					c.source, name)
			}
			m[name] = v
		}
		return d, m, nil
	}
	d1, m1, err := getDevVsysMap(c1)
	if err != nil {
		return err
	}
	d2, m2, err := getDevVsysMap(c2)
	if err != nil {
		return err
	}
	if d1.Name != "" && d2.Name != "" && d1.Name != d2.Name {
		return fmt.Errorf("Different device names: %s='%s', %s='%s'",
			c1.source, d1.Name, c2.source, d2.Name)
	}
	for _, v1 := range d1.Vsys {
		v2 := m2[v1.Name]
		if err := f(v1, v2); err != nil {
			return err
		}
	}
	for _, v2 := range d2.Vsys {
		if m1[v2.Name] == nil {
			if err := f(nil, v2); err != nil {
				return err
			}
		}
	}
	return nil
}

func nameAttr(n string) string {
	return "[@name='" + n + "']"
}

func textAttr(n string) string {
	return "[text()='" + n + "']"
}

func showErr(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "Error: "+format+"\n", args...)
}
