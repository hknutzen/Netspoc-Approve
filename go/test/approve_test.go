package approve_test

import (
	"fmt"
	"os"
	"os/user"
	"path"
	"regexp"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/asa"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/device"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/nsx"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/panos"
	"github.com/hknutzen/Netspoc-Approve/go/test/capture"
	"github.com/hknutzen/Netspoc-Approve/go/test/tstdata"
)

var count int

func TestApprove(t *testing.T) {
	os.Unsetenv("LANG")
	count = 0
	runTestFiles(t)
	t.Logf("Checked %d assertions", count)
}

func runTestFiles(t *testing.T) {
	dataFiles := tstdata.GetFiles("../testdata")
	for _, file := range dataFiles {
		file := file // capture range variable
		base := path.Base(file)
		prefix, _, _ := strings.Cut(strings.TrimSuffix(base, ".t"), "_")
		t.Run(base, func(t *testing.T) {
			l, err := tstdata.ParseFile(file)
			if err != nil {
				t.Fatal(err)
			}
			for _, descr := range l {
				var realDev device.RealDevice
				switch prefix {
				case "asa":
					realDev = asa.Setup()
				case "nsx":
					realDev = &nsx.State{}
				case "panos":
					realDev = &panos.State{}
				default:
					t.Fatal(fmt.Errorf("Unexpected test file %s with prefix '%s'",
						base, prefix))
				}
				descr := descr // capture range variable
				t.Run(descr.Title, func(t *testing.T) {
					runTest(t, descr, realDev, strings.ToUpper(prefix))
				})
			}
		})
	}
}

func runTest(t *testing.T,
	d *tstdata.Descr, realDev device.RealDevice, deviceType string) {

	if d.Todo {
		t.Skip("skipping TODO test")
	}

	deviceName := "router"

	// Run each test inside a fresh working directory,
	// where different subdirectories are created.
	workDir := t.TempDir()
	prevDir, _ := os.Getwd()
	defer func() { os.Chdir(prevDir) }()
	os.Chdir(workDir)

	// Initialize os.Args, add default options.
	os.Args = []string{"PROGRAM", "-q"}

	// Add more options.
	if d.Options != "" {
		options := strings.Fields(d.Options)
		os.Args = append(os.Args, options...)
	}

	os.Unsetenv("SIMULATE_ROUTER")
	if sc := d.Scenario; sc != "" {
		// Prepare simulation command.
		// Tell approve command to use simulation by setting environment variable.
		scenarioFile := "scenario"
		if err := os.WriteFile(scenarioFile, []byte(sc), 0644); err != nil {
			t.Fatal(err)
		}
		cmd := prevDir + "/../testdata/simulate-cisco.pl " + deviceName + " " +
			path.Join(workDir, scenarioFile)
		os.Setenv("SIMULATE_ROUTER", cmd)
		// Prepare credentials file. Declare current user as system user.
		credentialsFile := "credentials"
		u, _ := user.Current()
		id := u.Username
		line := "* " + id + " secret\n"
		if err := os.WriteFile(credentialsFile, []byte(line), 0644); err != nil {
			t.Fatal(err)
		}
		// Prepare config file.
		configFile := ".netspoc-approve"
		config := fmt.Sprintf(`
netspocdir = %s
lockfiledir = %s
checkbanner = NetSPoC
systemuser = %s
aaa_credentials = %s
timeout = 1
`, workDir, workDir, id, credentialsFile)
		if err := os.WriteFile(configFile, []byte(config), 0644); err != nil {
			t.Fatal(err)
		}
		// Set HOME directory, because configFile is searched there.
		os.Setenv("HOME", workDir)
		// Add option for logging.
		os.Args = append(os.Args, []string{"-L", workDir}...)
	} else {
		// Prepare file with device configuration.
		deviceFile := "device"
		if err := os.WriteFile(deviceFile, []byte(d.Device), 0644); err != nil {
			t.Fatal(err)
		}
		os.Args = append(os.Args, deviceFile)
	}

	// Prepare directory with files from Netspoc.
	codeDir := "code"
	tstdata.PrepareInDir(codeDir, d.Netspoc)
	// Add info file if not given above.
	infoFile := path.Join(codeDir, deviceName+".info")
	if _, err := os.Stat(infoFile); err != nil {
		info := fmt.Sprintf(`
{
 "model": "%s",
 "name_list": [ "%s" ],
 "ip_list": [ "10.1.13.33" ]
}
`, deviceType, deviceName)
		if err := os.WriteFile(infoFile, []byte(info), 0644); err != nil {
			t.Fatal(err)
		}
	}
	os.Args = append(os.Args, path.Join(codeDir, deviceName))

	// Add other params to command line.
	if d.Params != "" {
		os.Args = append(os.Args, strings.Fields(d.Params)...)
	}
	if d.Param != "" {
		os.Args = append(os.Args, d.Param)
	}

	os.Unsetenv("SHOW_DIAG")
	if d.ShowDiag {
		os.Setenv("SHOW_DIAG", "1")
	}

	// Call main function.
	var status int
	var stdout string
	stderr := capture.Capture(&os.Stderr, func() {
		stdout = capture.Capture(&os.Stdout, func() {
			status = capture.CatchPanic(func() int {
				return device.Main(realDev)
			})
		})
	})

	// Check result.
	if status == 0 {
		if d.Error != "" {
			t.Error("Unexpected success")
			return
		}
		if d.Warning != "" || stderr != "" {
			if d.Warning == "NONE" {
				d.Warning = ""
			}
			t.Run("Warning", func(t *testing.T) {
				countEq(t, d.Warning, stderr)
			})
		} else if d.Output == "" {
			t.Error("Missing output specification")
			return
		}
	} else {
		if d.Error == "" {
			t.Error("Unexpected failure")
		}
		countEq(t, d.Error, stderr)
	}
	if d.Output != "" {
		expected := d.Output
		if expected == "NONE" {
			expected = ""
		}
		if d.Scenario != "" {
			checkFiles(t, d.Output, workDir)
			return
		}
		// Join following line if it is indented.
		re := regexp.MustCompile(`\n +`)
		expected = re.ReplaceAllString(expected, "")
		countEq(t, expected, stdout)
	}
}

// Check files in dir against specification.
// Blocks of expected output are split by single lines of dashes,
// followed by file name.
func checkFiles(t *testing.T, spec, dir string) {
	re := regexp.MustCompile(`(?ms)^-+[ ]*\S+[ ]*\n`)
	il := re.FindAllStringIndex(spec, -1)

	if il == nil || il[0][0] != 0 {
		t.Fatal("Output spec must start with dashed line")
	}
	for i, p := range il {
		marker := spec[p[0] : p[1]-1] // without trailing "\n"
		pName := strings.Trim(marker, "- ")
		if pName == "" {
			t.Fatal("Missing file name in dashed line of output spec")
		}
		start := p[1]
		end := len(spec)
		if i+1 < len(il) {
			end = il[i+1][0]
		}
		block := spec[start:end]

		t.Run(pName, func(t *testing.T) {
			data, err := os.ReadFile(path.Join(dir, pName))
			if err != nil {
				t.Fatal(err)
			}
			// Add \n at end of file
			if l := len(data); l > 0 && data[l-1] != '\n' {
				data = append(data, '\n')
			}
			countEq(t, block, string(data))
		})
	}
}

func countEq(t *testing.T, expected, got string) {
	count++
	if d := cmp.Diff(expected, got); d != "" {
		t.Error(d)
	}
}
