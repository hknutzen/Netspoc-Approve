package approve_test

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/drc"
	"github.com/hknutzen/Netspoc-Approve/go/test/capture"
	"github.com/hknutzen/testtxt"
)

var count int

func TestApprove(t *testing.T) {
	os.Unsetenv("LANG")
	count = 0
	runTestFiles(t)
	t.Logf("Checked %d assertions", count)
}

type descr struct {
	Title    string
	Device   string
	Scenario string
	Netspoc  string
	Options  string
	Setup    string
	Output   string
	Warning  string
	Error    string
	Todo     bool
}

func runTestFiles(t *testing.T) {
	dataFiles, _ := filepath.Glob("../testdata/*.t")
	for _, file := range dataFiles {
		base := path.Base(file)
		prefix, _, _ := strings.Cut(strings.TrimSuffix(base, ".t"), "_")
		prefix = strings.ToUpper(prefix)
		if prefix == "LINUX" {
			prefix = "Linux"
		}
		t.Run(base, func(t *testing.T) {
			var l []descr
			if err := testtxt.ParseFile(file, &l); err != nil {
				t.Fatal(err)
			}
			for _, descr := range l {
				t.Run(descr.Title, func(t *testing.T) {
					runTest(t, descr, prefix)
				})
			}
		})
	}
}

func runTest(t *testing.T, d descr, devType string) {
	if d.Netspoc == "" {
		t.Fatal("missing =NETSPOC= in test")
	}
	if d.Output == "" && d.Warning == "" && d.Error == "" {
		t.Fatal("missing =OUTPUT|WARNING|ERROR= in test")
	}
	if d.Error != "" && d.Warning != "" {
		t.Fatalf("must not define =ERROR= together with =WARNING=")
	}
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
	os.Args = []string{"drc", "-q"}

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
		// Prepare credentials file. Declare user as system user.
		credentialsFile := "credentials"
		id := "admin"
		line := "* " + id + " secret\n"
		if err := os.WriteFile(credentialsFile, []byte(line), 0644); err != nil {
			t.Fatal(err)
		}
		lockDir := t.TempDir()
		// Prepare config file.
		configFile := ".netspoc-approve"
		config := fmt.Sprintf(`
netspocdir = %s
lockfiledir = %s
checkbanner = NetSPoC
systemuser = %s
aaa_credentials = %s
timeout = 1
`, workDir, lockDir, id, credentialsFile)
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
	testtxt.PrepareInDir(t, codeDir, deviceName, d.Netspoc)
	// Add info file if not given above.
	infoFile := path.Join(codeDir, deviceName+".info")
	info6File := path.Join(codeDir, "ipv6", deviceName+".info")
	if _, err := os.Stat(infoFile); err != nil {
		if _, err := os.Stat(info6File); err != nil {
			info := fmt.Sprintf(`
{
 "model": "%s",
 "name_list": [ "%s" ],
 "ip_list": [ "10.1.13.33" ]
}
`, devType, deviceName)
			if err := os.WriteFile(infoFile, []byte(info), 0644); err != nil {
				t.Fatal(err)
			}
		}
	}
	os.Args = append(os.Args, path.Join(codeDir, deviceName))

	// Execute shell commands to setup error cases in working directory.
	if d.Setup != "" {
		t.Cleanup(func() {
			// Make files writeable again if =SETUP= commands have
			// revoked file permissions.
			exec.Command("chmod", "-R", "u+rwx", workDir).Run()
		})
		cmd := exec.Command("bash", "-e")
		stdin, err := cmd.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		io.WriteString(stdin, "cd '"+workDir+"'\n")
		io.WriteString(stdin, d.Setup)
		stdin.Close()

		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("executing =SETUP=: %v\n%s", err, out)
		}
	}

	// Call main function.
	var status int
	var stdout string
	stderr := capture.Capture(&os.Stderr, func() {
		stdout = capture.Capture(&os.Stdout, func() {
			status = capture.CatchPanic(func() int {
				return drc.Main()
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
			checkFilesAndStdout(t, d.Output, workDir, stdout)
			return
		}
		// Join following line if it is indented.
		re := regexp.MustCompile(`\n +`)
		expected = re.ReplaceAllString(expected, "")
		countEq(t, expected, stdout)
	}
}

// Check stdout and files in dir against specification.
// Blocks of expected output are split by single lines of dashes,
// followed by file name.
// First optional block contains expected standard output.
func checkFilesAndStdout(t *testing.T, spec, dir, stdout string) {
	re := regexp.MustCompile(`(?ms)^-+[ ]*\S+[ ]*\n`)
	il := re.FindAllStringIndex(spec, -1)

	if il == nil || il[0][0] != 0 {
		expect := spec
		if il != nil {
			expect = spec[:il[0][0]]
		}
		t.Run("STDOUT", func(t *testing.T) {
			countEq(t, expect, stdout)
		})
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
