package approve_test

import (
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/doapprove"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/drc"
	"github.com/hknutzen/Netspoc-Approve/go/test/capture"
	"github.com/hknutzen/Netspoc-Approve/go/test/httpsim"
	"github.com/hknutzen/testtxt"
)

func talksHTTPS(model string) bool {
	switch model {
	case "NSX", "PAN-OS":
		return true
	}
	return false
}

var count int

func TestApprove(t *testing.T) {
	os.Unsetenv("LANG")
	count = 0
	runTestFiles(t)
	t.Logf("Checked %d assertions", count)
}

type descr struct {
	Title     string
	Device    string
	Scenario  string
	Netspoc   string
	Options   string
	Params    string
	Setup     string
	Output    string
	Warning   string
	Error     string
	DoApprove bool
	Todo      bool
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
	if d.DoApprove && d.Scenario == "" {
		t.Fatalf("must use =DO_APPROVE= only together with =SCENARIO=")
	}
	if d.Params != "" && d.Scenario == "" {
		t.Fatalf("must use =PARAMS= only together with =SCENARIO=")
	}
	if d.Todo {
		t.Skip("skipping TODO test")
	}

	deviceName := "router"

	// Run each test inside a fresh working directory,
	// where different subdirectories are created.
	workDir := t.TempDir()
	prevDir, _ := os.Getwd()
	defer os.Chdir(prevDir)
	os.Chdir(workDir)

	var codeDir string

	// Call command "drc" or "do-approve".
	// Initialize os.Args, add default options.
	var mainFunc func() int
	if d.Scenario == "" || !d.DoApprove {
		mainFunc = drc.Main
		os.Args = []string{"drc", "-q"}
		codeDir = "code"
	} else {
		mainFunc = doapprove.Main
		os.Args = []string{"do-approve"}
		policiesDir := path.Join(workDir, "policies")
		p1Dir := path.Join(policiesDir, "p1")
		os.MkdirAll(p1Dir, 0755)
		os.Symlink("p1", path.Join(policiesDir, "current"))
		codeDir = path.Join(p1Dir, "code")
	}
	// Add more options.
	if d.Options != "" {
		options := strings.Fields(d.Options)
		os.Args = append(os.Args, options...)
	}

	// Prepare directory with files from Netspoc.
	codeFile := path.Join(codeDir, deviceName)
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

	os.Unsetenv("SIMULATE_ROUTER")
	os.Unsetenv("TEST_TIME")
	var httpServer *httptest.Server
	if sc := d.Scenario; sc != "" {
		// Set simulated time in tests.
		os.Setenv("TEST_TIME", "2024-Sep-29 16:19:50")
		// Prepare simulation.
		// Tell approve command to use simulation by setting environment variable.
		if talksHTTPS(devType) {
			httpServer = httpsim.NewTLSServer(t, sc)
			defer httpServer.Close()
			os.Setenv("SIMULATE_ROUTER", httpServer.URL)
		} else {
			scenarioFile := "scenario"
			if err := os.WriteFile(scenarioFile, []byte(sc), 0644); err != nil {
				t.Fatal(err)
			}
			// Use in-process simulator by pointing SIMULATE_ROUTER at the scenario file
			os.Setenv("SIMULATE_ROUTER", path.Join(workDir, scenarioFile))
		}
		// Prepare credentials file. Declare user as system user.
		credentialsFile := path.Join(workDir, "credentials")
		line := "* admin secret\n"
		os.WriteFile(credentialsFile, []byte(line), 0644)
		// Prepare subdirectories.
		os.Mkdir(path.Join(workDir, "lock"), 0755)
		os.Mkdir(path.Join(workDir, "status"), 0755)
		os.Mkdir(path.Join(workDir, "history"), 0755)
		// Prepare config file.
		configFile := ".netspoc-approve"
		config := fmt.Sprintf(`
basedir = %s
checkbanner = NetSPoC
systemuser = admin
timeout = 1
`,
			workDir)
		if err := os.WriteFile(configFile, []byte(config), 0644); err != nil {
			t.Fatal(err)
		}
		// Set HOME directory, because configFile is searched there.
		os.Setenv("HOME", workDir)

		if p := d.Params; p != "" {
			if p == "NONE" {
				p = ""
			}
			os.Args = append(os.Args, strings.Fields(p)...)
		} else if d.DoApprove {
			os.Args = append(os.Args, "compare", deviceName)
		} else {
			// Add option for logging.
			os.Args = append(os.Args, "-L", workDir, codeFile)
		}
	} else {
		// Prepare file with device configuration.
		deviceFile := "device"
		if err := os.WriteFile(deviceFile, []byte(d.Device), 0644); err != nil {
			t.Fatal(err)
		}
		os.Args = append(os.Args, deviceFile, codeFile)
	}

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
				return mainFunc()
			})
		})
	})

	// Normalize error messages.
	stderr = strings.ReplaceAll(stderr, workDir+"/", "")
	stdout = strings.ReplaceAll(stdout, workDir+"/", "")
	if httpServer != nil {
		stderr = strings.ReplaceAll(stderr, httpServer.URL, "TESTSERVER")
	}

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
		if d.Error == "NONE" {
			d.Error = ""
		}
		countEq(t, d.Error, stderr)
	}
	if d.Output != "" {
		if d.Output == "NONE" {
			d.Output = ""
		}
		if d.Scenario != "" {
			checkFilesAndStdout(t, d.Output, workDir, stdout, httpServer)
			return
		}
		// Join following line if it is indented.
		re := regexp.MustCompile(`\n +`)
		d.Output = re.ReplaceAllString(d.Output, "")
		countEq(t, d.Output, stdout)
	}
}

// Check stdout and files in dir against specification.
// Blocks of expected output are split by single lines of dashes,
// followed by file name.
// First optional block contains expected standard output.
func checkFilesAndStdout(
	t *testing.T, spec, dir, stdout string, srv *httptest.Server,
) {
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
			s := string(data)
			// Normalize error messages.
			s = strings.ReplaceAll(s, dir+"/", "")
			if srv != nil {
				s = strings.ReplaceAll(s, srv.URL, "TESTSERVER")
			}
			countEq(t, block, s)
		})
	}
}

func countEq(t *testing.T, expected, got string) {
	count++
	if d := cmp.Diff(expected, got); d != "" {
		t.Error(d)
	}
}
