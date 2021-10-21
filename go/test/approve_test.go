package approve_test

import (
	"github.com/hknutzen/Netspoc-Approve/go/pkg/panos"
	"github.com/hknutzen/Netspoc-Approve/go/test/capture"
	"github.com/hknutzen/Netspoc-Approve/go/test/tstdata"
	"gotest.tools/assert"
	"os"
	"path"
	"regexp"
	"strings"
	"testing"
)

var count int

func TestNetspoc(t *testing.T) {
	os.Unsetenv("LANG")
	count = 0
	runTestFiles(t)
	t.Logf("Checked %d assertions", count)
}

func runTestFiles(t *testing.T) {
	dataFiles := tstdata.GetFiles("../testdata")
	for _, file := range dataFiles {
		file := file // capture range variable
		t.Run(path.Base(file), func(t *testing.T) {
			l, err := tstdata.ParseFile(file)
			if err != nil {
				t.Fatal(err)
			}
			for _, descr := range l {
				descr := descr // capture range variable
				t.Run(descr.Title, func(t *testing.T) {
					runTest(t, descr)
				})
			}
		})
	}
}

func runTest(t *testing.T, d *tstdata.Descr) {

	if d.Todo {
		t.Skip("skipping TODO test")
	}

	// Run each test inside a fresh working directory,
	// where different subdirectories are created.
	workDir := t.TempDir()
	prevDir, _ := os.Getwd()
	defer func() { os.Chdir(prevDir) }()
	os.Chdir(workDir)

	// Initialize os.Args, add default options.
	os.Args = []string{"PROGRAM"}

	// Add more options.
	if d.Options != "" {
		options := strings.Fields(d.Options)
		os.Args = append(os.Args, options...)
	}

	// Prepare device file.
	deviceFile := "device"
	if err := os.WriteFile(deviceFile, []byte(d.Device), 0644); err != nil {
		t.Fatal(err)
	}
	os.Args = append(os.Args, deviceFile)

	// Prepare directory with files from Netspoc.
	codeDir := "code"
	tstdata.PrepareInDir(codeDir, d.Netspoc)
	os.Args = append(os.Args, path.Join(codeDir, "router"))

	// Add other params to command line.
	if d.Params != "" {
		os.Args = append(os.Args, strings.Fields(d.Params)...)
	}
	if d.Param != "" {
		os.Args = append(os.Args, d.Param)
	}

	if d.ShowDiag {
		os.Setenv("SHOW_DIAG", "1")
	} else {
		os.Unsetenv("SHOW_DIAG")
	}

	// Call main function.
	var status int
	var stdout string
	stderr := capture.Capture(&os.Stderr, func() {
		stdout = capture.Capture(&os.Stdout, func() {
			//status = capture.CatchPanic(panos.Main)
			status = panos.Main()
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
		// Join following line if it is indented.
		re := regexp.MustCompile(`\n +`)
		expected = re.ReplaceAllString(expected, "")
		countEq(t, expected, stdout)
	}
}

func countEq(t *testing.T, expected, got string) {
	count++
	assert.Equal(t, expected, got)
}
