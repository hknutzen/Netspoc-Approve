package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hknutzen/Netspoc-Approve/go/test/capture"
	"github.com/hknutzen/testtxt"
)

type descr struct {
	Title  string
	Input  string
	Setup  string
	Output string
	Error  string
}

func TestMain(t *testing.T) {
	dataFiles, _ := filepath.Glob("testdata/*.t")
	for _, file := range dataFiles {
		base := path.Base(file)
		t.Run(base, func(t *testing.T) {
			var l []descr
			if err := testtxt.ParseFile(file, &l); err != nil {
				t.Fatal(err)
			}
			for _, d := range l {
				t.Run(d.Title, func(t *testing.T) {
					runTest(t, d)
				})
			}
		})
	}
}

func runTest(t *testing.T, d descr) {
	workDir := t.TempDir()

	policies := filepath.Join(workDir, "policies")
	os.Mkdir(policies, 0744)
	os.Mkdir(filepath.Join(workDir, "status"), 0744)

	// Initialize os.Args, add default options.
	os.Args = []string{"missing-approve"}

	// Prepare config file.
	configFile := filepath.Join(workDir, ".netspoc-approve")
	config := fmt.Sprintln("basedir = ", workDir)
	if err := os.WriteFile(configFile, []byte(config), 0644); err != nil {
		t.Fatal(err)
	}

	// Set HOME directory, because configFile is searched there.
	os.Setenv("HOME", workDir)

	// Prepare directory with input files.
	testtxt.PrepareInDir(t, workDir, "INPUT", d.Input)

	// Set 'current' policy to 'p2'.
	os.Symlink("p2", path.Join(policies, "current"))

	// Execute shell commands to change content of working directory.
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
				return Main()
			})
		})
	})

	// Check result.
	stderr = strings.ReplaceAll(stderr, workDir+"/", "")
	if status == 0 {
		if d.Error != "" {
			t.Error("Unexpected success")
			return
		}
		if stderr != "" {
			t.Error("Unexpected stderr:", stderr)
		}
		if d.Output == "" {
			t.Error("Missing output specification")
		}
	} else {
		if d.Error == "" {
			t.Error("Unexpected failure")
		}
		eq(t, d.Error, stderr)
	}
	if expected := d.Output; expected != "" {
		if expected == "NONE" {
			expected = ""
		}
		eq(t, expected, stdout)
	}
}

func eq(t *testing.T, expected, got string) {
	if d := cmp.Diff(expected, got); d != "" {
		t.Error(d)
	}
}
