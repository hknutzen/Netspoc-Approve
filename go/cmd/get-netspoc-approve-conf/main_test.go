package main

import (
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hknutzen/Netspoc-Approve/go/test/capture"
	"github.com/hknutzen/testtxt"
)

type descr struct {
	Title   string
	Config  string
	Options string
	Output  string
	Warning string
	Error   string
	Todo    bool
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
	if d.Output == "" && d.Warning == "" && d.Error == "" {
		t.Fatal("missing =OUTPUT|WARNING|ERROR= in test")
	}
	if d.Error != "" && d.Warning != "" {
		t.Fatalf("must not define =ERROR= together with =WARNING=")
	}
	if d.Todo {
		t.Skip("skipping TODO test")
	}
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

	configFile := ".netspoc-approve"
	if err := os.WriteFile(configFile, []byte(d.Config), 0644); err != nil {
		t.Fatal(err)
	}

	// Set HOME directory, because configFile is searched there.
	os.Setenv("HOME", workDir)

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
		if d.Warning != "" || stderr != "" {
			if d.Warning == "NONE" {
				d.Warning = ""
			}
			t.Run("Warning", func(t *testing.T) {
				eq(t, d.Warning, stderr)
			})
		} else if d.Output == "" {
			t.Error("Missing output specification")
			return
		}
	} else {
		if d.Error == "" {
			t.Error("Unexpected failure")
		}
		eq(t, d.Error, stderr)
	}
	if d.Output != "" {
		eq(t, d.Output, stdout)
	}
}

func eq(t *testing.T, expected, got string) {
	if d := cmp.Diff(expected, got); d != "" {
		t.Error(d)
	}
}
