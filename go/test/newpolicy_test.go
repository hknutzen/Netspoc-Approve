package approve_test

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

var dir string

func TestNewpolicy(t *testing.T) {
	if _, err := exec.LookPath("netspoc"); err != nil {
		t.Skip("skipping test on CI server")
	}
	// Set up PATH, such that commands in Netspoc-Approve/bin are found.
	approveBin, _ := filepath.Abs("../../bin")
	os.Setenv("PATH", fmt.Sprintf("%s:%s", approveBin, os.Getenv("PATH")))

	// Create working directory; set as current directory for relative paths.
	// Set as HOME directory for config file .netspoc-approve.
	dir = t.TempDir()
	os.Chdir(dir)
	os.Setenv("HOME", dir)

	setupBin()
	setupNetspoc(`-- config
quiet = 1;
-- topology
network:n1 = { ip = 10.1.1.0/24; }
`)
	// Let newpolicy.sh wait on 'git clone'.
	waitFH, _ := os.OpenFile("do-wait", os.O_CREATE|os.O_RDONLY, 0644)
	syscall.Flock(int(waitFH.Fd()), syscall.LOCK_EX)

	// Start first test.
	j1 := startNewpolicy()
	waitForDir("policies/next")
	j2 := startNewpolicy()
	changeNetspoc(`-- topology
network:n1 = { ip = 10.1.1.0/24; }  # Comment
`)
	j3 := startNewpolicy()
	// Let 'git clone' proceed.
	waitFH.Close()
	waitFinished()
	j4 := startNewpolicy()
	waitFinished()
	checkNewpolicy(t, j1, "Start and show",
		`Processing scheduled
Current policy is p1
`)
	checkNewpolicy(t, j2, "Already running",
		`Processing scheduled
Process is already running
Current policy is p1
`)
	checkNewpolicy(t, j3, "After locked commit",
		`Processing scheduled
Process is already running
Current policy is p1
`)
	checkNewpolicy(t, j4, "After commit",
		`Processing scheduled
Current policy is p2
`)
	runNewpolicy(t, "Up to date",
		`Processing scheduled
Nothing changed
Current policy is p2
`)
	changeNetspoc(`-- topology
network:n1 = { ip = 10.1.1.0/24; }  BAD_SYNTAX
`)
	runNewpolicy(t, "Bad commit is reverted",
		`Processing scheduled
Current policy is p3
`)
	checkMail(t, "Mails on bad commit",
		`mail -s Newpolicy failed! user@example.com,admin1@example.com
commit <HASH>
Author: Test User <user@example.com>

    test
---
Error: Typed name expected at line 1 of policies/next/src/topology, near "10.1.1.0/24; }  --HERE-->BAD_SYNTAX"
Aborted
Newest changeset failed to compile
Left current policy as 'p2'
--END--
mail -s Your commit has been reverted user@example.com,admin1@example.com
commit <HASH>
Author: Test User <user@example.com>

    test
--END--
`)
	changeNetspoc(`-- topology
network:n1 = { ip = 10.1.1.0/24; }  BAD_SYNTAX1
`)
	changeNetspoc(`-- topology
network:n1 = { ip = 10.1.1.0/24; }  BAD_SYNTAX2
`)
	runNewpolicy(t, "Two bad commits can't be reverted",
		`Processing scheduled
Error: Typed name expected at line 1 of policies/next/src/topology, near "10.1.1.0/24; }  --HERE-->BAD_SYNTAX1"
Aborted
Newest changeset failed to compile
Left current policy as 'p3'
`)
	checkMail(t, "Mails on two bad commits",
		`mail -s Newpolicy failed! user@example.com,admin1@example.com
commit <HASH>
Author: Test User <user@example.com>

    test
---
Error: Typed name expected at line 1 of policies/next/src/topology, near "10.1.1.0/24; }  --HERE-->BAD_SYNTAX2"
Aborted
Newest changeset failed to compile
Left current policy as 'p3'
--END--
mail -s Your commit has been reverted user@example.com,admin1@example.com
commit <HASH>
Author: Test User <user@example.com>

    test
--END--
mail -s Newpolicy failed! ,admin1@example.com
commit <HASH>
Author: System User <>

    Revert "test"
---
Error: Typed name expected at line 1 of policies/next/src/topology, near "10.1.1.0/24; }  --HERE-->BAD_SYNTAX1"
Aborted
Newest changeset failed to compile
Left current policy as 'p3'
--END--
`)
	changeNetspoc(`-- topology
network:n1 = { ip = 10.1.1.0/24; }  # Change1
`)
	// Remove symlink and check if policy number is restored from file
	// src/POLICY.
	os.Remove("policies/current")
	runNewpolicy(t, "Restore policy number from file",
		`Processing scheduled
Current policy is p4
`)
	// Take larger value from POLICY file
	changeNetspoc(`-- topology
network:n1 = { ip = 10.1.1.0/24; }  # Change2
-- POLICY
# p123
`)
	runNewpolicy(t, "Take larger policy number from file",
		`Processing scheduled
Current policy is p124
`)
	// Take larger value from symbolic link
	changeNetspoc(`-- topology
network:n1 = { ip = 10.1.1.0/24; }  # Change3
-- POLICY
# p9
`)
	runNewpolicy(t, "Take larger policy number from symlink",
		`Processing scheduled
Current policy is p125
`)
}

func setupNetspoc(input string) {
	// Prevent warnings from git.
	exec.Command("git", "config", "--global", "user.name", "System User").Run()
	exec.Command("git", "config", "--global", "user.email", "").Run()
	exec.Command("git", "config", "--global", "init.defaultBranch", "master").Run()
	exec.Command("git", "config", "--global", "pull.rebase", "true").Run()

	tmp := path.Join(dir, "tmp-git")
	os.Mkdir(tmp, 0700)
	prepareDir(tmp, input)
	os.Chdir(tmp)
	// Initialize git repository.
	exec.Command("git", "init", "--quiet").Run()
	exec.Command("git", "add", ".").Run()
	exec.Command("git", "commit", "-m", "initial").Run()
	os.Chdir(dir)
	// Checkout into bare directory
	bare := path.Join(dir, "netspoc.git")
	exec.Command("git", "clone", "--quiet", "--bare", tmp, bare).Run()
	os.RemoveAll(tmp)
	// Checkout into directory 'netspoc'
	netspoc := path.Join(dir, "netspoc")
	exec.Command("git", "clone", "--quiet", bare, netspoc).Run()
	os.Chdir(netspoc)
	exec.Command("git", "config", "--local", "user.name", "Test User").Run()
	exec.Command("git", "config", "--local", "user.email", "user@example.com").Run()
	os.Chdir(dir)

	// Create config file .netspoc-approve for newpolicy
	os.Mkdir("policies", 0700)
	os.Mkdir("lock", 0700)
	os.WriteFile(".netspoc-approve",
		[]byte(fmt.Sprintf(`
basedir = %s
netspoc_git = file://%s
admin_emails = admin1@example.com
`, dir, bare)), 0600)
}

func changeNetspoc(input string) {
	os.Chdir(dir)
	os.Chdir("netspoc")
	exec.Command("git", "pull", "--quiet").Run()
	prepareDir(".", input)
	exec.Command("git", "add", "--all").Run()
	exec.Command("git", "commit", "-m", "test").Run()
	exec.Command("git", "push", "--quiet").Run()
	os.Chdir(dir)
}

// Fill directory with files from input.
// Parts of input are marked by single lines of dashes
// followed by a filename.
func prepareDir(dir, input string) {
	re := regexp.MustCompile(`(?ms)^-+[ ]*\S+[ ]*\n`)
	il := re.FindAllStringIndex(input, -1)
	if il == nil {
		log.Fatal("Missing filename before first input block")
	}
	if il[0][0] != 0 {
		log.Fatal("Missing file marker in first line of input:\n" + input)
	}
	for i, p := range il {
		marker := input[p[0] : p[1]-1] // without trailing "\n"
		pName := strings.Trim(marker, "- ")
		file := path.Join(dir, pName)
		start := p[1]
		end := len(input)
		if i+1 < len(il) {
			end = il[i+1][0]
		}
		if err := os.MkdirAll(path.Dir(file), 0755); err != nil {
			log.Fatalf("Can't create directory for '%s': %v", file, err)
		}
		data := input[start:end]
		if err := os.WriteFile(file, []byte(data), 0644); err != nil {
			log.Fatal(err)
		}
	}
}

func setupBin() {
	myBin := path.Join(dir, "my-bin")
	os.Mkdir(myBin, 0700)

	// Install version of git, that can be controlled to wait after
	// completion.
	origGit, _ := exec.Command("which", "git").Output()
	origGit = bytes.TrimSpace(origGit)
	os.WriteFile(path.Join(myBin, "git"),
		[]byte(fmt.Sprintf(`#!/bin/bash
%s "$@"
status=$?

# Wait when "git clone" is called inside newpolicy-daemon.
if echo $* | grep -q '^clone'; then
   flock %s/do-wait -c true 2>/dev/null
fi

exit $status
`, string(origGit), dir)), 0700)

	// Install dummy version of 'mail' command.
	os.WriteFile(path.Join(myBin, "mail"),
		[]byte(fmt.Sprintf(`#!/bin/sh
{ echo mail "$@"; cat; echo --END--; } >> %s/mail
`, dir)), 0700)
	os.Setenv("PATH", fmt.Sprintf("%s/my-bin:%s", dir, os.Getenv("PATH")))
}

type npJob struct {
	cmd *exec.Cmd
	out io.Reader
}

func startNewpolicy() npJob {
	cmd := exec.Command("newpolicy")
	outFH, err := cmd.StdoutPipe()
	if err != nil {
		panic(err)
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		panic(err)
	}
	return npJob{cmd, outFH}
}

func checkNewpolicy(t *testing.T, j npJob, title, expected string) {
	t.Run(title, func(t *testing.T) {
		data, _ := io.ReadAll(j.out)
		got := string(data)
		// Normalize error messages.
		got = strings.ReplaceAll(got, dir+"/", "")
		if err := j.cmd.Wait(); err != nil {
			t.Error(err)
		}
		if d := cmp.Diff(expected, got); d != "" {
			t.Error(d)
		}
	})
}

func runNewpolicy(t *testing.T, title, expected string) {
	j := startNewpolicy()
	checkNewpolicy(t, j, title, expected)
}

func waitFinished() {
	fh, err := os.OpenFile("policies/LOCK", os.O_CREATE|os.O_RDONLY, 0644)
	if err != nil {
		panic(err)
	}
	syscall.Flock(int(fh.Fd()), syscall.LOCK_SH)
	fh.Close()
}

func waitForDir(d string) {
	for {
		if _, err := os.Stat(path.Join(dir, d)); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
}

var commitRe = regexp.MustCompile(`commit [0-9a-f]{40}`)

func checkMail(t *testing.T, title, expected string) {
	t.Run(title, func(t *testing.T) {
		name := path.Join(dir, "mail")
		data, _ := os.ReadFile(name)
		got := string(data)
		// Normalize error messages.
		got = commitRe.ReplaceAllString(got, "commit <HASH>")
		got = strings.ReplaceAll(got, dir+"/", "")
		os.Remove(name)
		if d := cmp.Diff(expected, string(got)); d != "" {
			t.Error(d)
		}
	})
}
