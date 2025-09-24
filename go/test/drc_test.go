package approve_test

import (
	"io"
	"os"
	"path"
	"strings"
	"sync"
	"testing"

	"github.com/creack/pty"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/drc"
	"github.com/hknutzen/testtxt"
)

func TestDrc(t *testing.T) {
	workDir := t.TempDir()
	prevDir, _ := os.Getwd()
	defer func() { os.Chdir(prevDir) }()
	os.Chdir(workDir)
	testtxt.PrepareFileOrDir(t, workDir, inFiles)
	// Use in-process simulator with the scenario file prepared above.
	os.Setenv("SIMULATE_ROUTER", path.Join(workDir, "scenario"))
	os.Setenv("HOME", workDir)
	pty, tty, err := pty.Open()
	if err != nil {
		t.Fatalf("pty.Open: %v", err)
	}
	oldOut := os.Stdout
	oldErr := os.Stderr
	oldIn := os.Stdin
	defer func() { os.Stdout = oldOut; os.Stderr = oldErr; os.Stdin = oldIn }()
	os.Stdout = tty
	os.Stderr = tty
	os.Stdin = tty
	os.Args = []string{
		"drc", "-q", "-C", "-u", "adm", "-L", workDir, "code/router"}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { drc.Main(); tty.Close(); pty.Close(); wg.Done() }()
	var buf = make([]byte, 256)
	nr, _ := pty.Read(buf)
	got := string(buf[:nr])
	expected := "Enter password"
	if !strings.HasPrefix(got, expected) {
		t.Fatalf("Expected %q but got %q", expected, got)
	}
	io.WriteString(pty, "adm-secret\n")
	wg.Wait()
	checkFilesAndStdout(t, outFiles, workDir, "", nil)
}

var inFiles = `--scenario
Enter Password:<!>
banner motd  managed by NetSPoC
router>
# sh ver
Cisco IOS Software, C2900 Software (C2900-UNIVERSALK9-M), Version 15.1(4)M4,
--credentials
* adm adm-secret
--.netspoc-approve
basedir = .
checkbanner = NetSPoC
systemuser = none
timeout = 1
--code/router
ip route 10.0.0.0 255.0.0.0 10.11.22.33
--code/router.info
{
 "model": "IOS",
 "name_list": [ "router" ],
 "ip_list": [ "10.1.13.33" ]
}
`

var outFiles = `--router.login
Enter Password:adm-secret

banner motd  managed by NetSPoC
router>enable
router#
router#term len 0
router#term width 512
router#sh ver
Cisco IOS Software, C2900 Software (C2900-UNIVERSALK9-M), Version 15.1(4)M4,
router#
router#
--router.cmp
ip route 10.0.0.0 255.0.0.0 10.11.22.33
`
