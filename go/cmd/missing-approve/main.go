package main

/*
missing-approve -- Show devices with missing approve.

https://github.com/hknutzen/Netspoc-Approve
(c) 2024 by Heinz Knutzen <heinz.knutzen@gmail.com>

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

import (
	"compress/bzip2"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/hknutzen/Netspoc-Approve/go/pkg/program"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/status"
)

func main() {
	os.Exit(Main())
}

func Main() int {
	cfg, err := program.LoadConfig()
	if err != nil {
		return abort("%v", err)
	}
	base := cfg.NetspocDir
	policyDir, err := filepath.EvalSymlinks(path.Join(base, "current"))
	if err != nil {
		return abort("Can't get 'current' policy directory: %v", err)
	}
	policy := filepath.Base(policyDir)
	codeDir := path.Join(policyDir, "code")
	statusDir := cfg.StatusDir

	// Ignore ipv6 file, if ipv4 file already has been processed.
	seen := make(map[string]bool)
	err =
		filepath.WalkDir(codeDir, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			// Enter subdirectory ipv6/ oder ipv4/
			if d.IsDir() {
				return nil
			}
			device := d.Name()
			// Ignore files *.{info,config,rules}
			if strings.Contains(device, ".") {
				return nil
			}
			if !seen[device] {
				seen[device] = true
				check(device, statusDir, base, policy)
			}
			return nil
		})
	if err != nil {
		return abort("%v", err)
	}
	return 0
}

func check(device, statusDir, base, policy string) {
	v := status.Read(statusDir, device)

	devicePolicy := ""
	approveTime := int64(0)

	// Check status of last approve.
	switch v.Approve.Result {
	case "OK", "WARNINGS":
		devicePolicy = v.Approve.Policy
		approveTime = v.Approve.Time
	}

	// Check status of last compare.
	if approveTime < v.Compare.Time {
		switch v.Compare.Result {
		case "UPTODATE":
			devicePolicy = v.Compare.Policy
		case "DIFF":
			devicePolicy = ""
		}
	}

	switch devicePolicy {
	case "":
		// Both failed.
		fmt.Println(device)
		return
	case policy:
		// If device' policy is equal to current policy, we are finished.
		return
	}

	// Compare Netspoc code of device policy with Netspoc code of current policy.
	for _, dir := range []string{"code", "code/ipv6", "code/ipv4"} {
		for _, ext := range []string{"", ".raw"} {
			p1 := path.Join(base, devicePolicy, dir, device+ext)
			p2 := path.Join(base, policy, dir, device+ext)
			d1 := readFile(p1)
			d2, _ := os.ReadFile(p2)
			if !slices.Equal(d1, d2) {
				fmt.Println(device)
				return
			}
		}
	}
}

func readFile(p string) []byte {
	if d, err := os.ReadFile(p); err == nil {
		return d
	}
	if fh, err := os.Open(p + ".bz2"); err == nil {
		if d, err := io.ReadAll(bzip2.NewReader(fh)); err == nil {
			return d
		}
	}
	return nil
}

func abort(format string, args ...interface{}) int {
	fmt.Fprintf(os.Stderr, "Error: "+format+"\n", args...)
	return 1
}
