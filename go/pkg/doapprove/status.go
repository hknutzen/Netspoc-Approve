package doapprove

import (
	"os"
	"path"
	"strconv"
	"strings"
)

const (
	DEVICENAME int = iota
	APP_MESSAGE
	APP_POLICY
	APP_STATUS // same as for DEV_STATUS
	APP_TIME   // date cleartext
	APP_USER
	DEV_MESSAGE
	DEV_POLICY
	DEV_STATUS // ***WARNINGS***, ***ERRORS***  or OK
	DEV_TIME   // date cleartext
	DEV_USER
	COMP_COMP
	COMP_RESULT // DIFF or UPTODATE
	COMP_POLICY
	COMP_CTIME // date cleartext
	COMP_TIME  // seconds since 1970
	COMP_DTIME // DEV_TIME in seconds
	STATUS_LEN
)

func setApproveStatus(statusDir, device, policy, result string) {
	v := readStatus(statusDir, device)
	changeStatus(v, map[int]string{
		APP_STATUS: result,
		APP_POLICY: policy,
		COMP_DTIME: getUnixTime(),
		// Unused
		DEV_POLICY: "",
		DEV_STATUS: "",
		APP_TIME:   "",
		DEV_TIME:   "",
		APP_USER:   "",
		DEV_USER:   "",
	})
	writeStatus(statusDir, device, v)
}

func setCompareStatus(statusDir, device, policy string, changed bool) {
	v := readStatus(statusDir, device)
	result := ""
	if !changed {
		result = "UPTODATE"
	} else if v[COMP_RESULT] != "DIFF" || isLess(v[COMP_TIME], v[COMP_DTIME]) {
		// Only update compare status,
		// - if status changes to diff for first time,
		// - or device was approved since last compare.
		result = "DIFF"
	} else {
		return
	}
	changeStatus(v, map[int]string{
		COMP_RESULT: result,
		COMP_POLICY: policy,
		COMP_TIME:   getUnixTime(),
		// Unused
		COMP_CTIME: "",
	})
	writeStatus(statusDir, device, v)
}

func readStatus(statusDir, device string) []string {
	fname := path.Join(statusDir, device)
	data, _ := os.ReadFile(fname)
	values := make([]string, STATUS_LEN)
	copy(values, strings.Split(string(data), ";"))
	return values
}

func changeStatus(values []string, change map[int]string) {
	for i, v := range change {
		values[i] = v
	}
}

func writeStatus(statusDir, device string, values []string) {
	fname := path.Join(statusDir, device)
	values[0] = device
	result := strings.Join(values, ";") + ";\n"
	if err := os.WriteFile(fname, []byte(result), 0644); err != nil {
		abort("can't %v", err)
	}
}

func getUnixTime() string {
	return strconv.FormatInt(myTimeNow().Unix(), 10)
}

func isLess(t1, t2 string) bool {
	i1, _ := strconv.ParseInt(t1, 10, 64)
	i2, _ := strconv.ParseInt(t2, 10, 64)
	return i1 < i2
}
