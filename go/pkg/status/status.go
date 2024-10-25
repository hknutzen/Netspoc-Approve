package status

import (
	"encoding/json"
	"os"
	"path"

	"github.com/hknutzen/Netspoc-Approve/go/pkg/mytime"
)

type action struct {
	Result string `json:"result"`
	Policy string `json:"policy"`
	Time   int64  `json:"time"`
}
type status struct {
	Approve action `json:"approve"`
	Compare action `json:"compare"`
}

func SetApprove(statusDir, device, policy, result string) {
	v := Read(statusDir, device)
	v.Approve = action{result, policy, mytime.Now().Unix()}
	write(statusDir, device, v)
}

func SetCompare(statusDir, device, policy string, changed bool) {
	v := Read(statusDir, device)
	result := ""
	if !changed {
		result = "UPTODATE"
	} else if v.Compare.Result != "DIFF" || v.Compare.Time < v.Approve.Time {
		// Only update compare status,
		// - if status changes to diff for first time,
		// - or device was approved since last compare.
		result = "DIFF"
	} else {
		return
	}
	v.Compare = action{result, policy, mytime.Now().Unix()}
	write(statusDir, device, v)
}

func Read(statusDir, device string) status {
	fname := path.Join(statusDir, device)
	data, _ := os.ReadFile(fname)
	var v status
	json.Unmarshal(data, &v)
	return v
}

func write(statusDir, device string, v status) {
	fname := path.Join(statusDir, device)
	data, _ := json.Marshal(v)
	if err := os.WriteFile(fname, data, 0644); err != nil {
		panic(err)
	}
}
