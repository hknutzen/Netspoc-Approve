package status

import (
	"encoding/json"
	"os"
	"path"

	"github.com/hknutzen/Netspoc-Approve/go/pkg/mytime"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/program"
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

func SetApprove(cfg *program.Config, device, policy string, failed bool) {
	v := Read(cfg, device)
	result := "OK"
	if failed {
		result = "FAILED"
	}
	v.Approve = action{result, policy, mytime.Now().Unix()}
	write(cfg, device, v)
}

func SetCompare(cfg *program.Config, device, policy string, changed bool) {
	v := Read(cfg, device)
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
	write(cfg, device, v)
}

func Read(cfg *program.Config, device string) status {
	fname := path.Join(cfg.BaseDir, "status", device)
	data, _ := os.ReadFile(fname)
	var v status
	json.Unmarshal(data, &v)
	return v
}

func write(cfg *program.Config, device string, v status) {
	statusDir := path.Join(cfg.BaseDir, "status")
	os.Mkdir(statusDir, 0755)
	fname := path.Join(statusDir, device)
	data, _ := json.Marshal(v)
	if err := os.WriteFile(fname, data, 0644); err != nil {
		panic(err)
	}
}
