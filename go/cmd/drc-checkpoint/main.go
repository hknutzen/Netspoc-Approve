package main

import (
	"os"

	chkp "github.com/hknutzen/Netspoc-Approve/go/pkg/checkpoint"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/device"
)

func main() {
	os.Exit(device.Main(&chkp.State{}))
}
