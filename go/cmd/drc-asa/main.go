package main

import (
	"os"

	"github.com/hknutzen/Netspoc-Approve/go/pkg/asa"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/device"
)

func main() {
	os.Exit(device.Main(&asa.State{}))
}
