package main

import (
	"os"

	"github.com/hknutzen/Netspoc-Approve/go/pkg/device"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/nsx"
)

func main() {
	os.Exit(device.Main(&nsx.State{}))
}
