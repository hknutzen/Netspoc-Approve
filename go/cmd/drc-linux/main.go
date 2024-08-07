package main

import (
	"os"

	"github.com/hknutzen/Netspoc-Approve/go/pkg/device"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/linux"
)

func main() {
	os.Exit(device.Main(&linux.State{}))
}
