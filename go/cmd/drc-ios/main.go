package main

import (
	"os"

	"github.com/hknutzen/Netspoc-Approve/go/pkg/device"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/ios"
)

func main() {
	os.Exit(device.Main(ios.Setup()))
}
