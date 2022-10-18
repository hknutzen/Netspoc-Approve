package main

import (
	"os"

	"github.com/hknutzen/Netspoc-Approve/go/pkg/device"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/panos"
)

func main() {
	os.Exit(device.Main(panos.State))
}
