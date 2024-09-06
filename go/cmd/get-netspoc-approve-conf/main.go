package main

import (
	"fmt"
	"os"

	"github.com/hknutzen/Netspoc-Approve/go/pkg/device"
)

func main() {
	os.Exit(Main())
}

func Main() int {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s KEY\n", os.Args[0])
		return 1
	}
	c, err := device.LoadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	key := os.Args[1]
	fmt.Println(c.GetVal(key))
	return 0
}
