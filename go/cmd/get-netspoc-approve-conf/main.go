package main

import (
	"fmt"
	"os"

	"github.com/hknutzen/Netspoc-Approve/go/pkg/program"
)

func main() {
	os.Exit(Main())
}

func Main() int {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s KEY\n", os.Args[0])
		return 1
	}
	cfg, err := program.LoadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	key := os.Args[1]
	fmt.Println(cfg.GetVal(key))
	return 0
}
