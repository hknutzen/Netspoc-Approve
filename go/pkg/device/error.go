package device

import (
	"fmt"
	"os"
)

func abort(f string, l ...interface{}) {
	fmt.Fprintf(os.Stderr, "Abort: "+f+"\n", l...)
	os.Exit(1)
}

func warn(f string, l ...interface{}) {
	fmt.Fprintf(os.Stderr, "Warning: "+f+"\n", l...)
}
