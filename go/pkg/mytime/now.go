package mytime

import (
	"os"
	"time"
)

func Now() time.Time {
	if v := os.Getenv("TEST_TIME"); v != "" {
		t, err := time.Parse("2006-Jan-02 15:04:05", v)
		if err != nil {
			panic(err)
		}
		return t
	}
	return time.Now()
}
