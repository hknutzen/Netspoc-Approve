package errlog

type bailout struct{}

func HandleAbort(f func() int) (exitCode int) {
	defer func() {
		if e := recover(); e != nil {
			if _, ok := e.(bailout); !ok {
				panic(e) // Resume same panic if it's not a bailout.
			}
			exitCode = 1
		}
	}()
	return f()
}

func Abort(format string, args ...interface{}) {
	PrintWithMarker("ERROR>>> ", format, args...)
	panic(bailout{})
}
