package codefiles

import "path"

func GetIPv6Fname(p string) string {
	dir := path.Dir(p)
	base := path.Base(p)
	return dir + "/ipv6/" + base
}

func GetHostname(fName string) string {
	return path.Base(fName)
}
