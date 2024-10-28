############################################################
=TITLE=no valid status file for ipv4 device
=INPUT=
--p2/code/A
lalala
=OUTPUT=
A
=END=

############################################################
=TITLE=no valid status file for ipv4 device in ipv6 mode
=INPUT=
--p2/code/ipv4/A
lalala
=OUTPUT=
A
=END=

############################################################
=TITLE=no valid status file for ipv6 device in ipv4 mode
=INPUT=
--p2/code/ipv6/A
lalala
=OUTPUT=
A
=END=

############################################################
=TITLE=missing status file for ipv4 and ipv6 devices
=INPUT=
--p2/code/A
Code for device A
--p2/code/B
IPv4 code
--p2/code/ipv6/B
IPv6 code
=OUTPUT=
A
B
=END=

############################################################
=TITLE=last approved/compared version differs from current version
# But IPv4 file of device B is equal
=INPUT=
--p2/code/A
Code for device A
--p2/code/B
IPv4 code
--p2/code/ipv6/B
IPv6 code
--p1/code/A
Old code for device A
--p1/code/B
IPv4 code
--p1/code/ipv6/B
Old IPv6 code
--status/A
{"approve":{"result":"OK","policy":"p1","time":1519980388},
 "compare":{"result":"UPTODATE","policy":"p1","time":1519980299}
}
--status/B
{"approve":{"result":"FAILED","policy":"p2","time":1519980388},
 "compare":{"result":"UPTODATE","policy":"p1","time":1519980492}
}
=OUTPUT=
A
B
=END=

############################################################
=TITLE=last approved/compared version equals current version
=INPUT=
--p2/code/A
Code for device A
--p2/code/B
IPv4 code
--p2/code/ipv6/B
IPv6 code
--p1/code/A
Code for device A
--p1/code/B
IPv4 code
--p1/code/ipv6/B
IPv6 code
--status/A
{"approve":{"result":"OK","policy":"p1","time":1519980388},
 "compare":{"result":"UPTODATE","policy":"p1","time":1519980299}
}
--status/B
{"approve":{"result":"FAILED","policy":"p2","time":1519980388},
 "compare":{"result":"UPTODATE","policy":"p1","time":1519980492}
}
=OUTPUT=NONE

############################################################
=TITLE=take older compared version if approve failed
=INPUT=
--p2/code/A
Code for device A
--p1/code/A
Code for device A
--status/A
{"approve":{"result":"FAILED","policy":"p2","time":1519980500},
 "compare":{"result":"UPTODATE","policy":"p1","time":1519980492}
}
=OUTPUT=NONE

############################################################
=TITLE=ignore older approved version if compare finds diff
=INPUT=
--p2/code/A
Code for device A
--p1/code/A
Code for device A
--status/A
{"approve":{"result":"OK","policy":"p1","time":1519980388},
 "compare":{"result":"DIFF","policy":"p2","time":1519980492}
}
=OUTPUT=
A
=END=

############################################################
=TITLE=older version is missing
=INPUT=
--p2/code/A
Code for device A
--status/A
{"approve":{"result":"FAILED","policy":"p2","time":1519980500},
 "compare":{"result":"UPTODATE","policy":"p1","time":1519980492}
}
=OUTPUT=
A
=END=

############################################################
=TITLE=device was never approved or compared
=INPUT=
--p2/code/A
Code for device A
=OUTPUT=
A
=END=

############################################################
=TITLE=device was already approved with current version
=INPUT=
--p2/code/A
Code for device A
--status/A
{"approve":{"result":"OK","policy":"p2","time":1519980388},
 "compare":{"result":"","policy":"","time":0}
}
=OUTPUT=NONE

############################################################
=TITLE=device was already compared with current version
=INPUT=
--p2/code/A
Code for device A
--status/A
{"approve":{"result":"","policy":"","time":0},
 "compare":{"result":"UPTODATE","policy":"p2","time":1519980492}
}
=OUTPUT=NONE

############################################################
=TITLE=compare with bzipped version
=INPUT=
--p2/code/A
Code for device A
--p1/code/A
Code for device A
--status/A
{"approve":{"result":"","policy":"","time":0},
 "compare":{"result":"UPTODATE","policy":"p1","time":1519980492}
}
=SETUP=
bzip2 p1/code/A
=OUTPUT=NONE

############################################################
=TITLE=gzip isn't supported
=INPUT=
--p2/code/A
Code for device A
--p1/code/A
Code for device A
--status/A
{"approve":{"result":"","policy":"","time":0},
 "compare":{"result":"UPTODATE","policy":"p1","time":1519980492}
}
=SETUP=
gzip p1/code/A
=OUTPUT=
A
=END=

############################################################
=TITLE=compare with changed bzipped version
=INPUT=
--p2/code/A
Code for device A
--p1/code/A
Old code for device A
--status/A
{"approve":{"result":"","policy":"","time":0},
 "compare":{"result":"UPTODATE","policy":"p1","time":1519980492}
}
=SETUP=
bzip2 p1/code/A
=OUTPUT=
A
=END=

############################################################
=TITLE=ignore file with dot
=INPUT=
--p2/code/A
Code for device A
--p2/code/A.info
version 2
--p1/code/A
Code for device A
--p1/code/A.info
version 1
--status/A
{"approve":{"result":"","policy":"","time":0},
 "compare":{"result":"UPTODATE","policy":"p1","time":1519980492}
}
=OUTPUT=NONE

############################################################
=TITLE=Changed raw file
=INPUT=
--p2/code/A
Code for device A
--p2/code/A.raw
raw2
--p1/code/A
Code for device A
--p1/code/A.raw
raw1
--status/A
{"approve":{"result":"","policy":"","time":0},
 "compare":{"result":"UPTODATE","policy":"p1","time":1519980492}
}
=OUTPUT=
A
=END=
