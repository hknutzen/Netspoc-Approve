=TEMPL=usage
Usage: drc [options] FILE1
     : drc [-q] FILE1 FILE2
      --LOGFILE string   Path to redirect STDERR
  -C, --compare          Compare only
  -L, --logdir string    Path for saving session logs
  -q, --quiet            No info messages
  -u, --user string      Username for login to remote device
  -v, --version          Show version
=END=

############################################################
=TITLE=Option -h
=SCENARIO=NONE
=NETSPOC=NONE
=OPTIONS=-h
=ERROR=
[[usage]]
=END=

############################################################
=TITLE=Invalid option
=NETSPOC=NONE
=OPTIONS=-x
=ERROR=
Error: unknown shorthand flag: 'x' in -x
[[usage]]
=END=

############################################################
=TITLE=Invalid option for file compare
=NETSPOC=NONE
=OPTIONS=-q -C
=ERROR=
[[usage]]
=END=

############################################################
=TITLE=Show version
=NETSPOC=NONE
=OPTIONS=-v
=WARNING=
version devel
=END=

############################################################
=TITLE=Missing first argument
=SCENARIO=NONE
=NETSPOC=NONE
=PARAMS=NONE
=ERROR=
[[usage]]
=END=

############################################################
=TITLE=More than two arguments
=SCENARIO=NONE
=NETSPOC=NONE
=PARAMS=a b c
=ERROR=
[[usage]]
=END=

############################################################
=TITLE=Missing device type
=NETSPOC=
--router.info
{"ip_list": ["1.2.3.4"] }
=ERROR=
ERROR>>> Unexpected model "" in file code/router.info
=END=

############################################################
=TITLE=Missing config file
=SCENARIO=NONE
=NETSPOC=NONE
=SETUP=
rm .netspoc-approve
=ERROR=
Error: No config file found in [.netspoc-approve /usr/local/etc/netspoc-approve /etc/netspoc-approve]
=END=

############################################################
=TITLE=Missing lockfile dir
=SCENARIO=NONE
=NETSPOC=NONE
=SETUP=
rmdir LOCK
=ERROR=
Error: open LOCK/router: no such file or directory
=END=
