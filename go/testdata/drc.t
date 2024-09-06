
############################################################
=TITLE=Missing device type
=NETSPOC=
--router.info
{"ip_list": ["1.2.3.4"] }
=ERROR=
ERROR>>> Unexpected model "" in file code/router.info
=END=

############################################################
=TITLE=Invalid option
=NETSPOC=NONE
=OPTIONS=-x
=ERROR=
Error: unknown shorthand flag: 'x' in -x
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
=TITLE=Show version
=NETSPOC=NONE
=OPTIONS=-v
=WARNING=
version devel
=END=
