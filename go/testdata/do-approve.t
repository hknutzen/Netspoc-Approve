############################################################
=TITLE=Unknown option
=DO_APPROVE=
=SCENARIO=NONE
=NETSPOC=NONE
=PARAMS=--unknown
=ERROR=
Error: unknown flag: --unknown
Usage: do-approve [options] approve|compare DEVICE
  -b, --brief   Suppress message about unreachable device
=END=

############################################################
=TITLE=Option -h
=DO_APPROVE=
=SCENARIO=NONE
=NETSPOC=NONE
=PARAMS=-h
=ERROR=
Usage: do-approve [options] approve|compare DEVICE
  -b, --brief   Suppress message about unreachable device
=END=

############################################################
=TITLE=Missing first argument
=DO_APPROVE=
=SCENARIO=NONE
=NETSPOC=NONE
=PARAMS=NONE
=ERROR=
Usage: do-approve [options] approve|compare DEVICE
  -b, --brief   Suppress message about unreachable device
=END=

############################################################
=TITLE=Wrong first argument
=DO_APPROVE=
=SCENARIO=NONE
=NETSPOC=NONE
=PARAMS=blabla router
=ERROR=
Usage: do-approve [options] approve|compare DEVICE
  -b, --brief   Suppress message about unreachable device
=END=

############################################################
=TITLE=Missing second argument
=DO_APPROVE=
=SCENARIO=NONE
=NETSPOC=NONE
=PARAMS=compare
=ERROR=
Usage: do-approve [options] approve|compare DEVICE
  -b, --brief   Suppress message about unreachable device
=END=

############################################################
=TITLE=Too many arguments
=DO_APPROVE=
=SCENARIO=NONE
=NETSPOC=NONE
=PARAMS=compare router1 router2
=ERROR=
Usage: do-approve [options] approve|compare DEVICE
  -b, --brief   Suppress message about unreachable device
=END=

############################################################
=TITLE=Missing config file
=DO_APPROVE=
=SCENARIO=NONE
=NETSPOC=NONE
=SETUP=
rm .netspoc-approve
=ERROR=
Error: No config file found in [.netspoc-approve /usr/local/etc/netspoc-approve /etc/netspoc-approve]
=END=

############################################################
=TITLE=Missing link to current policy
=DO_APPROVE=
=SCENARIO=NONE
=NETSPOC=NONE
=SETUP=
rm policies/current
=ERROR=
Error: Can't get 'current' policy directory: lstat policies/current: no such file or directory
=END=

############################################################
=TITLE=Unknown device
=DO_APPROVE=
=SCENARIO=NONE
=NETSPOC=NONE
=SETUP=
rm policies/p1/code/router
=ERROR=
Error: unknown device "router"
=END=

############################################################
=TITLE=Missing lockfile dir
=DO_APPROVE=
=SCENARIO=NONE
=NETSPOC=NONE
=SETUP=
chmod a-rwx lock
=ERROR=
Error: open lock/router: permission denied
=END=

############################################################
=TITLE=Missing history dir
=DO_APPROVE=
=SCENARIO=NONE
=NETSPOC=NONE
=SETUP=
rmdir history
touch history
=ERROR=
Error: can't open history/router: not a directory
=END=

############################################################
=TITLE=Invalid model DO-APPROVE from file name of test
=DO_APPROVE=
=SCENARIO=NONE
=NETSPOC=NONE
=ERROR=
FAILED, details in policies/p1/log/router.compare
=OUTPUT=
ERROR>>> Unexpected model "DO-APPROVE" in file policies/p1/code/router.info
--policies/p1/log/router.compare
ERROR>>> Unexpected model "DO-APPROVE" in file policies/p1/code/router.info
=END=

############################################################
=TITLE=Unreadable logfile
=DO_APPROVE=
=SCENARIO=NONE
=NETSPOC=NONE
=SETUP=
mkdir -p policies/p1/log/router.compare.1727626790
touch policies/p1/log/router.compare
chmod a-r policies/p1/log/router.compare
=ERROR=
Error: can't open policies/p1/log/router.compare: permission denied
=END=
