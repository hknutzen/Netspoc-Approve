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
=PARAMS=blabla
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
rm netspoc/current
=ERROR=
Error: Can't get 'current' policy directory: lstat netspoc/current: no such file or directory
=END=

############################################################
=TITLE=Unknown device
=DO_APPROVE=
=SCENARIO=NONE
=NETSPOC=NONE
=SETUP=
rm netspoc/p1/code/router
=ERROR=
Error: unknown device "router"
=END=

############################################################
=TITLE=Missing lockfile dir
=DO_APPROVE=
=SCENARIO=NONE
=NETSPOC=NONE
=SETUP=
rmdir LOCK
=ERROR=
Error: open LOCK/router: no such file or directory
=END=

############################################################
=TITLE=Missing history dir
=DO_APPROVE=
=SCENARIO=NONE
=NETSPOC=NONE
=SETUP=
rmdir history
=ERROR=
Error: can't open history/router: no such file or directory
=END=

############################################################
=TITLE=Invalid model DO-APPROVE from file name of test
=DO_APPROVE=
=SCENARIO=NONE
=NETSPOC=NONE
=ERROR=
FAILED, details in netspoc/p1/log/router.compare
=OUTPUT=
ERROR>>> Unexpected model "DO-APPROVE" in file netspoc/p1/code/router.info
--netspoc/p1/log/router.compare
ERROR>>> Unexpected model "DO-APPROVE" in file netspoc/p1/code/router.info
=END=
