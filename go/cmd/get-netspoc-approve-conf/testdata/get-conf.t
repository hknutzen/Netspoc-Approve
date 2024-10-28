
############################################################
=TITLE=Missing argument
=CONFIG=
netspocdir = /tmp
lockfiledir = /tmp
checkbanner = NetSPoC
=ERROR=
Usage: PROGRAM KEY
=END=

############################################################
=TITLE=Read default value
=CONFIG=
netspocdir = /tmp
lockfiledir = /tmp
=OUTPUT=
60
=OPTIONS=timeout

############################################################
=TITLE=Read changed default value
=CONFIG=
netspocdir = /tmp
lockfiledir = /tmp
timeout = 10
=OUTPUT=
10
=OPTIONS=timeout

############################################################
=TITLE=Duplicate option
=CONFIG=
netspocdir = /tmp
lockfiledir = /tmp
timeout = 10
timeout = 20
=WARNING=
WARNING>>> Ignoring duplicate key 'timeout' in .netspoc-approve
=OUTPUT=
10
=OPTIONS=timeout

############################################################
=TITLE=Warn on invalid config lines
=CONFIG=
netspocdir = /tmp
INVALID
INVALID value
INVALID =
lockfiledir = /tmp
KEY = VALUE
checkbanner = NetSPoC
timeout = 1
=WARNING=
WARNING>>> Ignoring line 'INVALID' in .netspoc-approve
WARNING>>> Ignoring line 'INVALID value' in .netspoc-approve
WARNING>>> Ignoring line 'INVALID =' in .netspoc-approve
WARNING>>> Ignoring key 'KEY' in .netspoc-approve
=OUTPUT=
NetSPoC
=OPTIONS=checkbanner

############################################################
=TITLE=Invalid regexp in checkbanner
=CONFIG=
checkbanner = ***
=ERROR=
Error: Invalid regexp in 'checkbanner' of .netspoc-approve: error parsing regexp: missing argument to repetition operator: `*`
=OPTIONS=checkbanner

############################################################
=TITLE=Read empty checkbanner
=CONFIG=
netspocdir = /tmp
lockfiledir = /tmp
=OUTPUT=

=OPTIONS=checkbanner

############################################################
=TITLE=Invalid server_ip_list
=CONFIG=
server_ip_list = 10.1.2.3 10.4.5
=ERROR=
Error: Expected IP address in 'server_ip_list' of .netspoc-approve: ParseAddr("10.4.5"): IPv4 address too short
=OPTIONS=server_ip_list

############################################################
=TITLE=Read empty server_ip_list
=CONFIG=
netspocdir = /tmp
lockfiledir = /tmp
=OUTPUT=

=OPTIONS=server_ip_list

############################################################
=TITLE=More than one value
=CONFIG=
netspocdir = /tmp1 /tmp2
=ERROR=
Error: Expected exactly one value for "netspocdir" in .netspoc-approve: [/tmp1 /tmp2]
=OPTIONS=netspocdir

############################################################
=TITLE=Invalid timeout value
=CONFIG=
timeout = today
=ERROR=
Error: Expected integer value for 'timeout' in .netspoc-approve: strconv.Atoi: parsing "today": invalid syntax
=OPTIONS=timeout

############################################################
=TITLE=Negative timeout value
=CONFIG=
timeout = -1
=ERROR=
Error: Expected positive integer for 'timeout' in .netspoc-approve: -1
=OPTIONS=timeout

############################################################
=TITLE=Missing required option
=CONFIG=
lockfiledir = /tmp
checkbanner = NetSPoC
=ERROR=
Error: Missing 'netspocdir' in .netspoc-approve
=OPTIONS=checkbanner

############################################################
=TITLE= Get netspocdir from basedir
=CONFIG=
basedir = /tmp
=OUTPUT=
/tmp/policies
=OPTIONS=netspocdir

############################################################
=TITLE= Don't overwrite given netspocdir from basedir
=CONFIG=
basedir = /tmp
netspocdir = /other/netspoc
=OUTPUT=
/other/netspoc
=OPTIONS=netspocdir

############################################################
=TITLE=Read netspocdir
=CONFIG=
netspocdir = /tmp
lockfiledir = /tmp
=OUTPUT=
/tmp
=OPTIONS=netspocdir

############################################################
=TITLE=Read lockfiledir
=CONFIG=
netspocdir = /tmp
lockfiledir = /tmp
=OUTPUT=
/tmp
=OPTIONS=lockfiledir

############################################################
=TITLE=Read netspoc_git
=CONFIG=
netspocdir = /tmp
lockfiledir = /tmp
netspoc_git = /opt/git/netspoc.git
=OUTPUT=
/opt/git/netspoc.git
=OPTIONS=netspoc_git

############################################################
=TITLE=Read historydir
=CONFIG=
netspocdir = /tmp
lockfiledir = /tmp
historydir = abc
=OUTPUT=
abc
=OPTIONS=historydir

############################################################
=TITLE=Read statusdir
=CONFIG=
netspocdir = /tmp
lockfiledir = /tmp
statusdir = abc-345
=OUTPUT=
abc-345
=OPTIONS=statusdir

############################################################
=TITLE=Read aaa_credentials
=CONFIG=
netspocdir = /tmp
lockfiledir = /tmp
aaa_credentials = .file
=OUTPUT=
.file
=OPTIONS=aaa_credentials

############################################################
=TITLE=Read systemuser
=CONFIG=
netspocdir = /tmp
lockfiledir = /tmp
systemuser = netspoc_user
=OUTPUT=
netspoc_user
=OPTIONS=systemuser

############################################################
=TITLE=Read server_ip_list
=CONFIG=
netspocdir = /tmp
lockfiledir = /tmp
server_ip_list = 10.1.2.3 10.4.5.6 dead::beef
=OUTPUT=
10.1.2.3 10.4.5.6 dead::beef
=OPTIONS=server_ip_list

############################################################
=TITLE=Read login_timeout
=CONFIG=
netspocdir = /tmp
lockfiledir = /tmp
login_timeout = 3
=OUTPUT=
3
=OPTIONS=login_timeout

############################################################
=TITLE=Read keep_history
=CONFIG=
netspocdir = /tmp
lockfiledir = /tmp
keep_history = 30
=OUTPUT=
30
=OPTIONS=keep_history

############################################################
=TITLE=Read compress_at
=CONFIG=
netspocdir = /tmp
lockfiledir = /tmp
compress_at = 7
=OUTPUT=
7
=OPTIONS=compress_at

############################################################
=TITLE=Read unknown key
=CONFIG=
netspocdir = /tmp
lockfiledir = /tmp
=OUTPUT=

=OPTIONS=UNKNOWN
