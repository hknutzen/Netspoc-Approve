
############################################################
=TITLE=Missing argument
=CONFIG=
basedir = /tmp
checkbanner = NetSPoC
=ERROR=
Usage: PROGRAM KEY
=END=

############################################################
=TITLE=Read default value
=CONFIG=
basedir = /tmp
=OUTPUT=
60
=OPTIONS=timeout

############################################################
=TITLE=Read changed default value
=CONFIG=
basedir = /tmp
timeout = 10
=OUTPUT=
10
=OPTIONS=timeout

############################################################
=TITLE=Duplicate option
=CONFIG=
basedir = /tmp
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
INVALID
INVALID value
basedir = /tmp
INVALID =
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
basedir = /tmp
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
basedir = /tmp
=OUTPUT=

=OPTIONS=server_ip_list

############################################################
=TITLE=More than one value
=CONFIG=
basedir = /tmp1 /tmp2
=ERROR=
Error: Expected exactly one value for "basedir" in .netspoc-approve: [/tmp1 /tmp2]
=OPTIONS=basedir

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
checkbanner = NetSPoC
=ERROR=
Error: Missing 'basedir' in .netspoc-approve
=OPTIONS=checkbanner

############################################################
=TITLE=Read basedir
=CONFIG=
basedir = /tmp
=OUTPUT=
/tmp
=OPTIONS=basedir

############################################################
=TITLE=Read netspoc_git
=CONFIG=
basedir = /tmp
netspoc_git = /opt/git/netspoc.git
=OUTPUT=
/opt/git/netspoc.git
=OPTIONS=netspoc_git

############################################################
=TITLE=Read admin_emails
=CONFIG=
basedir = /tmp
admin_emails = a@example.com,b@example.com
=OUTPUT=
a@example.com,b@example.com
=OPTIONS=admin_emails

############################################################
=TITLE=Read systemuser
=CONFIG=
basedir = /tmp
systemuser = netspoc_user
=OUTPUT=
netspoc_user
=OPTIONS=systemuser

############################################################
=TITLE=Read server_ip_list
=CONFIG=
basedir = /tmp
server_ip_list = 10.1.2.3 10.4.5.6 dead::beef
=OUTPUT=
10.1.2.3 10.4.5.6 dead::beef
=OPTIONS=server_ip_list

############################################################
=TITLE=Read login_timeout
=CONFIG=
basedir = /tmp
login_timeout = 3
=OUTPUT=
3
=OPTIONS=login_timeout

############################################################
=TITLE=Read keep_history
=CONFIG=
basedir = /tmp
keep_history = 30
=OUTPUT=
30
=OPTIONS=keep_history

############################################################
=TITLE=Read compress_at
=CONFIG=
basedir = /tmp
compress_at = 7
=OUTPUT=
7
=OPTIONS=compress_at

############################################################
=TITLE=Read unknown key
=CONFIG=
basedir = /tmp
=OUTPUT=

=OPTIONS=UNKNOWN
