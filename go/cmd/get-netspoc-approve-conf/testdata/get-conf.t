
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
=TITLE=Missing required option
=CONFIG=
lockfiledir = /tmp
checkbanner = NetSPoC
=ERROR=
Error: Missing 'netspocdir' in .netspoc-approve
=OPTIONS=checkbanner

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
=TITLE=Ignore multi word value
=CONFIG=
netspocdir = /tmp
lockfiledir = /tmp
checkbanner = NetSPoC managed device
=WARNING=
WARNING>>> Ignoring line 'checkbanner = NetSPoC managed device' in .netspoc-approve
=OUTPUT=

=OPTIONS=checkbanner

############################################################
=TITLE=Warn on invalid config lines
=CONFIG=
netspocdir = /tmp
INVALID
lockfiledir = /tmp
KEY = VALUE
checkbanner = NetSPoC
timeout = 1
=WARNING=
WARNING>>> Ignoring line 'INVALID' in .netspoc-approve
WARNING>>> Ignoring key 'KEY' in .netspoc-approve
=OUTPUT=
NetSPoC
=OPTIONS=checkbanner
