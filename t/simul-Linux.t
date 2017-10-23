#!/usr/bin/perl

use strict;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Approve;

my($scenario, $in, $out, $title);

############################################################
$title = "Login with unknown SSH key, change routing and iptables";
############################################################
$scenario = <<'END';
The authenticity of host 'router (10.1.1.1)' can't be established.
ECDSA key fingerprint is ee:6e:ee:00:33:aa:22:88:44:66:44:33:aa:77:42:f5.
Are you sure you want to continue connecting (yes/no)? <!>
--- managed by NetsSPoC ---
root@linux-router:~#
# echo $?
0
# uname -r
3.2.89-2.custom
# uname -m
i686
# hostname -s
router
# grep 'NetSPoC' /etc/issue
--- managed by NetsSPoC ---
# which iptables-restore
/sbin/iptables-restore
# ip route show
0.0.0.0/0 via 10.1.1.1
# iptables-save
*filter
:INPUT DROP
-A INPUT -j ACCEPT -s 10.1.11.111 -d 10.10.1.2 -p tcp --dport 23
COMMIT
# /usr/sbin/backup
tar: Removing leading `/' from member names
END

$in = <<'END';
ip route add 0.0.0.0/0 via 10.1.1.99

*filter
:INPUT DROP
-A INPUT -j ACCEPT -s 10.1.11.111 -d 10.10.1.2 -p tcp --dport 22
END

$out = <<'END';
--router.login
The authenticity of host 'router (10.1.1.1)' can't be established.
ECDSA key fingerprint is ee:6e:ee:00:33:aa:22:88:44:66:44:33:aa:77:42:f5.
Are you sure you want to continue connecting (yes/no)? yes

--- managed by NetsSPoC ---
root@linux-router:~#PS1=router#
router#echo $?
0
router#uname -r
3.2.89-2.custom
router#uname -m
i686
router#hostname -s
router
router#grep 'NetSPoC' /etc/issue
--- managed by NetsSPoC ---
router#
--router.change
ip route del 0.0.0.0/0 via 10.1.1.1
router#ip route add 0.0.0.0/0 via 10.1.1.99
router#echo $?
0
router#which iptables-restore
/sbin/iptables-restore
router#chmod a+x /etc/network/packet-filter.new
router#echo $?
0
router#/etc/network/packet-filter.new
router#echo $?
0
router#mv -f /etc/network/routing.new /etc/network/routing
router#echo $?
0
router#mv -f /etc/network/packet-filter.new /etc/network/packet-filter
router#echo $?
0
router#ls /etc/router-version
router#echo $?
0
router#/usr/sbin/backup
tar: Removing leading `/' from member names
router#echo $?
0
router#
END

simul_run($title, 'Linux', $scenario, $in, $out);

############################################################
$title = "Unexpected echo in response to command input";
############################################################
$scenario = <<'END';

prompt#
# \BANNER1/
xxx
# echo $?
0
# una\BANNER1/me -r
3.2.89-2.custom
END

$in = '';

$out = <<'END';
ERROR>>> Got unexpected echo in response to 'uname -r':
'unaxxx
me -r
3.2.89-2.custom'
END

simul_err($title, 'Linux', $scenario, $in, $out);

############################################################
$title = "Command with failure status";
############################################################
$scenario = <<'END';

prompt#
END

$in = '';

$out = <<'END';
ERROR>>> PS1=router# failed (exit status)
END

simul_err($title, 'Linux', $scenario, $in, $out);

############################################################
$title = "SSH timeout";
############################################################
$scenario = '';
$in = '';

$out = <<'END';
ERROR>>> TIMEOUT
END

simul_err($title, 'Linux', $scenario, $in, $out);

############################################################
done_testing;
