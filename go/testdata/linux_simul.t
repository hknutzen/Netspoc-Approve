############################################################
=TITLE=Login with unknown SSH key, change routing and iptables
=TEMPL=scenario
The authenticity of host 'router (10.1.1.1)' can't be established.
ECDSA key fingerprint is ee:6e:ee:00:33:aa:22:88:44:66:44:33:aa:77:42:f5.
Are you sure you want to continue connecting (yes/no)? <!>
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
--- managed by NetSPoC ---
# which iptables-restore
/sbin/iptables-restore
# ip route show
0.0.0.0/0 via 10.1.1.1
# iptables-save
*filter
:INPUT DROP
-A INPUT -j ACCEPT -s 10.1.11.111 -d 10.10.1.2 -p tcp --dport 23
COMMIT

=SCENARIO=[[scenario]]
=NETSPOC=
ip route add 0.0.0.0/0 via 10.1.1.99

*filter
:INPUT DROP
-A INPUT -j ACCEPT -s 10.1.11.111 -d 10.10.1.2 -p tcp --dport 22
=OUTPUT=
--router.login
The authenticity of host 'router (10.1.1.1)' can't be established.
ECDSA key fingerprint is ee:6e:ee:00:33:aa:22:88:44:66:44:33:aa:77:42:f5.
Are you sure you want to continue connecting (yes/no)? yes

root@linux-router:~#PS1=router#
router#uname -r
3.2.89-2.custom
router#uname -m
i686
router#hostname -s
router
router#grep 'NetSPoC' /etc/issue
--- managed by NetSPoC ---
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
router#mv -f /etc/network/packet-filter.new /etc/network/packet-filter
router#echo $?
0
router#
=END=

############################################################
=TITLE=Unexpected output of command
=SCENARIO=
[[scenario]]
# ip route del 0.0.0.0/0 via 10.1.1.1
RTNETLINK answers: Invalid argument
=NETSPOC=NONE
=ERROR=
ERROR>>> Got unexpected output from 'ip route del 0.0.0.0/0 via 10.1.1.1':
ERROR>>> RTNETLINK answers: Invalid argument
=END=

############################################################
=TITLE=Unexpected echo in response to command
# Use banner to garble echo of command.
=SCENARIO=

root@linux-router:~#
# echo $?
0
# \BANNER1/
xxx
# una\BANNER1/me -r
3.2.89-2.custom
=NETSPOC=NONE
=ERROR=
ERROR>>> Got unexpected echo in response to 'uname -r':
ERROR>>> unaxxx
ERROR>>> me -r
ERROR>>> 3.2.89-2.custom
=END=

############################################################
=TITLE=Unexpected exit status of command
=SCENARIO=

root@linux-router:~#
# echo $?
1
# uname -r
3.2.89-2.custom
#uname -m
i686
#hostname -s
router
=NETSPOC=
ip route add 0.0.0.0/0 via 10.1.1.99
=ERROR=
ERROR>>> ip route add 0.0.0.0/0 via 10.1.1.99 failed (exit status)
=END=

############################################################
=TITLE=Timeout
=SCENARIO=

=NETSPOC=NONE
=ERROR=
ERROR>>> while waiting for login prompt '\r\n\S*\s?[%>$#]\s?(?:\x27\S*)?|(?i)password:|\(yes/no.*\)\?': expect: timer expired after 3 seconds
=END=

############################################################
=TITLE=Authentication failed
=SCENARIO=
Enter Password:<!>
Enter Password:
=NETSPOC=NONE
=ERROR=
ERROR>>> Authentication failed
=END=

############################################################
=TITLE=Wrong device name
=SCENARIO=

router#
# echo $?
0
# uname -r
3.2.89-2.custom
# uname -m
i686
# hostname -s
xyz
=NETSPOC=
*filter
:INPUT DROP
-A INPUT -j ACCEPT -s 10.1.11.111 -d 10.10.1.2 -p tcp --dport 22
=ERROR=
ERROR>>> Wrong device name: "xyz", expected: "router"
=END=

############################################################
=TITLE=Unknown iptables-restore
=SCENARIO=

router#
# echo $?
0
# uname -r
3.2.89-2.custom
# uname -m
i686
# hostname -s
router
# grep 'NetSPoC' /etc/issue
--- managed by NetSPoC ---
=NETSPOC=
*filter
:INPUT DROP
-A INPUT -j ACCEPT -s 10.1.11.111 -d 10.10.1.2 -p tcp --dport 22
=ERROR=
ERROR>>> Can't find path of 'iptables-restore'
=END=

############################################################
=TITLE=Bad credentials file
=SCENARIO=[[scenario]]
=NETSPOC=
ip route add 0.0.0.0/0 via 10.1.1.99
=SETUP=
echo abc 123 >credentials
=ERROR=
ERROR>>> Expected 3 fields in lines of credentials
=END=
