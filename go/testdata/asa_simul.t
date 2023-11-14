=TEMPL=login_scenario
Are you sure you want to continue connecting (yes/no)?<!>
***********************************************************
**                 managed by NetSPoC                    **
***********************************************************
netspoc@10.1.2.3's password: <!>
Type help or '?' for a list of available commands.
router>
# sh pager
pager lines 24

# sh term

Width = 80, no monitor
terminal interactive
# show hostname
router
# sh ver
Cisco Adaptive Security Appliance Software Version 9.4(4)5
Hardware:   ASA5550, 4096 MB RAM, CPU Pentium 4 3000 MHz
Configuration last modified by netspoc at 10:40:44.291 CEDT Thu Oct 19 2017

=END=

############################################################
=TITLE=Login, set terminal, empty config
=SCENARIO=[[login_scenario]]
=NETSPOC=NONE
=OUTPUT=
--router.login
Are you sure you want to continue connecting (yes/no)?yes

***********************************************************
**                 managed by NetSPoC                    **
***********************************************************
netspoc@10.1.2.3's password: secret

Type help or '?' for a list of available commands.
router>enable
router#
router#sh pager
pager lines 24

router#terminal pager 0
router#sh term

Width = 80, no monitor
terminal interactive
router#configure terminal
router#terminal width 511
router#end
router#sh ver
Cisco Adaptive Security Appliance Software Version 9.4(4)5
Hardware:   ASA5550, 4096 MB RAM, CPU Pentium 4 3000 MHz
Configuration last modified by netspoc at 10:40:44.291 CEDT Thu Oct 19 2017
router#show hostname
router
router#
--router.config
write term
router#
--router.change
No changes applied
=END=

############################################################
=TITLE=Change routing, move ACL with two commands in one line
=SCENARIO=
[[login_scenario]]
# write term
interface Ethernet0/0
 nameif inside
route inside 0.0.0.0 0.0.0.0 10.1.2.3
access-list inside extended permit ip host 1.1.1.1 any
access-list inside extended permit ip host 2.2.2.2 any
access-list inside extended permit ip host 3.3.3.3 any
access-list inside extended permit ip host 4.4.4.4 any
access-group inside in interface inside
# write memory
Building configuration...
Cryptochecksum: abcdef01 44444444 12345678 98765432

123456 bytes copied in 0.330 secs
[OK]
=NETSPOC=
route inside 0.0.0.0 0.0.0.0 10.1.2.4
access-list inside extended permit ip host 1.1.1.1 any
access-list inside extended permit ip host 4.4.4.4 any
access-list inside extended permit ip host 2.2.2.2 any
access-list inside extended permit ip host 3.3.3.3 any
access-group inside in interface inside
=END=
# Two commands to change route and access-list
# are send in one packet.
# This results in two prompts received in one packet.
=OUTPUT=
--router.config
write term
interface Ethernet0/0
 nameif inside
route inside 0.0.0.0 0.0.0.0 10.1.2.3
access-list inside extended permit ip host 1.1.1.1 any
access-list inside extended permit ip host 2.2.2.2 any
access-list inside extended permit ip host 3.3.3.3 any
access-list inside extended permit ip host 4.4.4.4 any
access-group inside in interface inside
router#
--router.change
configure terminal
router#no route inside 0.0.0.0 0.0.0.0 10.1.2.3
router#route inside 0.0.0.0 0.0.0.0 10.1.2.4
router#no access-list inside line 4 extended permit ip host 4.4.4.4 any
router#access-list inside line 2 extended permit ip host 4.4.4.4 any
router#end
router#write memory
Building configuration...
Cryptochecksum: abcdef01 44444444 12345678 98765432

123456 bytes copied in 0.330 secs
[OK]
router#
=END=

############################################################
=TITLE=Expected WARNING with object-group
=SCENARIO=
[[login_scenario]]
# write term
interface Ethernet0/0
 nameif inside
access-list inside extended deny ip any any
access-group inside in interface inside
# access-list inside-DRC-0 extended permit ip object-group g1-DRC-0 object-group g1-DRC-0
WARNING: Same object-group is used more than once in one config line. This config is redundant. Please use seperate object-groups
# write memory
[OK]
=NETSPOC=
object-group network g1
 network-object host 1.1.1.1
access-list inside extended permit ip object-group g1 object-group g1
access-group inside in interface inside
=OUTPUT=
--router.change
configure terminal
router#object-group network g1-DRC-0
router#network-object host 1.1.1.1
router#access-list inside-DRC-0 extended permit ip object-group g1-DRC-0 object-group g1-DRC-0
WARNING: Same object-group is used more than once in one config line. This config is redundant. Please use seperate object-groups
router#access-group inside-DRC-0 in interface inside
router#clear configure access-list inside
router#end
router#write memory
[OK]
router#
=END=

############################################################
=TITLE=Expected WARNING with tunnel-group l2l
=SCENARIO=
[[login_scenario]]
# tunnel-group some-name-DRC-0 type ipsec-l2l
WARNING: For IKEv1, L2L tunnel-groups that have names which are not an IP
address may only be used if the tunnel authentication
method is Digital Certificates and/or The peer is
configured to use Aggressive Mode
# write memory
[OK]
=NETSPOC=
crypto ca certificate map some-name 10
 subject-name attr ea eq some-name
tunnel-group some-name type ipsec-l2l
tunnel-group some-name ipsec-attributes
 peer-id-validate nocheck
 ikev2 local-authentication certificate Trustpoint2
 ikev2 remote-authentication certificate
tunnel-group-map some-name 10 some-name
=OUTPUT=
--router.change
configure terminal
router#crypto ca certificate map some-name-DRC-0 10
router#subject-name attr ea eq some-name
router#tunnel-group some-name-DRC-0 type ipsec-l2l
WARNING: For IKEv1, L2L tunnel-groups that have names which are not an IP
address may only be used if the tunnel authentication
method is Digital Certificates and/or The peer is
configured to use Aggressive Mode
router#tunnel-group some-name-DRC-0 ipsec-attributes
router#peer-id-validate nocheck
router#ikev2 local-authentication certificate Trustpoint2
router#ikev2 remote-authentication certificate
router#tunnel-group-map some-name-DRC-0 10 some-name-DRC-0
router#end
router#write memory
[OK]
router#
=END=

############################################################
=TITLE=Expected command output: INFO
=SCENARIO=
[[login_scenario]]
# certificate-group-map map-1-DRC-0 10 tunnel-1-DRC-0
INFO: If a certificate map is configured ASA  will ask all users loading the logon page for a client certificate.
# write memory
[OK]
=NETSPOC=
crypto ca certificate map map-1 10
 subject-name attr ea co @SUB.EXAMPLE.com
tunnel-group tunnel-1 type remote-access
tunnel-group tunnel-1 general-attributes
tunnel-group tunnel-1 ipsec-attributes
 peer-id-validate req
 isakmp ikev1-user-authentication none
 trust-point ASDM_TrustPoint1
webvpn
 certificate-group-map map-1 10 tunnel-1
=OUTPUT=
--router.change
configure terminal
router#crypto ca certificate map map-1-DRC-0 10
router#subject-name attr ea co @sub.example.com
router#tunnel-group tunnel-1-DRC-0 type remote-access
router#tunnel-group tunnel-1-DRC-0 general-attributes
router#tunnel-group tunnel-1-DRC-0 ipsec-attributes
router#peer-id-validate req
router#isakmp ikev1-user-authentication none
router#trust-point ASDM_TrustPoint1
router#webvpn
router#certificate-group-map map-1-DRC-0 10 tunnel-1-DRC-0
INFO: If a certificate map is configured ASA  will ask all users loading the logon page for a client certificate.
router#end
router#write memory
[OK]
router#
=END=

############################################################
=TITLE=Unexpected warning
=SCENARIO=
[[login_scenario]]
# route inside 0.0.0.0 0.0.0.0 10.1.2.4
WARNING: Route already exists
# write memory
[OK]
=NETSPOC=
route inside 0.0.0.0 0.0.0.0 10.1.2.4
=WARNING=
WARNING>>> Got unexpected output from 'route inside 0.0.0.0 0.0.0.0 10.1.2.4':
WARNING>>> WARNING: Route already exists
=END=

############################################################
=TITLE=Unexpected command output
=SCENARIO=
[[login_scenario]]
# configure terminal
foo
=NETSPOC=
route inside 0.0.0.0 0.0.0.0 10.1.2.4
=ERROR=
ERROR>>> Got unexpected output from 'configure terminal':
ERROR>>> foo
=END=

############################################################
=TITLE=Invalid reference in device config
=SCENARIO=
[[login_scenario]]
# write term
interface Ethernet0/0
 nameif inside
access-group inside in interface inside
=NETSPOC=
access-list inside extended permit ip host 1.1.1.1 any
access-group inside in interface inside
=ERROR=
ERROR>>> While reading device: 'access-group inside in interface inside' references unknown 'access-list inside'
=END=

############################################################
=TITLE=Can't login
=SCENARIO=
netspoc@10.1.2.3's password: <!>
netspoc@10.1.2.3's password: <!>
Connection to 172.20.82.1 closed by remote host.
=NETSPOC=NONE
=ERROR=
ERROR>>> while waiting for prompt '[>#]': expect: timer expired after 1 seconds
=END=

############################################################
=TITLE=Wrong hostname
=SCENARIO=
netspoc@10.1.2.3's password: <!>
router#
# show hostname
wrong
=NETSPOC=NONE
=ERROR=
ERROR>>> Wrong device name: "wrong", expected: "router"
=END=

############################################################
=TITLE=Missing NetSPoC banner
=SCENARIO=
netspoc@10.1.2.3's password: <!>
router#
# show hostname
router
=NETSPOC=
route inside 0.0.0.0 0.0.0.0 10.1.2.4
=ERROR=
ERROR>>> Missing banner at NetSPoC managed device
=END=

############################################################
=TITLE=Write memory failed
=SCENARIO=
** managed by NetSPoC **
netspoc@10.1.2.3's password: <!>
router#
# show hostname
router
# write memory
FAILED
=NETSPOC=
route inside 0.0.0.0 0.0.0.0 10.1.2.4
=ERROR=
ERROR>>> Command 'write memory' failed, missing [OK] in output:
ERROR>>> FAILED
=END=
