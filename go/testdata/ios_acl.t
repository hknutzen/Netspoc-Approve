############################################################
=TITLE= Rule for device access located before removed deny rule
=DEVICE=
ip access-list extended test
 permit tcp host 10.1.1.11 host 10.3.4.1 eq 22
 permit tcp host 10.1.1.11 host 10.5.6.1 eq 22
 deny ip any host 10.1.2.0
 permit tcp any 10.3.4.0 0.0.0.255 eq 80
 permit tcp any 10.3.4.0 0.0.0.255 eq 443
 deny ip any any

interface Ethernet1
 ip access-group test in
=NETSPOC=
ip access-list extended test
 permit tcp host 10.1.1.11 host 10.5.6.1 eq 22
 permit tcp host 10.1.1.11 host 10.9.9.1 eq 22
 permit tcp any 10.3.4.0 0.0.0.255 eq 80
 permit tcp any 10.3.4.0 0.0.0.255 eq 443
 deny ip any any

interface Ethernet1
 ip access-group test in
=OUTPUT=
ip access-list resequence test 10000 10000
ip access-list extended test
30001 permit tcp host 10.1.1.11 host 10.9.9.1 eq 22
no 30000
no 10000
ip access-list resequence test 10 10
=END=

############################################################
=TITLE= Rule for device access located before inserted deny rule
=DEVICE=
ip access-list extended test
 permit tcp host 10.1.1.11 host 10.5.6.1 eq 22
 permit tcp host 10.1.1.11 host 10.9.9.1 eq 22
 permit tcp any 10.3.4.0 0.0.0.255 eq 80
 permit tcp any 10.3.4.0 0.0.0.255 eq 443
 deny ip any any

interface Ethernet1
 ip access-group test in
=NETSPOC=
ip access-list extended test
 permit tcp host 10.1.1.11 host 10.3.4.1 eq 22
 permit tcp host 10.1.1.11 host 10.5.6.1 eq 22
 deny ip any host 10.1.2.0
 permit tcp any 10.3.4.0 0.0.0.255 eq 80
 permit tcp any 10.3.4.0 0.0.0.255 eq 443
 deny ip any any

interface Ethernet1
 ip access-group test in
=OUTPUT=
ip access-list resequence test 10000 10000
ip access-list extended test
1 permit tcp host 10.1.1.11 host 10.3.4.1 eq 22
20001 deny ip any host 10.1.2.0
no 20000
ip access-list resequence test 10 10
=END=

############################################################
=TITLE=Move deny rule before permit block (1)
=DEVICE=
ip access-list extended test
 permit tcp any host 10.3.4.3
 permit tcp any host 10.3.4.4
 permit tcp any host 10.3.4.1
 permit tcp any host 10.3.4.2
 deny ip host 10.1.2.3 any

interface Ethernet1
 ip access-group test in
=NETSPOC=
ip access-list extended test
 deny ip host 10.1.2.3 any
 permit tcp any host 10.3.4.3
 permit tcp any host 10.3.4.4
 permit tcp any host 10.3.4.1
 permit tcp any host 10.3.4.2

interface Ethernet1
 ip access-group test in
=OUTPUT=
ip access-list resequence test 10000 10000
ip access-list extended test
no 50000\N 1 deny ip host 10.1.2.3 any
ip access-list resequence test 10 10
=END=

############################################################
=TITLE=Must not move deny rule in middle of permit block
=DEVICE=
ip access-list extended test
 permit tcp any host 10.3.4.3
 permit tcp any host 10.3.4.2
 permit tcp any host 10.3.4.4
 deny ip host 10.1.2.3 any

interface Ethernet1
 ip access-group test in
=NETSPOC=
ip access-list extended test
 deny ip host 10.1.2.3 any
 permit tcp any host 10.3.4.2
 permit tcp any host 10.3.4.3
 permit tcp any host 10.3.4.4

interface Ethernet1
 ip access-group test in
=OUTPUT=
ip access-list resequence test 10000 10000
ip access-list extended test
no 40000\N 10001 deny ip host 10.1.2.3 any
no 10000\N 20001 permit tcp any host 10.3.4.3
ip access-list resequence test 10 10
=END=

############################################################
=TITLE=Move deny in front of moved line
=DEVICE=
ip access-list extended test
 permit tcp any host 10.3.4.1
 permit tcp any host 10.3.4.2
 permit tcp any host 10.3.4.3
 deny ip host 10.1.1.2 any

interface Ethernet1
 ip access-group test in
=NETSPOC=
ip access-list extended test
 deny ip host 10.1.1.2 any
 permit tcp any host 10.3.4.2
 permit tcp any host 10.3.4.3
 deny ip host 10.1.1.1 any
 permit tcp any host 10.3.4.1

interface Ethernet1
 ip access-group test in
=OUTPUT=
ip access-list resequence test 10000 10000
ip access-list extended test
no 40000\N 10001 deny ip host 10.1.1.2 any
40001 deny ip host 10.1.1.1 any
no 10000\N 40002 permit tcp any host 10.3.4.1
ip access-list resequence test 10 10
=END=

############################################################
=TITLE=Insert deny rule into permutated permit blocks
=DEVICE=
ip access-list extended test
 permit tcp any host 10.3.4.1
 permit tcp any host 10.3.4.6
 permit tcp any host 10.3.4.2
 permit tcp any host 10.3.4.3
 permit tcp any host 10.3.4.5
 permit tcp any host 10.3.4.4
 deny ip host 10.1.2.3 any
 permit tcp any host 10.3.5.3
 permit tcp any host 10.3.5.2
 permit tcp any host 10.3.5.1

interface Ethernet1
 ip access-group test in
=NETSPOC=
ip access-list extended test
 permit tcp any host 10.3.4.6
 permit tcp any host 10.3.4.1
 permit tcp any host 10.3.4.2
 deny ip host 10.1.2.3 any
 permit tcp any host 10.3.4.3
 permit tcp any host 10.3.4.4
 permit tcp any host 10.3.4.5
 permit tcp any host 10.3.5.1
 permit tcp any host 10.3.5.2
 permit tcp any host 10.3.5.3

interface Ethernet1
 ip access-group test in
=OUTPUT=
ip access-list resequence test 10000 10000
ip access-list extended test
no 70000\N 30001 deny ip host 10.1.2.3 any
no 50000\N 90001 permit tcp any host 10.3.4.5
ip access-list resequence test 10 10
=END=

############################################################
=TITLE=Add permit line before deny block
=DEVICE=
ip access-list extended inside
 permit ip host 4.4.4.4 any
 deny ip any host 3.3.3.3
 deny ip any host 2.2.2.2
 deny ip any host 1.1.1.1
interface Ethernet0/0
 ip access-group inside in
=NETSPOC=
ip access-list extended inside
 permit ip host 5.5.5.5 any
 permit ip host 4.4.4.4 any
 deny ip any host 1.1.1.1
 deny ip any host 2.2.2.2
 deny ip any host 3.3.3.3
interface Ethernet0/0
 ip access-group inside in
=OUTPUT=
ip access-list resequence inside 10000 10000
ip access-list extended inside
1 permit ip host 5.5.5.5 any
ip access-list resequence inside 10 10
=END=

############################################################
=TITLE=Add permit line inside deny block
=DEVICE=
ip access-list extended inside
 permit ip host 5.5.5.5 any
 deny ip any host 3.3.3.3
 deny ip any host 2.2.2.2
 deny ip any host 1.1.1.1
interface Ethernet0/0
 ip access-group inside in
=NETSPOC=
ip access-list extended inside
 permit ip host 5.5.5.5 any
 deny ip any host 2.2.2.2
 permit ip host 4.4.4.4 any
 deny ip any host 3.3.3.3
 deny ip any host 1.1.1.1
interface Ethernet0/0
 ip access-group inside in
=OUTPUT=
ip access-list resequence inside 10000 10000
ip access-list extended inside
30001 permit ip host 4.4.4.4 any
no 20000\N 30002 deny ip any host 3.3.3.3
ip access-list resequence inside 10 10
=END=

############################################################
=TITLE=Add permit line behind deny block
=DEVICE=
ip access-list extended inside
 deny ip any host 3.3.3.3
 deny ip any host 2.2.2.2
 deny ip any host 1.1.1.1
interface Ethernet0/0
 ip access-group inside in
=NETSPOC=
ip access-list extended inside
 deny ip any host 1.1.1.1
 deny ip any host 2.2.2.2
 deny ip any host 3.3.3.3
 permit ip host 5.5.5.5 any
interface Ethernet0/0
 ip access-group inside in
=OUTPUT=
ip access-list resequence inside 10000 10000
ip access-list extended inside
30003 permit ip host 5.5.5.5 any
ip access-list resequence inside 10 10
=END=

############################################################
=TITLE=Move permit line before first line of block
=DEVICE=
ip access-list extended test
 permit ip any host 1.1.1.1
 permit ip any host 2.2.2.2
 permit ip any host 3.3.3.3
 permit ip any host 4.4.4.4
 permit ip any host 5.5.5.5

interface Ethernet1
 ip access-group test in
=NETSPOC=
ip access-list extended test
 permit ip any host 5.5.5.5
 permit ip any host 1.1.1.1
 permit ip any host 2.2.2.2
 permit ip any host 3.3.3.3
 permit ip any host 4.4.4.4

interface Ethernet1
 ip access-group test in
=OUTPUT=NONE

############################################################
=TITLE=Move permit line after last line of block
=DEVICE=
ip access-list extended test
 permit ip any host 1.1.1.1
 permit ip any host 2.2.2.2
 permit ip any host 3.3.3.3
 permit ip any host 4.4.4.4
 permit ip any host 5.5.5.5

interface Ethernet1
 ip access-group test in
=NETSPOC=
ip access-list extended test
 permit ip any host 2.2.2.2
 permit ip any host 3.3.3.3
 permit ip any host 4.4.4.4
 permit ip any host 5.5.5.5
 permit ip any host 1.1.1.1

interface Ethernet1
 ip access-group test in
=OUTPUT=NONE

############################################################
=TITLE=Add permit line to permit block
=DEVICE=
ip access-list extended test
 permit ip any host 1.1.1.1
 permit ip any host 2.2.2.2
 permit ip any host 3.3.3.3
 permit ip any host 4.4.4.4
 permit ip any host 5.5.5.5
 permit ip any host 6.6.6.6

interface Ethernet1
 ip access-group test in
=NETSPOC=
ip access-list extended test
 permit ip any host 3.3.3.3
 permit ip any host 4.4.4.4
 permit ip any host 5.5.5.5
 permit ip any host 1.1.1.1
 permit ip any host 2.2.2.2
 permit ip any host 7.7.7.7
 permit ip any host 6.6.6.6

interface Ethernet1
 ip access-group test in
=OUTPUT=
ip access-list resequence test 10000 10000
ip access-list extended test
50003 permit ip any host 7.7.7.7
ip access-list resequence test 10 10
=END=

############################################################
=TITLE=Add at end of ACL
=DEVICE=
ip access-list extended test
 permit icmp any any echo-reply

interface Ethernet1
 ip access-group test in
=NETSPOC=
ip access-list extended test
 permit icmp any any 0
 permit ip any host 10.0.1.3
 permit ip any host 10.0.1.2
 permit ip any host 10.0.1.100

interface Ethernet1
 ip access-group test in
=OUTPUT=
ip access-list resequence test 10000 10000
ip access-list extended test
10001 permit ip any host 10.0.1.3
10002 permit ip any host 10.0.1.2
10003 permit ip any host 10.0.1.100
ip access-list resequence test 10 10
=END=

############################################################
=TITLE=Change ACL, prevent lockout (1)
# ACL lines must be deleted in reversed order,
# otherwise Netspoc server would be locked out.
=DEVICE=
ip access-list extended test
! Netspoc server to interface of device
 permit ip host 10.0.11.111 host 10.9.9.1
 deny ip any any

interface Ethernet1
 ip access-group test in
=NETSPOC=
ip access-list extended test
! Network management to interface of device
 permit ip 10.0.11.0 0.0.0.255 host 10.9.9.1
 deny ip any any

interface Ethernet1
 ip access-group test in
=OUTPUT=
ip access-list resequence test 10000 10000
ip access-list extended test
10001 permit ip 10.0.11.0 0.0.0.255 host 10.9.9.1
no 10000
ip access-list resequence test 10 10
=END=

############################################################
=TITLE=Change ACL, prevent lockout (2)
# ACL lines must be deleted in reversed order,
# otherwise Netspoc server would be locked out.
=DEVICE=
ip access-list extended test
! Netspoc server to interface of device
 permit ip host 10.0.11.111 host 10.9.9.1
 deny ip any host 10.9.9.1
 permit tcp host 10.2.3.4 host 10.3.4.5
 deny ip any any

interface Ethernet1
 ip access-group test in
=NETSPOC=
ip access-list extended test
 permit tcp host 10.2.3.4 host 10.3.4.5
! Network management to interface of device
 permit ip 10.0.11.0 0.0.0.255 host 10.9.9.1
 deny ip any any

interface Ethernet1
 ip access-group test in
=OUTPUT=
ip access-list resequence test 10000 10000
ip access-list extended test
30001 permit ip 10.0.11.0 0.0.0.255 host 10.9.9.1
no 20000
no 10000
ip access-list resequence test 10 10
=END=

############################################################
=TITLE=Change ACL, avoid ephemeral permit
=DEVICE=
ip access-list extended test
 permit tcp host 10.2.3.4 host 10.3.4.5
 permit tcp host 10.2.3.4 host 10.3.4.6
 permit udp host 10.2.3.4 host 10.3.4.5
 permit udp host 10.2.3.4 host 10.3.4.6
 deny ip host 10.1.2.3 host 10.1.1.1 log
 deny ip any any

interface Ethernet1
 ip access-group test in
=NETSPOC=
ip access-list extended test
 deny ip host 10.1.2.3 host 10.1.1.1 log
 permit ip any host 10.1.1.1
 permit tcp host 10.2.3.4 host 10.3.4.5
 permit tcp host 10.2.3.4 host 10.3.4.6
 permit udp host 10.2.3.4 host 10.3.4.5
 permit udp host 10.2.3.4 host 10.3.4.6
 deny ip any any

interface Ethernet1
 ip access-group test in
=OUTPUT=
ip access-list resequence test 10000 10000
ip access-list extended test
no 50000\N 1 deny ip host 10.1.2.3 host 10.1.1.1 log
2 permit ip any host 10.1.1.1
ip access-list resequence test 10 10
=END=

############################################################
=TITLE=Handle ACL with remark
=DEVICE=
ip access-list extended inside
 remark Test0
 remark Test1
 permit ip host 1.1.1.1 any
 permit ip host 2.2.2.2 any
 remark Test2
 permit ip host 4.4.4.4 any
interface Ethernet0/0
 ip access-group inside in
=NETSPOC=
ip access-list extended inside
 remark Test0
 permit ip host 1.1.1.1 any
 remark Test1
 permit ip host 4.4.4.4 any
 permit ip host 5.5.5.5 any
 remark Test3
interface Ethernet0/0
 ip access-group inside in
=OUTPUT=
ip access-list resequence inside 10000 10000
ip access-list extended inside
60001 permit ip host 5.5.5.5 any
60002 remark Test3
no 50000
no 40000
ip access-list resequence inside 10 10
=END=

############################################################
=TITLE=Permit- and deny-blocks with remarks
=DEVICE=
ip access-list extended inside
 remark Test1
 permit ip host 1.1.1.1 any
 remark Test2
 permit ip host 2.2.2.2 any
 remark Test3
 deny ip host 3.3.3.3 any
 remark Test5
 deny ip host 5.5.5.5 any
 remark Test4
 deny ip host 4.4.4.4 any
 remark Test6
 permit ip host 6.6.6.6 any
 remark The end
interface Ethernet0/0
 ip access-group inside in
=NETSPOC=
ip access-list extended inside
 remark UDP
 deny udp any any
 remark Test1
 permit ip host 1.1.1.1 any
 remark Test3
 deny ip host 3.3.3.3 any
 remark Test4
 permit ip host 1.4.1.4 any
 deny ip host 4.4.4.4 any
 remark Test5 + 1.5
 deny ip host 5.5.5.5 any
 deny ip host 1.5.1.5 any
 remark Test6
 permit ip host 6.6.6.6 any
 permit ip host 2.2.2.2 any
 remark The end
interface Ethernet0/0
 ip access-group inside in
=OUTPUT=
ip access-list resequence inside 10000 10000
ip access-list extended inside
1 remark UDP
2 deny udp any any
90001 permit ip host 1.4.1.4 any
100001 remark Test5 + 1.5
no 80000\N 100002 deny ip host 5.5.5.5 any
100003 deny ip host 1.5.1.5 any
no 40000\N 120001 permit ip host 2.2.2.2 any
no 70000
no 30000
ip access-list resequence inside 10 10
=END=
