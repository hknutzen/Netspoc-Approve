
############################################################
=TITLE=Ignore commands in banner
=DEVICE=
banner motd ^CCC
ip route 0.0.0.0 0.0.0.0 10.1.1.1
^C
ip route 0.0.0.0 0.0.0.0 10.2.2.2
=NETSPOC=
ip route 0.0.0.0 0.0.0.0 10.3.3.3
=OUTPUT=
no ip route 0.0.0.0 0.0.0.0 10.2.2.2\N ip route 0.0.0.0 0.0.0.0 10.3.3.3
=END=

############################################################
=TITLE=Skip certificate chain
=DEVICE=
crypto pki certificate chain VPND012345
 certificate 6D0002F1B7E1307AF07D82AEEF00000002F1B7
  00000000 11111111 22222222 33333333 44444444 55555555 66666666 77777777
  88888888 99999999 AAAAAAAA BBBBBBBB CCCCCCCC DDDDDDDD EEEEEEEE FFFFFFFF
  ABCDEFAB EEEEFFFF EE
  	quit
ip route 0.0.0.0 0.0.0.0 10.2.2.2
=NETSPOC=
ip route 0.0.0.0 0.0.0.0 10.2.2.2
=OUTPUT=NONE

############################################################
=TITLE=Parse routing and ACL
=TEMPL=input
ip route 10.20.0.0 255.255.0.0 10.1.2.3
ip route 0.0.0.0 0.0.0.0 10.1.2.3

ip access-list extended Ethernet0_in
 deny ip any any
interface Ethernet0
 ip access-group Ethernet0_in in

ip access-list extended Ethernet1_in
 permit udp 10.0.6.0 0.0.0.255 10.0.2.0 0.0.0.255 eq 123
 permit 50 10.0.5.0 0.0.0.255 host 10.0.1.11
 permit udp host 10.0.12.3 host 10.0.1.11 eq 7938
 permit tcp any host 10.0.1.11 range 7937 8999
 permit icmp any host 10.0.1.11 3 4
 deny ip any any log
interface Ethernet1
 ip access-group Ethernet1_in in
=DEVICE=[[input]]
=NETSPOC=[[input]]
=OUTPUT=NONE

############################################################
=TITLE=Parse crypto map
=TEMPL=input
ip access-list extended crypto-Dialer1-1
 permit ip 10.156.9.128 0.0.0.7 any

ip access-list extended crypto-filter-Dialer1-1
 permit udp 10.1.11.0 0.0.0.255 host 10.156.9.129 gt 1023
 deny ip any any

crypto map crypto-Dialer1 1 ipsec-isakmp
 match address crypto-Dialer1-1
 set ip access-group crypto-filter-Dialer1-1 in
 set peer 193.101.67.17

ip access-list extended Dialer1_in
 permit 50 host 193.101.67.17 any
 permit 50 host 193.101.67.20 any
 deny ip any any
ip access-list extended Vlan10_in
 permit tcp 10.156.9.128 0.0.0.7 10.1.45.10 0.0.0.1 range 950 969
 deny ip any any

interface Dialer1
 crypto map crypto-Dialer1
 ip address negotiated
 ip access-group Dialer1_in in
interface Vlan10
 ip address 10.156.9.129 255.255.255.248
 ip access-group Vlan10_in in
=DEVICE=[[input]]
=NETSPOC=[[input]]
=OUTPUT=NONE

############################################################
=TITLE=Change routing
=DEVICE=
ip route 10.20.0.0 255.255.0.0 10.1.2.3
ip route 10.30.0.0 255.255.0.0 10.1.2.3
ip route 10.40.0.0 255.255.0.0 10.1.2.3
ip route vrf 013 10.30.0.0 255.255.0.0 10.3.3.3
ip route vrf 013 10.40.0.0 255.255.0.0 10.3.3.4
=NETSPOC=
ip route 10.10.0.0 255.255.0.0 10.1.2.3
ip route 10.20.0.0 255.255.0.0 10.1.2.3
ip route 10.40.0.0 255.255.0.0 10.1.2.4
ip route vrf 013 10.20.0.0 255.255.0.0 10.3.3.3
ip route vrf 013 10.30.0.0 255.255.0.0 10.3.3.4
=OUTPUT=
ip route 10.10.0.0 255.255.0.0 10.1.2.3
no ip route 10.40.0.0 255.255.0.0 10.1.2.3\N ip route 10.40.0.0 255.255.0.0 10.1.2.4
ip route vrf 013 10.20.0.0 255.255.0.0 10.3.3.3
no ip route vrf 013 10.30.0.0 255.255.0.0 10.3.3.3\N ip route vrf 013 10.30.0.0 255.255.0.0 10.3.3.4
no ip route 10.30.0.0 255.255.0.0 10.1.2.3
no ip route vrf 013 10.40.0.0 255.255.0.0 10.3.3.4
=END=

############################################################
=TITLE=Change IPv6 routing with vrf
=DEVICE=
ipv6 route vrf 001 10::3:0/120 10::2:2 1
ipv6 route vrf 013 10::4:0/120 10::2:2 2
=NETSPOC=
--ipv6/router
ipv6 route vrf 001 10::3:0/120 10::2:1
ipv6 route vrf 013 10::4:0/120 10::2:2
ipv6 route vrf 013 10::5:0/120 10::2:2
=OUTPUT=
no ipv6 route vrf 001 10::3:0/120 10::2:2 1\N ipv6 route vrf 001 10::3:0/120 10::2:1
ipv6 route vrf 013 10::5:0/120 10::2:2
=END=

############################################################
=TITLE=Leave routing in global VRF unchanged
# Routes and ACL in global VRF
=DEVICE=
ip route 10.20.0.0 255.255.0.0 10.1.2.3
ip route 10.30.0.0 255.255.0.0 10.1.2.3
ip route 10.40.0.0 255.255.0.0 10.1.2.3
ip access-list extended acl2
 permit ip any host 10.0.1.1
interface Ethernet2
 ip access-group acl2 in
=NETSPOC=
# Only ACL is configured from Netspoc, routes are left unchanged
ip access-list extended acl2
 permit ip any host 10.0.1.1
interface Ethernet2
 ip access-group acl2 in
=OUTPUT=NONE
=WARNING=
No IPv4 routing specified, leaving untouched
comp: device unchanged
=OPTIONS=--quiet=false

############################################################
=TITLE=Route with interface name
=DEVICE=
ip route 0.0.0.0 0.0.0.0 Dialer1
ip route 10.10.0.0 255.255.0.0 serial0 10.1.2.3
ip route 10.20.0.0 255.255.0.0 10.1.2.3
=NETSPOC=NONE
=OUTPUT=NONE
=WARNING=
No IPv4 routing specified, leaving untouched
comp: device unchanged
=OPTIONS=--quiet=false

############################################################
=TITLE=Named static route
=DEVICE=
ip route 10.10.0.0 255.255.0.0 10.1.2.3 name x
ip route 10.20.0.0 255.255.0.0 10.1.2.3
=NETSPOC=
ip route 10.10.0.0 255.255.0.0 10.1.2.3
ip route 10.20.0.0 255.255.0.0 10.1.2.3
=OUTPUT=
no ip route 10.10.0.0 255.255.0.0 10.1.2.3 name x\N ip route 10.10.0.0 255.255.0.0 10.1.2.3
=END=

############################################################
=TITLE=Parse ACL with named protocols and log attribute
=DEVICE=
ip access-list extended test-DRC-0
 permit ahp any 10.0.1.11
 permit esp any 10.0.1.11
 permit icmp any host 10.0.1.11 packet-too-big
 permit udp 10.0.6.0 0.0.0.255 host 10.0.1.11 eq ntp
 permit gre 10.0.5.0 0.0.0.255 host 10.0.1.11
 permit igmp 10.0.5.0 0.0.0.255 host 10.0.1.11
 permit udp host 10.0.12.3 host 10.0.1.11 eq www
 permit tcp any host 10.0.1.11 range 70 www
 deny ip any any

interface Serial1
 ip unnumbered Ethernet1
 ip access-group test-DRC-0 in
=NETSPOC=
ip access-list extended test
 permit icmp any host 10.0.1.11 3 4
 permit udp 10.0.6.0 0.0.0.255 host 10.0.1.11 eq 123
 permit 47 10.0.5.0 0.0.0.255 host 10.0.1.11
 permit 2 10.0.5.0 0.0.0.255 host 10.0.1.11
 permit esp any 10.0.1.11
! permit udp host 10.0.12.3 host 10.0.1.11 eq 80
 permit tcp any host 10.0.1.11 range 70 80
 permit ahp any 10.0.1.11
 deny ip any any log-input

interface Serial1
 ip unnumbered Ethernet1
 ip access-group test in
=OUTPUT=
ip access-list resequence test-DRC-0 10000 10000
ip access-list extended test-DRC-0
no 10000\N 90001 permit 51 any 10.0.1.11
no 90000\N 90002 deny ip any any log-input
no 70000
ip access-list resequence test-DRC-0 10 10
=END=

############################################################
=TITLE=Ignore referenced but unknown ACL
=DEVICE=
interface eth0
 ip address 10.1.1.1 255.255.255.0
 ip access-group eth0_in-DRC-0 in
 ip access-group eth0_out-DRC-0 out
interface eth1
 shutdown
 ip access-group eth1_in-DRC-0 in
=NETSPOC=NONE
=OUTPUT=NONE

############################################################
=TITLE=Bug fix: Recognize ACL at shutdown interface als unchanged
=DEVICE=
ip access-list extended Vlan113_in-DRC-2
 permit udp any 10.11.11.0 0.0.0.63
 deny   ip any any
interface Vlan113
 vrf forwarding 013
 ip address 10.1.1.1 255.255.255.128
 ip access-group Vlan113_in-DRC-2 in
 shutdown
=NETSPOC=
ip access-list extended Vlan113_in
 permit udp any 10.11.11.0 0.0.0.63
 deny   ip any any
interface Vlan113
 vrf forwarding 013
 ip address 10.1.1.1 255.255.255.128
 ip access-group Vlan113_in in
=OUTPUT=NONE

############################################################
=TITLE=Change ACL at shutdown interface
=DEVICE=
ip access-list extended Vlan113_in-DRC-2
 permit udp any 10.11.11.0 0.0.0.63
 deny   ip any any
interface Vlan113
 vrf forwarding 013
 ip address 10.1.1.1 255.255.255.128
 ip access-group Vlan113_in-DRC-2 in
 shutdown
=NETSPOC=
ip access-list extended Vlan113_in
 permit udp any host 10.11.11.11
 deny   ip any any
interface Vlan113
 vrf forwarding 013
 ip address 10.1.1.1 255.255.255.128
 ip access-group Vlan113_in in
=OUTPUT=
ip access-list resequence Vlan113_in-DRC-2 10000 10000
ip access-list extended Vlan113_in-DRC-2
10001 permit udp any host 10.11.11.11
no 10000
ip access-list resequence Vlan113_in-DRC-2 10 10
=END=

############################################################
=TITLE=Bug fix: Must not mark unknown interface of device as needed
=DEVICE=
ip access-list extended eth0_in-DRC-0
 permit esp host 10.1.1.1 any
 deny   ip any any
interface Null0
 no ip unreachables
interface eth0
 ip address dhcp
 ip access-group eth0_in-DRC-0 in
=NETSPOC=
ip access-list extended eth0_in
 permit 50 host 10.1.1.1 any
 deny ip any any
interface eth0
 ip address negotiated
 ip access-group eth0_in in
=OUTPUT=NONE

############################################################
=TITLE=Bind ACL at interface with referenced but unknown ACL
# But handle known ACL.
=DEVICE=
ip access-list extended eth0_out-DRC-0
 deny ip any any
interface eth0
 ip address 10.1.1.1 255.255.255.0
 ip access-group eth0_in-DRC-0 in
 ip access-group eth0_out-DRC-0 out
=NETSPOC=
ip access-list extended eth0_in
 deny ip any any
ip access-list extended eth0_out
 permit tcp 10.1.1.0 255.255.255.0 any eq 80
 deny ip any any
interface eth0
 ip address 10.1.1.1 255.255.255.0
 ip access-group eth0_in in
 ip access-group eth0_out out
=OUTPUT=
interface eth0
no ip access-group eth0_in-DRC-0 in
ip access-list resequence eth0_out-DRC-0 10000 10000
ip access-list extended eth0_out-DRC-0
1 permit tcp 10.1.1.0 255.255.255.0 any eq 80
ip access-list resequence eth0_out-DRC-0 10 10
ip access-list extended eth0_in-DRC-0
deny ip any any
exit
interface eth0
ip access-group eth0_in-DRC-0 in
=END=

############################################################
=TITLE=Must not delete ACL referenced by shutdown or by unknown interface
=DEVICE=
ip access-list extended eth0_in-DRC-0
 deny ip any any
interface eth0
 shutdown
 ip access-group eth0_in-DRC-0 in
interface eth1
 ip address 10.1.1.1 255.255.255.0
 ip access-group eth0_in-DRC-0 in
interface eth2
 ip address 10.1.2.1 255.255.255.0
 ip access-group eth0_in-DRC-0 in
=NETSPOC=
interface eth2
 ip address 10.1.2.1 255.255.255.0
=WARNING=
WARNING>>> Interface 'eth1' on device is not known by Netspoc
=OUTPUT=
interface eth2
no ip access-group eth0_in-DRC-0 in
=END=

############################################################
=TITLE=Change ACL referenced from two interfaces
=DEVICE=
ip access-list extended test
 permit udp 10.0.6.0 0.0.0.255 host 10.0.1.11 eq ntp
interface Serial1
 ip unnumbered Ethernet1
 ip access-group test in
interface Serial2
 ip unnumbered Ethernet1
 ip access-group test in
=NETSPOC=
ip access-list extended test1
 permit udp 10.0.6.0 0.0.0.255 host 10.0.1.11 eq 123
interface Serial1
 ip unnumbered Ethernet1
 ip access-group test1 in
ip access-list extended test2
 permit udp 10.0.6.0 0.0.0.255 host 10.0.1.11 eq 122
interface Serial2
 ip unnumbered Ethernet1
 ip access-group test2 in
=OUTPUT=
ip access-list extended test2-DRC-0
permit udp 10.0.6.0 0.0.0.255 host 10.0.1.11 eq 122
exit
interface Serial2
ip access-group test2-DRC-0 in
=END=

############################################################
=TITLE=Reference same ACL two times
=DEVICE=
ip access-list extended test-DRC-0
 permit udp 10.0.6.0 0.0.0.255 host 10.0.1.11 eq ntp
interface Serial1
 ip unnumbered Ethernet1
 ip access-group test-DRC-0 in
 ip access-group test-DRC-0 out
=NETSPOC=
ip access-list extended test
 permit udp 10.0.6.0 0.0.0.255 host 10.0.1.11 eq ntp
interface Serial1
 ip unnumbered Ethernet1
 ip access-group test in
 ip access-group test out
=OUTPUT=NONE

############################################################
=TITLE=Ignore sequence numbers
=DEVICE=
ip access-list extended inside
 10 remark Test1
 10 permit ip host 1.1.1.1 any
 700 permit ip host 2.2.2.2 any
 8000 remark Test2
 90000 permit ip host 4.4.4.4 any
interface Ethernet0/0
 ip access-group inside in
=NETSPOC=
ip access-list extended inside
 remark Test1
 permit ip host 1.1.1.1 any
 permit ip host 2.2.2.2 any
 remark Test2
 permit ip host 4.4.4.4 any
interface Ethernet0/0
 ip access-group inside in
=OUTPUT=NONE

############################################################
=TITLE=Remove incoming, add outgoing ACL
=DEVICE=
ip access-list extended test
 permit ip any host 10.0.1.1
interface Ethernet1
 ip access-group test in
=NETSPOC=
ip access-list extended test
 permit ip host 10.0.1.1 any
interface Ethernet1
 ip access-group test out
=OUTPUT=
interface Ethernet1
no ip access-group test in
ip access-list extended test-DRC-0
permit ip host 10.0.1.1 any
exit
interface Ethernet1
ip access-group test-DRC-0 out
exit
no ip access-list extended test
=END=

############################################################
=TITLE=ACL with unknown keyword
=DEVICE=
ip access-list extended test
 permit ip any host 10.0.1.1 fragments

interface Ethernet1
 ip access-group test in
=NETSPOC=
ip access-list extended test
 permit ip any host 10.0.1.1

interface Ethernet1
 ip access-group test in
=OUTPUT=
ip access-list extended test
no permit ip any host 10.0.1.1 fragments
permit ip any host 10.0.1.1
=END=

############################################################
=TITLE=Crypto maps differ in peer and in name
# match address of crypto-map is currently not handled.
=DEVICE=
crypto map VPN 1 ipsec-isakmp
 set peer 10.156.4.2

interface Ethernet1
 crypto map VPN
=NETSPOC=
ip access-list extended crypto-Ethernet1-1
 permit ip any 10.127.18.0 0.0.0.255
ip access-list extended crypto-filter-Ethernet1-1
 permit tcp host 10.127.18.1 host 10.1.11.40 eq 49
 deny ip any any
crypto map crypto-Ethernet1 1 ipsec-isakmp
 match address crypto-Ethernet1-1
 set ip access-group crypto-filter-Ethernet1-1 in
 set peer 10.156.4.206

interface Ethernet1
 crypto map crypto-Ethernet1
=OUTPUT=
ip access-list extended crypto-filter-Ethernet1-1-DRC-0
permit tcp host 10.127.18.1 host 10.1.11.40 eq 49
deny ip any any
crypto map VPN 2 ipsec-isakmp
set ip access-group crypto-filter-Ethernet1-1-DRC-0 in
set peer 10.156.4.206
exit
no crypto map VPN 1 ipsec-isakmp
=END=

############################################################
=TITLE=Remove crypto map part from device
=DEVICE=
crypto map VPN 1 ipsec-isakmp
 set peer 10.156.4.1
crypto map VPN 2 ipsec-isakmp
 set peer 10.156.4.2

interface Ethernet1
 crypto map VPN
=NETSPOC=
crypto map VPN 2 ipsec-isakmp
 set peer 10.156.4.2

interface Ethernet1
 crypto map VPN
=OUTPUT=
no crypto map VPN 1 ipsec-isakmp
=END=

############################################################
=TITLE=Remove crypto map from device
=DEVICE=
crypto map VPN 1 ipsec-isakmp
 set peer 10.156.4.1

interface Ethernet1
 crypto map VPN
=NETSPOC=
interface Ethernet1
=OUTPUT=
interface Ethernet1
no crypto map VPN
exit
no crypto map VPN 1 ipsec-isakmp
=END=

############################################################
=TITLE=Add crypto map to device
=DEVICE=
interface Ethernet1
=NETSPOC=
crypto map VPN 1 ipsec-isakmp
 set peer 10.156.4.1

interface Ethernet1
 crypto map VPN
=OUTPUT=
crypto map VPN-DRC-0 1 ipsec-isakmp
set peer 10.156.4.1
exit
interface Ethernet1
crypto map VPN-DRC-0
=END=

############################################################
=TITLE=Change crypto filter ACL
=DEVICE=
ip access-list extended crypto-Ethernet1-1
 permit ip any 10.127.18.0 0.0.0.255
ip access-list extended crypto-filter-Ethernet1-1
 permit tcp any host 10.1.13.30
 permit tcp any host 10.1.13.31
 permit tcp any host 10.1.13.32
 permit tcp any host 10.1.13.33
 deny ip any any
crypto map crypto-Ethernet1 1 ipsec-isakmp
 match address crypto-Ethernet1-1
 set ip access-group crypto-filter-Ethernet1-1 in
 set peer 10.156.4.206

interface Ethernet1
 crypto map crypto-Ethernet1
=NETSPOC=
ip access-list extended crypto-Ethernet1-1
 permit ip any 10.127.18.0 0.0.0.255
ip access-list extended crypto-filter-Ethernet1-1
 permit tcp any host 10.1.13.33
 permit tcp any host 10.1.13.34
 permit tcp any host 10.1.13.31
 permit tcp any host 10.1.13.32
 deny ip any any
crypto map crypto-Ethernet1 1 ipsec-isakmp
 match address crypto-Ethernet1-1
 set ip access-group crypto-filter-Ethernet1-1 in
 set peer 10.156.4.206

interface Ethernet1
 crypto map crypto-Ethernet1
=OUTPUT=
ip access-list resequence crypto-filter-Ethernet1-1 10000 10000
ip access-list extended crypto-filter-Ethernet1-1
10002 permit tcp any host 10.1.13.34
no 10000
ip access-list resequence crypto-filter-Ethernet1-1 10 10
=END=

############################################################
=TITLE=Change incoming crypto filter ACL
=DEVICE=
ip access-list extended crypto-filter-Ethernet1-1
 permit tcp host 10.127.18.1 host 10.1.11.40 eq 48
! permit tcp host 10.127.18.1 host 10.1.11.40 eq 49
 deny ip any any
crypto map VPN 1 ipsec-isakmp
 set ip access-group crypto-filter-Ethernet1-1 in
 set peer 10.156.4.206

interface Ethernet1
 crypto map VPN
=NETSPOC=
ip access-list extended crypto-filter-Ethernet1-1
! permit tcp host 10.127.18.1 host 10.1.11.40 eq 48
 permit tcp host 10.127.18.1 host 10.1.11.40 eq 49
 deny ip any any
crypto map crypto-Ethernet1 1 ipsec-isakmp
 set ip access-group crypto-filter-Ethernet1-1 in
 set peer 10.156.4.206

interface Ethernet1
 crypto map crypto-Ethernet1
=OUTPUT=
ip access-list resequence crypto-filter-Ethernet1-1 10000 10000
ip access-list extended crypto-filter-Ethernet1-1
10001 permit tcp host 10.127.18.1 host 10.1.11.40 eq 49
no 10000
ip access-list resequence crypto-filter-Ethernet1-1 10 10
=END=

############################################################
=TITLE=Change outgoing crypto filter ACL
=DEVICE=
ip access-list extended crypto-Ethernet1-1
 permit ip any 10.127.18.0 0.0.0.255
ip access-list extended crypto-filter-Ethernet1-1
 permit tcp host 10.127.18.1 host 10.1.11.40 eq 48
! permit tcp host 10.127.18.1 host 10.1.11.40 eq 49
 deny ip any any
crypto map crypto-Ethernet1 1 ipsec-isakmp
 match address crypto-Ethernet1-1
 set ip access-group crypto-filter-Ethernet1-1 out
 set peer 10.156.4.206

interface Ethernet1
 crypto map crypto-Ethernet1
=NETSPOC=
ip access-list extended crypto-Ethernet1-1
 permit ip any 10.127.18.0 0.0.0.255
ip access-list extended crypto-filter-Ethernet1-1
! permit tcp host 10.127.18.1 host 10.1.11.40 eq 48
 permit tcp host 10.127.18.1 host 10.1.11.40 eq 49
 deny ip any any
crypto map crypto-Ethernet1 1 ipsec-isakmp
 match address crypto-Ethernet1-1
 set ip access-group crypto-filter-Ethernet1-1 out
 set peer 10.156.4.206

interface Ethernet1
 crypto map crypto-Ethernet1
=OUTPUT=
ip access-list resequence crypto-filter-Ethernet1-1 10000 10000
ip access-list extended crypto-filter-Ethernet1-1
10001 permit tcp host 10.127.18.1 host 10.1.11.40 eq 49
no 10000
ip access-list resequence crypto-filter-Ethernet1-1 10 10
=END=

############################################################
=TITLE=Move incoming to outgoing crypto filter ACL
=DEVICE=
ip access-list extended crypto-Ethernet1-1
 permit ip any 10.127.18.0 0.0.0.255
ip access-list extended crypto-filter-Ethernet1-1-DRC-0
 permit tcp host 10.127.18.1 host 10.1.11.40 eq 48
! permit tcp host 10.127.18.1 host 10.1.11.40 eq 49
 deny ip any any
crypto map crypto-Ethernet1 1 ipsec-isakmp
 match address crypto-Ethernet1-1
 set ip access-group crypto-filter-Ethernet1-1-DRC-0 in
 set peer 10.156.4.206

interface Ethernet1
 crypto map crypto-Ethernet1
=NETSPOC=
ip access-list extended crypto-Ethernet1-1
 permit ip any 10.127.18.0 0.0.0.255
ip access-list extended crypto-filter-Ethernet1-1
 permit tcp host 10.127.18.1 host 10.1.11.40 eq 48
 permit tcp host 10.127.18.1 host 10.1.11.40 eq 49
 deny ip any any
crypto map crypto-Ethernet1 1 ipsec-isakmp
 match address crypto-Ethernet1-1
 set ip access-group crypto-filter-Ethernet1-1 out
 set peer 10.156.4.206

interface Ethernet1
 crypto map crypto-Ethernet1
=OUTPUT=
crypto map crypto-Ethernet1 1 ipsec-isakmp
no set ip access-group crypto-filter-Ethernet1-1-DRC-0 in
ip access-list extended crypto-filter-Ethernet1-1-DRC-1
permit tcp host 10.127.18.1 host 10.1.11.40 eq 48
permit tcp host 10.127.18.1 host 10.1.11.40 eq 49
deny ip any any
exit
crypto map crypto-Ethernet1 1 ipsec-isakmp
set ip access-group crypto-filter-Ethernet1-1-DRC-1 out
exit
no ip access-list extended crypto-filter-Ethernet1-1-DRC-0
=END=

############################################################
=TITLE=Interface with dhcp address
=DEVICE=
interface Ethernet1
 ip address dhcp
interface Ethernet2
 ip address 10.0.0.1 255.255.255.0
=NETSPOC=
interface Ethernet1
 ip address negotiated
interface Ethernet2
 ip address 10.0.0.1 255.255.255.0
=OUTPUT=NONE

############################################################
=TITLE=Unnumbered interface
=DEVICE=
interface Serial1
 ip address 10.0.0.1 255.255.255.0
=NETSPOC=
interface Serial1
 ip unnumbered Serial2
=WARNING=
WARNING>>> Different address defined for interface Serial1: Device: "10.0.0.1 255.255.255.0", Netspoc: "unnumbered"
=END=

############################################################
=TITLE=Check Netspoc interfaces
=DEVICE=
interface Serial1
 ip address 10.1.1.1 255.255.255.0
interface Serial2
 ip address 10.1.2.1 255.255.255.0
=NETSPOC=
interface Serial1
 ip address 10.1.1.1 255.255.255.0
interface Serial3
 ip address 10.1.3.1 255.255.255.0
=ERROR=
WARNING>>> Interface 'Serial2' on device is not known by Netspoc
ERROR>>> Interface 'Serial3' from Netspoc not known on device
=END=

############################################################
=TITLE=Check device interfaces, leave ACL of unknown interface unchanged
=DEVICE=
ip access-list extended test1-DRC-0
 permit ip any 10.127.18.0 0.0.0.255
interface Serial1
 ip address 10.1.1.1 255.255.255.0
interface Serial2
 ip address 10.1.2.1 255.255.255.0
 ip address 10.1.2.250 255.255.255.0 secondary
 ip address 1.1.1.1 255.255.255.0 secondary
interface Serial3
 ip address 10.1.3.1 255.255.255.0
 ip access-group test1-DRC-0 in
=NETSPOC=
ip access-list extended test1
 permit ip any 10.127.18.0 0.0.0.255
interface Serial1
 ip address 1.1.1.1 255.0.0.0
 ip address 10.1.2.1 255.255.255.0 secondary
 ip address 10.1.2.250 255.255.255.0 secondary
 ip access-group test1 in
ip access-list extended test2
 permit ip any 10.127.18.0 0.0.0.255
interface Serial2
 ip address 10.1.2.1 255.255.255.0 secondary
 ip address 10.1.2.250 255.255.255.0
 ip address 1.1.1.1 255.255.255.0 secondary
 ip access-group test2 in
ip access-list extended test
 deny ip any any log-input
=WARNING=
WARNING>>> Different address defined for interface Serial1: Device: "10.1.1.1 255.255.255.0", Netspoc: "1.1.1.1 255.0.0.0,10.1.2.1 255.255.255.0,10.1.2.250 255.255.255.0"
WARNING>>> Interface 'Serial3' on device is not known by Netspoc
=OUTPUT=
ip access-list extended test1-DRC-1
permit ip any 10.127.18.0 0.0.0.255
exit
interface Serial1
ip access-group test1-DRC-1 in
ip access-list extended test2-DRC-0
permit ip any 10.127.18.0 0.0.0.255
exit
interface Serial2
ip access-group test2-DRC-0 in
=END=

############################################################
=TITLE=Check 'ip inspect'
=DEVICE=
interface Serial1
 ip address 10.1.1.1 255.255.255.0
 ip inspect NAME in
interface Serial2
 ip address 10.1.2.1 255.255.255.0
=NETSPOC=
interface Serial1
 ip address 10.1.2.1 255.255.255.0
interface Serial2
 ip address 10.1.2.1 255.255.255.0
 ip inspect NAME in
 ip access-group test in
ip access-list extended test
 deny ip any any log-input
=ERROR=
WARNING>>> Different address defined for interface Serial1: Device: "10.1.1.1 255.255.255.0", Netspoc: "10.1.2.1 255.255.255.0"
ERROR>>> Different 'ip inspect' defined for interface Serial1: Device: enabled, Netspoc: disabled
=END=

############################################################
=TITLE=Only change VRFs mentioned in Netspoc, leave other ACL unchanged
=DEVICE=
ip route vrf 002 10.20.0.0 255.255.0.0 10.2.2.2
ip access-list extended acl2-DRC-0
 permit ip any host 10.0.1.1
interface Ethernet1
 ip address 10.0.1.1 255.255.255.0
 ip vrf forwarding 001
 ip access-group acl2-DRC-0 in
interface Ethernet2
 ip address 10.0.2.1 255.255.255.0
 ip vrf forwarding 002
ip access-list extended crypto-filter-Ethernet3-1-DRC-0
 permit tcp host 10.127.18.1 host 10.1.11.40 eq 48
 deny ip any any
crypto map crypto-Ethernet3 1 ipsec-isakmp
 set ip access-group crypto-filter-Ethernet3-1-DRC-0 in
 set peer 10.156.4.206
interface Ethernet3
 ip address 10.0.3.1 255.255.255.0
 crypto map crypto-Ethernet3
=NETSPOC=
ip route vrf 013 10.30.0.0 255.255.0.0 10.3.3.3
ip access-list extended acl2
 permit ip any host 10.0.1.1
interface Ethernet2
 ip address 10.0.2.1 255.255.255.0
 ip vrf forwarding 002
 ip access-group acl2 in
=OUTPUT=
ip access-list extended acl2-DRC-1
permit ip any host 10.0.1.1
exit
interface Ethernet2
ip access-group acl2-DRC-1 in
ip route vrf 013 10.30.0.0 255.255.0.0 10.3.3.3
=WARNING=
Leaving VRF <global> untouched
Leaving VRF 001 untouched
No IPv4 routing specified for VRF 002, leaving untouched
comp: *** device changed ***
=OPTIONS=--quiet=false

############################################################
=TITLE=Leave routing in unmanaged VRF unchanged
=DEVICE=
interface Vlan33
 ip address 10.1.1.193 255.255.255.192
 vrf forwarding 033
ip route 1.1.1.10 255.255.255.255 11.11.11.1
=NETSPOC=
interface Vlan33
 ip address 10.1.1.193 255.255.255.192
 ip vrf forwarding 033
=WARNING=
Leaving VRF <global> untouched
comp: device unchanged
=OPTIONS=--quiet=false


############################################################
=TITLE=Check VRF of interfaces
=DEVICE=
interface Serial1
 ip address 10.1.1.1 255.255.255.0
interface Serial2
 ip address 10.1.2.1 255.255.255.0
 ip vrf forwarding 014
interface Serial3
 ip address 10.1.3.1 255.255.255.0
 ip vrf forwarding 013
=NETSPOC=
interface Serial1
 ip address 10.1.1.1 255.255.255.0
 ip vrf forwarding 013
interface Serial2
 ip address 10.1.2.1 255.255.255.0
 ip vrf forwarding 014
interface Serial3
 ip address 10.1.3.1 255.255.255.0
=ERROR=
ERROR>>> Different VRFs defined for interface Serial1: Device: <global>, Netspoc: 013
=END=

############################################################
=TITLE=Unknown interface in VRF
=DEVICE=
ip route 10.20.0.0 255.255.0.0 10.1.2.3
ip access-list extended acl1
 permit ip any host 10.0.1.1
interface Ethernet1
 ip address 10.0.9.1 255.255.255.0
 ip access-group acl1 in
ip route vrf 013 10.30.0.0 255.255.0.0 10.1.2.3
ip access-list extended acl2
 permit ip any host 10.0.1.1
interface Ethernet2
 ip address 10.0.0.1 255.255.255.0
 ip vrf forwarding 013
 ip access-group acl2 in
=NETSPOC=
ip route 10.20.0.0 255.255.0.0 10.1.2.3
ip route vrf 013 10.30.0.0 255.255.0.0 10.1.2.3
ip access-list extended acl2
 permit ip any host 10.0.1.1
interface Ethernet2
 ip address 10.0.0.1 255.255.255.0
 ip vrf forwarding 013
 ip access-group acl2 in
=WARNING=
WARNING>>> Interface 'Ethernet1' on device is not known by Netspoc
=END=

############################################################
=TITLE=Leave routing of global VRF unchanged
=DEVICE=
ip route 10.20.0.0 255.255.0.0 10.1.2.3
ip access-list extended acl1
 permit ip any host 10.0.1.1
interface Ethernet1
 ip address 10.0.9.1 255.255.255.0
 ip access-group acl1 in
ip route vrf 013 10.30.0.0 255.255.0.0 10.1.2.3
ip access-list extended acl2
 permit ip any host 10.0.1.1
interface Ethernet2
 ip address 10.0.0.1 255.255.255.0
 vrf forwarding 013
 ip access-group acl2 in
=NETSPOC=
ip route vrf 013 10.30.0.0 255.255.0.0 10.1.2.4
ip access-list extended acl2
 permit ip any host 10.0.1.1
interface Ethernet2
 ip address 10.0.0.1 255.255.255.0
 ip vrf forwarding 013
 ip access-group acl2 in
=OUTPUT=
no ip route vrf 013 10.30.0.0 255.255.0.0 10.1.2.3\N ip route vrf 013 10.30.0.0 255.255.0.0 10.1.2.4
=END=

############################################################
=TITLE=Crypto of unmanaged VRF is left unchanged
=DEVICE=
ip access-list extended crypto-filter2
 permit tcp host 10.1.1.1 host 10.2.2.2 eq 80
ip access-list extended crypto-filter-Ethernet1-1-DRC-0
 permit tcp host 10.127.18.1 host 10.1.11.40 eq 48
 deny ip any any
crypto map crypto-Ethernet1 1 ipsec-isakmp
 set ip access-group crypto-filter-Ethernet1-1-DRC-0 in
 set peer 10.156.4.206
crypto map crypto-Ethernet2 1 ipsec-isakmp
 set ip access-group crypto-filter2 in
 set peer 10.156.1.2

interface Ethernet1
 ip vrf forwarding 013
 crypto map crypto-Ethernet1
interface Ethernet2
 crypto map crypto-Ethernet2
=NETSPOC=
ip access-list extended crypto-filter-Ethernet1-1-DRC-0
 permit tcp host 10.127.18.1 host 10.1.11.40 eq 49
 deny ip any any
crypto map crypto-Ethernet1 1 ipsec-isakmp
 set ip access-group crypto-filter-Ethernet1-1-DRC-0 in
 set peer 10.156.4.206

interface Ethernet1
 ip vrf forwarding 013
 crypto map crypto-Ethernet1
=OUTPUT=
ip access-list resequence crypto-filter-Ethernet1-1-DRC-0 10000 10000
ip access-list extended crypto-filter-Ethernet1-1-DRC-0
10001 permit tcp host 10.127.18.1 host 10.1.11.40 eq 49
no 10000
ip access-list resequence crypto-filter-Ethernet1-1-DRC-0 10 10
=END=

############################################################
=TITLE=Leave crypto map gdoi unchanged
=DEVICE=
crypto map GDOI-03 10 gdoi
 set group GDOI-03
interface eth0
 ip address 10.1.2.3 255.255.255.252
 crypto map GDOI-03
interface eth1
 ip address 10.1.2.5 255.255.255.252
 crypto map GDOI-03
=NETSPOC=
interface eth0
 ip address 10.1.2.3 255.255.255.252
interface eth1
 ip address 10.1.2.5 255.255.255.252
=OUTPUT=NONE
