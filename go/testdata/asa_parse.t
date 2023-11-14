=TEMPL=minimal_device
interface Ethernet0/0
 nameif inside
interface Ethernet0/1
 nameif outside
=TEMPL=minimal_device1
interface Ethernet0/0
 nameif inside
=TEMPL=crypto_ASA
interface Ethernet0/1
 nameif outside
=END=

############################################################
=TITLE=Add IPV6 access list
=DEVICE=[[minimal_device]]
=NETSPOC=
--ipv6/router
access-list inside_in extended permit tcp 1000::abcd:1:0/96 1000::abcd:2:0/96 range 80 90
access-list inside_in extended deny ip any6 any6
access-group inside_in in interface inside

access-list outside_in extended deny ip any6 any6
access-group outside_in in interface outside
=OUTPUT=
access-list inside_in-DRC-0 extended permit tcp 1000::abcd:1:0/96 1000::abcd:2:0/96 range 80 90
access-list inside_in-DRC-0 extended deny ip any6 any6
access-group inside_in-DRC-0 in interface inside
access-list outside_in-DRC-0 extended deny ip any6 any6
access-group outside_in-DRC-0 in interface outside
=END=

############################################################
=TITLE=Add and delete IPV6-access list
=DEVICE=
[[minimal_device]]
access-list inside_in extended permit tcp 1000::abcd:1:0/96 1000::abcd:2:0/96 range 80 90
access-list inside_in extended deny ip any6 any6
access-group inside_in in interface inside
access-list outside_in extended deny ip any6 any6
access-group outside_in in interface outside
=NETSPOC=
--ipv6/router
access-list inside_in extended permit tcp 1000::abcd:1:0/120 1000::abcd:2:0/96 range 80 90
access-list inside_in extended deny ip any6 any6
access-group inside_in in interface inside

access-list outside_in extended deny ip any6 any6
access-group outside_in in interface outside
=OUTPUT=
access-list inside_in line 2 extended permit tcp 1000::abcd:1:0/120 1000::abcd:2:0/96 range 80 90
no access-list inside_in line 1 extended permit tcp 1000::abcd:1:0/96 1000::abcd:2:0/96 range 80 90
=END=

############################################################
=TITLE=IPv6 routing - add new route
=DEVICE=NONE
=NETSPOC=
--ipv6/router
ipv6 route outside 10::3:0/120 10::2:2
=OUTPUT=
ipv6 route outside 10::3:0/120 10::2:2
=END=

############################################################
=TITLE=IPv4 + v6 routing - no routes from Netspoc
=DEVICE=
route outside 10.1.3.0 255.255.255.0 10.1.1.1
route outside 10.1.4.0 255.255.255.0 10.1.1.2
ipv6 route outside 10::3:0/120 10::2:2
ipv6 route outside 10::4:0/120 10::2:2
ipv6 route outside 10::8:0/117 10::2:2
=NETSPOC=NONE
=OUTPUT=NONE

############################################################
=TITLE=IPv6 routing - unchanged
=DEVICE=
ipv6 route outside 10::3:0/120 10::2:2 1
ipv6 route outside 10::4:0/120 10::2:2 2
ipv6 route outside 10::8:0/117 10::2:2
=NETSPOC=
--ipv6/router
ipv6 route outside 10::4:0/120 10::2:2
ipv6 route outside 10::8:0/117 10::2:2
ipv6 route outside 10::3:0/120 10::2:2 3
=OUTPUT=NONE

############################################################
=TITLE=IPv4 routing - unchanged
=DEVICE=
route outside 10.1.3.0 255.255.255.0 10.1.1.1 44
route outside 10.1.4.0 255.255.255.0 10.1.1.2
route outside 10.1.8.0 255.255.248.0 10.1.1.1 55
=NETSPOC=
--router
route outside 10.1.8.0 255.255.248.0 10.1.1.1
route outside 10.1.4.0 255.255.255.0 10.1.1.2
route outside 10.1.3.0 255.255.255.0 10.1.1.1 8
=OUTPUT=NONE

############################################################
=TITLE=IPv6 routing - replace network with smaller one
=DEVICE=
ipv6 route outside 10::/112 10::2:2
=NETSPOC=
--ipv6/router
ipv6 route outside 10::3:0/120 10::2:2
=OUTPUT=
ipv6 route outside 10::3:0/120 10::2:2
no ipv6 route outside 10::/112 10::2:2
=END=

############################################################
=TITLE=IPv6 routing - replace network with bigger one
=DEVICE=
ipv6 route outside 10::3:0/120 10::2:2
=NETSPOC=
--ipv6/router
ipv6 route outside 10::/112 10::2:2
=OUTPUT=
ipv6 route outside 10::/112 10::2:2
no ipv6 route outside 10::3:0/120 10::2:2
=END=

############################################################
=TITLE=IPv6 routing - change gateway
=DEVICE=
ipv6 route outside 10::3:0/120 10::2:2
=NETSPOC=
--ipv6/router
ipv6 route outside 10::3:0/120 10::2:3
=OUTPUT=
no ipv6 route outside 10::3:0/120 10::2:2\N ipv6 route outside 10::3:0/120 10::2:3
=END=

############################################################
=TITLE=IPv6 routing - change default route
=DEVICE=
ipv6 route outside ::/0 10::1.1
ipv6 route outside 10::3:0/120 10::2:2
=NETSPOC=
--ipv6/router
ipv6 route outside ::/0 10::2.2
ipv6 route outside 10::1:0/120 10::1.1
=OUTPUT=
ipv6 route outside 10::1:0/120 10::1.1
no ipv6 route outside ::/0 10::1.1\N ipv6 route outside ::/0 10::2.2
no ipv6 route outside 10::3:0/120 10::2:2
=END=

############################################################
=TITLE=IPv4 routing - change default route
=DEVICE=
route outside 0.0.0.0 0.0.0.0 10.1.1.1
route outside 10.1.3.0 255.255.255.0 10.1.2.2
=NETSPOC=
--router
route outside 0.0.0.0 0.0.0.0 10.1.2.2
route outside 10.1.1.0 255.255.255.0 10.1.1.1
=OUTPUT=
route outside 10.1.1.0 255.255.255.0 10.1.1.1
no route outside 0.0.0.0 0.0.0.0 10.1.1.1\N route outside 0.0.0.0 0.0.0.0 10.1.2.2
no route outside 10.1.3.0 255.255.255.0 10.1.2.2
=END=

############################################################
=TITLE=Handle protocol 1 as icmp in raw file
=DEVICE=[[minimal_device1]]
=NETSPOC=
--router
access-list inside_in extended permit tcp 10.1.1.0 255.255.255.252 10.9.9.0 255.255.255.0 range 80 90
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
--router.raw
access-list inside_in extended permit 1 any4 any4 3 6
access-group inside_in in interface inside
=OUTPUT=
access-list inside_in-DRC-0 extended permit icmp any4 any4 3 6
access-list inside_in-DRC-0 extended permit tcp 10.1.1.0 255.255.255.252 10.9.9.0 255.255.255.0 range 80 90
access-list inside_in-DRC-0 extended deny ip any4 any4
access-group inside_in-DRC-0 in interface inside
=END=

############################################################
=TITLE=Handle protocol 58 as icmp6 in raw file
=DEVICE=[[minimal_device1]]
=NETSPOC=
--ipv6/router
access-list inside_in extended permit tcp host 1000::abcd:1:12 1000::abcd:9:0/112 range 80 90
access-list inside_in extended deny ip any6 any6
access-group inside_in in interface inside
--router.raw
access-list inside_in extended permit 58 any6 any6 128
access-group inside_in in interface inside
=OUTPUT=
access-list inside_in-DRC-0 extended permit icmp6 any6 any6 128
access-list inside_in-DRC-0 extended permit tcp host 1000::abcd:1:12 1000::abcd:9:0/112 range 80 90
access-list inside_in-DRC-0 extended deny ip any6 any6
access-group inside_in-DRC-0 in interface inside
=END=

############################################################
=TITLE=Handle numeric icmp6 named type
=DEVICE=
[[minimal_device1]]
access-list inside_in extended permit icmp6 any6 any6 echo
access-list inside_in extended permit icmp6 any6 any6 echo-reply
access-group inside_in in interface inside
=NETSPOC=
--ipv6/router
access-list inside_in extended permit icmp6 any6 any6 128
access-list inside_in extended permit icmp6 any6 any6 129
access-group inside_in in interface inside
=OUTPUT=NONE

############################################################
=TITLE=Handle named log level
=DEVICE=
[[minimal_device1]]
access-list inside_in extended permit tcp any4 any4 log critical
access-list inside_in extended permit udp any4 any4 log debugging
access-group inside_in in interface inside
=NETSPOC=
access-list inside_in extended permit tcp any4 any4 log 2
access-list inside_in extended permit udp any4 any4 log 7
access-group inside_in in interface inside
=OUTPUT=NONE

############################################################
=TITLE=Check Netspoc interfaces
=DEVICE=
interface Ethernet0/0
 nameif inside
 ip address 10.1.1.1 255.255.255.0
interface Ethernet0/1
 nameif outside
 ip address 10.1.2.1 255.255.255.0
=NETSPOC=
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
=WARNING=
WARNING>>> Interface 'outside' on device is not known by Netspoc
=END=

############################################################
=TITLE=Ignore shutdown interface
=DEVICE=
interface Ethernet0/0
 nameif inside
 ip address 10.1.1.1 255.255.255.0
interface Ethernet0/1
 nameif outside
 shutdown
 ip address 10.1.2.1 255.255.255.0
=NETSPOC=
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
=WARNING=NONE

############################################################
=TITLE=Check device interfaces
=DEVICE=
interface Ethernet0/0
 nameif inside
 ip address 10.1.1.0 255.255.255.0
=NETSPOC=
access-list outside_in extended deny ip any4 any4
access-group outside_in in interface outside
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
=ERROR=
ERROR>>> Interface 'outside' from Netspoc not known on device
=END=

############################################################
=TITLE=Check device interfaces, both configs from Netspoc
=DEVICE=
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
=NETSPOC=
access-list outside_in extended deny ip any4 any4
access-group outside_in in interface outside
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
=ERROR=
ERROR>>> Interface 'outside' from Netspoc not known on device
=END=

############################################################
=TITLE=Add sysopt
=DEVICE=NONE
=NETSPOC=
no sysopt connection permit-vpn
=OUTPUT=
no sysopt connection permit-vpn
=END=

############################################################
=TITLE=Remove sysopt
=DEVICE=
no sysopt connection permit-vpn
=NETSPOC=NONE
=OUTPUT=
sysopt connection permit-vpn
=END=

############################################################
=TITLE=Increment index of names
=DEVICE=
[[minimal_device1]]
object-group network g0-DRC-0
 network-object 10.0.6.0 255.255.255.0
access-list inside_in extended permit udp object-group g0-DRC-0 any4 eq 80
access-group inside_in in interface inside
=NETSPOC=
object-group network g0
 network-object 10.0.5.0 255.255.255.0
object-group network g1
 network-object 10.0.6.0 255.255.255.0
access-list inside_in extended permit udp object-group g0 any4 eq 79
access-list inside_in extended permit udp object-group g1 any4 eq 80
access-group inside_in in interface inside
=OUTPUT=
object-group network g0-DRC-1
network-object 10.0.5.0 255.255.255.0
access-list inside_in line 1 extended permit udp object-group g0-DRC-1 any4 eq 79
=END=

############################################################
=TITLE=Parse routing and ACL with object-groups
=TEMPL=input
[[minimal_device]]
route outside 10.20.0.0 255.255.0.0 10.1.2.3

access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside

object-group network g0
 network-object 10.0.6.0 255.255.255.0
 network-object 10.0.5.0 255.255.255.0
 network-object host 10.0.12.3

access-list outside_in extended permit udp object-group g0 host 10.0.1.11 eq sip
access-list outside_in extended permit tcp any host 10.0.1.11 range 7937 8999
access-list outside_in extended deny ip any4 any4
access-group outside_in in interface outside
=DEVICE=
[[minimal_device]]
=NETSPOC=[[input]]
=OUTPUT=
route outside 10.20.0.0 255.255.0.0 10.1.2.3
access-list inside_in-DRC-0 extended deny ip any4 any4
access-group inside_in-DRC-0 in interface inside
object-group network g0-DRC-0
network-object 10.0.5.0 255.255.255.0
network-object 10.0.6.0 255.255.255.0
network-object host 10.0.12.3
access-list outside_in-DRC-0 extended permit udp object-group g0-DRC-0 host 10.0.1.11 eq 5060
access-list outside_in-DRC-0 extended permit tcp any host 10.0.1.11 range 7937 8999
access-list outside_in-DRC-0 extended deny ip any4 any4
access-group outside_in-DRC-0 in interface outside
=END=

=TITLE=Unchanged routing and ACL with object-groups
=DEVICE=[[input]]
=NETSPOC=[[input]]
=OUTPUT=NONE

############################################################
=TITLE=Parse object-group of type tcp-udp
=TEMPL=input
[[minimal_device1]]
object-group service g1 tcp-udp
 port-object eq domain
 port-object eq http
access-list inside_in extended permit object-group g1 any4 any4
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
=DEVICE=
[[minimal_device1]]
=NETSPOC=[[input]]
=OUTPUT=
object-group service g1-DRC-0 tcp-udp
port-object eq domain
port-object eq http
access-list inside_in-DRC-0 extended permit object-group g1-DRC-0 any4 any4
access-list inside_in-DRC-0 extended deny ip any4 any4
access-group inside_in-DRC-0 in interface inside
=END=

=TITLE=Unchanged object-group of type tcp-udp
=DEVICE=[[input]]
=NETSPOC=[[input]]
=OUTPUT=NONE

############################################################
=TITLE=Parse unknown port specifier
=TEMPL=input
[[minimal_device1]]
access-list inside_in extended permit tcp any4 any4 foo 22
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
=DEVICE=
[[minimal_device1]]
=NETSPOC=[[input]]
=OUTPUT=
access-list inside_in-DRC-0 extended permit tcp any4 any4 foo 22
access-list inside_in-DRC-0 extended deny ip any4 any4
access-group inside_in-DRC-0 in interface inside
=END=

=TITLE=Unchanged unknown port specifier
=DEVICE=[[input]]
=NETSPOC=[[input]]
=OUTPUT=NONE

############################################################
=TITLE=Parse different port specifers
=TEMPL=input
[[minimal_device1]]
access-list inside_in extended permit tcp any4 any4 eq 22
access-list inside_in extended permit tcp any4 any4 neq 23
access-list inside_in extended permit tcp any4 any4 gt 1023
access-list inside_in extended permit tcp any4 any4 lt 9
access-list inside_in extended permit tcp any4 any4 range www 90
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
=DEVICE=
[[minimal_device1]]
=NETSPOC=[[input]]
=OUTPUT=
access-list inside_in-DRC-0 extended permit tcp any4 any4 eq 22
access-list inside_in-DRC-0 extended permit tcp any4 any4 neq 23
access-list inside_in-DRC-0 extended permit tcp any4 any4 gt 1023
access-list inside_in-DRC-0 extended permit tcp any4 any4 lt 9
access-list inside_in-DRC-0 extended permit tcp any4 any4 range 80 90
access-list inside_in-DRC-0 extended deny ip any4 any4
access-group inside_in-DRC-0 in interface inside
=END=

=TITLE=Unchanged different port specifers
=DEVICE=[[input]]
=NETSPOC=[[input]]
=OUTPUT=NONE

############################################################
=TITLE=Parse named port specifers
=TEMPL=input
[[minimal_device1]]
access-list inside_in extended permit tcp any4 any4 eq ssh
access-list inside_in extended permit tcp any4 any4 neq telnet
access-list inside_in extended permit udp any4 any4 eq snmp
access-list inside_in extended permit tcp any4 any4 lt echo
access-list inside_in extended permit tcp any4 any4 range www 90
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
=DEVICE=
[[minimal_device1]]
=NETSPOC=[[input]]
=OUTPUT=
access-list inside_in-DRC-0 extended permit tcp any4 any4 eq 22
access-list inside_in-DRC-0 extended permit tcp any4 any4 neq 23
access-list inside_in-DRC-0 extended permit udp any4 any4 eq 161
access-list inside_in-DRC-0 extended permit tcp any4 any4 lt 7
access-list inside_in-DRC-0 extended permit tcp any4 any4 range 80 90
access-list inside_in-DRC-0 extended deny ip any4 any4
access-group inside_in-DRC-0 in interface inside
=END=

=TITLE=Unchanged named port specifers
=DEVICE=[[input]]
=NETSPOC=[[input]]
=OUTPUT=NONE

############################################################
=TITLE=Parse named port specifers used together with object-group
=TEMPL=input
[[minimal_device1]]
object-group network g0
 network-object 10.0.6.0 255.255.255.0
access-list inside_in extended permit tcp host 10.11.9.1 object-group g0 range ftp telnet
access-group inside_in in interface inside
=DEVICE=
[[minimal_device1]]
=NETSPOC=[[input]]
=OUTPUT=
object-group network g0-DRC-0
network-object 10.0.6.0 255.255.255.0
access-list inside_in-DRC-0 extended permit tcp host 10.11.9.1 object-group g0-DRC-0 range 21 23
access-group inside_in-DRC-0 in interface inside
=END=

=TITLE=Unchanged named port specifers used together with object-group
=DEVICE=[[input]]
=NETSPOC=[[input]]
=OUTPUT=NONE

############################################################
=TITLE=Parse rule referencing 4 object-groups
=TEMPL=input
[[minimal_device1]]
object-group network g1
 network-object 10.0.6.0 255.255.255.0
object-group network g3
 network-object 10.0.7.0 255.255.255.0
object-group service g2
 service-object udp source eq 123
object-group service g4
 service-object udp destination eq 123
access-list inside_in extended permit udp object-group g1 object-group g2 object-group g3 object-group g4
access-group inside_in in interface inside
=DEVICE=
[[minimal_device1]]
=NETSPOC=[[input]]
=OUTPUT=
object-group network g1-DRC-0
network-object 10.0.6.0 255.255.255.0
object-group service g2-DRC-0
service-object udp source eq 123
object-group network g3-DRC-0
network-object 10.0.7.0 255.255.255.0
object-group service g4-DRC-0
service-object udp destination eq 123
access-list inside_in-DRC-0 extended permit udp object-group g1-DRC-0 object-group g2-DRC-0 object-group g3-DRC-0 object-group g4-DRC-0
access-group inside_in-DRC-0 in interface inside
=END=

=TITLE=Unchanged rule referencing 4 object-groups
=DEVICE=[[input]]
=NETSPOC=[[input]]
=OUTPUT=NONE

############################################################
=TITLE=Parse rule with src/dst port and 2 object-group
=TEMPL=input
[[minimal_device1]]
object-group network g1
 network-object 10.0.6.0 255.255.255.0
object-group network g2
 network-object 10.0.7.0 255.255.255.0
access-list inside_in extended permit udp object-group g1 eq ntp object-group g2 eq ntp
access-group inside_in in interface inside
=DEVICE=
[[minimal_device1]]
=NETSPOC=[[input]]
=OUTPUT=
object-group network g1-DRC-0
network-object 10.0.6.0 255.255.255.0
object-group network g2-DRC-0
network-object 10.0.7.0 255.255.255.0
access-list inside_in-DRC-0 extended permit udp object-group g1-DRC-0 eq 123 object-group g2-DRC-0 eq 123
access-group inside_in-DRC-0 in interface inside
=END=

=TITLE=Unchanged rule with src/dst port and 2 object-group
=DEVICE=[[input]]
=NETSPOC=[[input]]
=OUTPUT=NONE

############################################################
=TITLE=Leave object-group unchanged if found multiple times on device
=DEVICE=
[[minimal_device1]]
object-group network DM_INLINE_NETWORK_5
 network-object 10.0.6.0 255.255.255.0
object-group network g1-DRC-0
 network-object 10.0.6.0 255.255.255.0
access-list inside_in-DRC-0 extended permit udp any4 object-group g1-DRC-0 eq 161
access-group inside_in-DRC-0 in interface inside
=NETSPOC=
object-group network g1
 network-object 10.0.6.0 255.255.255.0
access-list inside_in extended permit udp any4 object-group g1 eq 161
access-group inside_in in interface inside
=OUTPUT=NONE

############################################################
=TITLE=Remove global ACL from device
=DEVICE=
access-list global_ACL extended permit tcp any4 any4 eq 22
access-group global_ACL global
=NETSPOC=NONE
=OUTPUT=
no access-group global_ACL global
clear configure access-list global_ACL
=END=

############################################################
=TITLE=Change ACL referenced from two interfaces
=DEVICE=
[[minimal_device]]
access-list outside_in extended permit tcp any4 any4 eq 22
access-group outside_in in interface inside
access-group outside_in in interface outside
=NETSPOC=
access-list outside_in extended permit tcp any4 any4 eq 22
access-list outside_in extended permit tcp any4 any4 eq 25
access-group outside_in in interface inside
access-group outside_in in interface outside
=OUTPUT=
access-list outside_in line 2 extended permit tcp any4 any4 eq 25
=END=

############################################################
=TITLE=Change only one ACL referenced from two interfaces
=DEVICE=
[[minimal_device]]
access-list outside_in extended permit tcp any4 any4 eq 22
access-group outside_in in interface inside
access-group outside_in in interface outside
=NETSPOC=
access-list outside_in extended permit tcp any4 any4 eq 22
access-list outside_in extended permit tcp any4 any4 eq 25
access-list inside_in extended permit tcp any4 any4 eq 22
access-group outside_in in interface inside
access-group inside_in in interface outside
=OUTPUT=
access-list outside_in line 2 extended permit tcp any4 any4 eq 25
access-list inside_in-DRC-0 extended permit tcp any4 any4 eq 22
access-group inside_in-DRC-0 in interface outside
=END=

############################################################
=TITLE=Parse crypto map, dynamic map with tunnel-group
=TEMPL=input
[[crypto_ASA]]
access-list crypto-acl1 extended permit ip 10.1.2.0 255.255.240.0 host 10.3.4.5
access-list crypto-acl2 extended permit ip 10.1.3.0 255.255.240.0 host 10.3.4.5

crypto ipsec ikev1 transform-set trans esp-3des esp-sha-hmac
crypto dynamic-map some-name 10 match address crypto-acl2
crypto map map-outside 10 match address crypto-acl1
crypto map map-outside 10 set pfs group2
crypto map map-outside 10 set peer 97.98.99.100
crypto map map-outside 10 set ikev1 transform-set trans
crypto map map-outside 10 set security-association lifetime seconds 43200
crypto map map-outside 10 set security-association lifetime kilobytes 4608000
crypto map map-outside 65000 ipsec-isakmp dynamic some-name
crypto map map-outside interface outside
crypto ca certificate map some-name 10
 subject-name attr ea eq some-name
 extended-key-usage co 1.3.6.1.4.1.311.20.2.2
tunnel-group some-name type ipsec-l2l
tunnel-group some-name ipsec-attributes
 peer-id-validate nocheck
 ikev2 local-authentication certificate Trustpoint2
 ikev2 remote-authentication certificate
tunnel-group-map some-name 10 some-name
=DEVICE=
[[crypto_ASA]]
=NETSPOC=[[input]]
=OUTPUT=
crypto ca certificate map some-name-DRC-0 10
subject-name attr ea eq some-name
extended-key-usage co 1.3.6.1.4.1.311.20.2.2
tunnel-group some-name-DRC-0 type ipsec-l2l
tunnel-group some-name-DRC-0 ipsec-attributes
peer-id-validate nocheck
ikev2 local-authentication certificate Trustpoint2
ikev2 remote-authentication certificate
tunnel-group-map some-name-DRC-0 10 some-name-DRC-0
access-list crypto-acl1-DRC-0 extended permit ip 10.1.2.0 255.255.240.0 host 10.3.4.5
crypto map map-outside 10 match address crypto-acl1-DRC-0
crypto map map-outside 10 set pfs
crypto map map-outside 10 set peer 97.98.99.100
crypto ipsec ikev1 transform-set trans-DRC-0 esp-3des esp-sha-hmac
crypto map map-outside 10 set ikev1 transform-set trans-DRC-0
crypto map map-outside 10 set security-association lifetime seconds 43200
crypto map map-outside 10 set security-association lifetime kilobytes 4608000
access-list crypto-acl2-DRC-0 extended permit ip 10.1.3.0 255.255.240.0 host 10.3.4.5
crypto dynamic-map some-name 10 match address crypto-acl2-DRC-0
crypto map map-outside 65000 ipsec-isakmp dynamic some-name
crypto map map-outside interface outside
=END=

=TITLE=Unchanged crypto map, dynamic map with tunnel-group
=DEVICE=[[input]]
=NETSPOC=[[input]]
=OUTPUT=NONE

############################################################
=TITLE=Parse default tunnel-group-map
=TEMPL=input
tunnel-group VPN-single type remote-access
tunnel-group VPN-single webvpn-attributes
 authentication certificate
tunnel-group-map default-group VPN-single
=DEVICE=NONE
=NETSPOC=[[input]]
=OUTPUT=
tunnel-group VPN-single-DRC-0 type remote-access
tunnel-group VPN-single-DRC-0 webvpn-attributes
authentication certificate
tunnel-group-map default-group VPN-single-DRC-0
=END=

=TITLE=Unchanged default tunnel-group-map
=DEVICE=[[input]]
=NETSPOC=[[input]]
=OUTPUT=NONE

############################################################
=TITLE=Change type of tunnel-group
=DEVICE=
tunnel-group VPN-single type remote-access
tunnel-group VPN-single webvpn-attributes
 authentication certificate
tunnel-group-map default-group VPN-single
=NETSPOC=
tunnel-group some-name type ipsec-l2l
tunnel-group some-name ipsec-attributes
 peer-id-validate nocheck
 ikev2 local-authentication certificate Trustpoint2
 ikev2 remote-authentication certificate
tunnel-group-map default-group some-name
=OUTPUT=
tunnel-group some-name-DRC-0 type ipsec-l2l
tunnel-group some-name-DRC-0 ipsec-attributes
peer-id-validate nocheck
ikev2 local-authentication certificate Trustpoint2
ikev2 remote-authentication certificate
tunnel-group-map default-group some-name-DRC-0
clear configure tunnel-group VPN-single
=END=

############################################################
=TITLE=Don't touch tunnel-group-map referencing built in
=DEVICE=
tunnel-group-map default-group DefaultL2LGroup
=NETSPOC=NONE
=OUTPUT=NONE

############################################################
=TITLE=Parse username, group-policy
=TEMPL=input
access-list split-tunnel standard permit 10.2.42.0 255.255.255.224
access-list vpn-filter extended permit ip host 10.1.1.67 10.2.42.0 255.255.255.224
access-list vpn-filter extended deny ip any4 any4
group-policy VPN-group internal
group-policy VPN-group attributes
 banner value Willkommen!
 dns-server 10.1.2.3 10.44.55.66
 anyconnect-custom perapp value SomeName
 split-tunnel-network-list value split-tunnel
 split-tunnel-policy tunnelspecified
 vpn-idle-timeout 60
username jon.doe@token.example.com nopassword
username jon.doe@token.example.com attributes
 vpn-framed-ip-address 10.1.1.67 255.255.254.0
 service-type remote-access
 vpn-filter value vpn-filter
 vpn-group-policy VPN-group
=DEVICE=NONE
=NETSPOC=[[input]]
=OUTPUT=
username jon.doe@token.example.com nopassword
access-list vpn-filter-DRC-0 extended permit ip host 10.1.1.67 10.2.42.0 255.255.255.224
access-list vpn-filter-DRC-0 extended deny ip any4 any4
group-policy VPN-group-DRC-0 internal
access-list split-tunnel-DRC-0 standard permit 10.2.42.0 255.255.255.224
group-policy VPN-group-DRC-0 attributes
banner value Willkommen!
dns-server 10.1.2.3 10.44.55.66
anyconnect-custom perapp value SomeName
split-tunnel-network-list value split-tunnel-DRC-0
split-tunnel-policy tunnelspecified
vpn-idle-timeout 60
username jon.doe@token.example.com attributes
vpn-framed-ip-address 10.1.1.67 255.255.254.0
service-type remote-access
vpn-filter value vpn-filter-DRC-0
vpn-group-policy VPN-group-DRC-0
=END=

=TITLE=Unchanged username, group-policy
=DEVICE=[[input]]
=NETSPOC=[[input]]
=OUTPUT=NONE

############################################################
=TITLE=Parse group-policy DfltGrpPolicy
=TEMPL=input
group-policy DfltGrpPolicy attributes
 banner value Willkommen!
 vpn-idle-timeout 240
 vpn-simultaneous-logins 1
 vpn-tunnel-protocol ikev2
=DEVICE=NONE
=NETSPOC=[[input]]
=OUTPUT=
group-policy DfltGrpPolicy attributes
banner value Willkommen!
vpn-idle-timeout 240
vpn-simultaneous-logins 1
vpn-tunnel-protocol ikev2
=END=

=TITLE=Unchanged group-policy DfltGrpPolicy
=DEVICE=[[input]]
=NETSPOC=[[input]]
=OUTPUT=NONE

############################################################
=TITLE=Parse tunnel-group of type ipsec-l2l (IP as name)
# Ignore pre-shared keys shown as '******'
# Ignore manually configured 'isakmp keepalive' commands.
=TEMPL=input
tunnel-group 193.155.130.1 type ipsec-l2l
tunnel-group 193.155.130.1 ipsec-attributes
 peer-id-validate nocheck
tunnel-group 193.155.130.2 type ipsec-l2l
tunnel-group 193.155.130.2 ipsec-attributes
 ikev2 local-authentication pre-shared-key ***
 ikev2 remote-authentication pre-shared-key ****
 isakmp keepalive disable
 isakmp keepalive threshold 15 retry 3
tunnel-group 193.155.130.3 type ipsec-l2l
tunnel-group 193.155.130.3 ipsec-attributes
 peer-id-validate nocheck
 ikev2 local-authentication certificate ASDM_TrustPoint1
 ikev2 remote-authentication certificate
crypto ca certificate map cert-map 10
 subject-name attr ea eq cert@example.com
tunnel-group-map cert-map 10 193.155.130.3
=DEVICE=NONE
=NETSPOC=[[input]]
=OUTPUT=
crypto ca certificate map cert-map-DRC-0 10
subject-name attr ea eq cert@example.com
tunnel-group 193.155.130.3 type ipsec-l2l
tunnel-group 193.155.130.3 ipsec-attributes
peer-id-validate nocheck
ikev2 local-authentication certificate ASDM_TrustPoint1
ikev2 remote-authentication certificate
tunnel-group-map cert-map-DRC-0 10 193.155.130.3
tunnel-group 193.155.130.1 type ipsec-l2l
tunnel-group 193.155.130.1 ipsec-attributes
peer-id-validate nocheck
tunnel-group 193.155.130.2 type ipsec-l2l
tunnel-group 193.155.130.2 ipsec-attributes
=END=

=TITLE=Unchanged tunnel-group of type ipsec-l2l (IP as name)
=DEVICE=[[input]]
=NETSPOC=[[input]]
=OUTPUT=NONE

############################################################
=TITLE=Modify username attributes
=DEVICE=
username jon.doe@token.example.com nopassword
username jon.doe@token.example.com attributes
 service-type remote-access
 vpn-framed-ip-address 10.1.2.3 255.0.0.0
 vpn-simultaneous-logins 4
 password-storage enable
=NETSPOC=
username jon.doe@token.example.com nopassword
username jon.doe@token.example.com attributes
 service-type remote-access
 vpn-framed-ip-address 10.11.22.33 255.255.0.0
 vpn-idle-timeout 60
=OUTPUT=
username jon.doe@token.example.com attributes
no vpn-framed-ip-address 10.1.2.3 255.0.0.0
no vpn-simultaneous-logins 4
no password-storage enable
vpn-framed-ip-address 10.11.22.33 255.255.0.0
vpn-idle-timeout 60
=END=

############################################################
=TITLE=Modify group-policy attributes
=DEVICE=
group-policy VPN-group internal
group-policy VPN-group attributes
 banner value Welcome!
 dns-server value 10.1.2.3 10.44.55.66
 split-tunnel-policy tunnelspecified
 vpn-idle-timeout 60
 pfs
 anyconnect-custom perapp value SomeName
username jon.doe@token.example.com nopassword
username jon.doe@token.example.com attributes
 vpn-group-policy VPN-group
=NETSPOC=
group-policy VPN-group internal
group-policy VPN-group attributes
 banner value Willkommen!
 dns-server value 10.1.2.3
 split-tunnel-policy tunnelall
 vpn-session-timeout 40
username jon.doe@token.example.com nopassword
username jon.doe@token.example.com attributes
 vpn-group-policy VPN-group
=OUTPUT=
group-policy VPN-group attributes
no banner value Welcome!
no dns-server value 10.1.2.3 10.44.55.66
no split-tunnel-policy tunnelspecified
no vpn-idle-timeout 60
no pfs
no anyconnect-custom perapp value SomeName
banner value Willkommen!
dns-server value 10.1.2.3
split-tunnel-policy tunnelall
vpn-session-timeout 40
=END=

############################################################
=TITLE=Remove group-policy and username
=DEVICE=
group-policy VPN-group internal
group-policy VPN-group attributes
 banner value Welcome!
 dns-server value 10.1.2.3 10.44.55.66
 split-tunnel-policy tunnelspecified
 vpn-idle-timeout 60
 pfs
username jon.doe@token.example.com nopassword
username jon.doe@token.example.com attributes
 vpn-group-policy VPN-group
=NETSPOC=NONE
=OUTPUT=
clear configure username jon.doe@token.example.com
clear configure group-policy VPN-group
=END=

############################################################
=TITLE=Clear group-policy DfltGrpPolicy
=DEVICE=
group-policy DfltGrpPolicy attributes
 banner value Willkommen!
 vpn-idle-timeout 240
 vpn-simultaneous-logins 1
 vpn-tunnel-protocol ikev2
=NETSPOC=NONE
=OUTPUT=
no group-policy DfltGrpPolicy attributes
=END=

############################################################
=TITLE=Parse tunnel-group, group-policy, ca cert map, pool
=TEMPL=input
access-list split-tunnel standard permit 10.1.0.0 255.255.255.0
access-list vpn-filter extended permit ip 10.1.2.192 255.255.255.192 10.1.0.0 255.255.255.0
access-list vpn-filter extended deny ip any4 any4
crypto ca certificate map ca-map 10
 subject-name attr ea co @sub.example.com
ip local pool pool 10.1.219.192-10.1.219.255 mask 0.0.0.63
group-policy VPN-group internal
group-policy VPN-group attributes
 address-pools value pool
 banner value Willkommen beim Zugang per VPN
 split-tunnel-network-list value split-tunnel
 split-tunnel-policy tunnelspecified
 vpn-filter value vpn-filter
 vpn-idle-timeout 60
tunnel-group VPN-tunnel type remote-access
tunnel-group VPN-tunnel general-attributes
 default-group-policy VPN-group
tunnel-group VPN-tunnel ipsec-attributes
 peer-id-validate req
 isakmp ikev1-user-authentication none
 trust-point ASDM_TrustPoint4
tunnel-group VPN-tunnel webvpn-attributes
 authentication aaa certificate
tunnel-group-map ca-map 20 VPN-tunnel
webvpn
 certificate-group-map ca-map 20 VPN-tunnel
=DEVICE=NONE
=NETSPOC=[[input]]
=OUTPUT=
crypto ca certificate map ca-map-DRC-0 10
subject-name attr ea co @sub.example.com
tunnel-group VPN-tunnel-DRC-0 type remote-access
group-policy VPN-group-DRC-0 internal
ip local pool pool-DRC-0 10.1.219.192-10.1.219.255 mask 0.0.0.63
access-list split-tunnel-DRC-0 standard permit 10.1.0.0 255.255.255.0
access-list vpn-filter-DRC-0 extended permit ip 10.1.2.192 255.255.255.192 10.1.0.0 255.255.255.0
access-list vpn-filter-DRC-0 extended deny ip any4 any4
group-policy VPN-group-DRC-0 attributes
address-pools value pool-DRC-0
banner value Willkommen beim Zugang per VPN
split-tunnel-network-list value split-tunnel-DRC-0
split-tunnel-policy tunnelspecified
vpn-filter value vpn-filter-DRC-0
vpn-idle-timeout 60
tunnel-group VPN-tunnel-DRC-0 general-attributes
default-group-policy VPN-group-DRC-0
tunnel-group VPN-tunnel-DRC-0 ipsec-attributes
peer-id-validate req
isakmp ikev1-user-authentication none
trust-point ASDM_TrustPoint4
tunnel-group VPN-tunnel-DRC-0 webvpn-attributes
authentication aaa certificate
tunnel-group-map ca-map-DRC-0 20 VPN-tunnel-DRC-0
webvpn
certificate-group-map ca-map-DRC-0 20 VPN-tunnel-DRC-0
=END=

=TITLE=Unchanged tunnel-group, group-policy, ca cert map, pool
=DEVICE=[[input]]
=NETSPOC=[[input]]
=OUTPUT=NONE

############################################################
=TITLE=Match tunnel-group-map by subject-name of ca-cert-map
=DEVICE=
tunnel-group VPN-tunnel1 type remote-access
tunnel-group VPN-tunnel1 general-attributes
tunnel-group VPN-tunnel1 ipsec-attributes
 trust-point ASDM_TrustPoint1
tunnel-group VPN-tunnel2 type remote-access
tunnel-group VPN-tunnel2 general-attributes
tunnel-group VPN-tunnel2 ipsec-attributes
 trust-point ASDM_TrustPoint2
crypto ca certificate map ca-map1 10
 subject-name attr ea co @b.example.com
crypto ca certificate map ca-map2 10
 subject-name attr ea eq x@a.example.com
 extended-key-usage co clientauth
tunnel-group-map default-group DefaultL2LGroup
tunnel-group-map ca-map1 20 VPN-tunnel1
tunnel-group-map ca-map2 20 VPN-tunnel2
=NETSPOC=
tunnel-group tunnel-a type remote-access
tunnel-group tunnel-a general-attributes
tunnel-group tunnel-a ipsec-attributes
 trust-point ASDM_TrustPoint2
tunnel-group tunnel-b type remote-access
tunnel-group tunnel-b general-attributes
tunnel-group tunnel-b ipsec-attributes
 peer-id-validate req
 isakmp ikev1-user-authentication none
 trust-point ASDM_TrustPoint1
crypto ca certificate map map-a 11
 extended-key-usage co clientauth
 subject-name attr ea eq X@A.example.com
crypto ca certificate map map-b 12
 subject-name attr ea co @b.EXAMPLE.com
tunnel-group-map map-a 20 tunnel-a
tunnel-group-map map-b 20 tunnel-b
=OUTPUT=
tunnel-group VPN-tunnel1 ipsec-attributes
peer-id-validate req
isakmp ikev1-user-authentication none
=END=

############################################################
=TITLE=Ignore ca certificate map with duplicate subject
=DEVICE=
crypto ca certificate map map1 10
 subject-name attr ea co @sub.example.com
crypto ca certificate map map2 10
 subject-name attr ea co @sub.example.com
tunnel-group VPN-tunnel1 type remote-access
tunnel-group VPN-tunnel1 general-attributes
tunnel-group VPN-tunnel1 ipsec-attributes
 trust-point ASDM_TrustPoint1
tunnel-group-map map2 10 VPN-tunnel1
=NETSPOC=
crypto ca certificate map map-b 12
 subject-name attr ea co @SUB.EXAMPLE.com
tunnel-group tunnel-b type remote-access
tunnel-group tunnel-b general-attributes
tunnel-group tunnel-b ipsec-attributes
 peer-id-validate req
 isakmp ikev1-user-authentication none
 trust-point ASDM_TrustPoint1
tunnel-group-map map-b 12 tunnel-b
=OUTPUT=
tunnel-group VPN-tunnel1 ipsec-attributes
peer-id-validate req
isakmp ikev1-user-authentication none
=END=

############################################################
=TITLE=Remove tunnel-group, crypto-ca-cert-map, tunnel-group-map
=DEVICE=
tunnel-group VPN-tunnel type remote-access
tunnel-group VPN-tunnel general-attributes
tunnel-group VPN-tunnel ipsec-attributes
 trust-point ASDM_TrustPoint4
crypto ca certificate map ca-map 10
 subject-name attr ea co @sub.example.com
tunnel-group-map ca-map 20 VPN-tunnel
=NETSPOC=NONE
=OUTPUT=
no tunnel-group-map ca-map 20 VPN-tunnel
clear configure crypto ca certificate map ca-map
clear configure tunnel-group VPN-tunnel
=END=

############################################################
=TITLE=Modify tunnel-group ipsec-attributes
=DEVICE=
tunnel-group VPN-tunnel type remote-access
tunnel-group VPN-tunnel general-attributes
tunnel-group VPN-tunnel ipsec-attributes
 trust-point ASDM_TrustPoint4
crypto ca certificate map ca-map 10
 subject-name attr ea co @sub.example.com
tunnel-group-map ca-map 20 VPN-tunnel
=NETSPOC=
tunnel-group VPN-tunnel type remote-access
tunnel-group VPN-tunnel general-attributes
tunnel-group VPN-tunnel ipsec-attributes
 trust-point ASDM_TrustPoint5
crypto ca certificate map ca-map 10
 subject-name attr ea co @sub.example.com
tunnel-group-map ca-map 20 VPN-tunnel
=OUTPUT=
tunnel-group VPN-tunnel ipsec-attributes
no trust-point ASDM_TrustPoint4
trust-point ASDM_TrustPoint5
=END=

############################################################
=TITLE=Break up identical references to group-policy
=DEVICE=
ip local pool pool 10.1.219.192-10.1.219.255 mask 0.0.0.63
access-list vpn-filter extended permit ip host 10.1.2.2 host 10.1.0.2
group-policy VPN-group internal
group-policy VPN-group attributes
 address-pools value pool
 vpn-filter value vpn-filter
tunnel-group 1.1.1.1 type ipsec-l2l
tunnel-group 1.1.1.1 general-attributes
 default-group-policy VPN-group
tunnel-group 1.1.1.2 type ipsec-l2l
tunnel-group 1.1.1.2 general-attributes
 default-group-policy VPN-group
=NETSPOC=
ip local pool pool 10.1.219.192-10.1.219.255 mask 0.0.0.63
access-list vpn-filter1 extended permit ip host 10.1.2.2 host 10.1.0.2
access-list vpn-filter2 extended permit ip host 10.1.2.3 host 10.1.0.3
group-policy VPN-group1 internal
group-policy VPN-group1 attributes
 address-pools value pool
 vpn-filter value vpn-filter1
group-policy VPN-group2 internal
group-policy VPN-group2 attributes
 address-pools value pool
 vpn-filter value vpn-filter2
tunnel-group 1.1.1.1 type ipsec-l2l
tunnel-group 1.1.1.1 general-attributes
 default-group-policy VPN-group1
tunnel-group 1.1.1.2 type ipsec-l2l
tunnel-group 1.1.1.2 general-attributes
 default-group-policy VPN-group2
=OUTPUT=
group-policy VPN-group2-DRC-0 internal
access-list vpn-filter2-DRC-0 extended permit ip host 10.1.2.3 host 10.1.0.3
group-policy VPN-group2-DRC-0 attributes
address-pools value pool
vpn-filter value vpn-filter2-DRC-0
exit
tunnel-group 1.1.1.2 general-attributes
default-group-policy VPN-group2-DRC-0
=END=

############################################################
=TITLE=Remove group-policy from Netspoc left over on device
=DEVICE=
ip local pool pool-DRC-0 10.1.23.0-10.1.23.127 mask 255.255.255.128
group-policy VPN-group-DRC-0 internal
group-policy VPN-group-DRC-0 attributes
 vpn-idle-timeout 120
 address-pools value pool-DRC-0
group-policy VPN-group-DRC-1 internal
group-policy VPN-group-DRC-1 attributes
 banner value Willkommen beim Dataport VPN Service XCS-Admin
 vpn-idle-timeout 120
 address-pools value pool-DRC-0
=NETSPOC=NONE
=OUTPUT=
clear configure group-policy VPN-group-DRC-0
clear configure group-policy VPN-group-DRC-1
no ip local pool pool-DRC-0 10.1.23.0-10.1.23.127 mask 255.255.255.128
=END=

############################################################
=TITLE=Remove tunnel- and certificate-group-map with all refs
=DEVICE=
access-list vpn-filter extended permit ip 10.1.2.192 255.255.255.192 10.1.0.0 255.255.255.0
crypto ca certificate map ca-map 10
 subject-name attr ea co @sub.example.com
ip local pool pool 10.1.219.192-10.1.219.255 mask 0.0.0.63
group-policy VPN-group internal
group-policy VPN-group attributes
 address-pools value pool
 vpn-filter value vpn-filter
tunnel-group VPN-tunnel type remote-access
tunnel-group VPN-tunnel general-attributes
 default-group-policy VPN-group
tunnel-group-map ca-map 20 VPN-tunnel
webvpn
 certificate-group-map ca-map 20 VPN-tunnel
=NETSPOC=NONE
=OUTPUT=
webvpn
no certificate-group-map ca-map 20 VPN-tunnel
no tunnel-group-map ca-map 20 VPN-tunnel
clear configure crypto ca certificate map ca-map
clear configure tunnel-group VPN-tunnel
clear configure group-policy VPN-group
clear configure access-list vpn-filter
no ip local pool pool 10.1.219.192-10.1.219.255 mask 0.0.0.63
=END=

############################################################
=TITLE=Break up identical references to tunnel-group
=DEVICE=
access-list vpn-filter extended permit ip 10.1.2.192 255.255.255.192 10.1.0.0 255.255.255.0
crypto ca certificate map ca-map 10
 subject-name attr ea co @sub.example.com
ip local pool pool 10.1.219.192-10.1.219.255 mask 0.0.0.63
group-policy VPN-group internal
group-policy VPN-group attributes
 address-pools value pool
 vpn-filter value vpn-filter
tunnel-group VPN-tunnel type remote-access
tunnel-group VPN-tunnel general-attributes
 default-group-policy VPN-group
tunnel-group-map ca-map 20 VPN-tunnel
webvpn
 certificate-group-map ca-map 20 VPN-tunnel
=NETSPOC=
access-list vpn-filter1 extended permit ip 10.1.2.192 255.255.255.192 10.1.0.0 255.255.255.0
access-list vpn-filter2 extended permit ip 10.1.2.192 255.255.255.192 10.2.0.0 255.255.255.0
crypto ca certificate map ca-map 10
 subject-name attr ea co @sub.example.com
ip local pool pool 10.1.219.192-10.1.219.255 mask 0.0.0.63
group-policy VPN-group1 internal
group-policy VPN-group1 attributes
 address-pools value pool
 vpn-filter value vpn-filter1
group-policy VPN-group2 internal
group-policy VPN-group2 attributes
 address-pools value pool
 vpn-filter value vpn-filter2
tunnel-group VPN-tunnel1 type remote-access
tunnel-group VPN-tunnel1 general-attributes
 default-group-policy VPN-group1
tunnel-group VPN-tunnel2 type remote-access
tunnel-group VPN-tunnel2 general-attributes
 default-group-policy VPN-group2
tunnel-group-map ca-map 20 VPN-tunnel1
webvpn
 certificate-group-map ca-map 20 VPN-tunnel2
=OUTPUT=
tunnel-group VPN-tunnel2-DRC-0 type remote-access
group-policy VPN-group2-DRC-0 internal
access-list vpn-filter2-DRC-0 extended permit ip 10.1.2.192 255.255.255.192 10.2.0.0 255.255.255.0
group-policy VPN-group2-DRC-0 attributes
address-pools value pool
vpn-filter value vpn-filter2-DRC-0
tunnel-group VPN-tunnel2-DRC-0 general-attributes
default-group-policy VPN-group2-DRC-0
exit
webvpn
certificate-group-map ca-map 20 VPN-tunnel2-DRC-0
=END=

############################################################
=TITLE=Change IP tunnel-group to mapped tunnel-group
=DEVICE=
tunnel-group 193.155.130.20 type ipsec-l2l
tunnel-group 193.155.130.20 ipsec-attributes
 ikev1 pre-shared-key *
 peer-id-validate nocheck
=NETSPOC=
tunnel-group 193.155.130.20 type ipsec-l2l
tunnel-group 193.155.130.20 ipsec-attributes
 trust-point ASDM_TrustPoint5
 ikev2 local-authentication certificate Trustpoint2
 ikev2 remote-authentication certificate
crypto ca certificate map ca-map 10
 subject-name attr ea eq some@example.com
tunnel-group-map ca-map 20 193.155.130.20
=OUTPUT=
crypto ca certificate map ca-map-DRC-0 10
subject-name attr ea eq some@example.com
exit
tunnel-group 193.155.130.20 ipsec-attributes
no peer-id-validate nocheck
trust-point ASDM_TrustPoint5
ikev2 local-authentication certificate Trustpoint2
ikev2 remote-authentication certificate
tunnel-group-map ca-map-DRC-0 20 193.155.130.20
=END=

############################################################
=TITLE=tunnelgroup-map references unknown tunnel-group
=DEVICE=
crypto ca certificate map ca-map 10
 subject-name attr ea eq some@example.com
tunnel-group-map ca-map 20 193.155.130.20
=NETSPOC=NONE
=ERROR=
ERROR>>> While reading device: 'tunnel-group-map ca-map 20 193.155.130.20' references unknown 'tunnel-group 193.155.130.20'
=END=

############################################################
=TITLE=Must not delete default tunnel-group
=DEVICE=
tunnel-group DefaultRAGroup type remote-access
tunnel-group DefaultRAGroup ipsec-attributes
 ikev2 local-authentication certificate Trustpoint2
 ikev2 remote-authentication certificate
=NETSPOC=NONE
=OUTPUT=
no tunnel-group DefaultRAGroup ipsec-attributes
=END=

############################################################
=TITLE=Modify ip local pool
=DEVICE=
ip local pool pool 10.1.219.192-10.1.219.255 mask 0.0.0.63
group-policy VPN-group internal
group-policy VPN-group attributes
 address-pools value pool
tunnel-group VPN-tunnel type remote-access
tunnel-group VPN-tunnel general-attributes
 default-group-policy VPN-group
crypto ca certificate map ca-map 10
 subject-name attr ea co @sub.example.com
tunnel-group-map ca-map 20 VPN-tunnel
=NETSPOC=
ip local pool pool 10.1.219.192-10.1.219.208 mask 0.0.0.15
group-policy VPN-group internal
group-policy VPN-group attributes
 address-pools value pool
tunnel-group VPN-tunnel type remote-access
tunnel-group VPN-tunnel general-attributes
 default-group-policy VPN-group
crypto ca certificate map ca-map 10
 subject-name attr ea co @sub.example.com
tunnel-group-map ca-map 20 VPN-tunnel
=OUTPUT=
ip local pool pool-DRC-0 10.1.219.192-10.1.219.208 mask 0.0.0.15
group-policy VPN-group attributes
address-pools value pool-DRC-0
no ip local pool pool 10.1.219.192-10.1.219.255 mask 0.0.0.63
=END=

############################################################
=TITLE=Add webvpn-attributes, delete ipsec-attributes
=DEVICE=
tunnel-group NAME type remote-access
tunnel-group NAME ipsec-attributes
 trust-point ASDM_TrustPoint5
crypto ca certificate map ca-map 10
 subject-name attr ea co @sub.example.com
tunnel-group-map ca-map 20 NAME
=NETSPOC=
tunnel-group VPN-tunnel type remote-access
tunnel-group VPN-tunnel webvpn-attributes
 authentication aaa
crypto ca certificate map ca-map 10
 subject-name attr ea co @sub.example.com
tunnel-group-map ca-map 20 VPN-tunnel
=OUTPUT=
no tunnel-group NAME ipsec-attributes
tunnel-group NAME webvpn-attributes
authentication aaa
=END=

############################################################
=TITLE=Add extended-key-usage
=DEVICE=
tunnel-group NAME type remote-access
tunnel-group NAME ipsec-attributes
 trust-point ASDM_TrustPoint5
crypto ca certificate map ca-map 10
 subject-name attr ea co @sub.example.com
tunnel-group-map ca-map 20 NAME
=NETSPOC=
tunnel-group VPN-tunnel type remote-access
tunnel-group VPN-tunnel ipsec-attributes
 trust-point ASDM_TrustPoint5
crypto ca certificate map ca-map 10
 subject-name attr ea co @sub.example.com
 extended-key-usage co clientauth
tunnel-group-map ca-map 20 VPN-tunnel
=OUTPUT=
crypto ca certificate map ca-map 10
extended-key-usage co clientauth
=END=

############################################################
=TITLE=Remove extended-key-usage
=DEVICE=
tunnel-group NAME type remote-access
tunnel-group NAME ipsec-attributes
 trust-point ASDM_TrustPoint5
crypto ca certificate map ca-map 10
 subject-name attr ea co @sub.example.com
 extended-key-usage co clientauth
tunnel-group-map ca-map 20 NAME
=NETSPOC=
tunnel-group VPN-tunnel type remote-access
tunnel-group VPN-tunnel ipsec-attributes
 trust-point ASDM_TrustPoint5
crypto ca certificate map ca-map 10
 subject-name attr ea co @sub.example.com
tunnel-group-map ca-map 20 VPN-tunnel
=OUTPUT=
crypto ca certificate map ca-map 10
no extended-key-usage co clientauth
=END=

############################################################
=TITLE=Change extended-key-usage
=DEVICE=
tunnel-group NAME type remote-access
tunnel-group NAME ipsec-attributes
 trust-point ASDM_TrustPoint5
crypto ca certificate map ca-map 10
 subject-name attr ea co @sub.example.com
 extended-key-usage co 1.3.6.1.4.1.311.20.2.2
tunnel-group-map ca-map 20 NAME
=NETSPOC=
tunnel-group VPN-tunnel type remote-access
tunnel-group VPN-tunnel ipsec-attributes
 trust-point ASDM_TrustPoint5
crypto ca certificate map ca-map 10
 subject-name attr ea co @sub.example.com
 extended-key-usage co clientauth
tunnel-group-map ca-map 20 VPN-tunnel
=OUTPUT=
crypto ca certificate map ca-map 10
no extended-key-usage co 1.3.6.1.4.1.311.20.2.2
extended-key-usage co clientauth
=END=

############################################################
=TITLE=Add certificate-group-map
=DEVICE=
tunnel-group NAME type remote-access
tunnel-group NAME ipsec-attributes
 trust-point ASDM_TrustPoint5
crypto ca certificate map ca-map 10
 subject-name attr ea co @sub.example.com
tunnel-group-map ca-map 20 NAME
=NETSPOC=
tunnel-group VPN-tunnel type remote-access
tunnel-group VPN-tunnel ipsec-attributes
 trust-point ASDM_TrustPoint5
crypto ca certificate map ca-map 10
 subject-name attr ea co @sub.example.com
tunnel-group-map ca-map 20 VPN-tunnel
webvpn
 certificate-group-map ca-map 20 VPN-tunnel
=OUTPUT=
webvpn
certificate-group-map ca-map 20 NAME
=END=

############################################################
=TITLE=Delete tunnel-group
=DEVICE=
tunnel-group 193.155.130.20 type ipsec-l2l
tunnel-group 193.155.130.20 ipsec-attributes
 pre-shared-key *
 peer-id-validate nocheck
=NETSPOC=NONE
=OUTPUT=
clear configure tunnel-group 193.155.130.20
=END=

############################################################
=TITLE=Insert and delete entries from crypto map sequence
=DEVICE=
[[crypto_ASA]]
crypto ipsec ikev1 transform-set Trans1a esp-3des esp-md5-hmac
crypto ipsec ikev1 transform-set Trans1b esp-3des esp-md5-hmac
crypto ipsec ikev1 transform-set Trans2 esp-aes-192 esp-sha-hmac
crypto ipsec ikev2 ipsec-proposal Proposal1
 protocol esp encryption aes-192 aes 3des
 protocol esp integrity sha-1
access-list crypto-outside-1 extended permit ip any4 10.0.1.0 255.255.255.0
crypto map crypto-outside 1 match address crypto-outside-1
crypto map crypto-outside 1 set peer 10.0.0.1
crypto map crypto-outside 1 set ikev1 transform-set Trans1b
access-list crypto-outside-3 extended permit ip any4 10.0.3.0 255.255.255.0
crypto map crypto-outside 3 match address crypto-outside-3
crypto map crypto-outside 3 set peer 10.0.0.3
crypto map crypto-outside 3 set ikev2 ipsec-proposal Proposal1
crypto map crypto-outside 3 set pfs
crypto map crypto-outside interface outside
=NETSPOC=
crypto ipsec ikev1 transform-set Trans1 esp-3des esp-md5-hmac
crypto ipsec ikev2 ipsec-proposal Proposal1
 protocol esp encryption aes-192 aes-256
 protocol esp integrity  sha-1
access-list crypto-outside-1 extended permit ip any4 10.0.2.0 255.255.255.0
crypto map crypto-outside 1 match address crypto-outside-1
crypto map crypto-outside 1 set peer 10.0.0.2
crypto map crypto-outside 1 set ikev1 transform-set Trans1
crypto map crypto-outside 1 set pfs group5
crypto map crypto-outside 3 set peer 10.0.0.3
crypto map crypto-outside 3 set ikev2 ipsec-proposal Proposal1
crypto map crypto-outside 3 set pfs group2
crypto map crypto-outside interface outside
=OUTPUT=
no crypto map crypto-outside 3 match address crypto-outside-3
crypto ipsec ikev2 ipsec-proposal Proposal1-DRC-0
protocol esp encryption aes-192 aes-256
protocol esp integrity sha-1
no crypto map crypto-outside 3 set ikev2 ipsec-proposal Proposal1
crypto map crypto-outside 3 set ikev2 ipsec-proposal Proposal1-DRC-0
access-list crypto-outside-1-DRC-0 extended permit ip any4 10.0.2.0 255.255.255.0
crypto map crypto-outside 2 match address crypto-outside-1-DRC-0
crypto map crypto-outside 2 set peer 10.0.0.2
crypto map crypto-outside 2 set ikev1 transform-set Trans1a
crypto map crypto-outside 2 set pfs group5
clear configure access-list crypto-outside-3
no crypto ipsec ikev2 ipsec-proposal Proposal1
no crypto map crypto-outside 1 match address crypto-outside-1
no crypto map crypto-outside 1 set peer 10.0.0.1
no crypto map crypto-outside 1 set ikev1 transform-set Trans1b
clear configure access-list crypto-outside-1
no crypto ipsec ikev1 transform-set Trans1b esp-3des esp-md5-hmac
=END=

############################################################
=TITLE=Incorporate unreferenced crypto map entry on device
=DEVICE=
[[crypto_ASA]]
crypto ipsec ikev1 transform-set Trans1 esp-3des esp-md5-hmac
crypto ipsec ikev1 transform-set Trans3 esp-aes-192 esp-sha-hmac
crypto map crypto-outside 1 set peer 10.0.0.1
crypto map crypto-outside 1 set ikev1 transform-set Trans1
crypto map crypto-outside 1 set pfs group5
crypto map crypto-outside 3 set peer 10.0.0.3
crypto map crypto-outside 3 set ikev1 transform-set Trans3
crypto map crypto-outside 3 set pfs
=NETSPOC=
crypto ipsec ikev1 transform-set Trans2 esp-3des esp-md5-hmac
crypto map crypto-outside 1 set peer 10.0.0.2
crypto map crypto-outside 1 set ikev1 transform-set Trans2
crypto map crypto-outside 1 set pfs group5
crypto map crypto-outside 3 set peer 10.0.0.3
crypto map crypto-outside 3 set ikev1 transform-set Trans2
crypto map crypto-outside 3 set pfs group5
crypto map crypto-outside interface outside
=OUTPUT=
no crypto map crypto-outside 3 set pfs
no crypto map crypto-outside 3 set ikev1 transform-set Trans3
crypto map crypto-outside 3 set ikev1 transform-set Trans1
crypto map crypto-outside 3 set pfs group5
crypto map crypto-outside 2 set peer 10.0.0.2
crypto map crypto-outside 2 set ikev1 transform-set Trans1
crypto map crypto-outside 2 set pfs group5
crypto map crypto-outside interface outside
no crypto ipsec ikev1 transform-set Trans3 esp-aes-192 esp-sha-hmac
no crypto map crypto-outside 1 set peer 10.0.0.1
no crypto map crypto-outside 1 set ikev1 transform-set Trans1
no crypto map crypto-outside 1 set pfs group5
=END=

############################################################
=TITLE=Remove crypto map
=DEVICE=
[[crypto_ASA]]
crypto ipsec ikev1 transform-set Trans1b-DRC-0 esp-3des esp-md5-hmac
access-list crypto-outside-1 extended permit ip any4 10.0.1.0 255.255.255.0
crypto map crypto-outside 1 match address crypto-outside-1
crypto map crypto-outside 1 set peer 10.0.0.1
crypto map crypto-outside 1 set ikev1 transform-set Trans1b-DRC-0
crypto map crypto-outside interface outside
=NETSPOC=
access-list outside_in extended deny ip any4 any4
access-group outside_in in interface outside
=OUTPUT=
access-list outside_in-DRC-0 extended deny ip any4 any4
access-group outside_in-DRC-0 in interface outside
no crypto map crypto-outside interface outside
no crypto map crypto-outside 1 match address crypto-outside-1
no crypto map crypto-outside 1 set peer 10.0.0.1
no crypto map crypto-outside 1 set ikev1 transform-set Trans1b-DRC-0
clear configure access-list crypto-outside-1
no crypto ipsec ikev1 transform-set Trans1b-DRC-0 esp-3des esp-md5-hmac
=END=

############################################################
=TITLE=Insert, change and delete dynamic crypto map
=DEVICE=
[[crypto_ASA]]
crypto ipsec ikev1 transform-set Trans1a esp-3des esp-md5-hmac
crypto ipsec ikev1 transform-set Trans1b esp-3des esp-sha-hmac
crypto ipsec ikev1 transform-set Trans3 esp-aes-256 esp-md5-hmac
access-list crypto-outside-65535 extended permit ip 10.1.1.0 255.255.255.0 10.99.2.0 255.255.255.0
access-list crypto-outside-65534 extended permit ip 10.1.3.0 255.255.255.0 10.99.2.0 255.255.255.0
access-list crypto-outside-65533 extended permit ip 10.1.4.0 255.255.255.0 10.99.2.0 255.255.255.0
crypto dynamic-map name4@example.com 40 match address crypto-outside-65533
crypto dynamic-map name4@example.com 40 set ikev1 transform-set Trans1a Trans1b
crypto dynamic-map name3@example.com 20 match address crypto-outside-65534
crypto dynamic-map name1@example.com 20 match address crypto-outside-65535
crypto dynamic-map name1@example.com 20 set ikev1 transform-set Trans1a Trans3
crypto dynamic-map name1@example.com 20 set pfs
crypto map crypto-outside 65533 ipsec-isakmp dynamic name4@example.com
crypto map crypto-outside 65534 ipsec-isakmp dynamic name3@example.com
crypto map crypto-outside 65535 ipsec-isakmp dynamic name1@example.com
crypto map crypto-outside interface outside
=NETSPOC=
crypto ipsec ikev1 transform-set Trans1 esp-3des esp-md5-hmac
crypto ipsec ikev1 transform-set Trans2 esp-aes esp-md5-hmac
access-list crypto-outside-1 extended permit ip 10.1.1.0 255.255.255.0 10.99.2.0 255.255.255.0
access-list crypto-outside-2 extended permit ip 10.1.2.0 255.255.255.0 10.99.2.0 255.255.255.0
access-list crypto-outside-3 extended permit ip 10.1.3.0 255.255.255.0 10.99.2.0 255.255.255.0
crypto dynamic-map name3@example.com 20 match address crypto-outside-3
crypto dynamic-map name3@example.com 20 set ikev1 transform-set Trans1 Trans2
crypto dynamic-map name2@example.com 20 match address crypto-outside-2
crypto dynamic-map name1@example.com 20 match address crypto-outside-1
crypto dynamic-map name1@example.com 20 set security-association lifetime seconds 3600
crypto map crypto-outside 65532 ipsec-isakmp dynamic name3@example.com
crypto map crypto-outside 65533 ipsec-isakmp dynamic name2@example.com
crypto map crypto-outside 65534 ipsec-isakmp dynamic name1@example.com
crypto map crypto-outside interface outside
=OUTPUT=
crypto ipsec ikev1 transform-set Trans2-DRC-0 esp-aes esp-md5-hmac
crypto dynamic-map name3@example.com 20 set ikev1 transform-set Trans1a Trans2-DRC-0
no crypto dynamic-map name1@example.com 20 set ikev1 transform-set Trans1a Trans3
no crypto dynamic-map name1@example.com 20 set pfs
crypto dynamic-map name1@example.com 20 set security-association lifetime seconds 3600
access-list crypto-outside-2-DRC-0 extended permit ip 10.1.2.0 255.255.255.0 10.99.2.0 255.255.255.0
crypto dynamic-map name2@example.com 20 match address crypto-outside-2-DRC-0
crypto map crypto-outside 65532 ipsec-isakmp dynamic name2@example.com
no crypto ipsec ikev1 transform-set Trans3 esp-aes-256 esp-md5-hmac
no crypto map crypto-outside 65533 ipsec-isakmp dynamic name4@example.com
no crypto dynamic-map name4@example.com 40 match address crypto-outside-65533
no crypto dynamic-map name4@example.com 40 set ikev1 transform-set Trans1a Trans1b
clear configure access-list crypto-outside-65533
no crypto ipsec ikev1 transform-set Trans1b esp-3des esp-sha-hmac
=END=

############################################################
=TITLE=Unchanged ldap map-values
=TEMPL=input
! vpn-filter-G1
access-list vpn-filter-G1 extended permit ip 10.3.4.8 255.255.255.248 any4
access-list vpn-filter-G1 extended deny ip any4 any4
ip local pool pool-G1 10.3.4.8-10.3.4.15 mask 255.255.255.248
group-policy VPN-group-G1 internal
group-policy VPN-group-G1 attributes
 address-pools value pool-G1
 vpn-filter value vpn-filter-G1

! vpn-filter-G2
access-list vpn-filter-G2 extended permit ip 10.3.4.16 255.255.255.248 any4
access-list vpn-filter-G2 extended deny ip any4 any4
ip local pool pool-G2 10.3.4.16-10.3.4.23 mask 255.255.255.248
group-policy VPN-group-G2 internal
group-policy VPN-group-G2 attributes
 address-pools value pool-G2
 vpn-filter value vpn-filter-G2

crypto ca certificate map ca-map-G1 10
 subject-name attr cn co G1
tunnel-group VPN-tunnel-G1 type remote-access
tunnel-group VPN-tunnel-G1 general-attributes
 authentication-server-group LDAP_KV
tunnel-group VPN-tunnel-G1 ipsec-attributes
 ikev1 trust-point ASDM_TrustPoint1
 ikev1 user-authentication none
tunnel-group VPN-tunnel-G1 webvpn-attributes
 authentication aaa certificate
tunnel-group-map ca-map-G1 10 VPN-tunnel-G1

aaa-server LDAP_KV protocol ldap
aaa-server LDAP_KV host X
 ldap-attribute-map LDAPMAP

webvpn
 certificate-group-map ca-map-G1 10 VPN-tunnel-G1

ldap attribute-map LDAPMAP
 map-name memberOf Group-Policy
 map-value memberOf CN=g-m1,OU=VPN,OU=group,DC=example,DC=com VPN-group-G1
 map-value memberOf "CN=g-m2,OU=VPN,OU=local group,DC=example,DC=com" VPN-group-G2
=DEVICE=[[input]]
=NETSPOC=[[input]]
=OUTPUT=NONE

############################################################
=TITLE=Transfer aaa-server manually
=DEVICE=NONE
=NETSPOC=[[input]]
=ERROR=
ERROR>>> 'aaa-server LDAP_KV' must be transferred manually
=END=

############################################################
=TITLE=Transfer ldap map manually
=DEVICE=
! vpn-filter-G1
crypto ca certificate map ca-map-G1 10
 subject-name attr cn co G1
tunnel-group VPN-tunnel-G1 type remote-access
tunnel-group VPN-tunnel-G1 general-attributes
 authentication-server-group LDAP_KV
tunnel-group VPN-tunnel-G1 ipsec-attributes
 ikev1 trust-point ASDM_TrustPoint1
 ikev1 user-authentication none
tunnel-group VPN-tunnel-G1 webvpn-attributes
 authentication aaa certificate
tunnel-group-map ca-map-G1 10 VPN-tunnel-G1

aaa-server LDAP_KV protocol ldap
aaa-server LDAP_KV (inside) host 10.2.8.16
 ldap-base-dn DC=example,DC=com
 ldap-scope subtree
 ldap-naming-attribute dNSHostName
 ldap-login-password *****
 ldap-login-dn CN=VPN,OU=Admin,DC=example,DC=com
=NETSPOC=[[input]]
=ERROR=
ERROR>>> 'ldap attribute-map LDAPMAP' must be transferred manually
=END=

############################################################
=TITLE=Reject aaa-server with different ldap maps
=DEVICE=
! vpn-filter-G1
crypto ca certificate map ca-map-G1 10
 subject-name attr cn co G1
tunnel-group VPN-tunnel-G1 type remote-access
tunnel-group VPN-tunnel-G1 general-attributes
 authentication-server-group LDAP_KV
tunnel-group VPN-tunnel-G1 ipsec-attributes
 ikev1 trust-point ASDM_TrustPoint1
 ikev1 user-authentication none
tunnel-group VPN-tunnel-G1 webvpn-attributes
 authentication aaa certificate
tunnel-group-map ca-map-G1 10 VPN-tunnel-G1

aaa-server LDAP_KV protocol ldap
aaa-server LDAP_KV (inside) host 10.2.8.8
 ldap-attribute-map MAP1
aaa-server LDAP_KV (inside) host 10.2.8.16
 ldap-attribute-map MAP2
=NETSPOC=[[input]]
=ERROR=
ERROR>>> aaa-server LDAP_KV must not use different values in 'ldap-attribute-map'
=END=

############################################################
=TITLE=Find existant aaa-server and ldap-map on device
=DEVICE=
aaa-server ABC protocol ldap
aaa-server ABC (inside) host 1.2.8.15
 ldap-attribute-map OTHER
ldap attribute-map OTHER
 map-name memberOf Group-Policy
aaa-server LDAP_KV protocol ldap
aaa-server LDAP_KV (inside) host 10.2.8.16
 ldap-base-dn DC=example,DC=com
 ldap-scope subtree
 ldap-naming-attribute dNSHostName
 ldap-login-password *****
 ldap-login-dn CN=VPN,OU=Admin,DC=example,DC=com
 ldap-attribute-map LDAPMAP
ldap attribute-map LDAPMAP
 map-name memberOf Group-Policy
=NETSPOC=[[input]]
=OUTPUT=
crypto ca certificate map ca-map-G1-DRC-0 10
subject-name attr cn co g1
tunnel-group VPN-tunnel-G1-DRC-0 type remote-access
group-policy VPN-group-G1-DRC-0 internal
ip local pool pool-G1-DRC-0 10.3.4.8-10.3.4.15 mask 255.255.255.248
access-list vpn-filter-G1-DRC-0 extended permit ip 10.3.4.8 255.255.255.248 any4
access-list vpn-filter-G1-DRC-0 extended deny ip any4 any4
group-policy VPN-group-G1-DRC-0 attributes
address-pools value pool-G1-DRC-0
vpn-filter value vpn-filter-G1-DRC-0
exit
ldap attribute-map LDAPMAP
map-value memberOf "CN=g-m1,OU=VPN,OU=group,DC=example,DC=com" VPN-group-G1-DRC-0
group-policy VPN-group-G2-DRC-0 internal
ip local pool pool-G2-DRC-0 10.3.4.16-10.3.4.23 mask 255.255.255.248
access-list vpn-filter-G2-DRC-0 extended permit ip 10.3.4.16 255.255.255.248 any4
access-list vpn-filter-G2-DRC-0 extended deny ip any4 any4
group-policy VPN-group-G2-DRC-0 attributes
address-pools value pool-G2-DRC-0
vpn-filter value vpn-filter-G2-DRC-0
exit
ldap attribute-map LDAPMAP
map-value memberOf "CN=g-m2,OU=VPN,OU=local group,DC=example,DC=com" VPN-group-G2-DRC-0
tunnel-group VPN-tunnel-G1-DRC-0 general-attributes
authentication-server-group LDAP_KV
tunnel-group VPN-tunnel-G1-DRC-0 ipsec-attributes
ikev1 trust-point ASDM_TrustPoint1
ikev1 user-authentication none
tunnel-group VPN-tunnel-G1-DRC-0 webvpn-attributes
authentication aaa certificate
tunnel-group-map ca-map-G1-DRC-0 10 VPN-tunnel-G1-DRC-0
webvpn
certificate-group-map ca-map-G1-DRC-0 10 VPN-tunnel-G1-DRC-0
=END=

############################################################
=TITLE=Change authentication server at tunnel-group
=DEVICE=
access-list vpn-filter-G1 extended permit ip 10.3.4.8 255.255.255.248 any4
access-list vpn-filter-G1 extended deny ip any4 any4
crypto ca certificate map ca-map-G1 10
 subject-name attr cn co G1
ip local pool pool-G1 10.3.4.8-10.3.4.15 mask 255.255.255.248
group-policy VPN-group-G1 internal
group-policy VPN-group-G1 attributes
 address-pools value pool-G1
 vpn-filter value vpn-filter-G1
access-list vpn-filter-G2 extended permit ip 10.3.4.16 255.255.255.248 any4
access-list vpn-filter-G2 extended deny ip any4 any4
ip local pool pool-G2 10.3.4.16-10.3.4.23 mask 255.255.255.248
group-policy VPN-group-G2 internal
group-policy VPN-group-G2 attributes
 address-pools value pool-G2
 vpn-filter value vpn-filter-G2
tunnel-group VPN-tunnel-G1 type remote-access
tunnel-group VPN-tunnel-G1 general-attributes
 authentication-server-group OLD
tunnel-group VPN-tunnel-G1 ipsec-attributes
 ikev1 trust-point ASDM_TrustPoint1
 ikev1 user-authentication none
tunnel-group VPN-tunnel-G1 webvpn-attributes
 authentication aaa certificate
tunnel-group-map ca-map-G1 10 VPN-tunnel-G1

aaa-server LDAP_KV protocol ldap
aaa-server LDAP_KV (inside) host 10.2.8.16
 ldap-base-dn DC=example,DC=com
 ldap-scope subtree
 ldap-naming-attribute dNSHostName
 ldap-login-password *****
 ldap-login-dn CN=VPN,OU=Admin,DC=example,DC=com
 ldap-attribute-map LDAPMAP

aaa-server OLD protocol ldap
aaa-server OLD (inside) host 10.2.9.16
 ldap-base-dn DC=example,DC=com
 ldap-scope subtree
 ldap-naming-attribute dNSHostName
 ldap-login-password *****
 ldap-login-dn CN=VPN,OU=Admin,DC=example,DC=com
 ldap-attribute-map LDAPMAP

webvpn
 certificate-group-map ca-map-G1 10 VPN-tunnel-G1

ldap attribute-map LDAPMAP
 map-name memberOf Group-Policy
 map-value memberOf "CN=g-m1,OU=VPN,OU=group,DC=example,DC=com" VPN-group-G1
 map-value memberOf "CN=g-m2,OU=VPN,OU=local group,DC=example,DC=com" VPN-group-G2
=NETSPOC=[[input]]
=OUTPUT=
tunnel-group VPN-tunnel-G1 general-attributes
authentication-server-group LDAP_KV
=END=

############################################################
=TITLE=Insert, unchanged and remove ldap map-value
=DEVICE=
access-list vpn-filter-G2 extended permit ip 10.3.4.16 255.255.255.248 any4
access-list vpn-filter-G2 extended deny ip any4 any4
ip local pool pool-G2 10.3.4.16-10.3.4.23 mask 255.255.255.248
group-policy VPN-group-G2 internal
group-policy VPN-group-G2 attributes
 address-pools value pool-G2
 vpn-filter value vpn-filter-G2

access-list vpn-filter-G3 extended permit ip 10.3.4.24 255.255.255.248 any4
access-list vpn-filter-G3 extended deny ip any4 any4
ip local pool pool-G3 10.3.4.24-10.3.4.31 mask 255.255.255.248
group-policy VPN-group-G3 internal
group-policy VPN-group-G3 attributes
 address-pools value pool-G3
 vpn-filter value vpn-filter-G3

crypto ca certificate map ca-map-G1 10
 subject-name attr cn co G1
tunnel-group VPN-tunnel-G1 type remote-access
tunnel-group VPN-tunnel-G1 general-attributes
 authentication-server-group LDAP_KV
tunnel-group VPN-tunnel-G1 ipsec-attributes
 ikev1 trust-point ASDM_TrustPoint1
 ikev1 user-authentication none
tunnel-group VPN-tunnel-G1 webvpn-attributes
 authentication aaa certificate
tunnel-group-map ca-map-G1 10 VPN-tunnel-G1

aaa-server LDAP_KV protocol ldap
aaa-server LDAP_KV (inside) host 10.2.8.16
 ldap-base-dn DC=example,DC=com
 ldap-scope subtree
 ldap-naming-attribute dNSHostName
 ldap-login-password *****
 ldap-login-dn CN=VPN,OU=Admin,DC=example,DC=com
 ldap-attribute-map LDAPMAP

! With two spaces of indentation and indented first argument
! Also two spaces in strings argument.
ldap attribute-map LDAPMAP
  map-name  memberOf Group-Policy
  map-value memberOf "CN=g-m3,OU=VPN,OU=hi  h\"o\" x,DC=example,DC=com" VPN-group-G3
  map-value memberOf "CN=g-m2,OU=VPN,OU=local group,DC=example,DC=com" VPN-group-G2
=NETSPOC=[[input]]
=OUTPUT=
ldap attribute-map LDAPMAP
no map-value memberOf "CN=g-m3,OU=VPN,OU=hi h\"o\" x,DC=example,DC=com" VPN-group-G3
group-policy VPN-group-G1-DRC-0 internal
ip local pool pool-G1-DRC-0 10.3.4.8-10.3.4.15 mask 255.255.255.248
access-list vpn-filter-G1-DRC-0 extended permit ip 10.3.4.8 255.255.255.248 any4
access-list vpn-filter-G1-DRC-0 extended deny ip any4 any4
group-policy VPN-group-G1-DRC-0 attributes
address-pools value pool-G1-DRC-0
vpn-filter value vpn-filter-G1-DRC-0
exit
ldap attribute-map LDAPMAP
map-value memberOf "CN=g-m1,OU=VPN,OU=group,DC=example,DC=com" VPN-group-G1-DRC-0
webvpn
certificate-group-map ca-map-G1 10 VPN-tunnel-G1
clear configure group-policy VPN-group-G3
clear configure access-list vpn-filter-G3
no ip local pool pool-G3 10.3.4.24-10.3.4.31 mask 255.255.255.248
=END=

############################################################
=TITLE=Mixed indentation of ldap map-value
=DEVICE=
! With mixed indentation
ldap attribute-map LDAPMAP
  map-name memberOf Group-Policy
 map-value memberOf "CN=g-m1,OU=VPN,DC=example,DC=com" VPN-group-G1
  map-value memberOf "CN=g-m2,OU=VPN,DC=example,DC=com" VPN-group-G2
=NETSPOC=NONE
=ERROR=
ERROR>>> While reading device: Bad indentation in subcommands:
>>  map-name memberOf Group-Policy<<
>> map-value memberOf "CN=g-m1,OU=VPN,DC=example,DC=com" VPN-group-G1<<
=END=
