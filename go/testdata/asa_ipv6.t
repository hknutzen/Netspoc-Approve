
=TEMPL=minimal_device
interface Ethernet0/0
 nameif inside
interface Ethernet0/1
 nameif outside
=TEMPL=minimal_device1
interface Ethernet0/0
 nameif inside
=END=

############################################################
=TITLE=Alter IPv6 routing, leaving IPv4 routing untouched
=DEVICE=
[[minimal_device1]]
ipv6 route outside 10::3:0/112 10::2:2
route inside 10.20.0.0 255.255.255.0 10.1.2.3
route inside 10.22.0.0 255.255.0.0 10.1.2.4
=NETSPOC=
--router
access-list inside_in extended permit tcp host 10.1.1.1 any range 80 90
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
--ipv6/router
ipv6 route E2 1000::abcd:3:0/120 1000::abcd:2:2
=OUTPUT=
access-list inside_in-DRC-0 extended permit tcp host 10.1.1.1 any range 80 90
access-list inside_in-DRC-0 extended deny ip any4 any4
access-group inside_in-DRC-0 in interface inside
ipv6 route E2 1000::abcd:3:0/120 1000::abcd:2:2
no ipv6 route outside 10::3:0/112 10::2:2
=END=

############################################################
=TITLE=Leave IPv4 + v6 routing unchanged
=DEVICE=
route outside 10.1.3.0 255.255.255.0 10.1.1.1
route outside 10.1.4.0 255.255.255.0 10.1.1.2
ipv6 route outside 10::3:0/120 10::2:2
ipv6 route outside 10::4:0/120 10::2:2
ipv6 route outside 10::8:0/117 10::2:2
=NETSPOC=NONE
=OUTPUT=NONE

############################################################
=TITLE=Merge IPv4 and IPv6 routing
=DEVICE=NONE
=NETSPOC=
--router
route inside 10.20.0.0 255.255.255.0 10.1.2.3
route inside 10.22.0.0 255.255.0.0 10.1.2.4
--ipv6/router
ipv6 route inside 10::3:0/120 10::2:2
ipv6 route inside 10::2:0/1 10::2:5
=OUTPUT=
ipv6 route inside 10::3:0/120 10::2:2
ipv6 route inside 10::2:0/1 10::2:5
route inside 10.20.0.0 255.255.255.0 10.1.2.3
route inside 10.22.0.0 255.255.0.0 10.1.2.4
=END=

############################################################
=TITLE=add IPv6 route
=DEVICE=NONE
=NETSPOC=
--ipv6/router
ipv6 route outside 10::3:0/120 10::2:2
ipv6 route inside 10::2:0/1 10::2:5
=OUTPUT=
ipv6 route outside 10::3:0/120 10::2:2
ipv6 route inside 10::2:0/1 10::2:5
=END=

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
=TITLE=Invalid reference in IPv6
=DEVICE=NONE
=NETSPOC=
--ipv6/router
access-group outside_in in interface outside
=ERROR=
ERROR>>> While reading file router: 'access-group outside_in in interface outside' references unknown 'access-list outside_in'
=END=

############################################################
=TITLE=ipv4 and ipv6 configs and raw with ipv4 and ipv6
=DEVICE=[[minimal_device1]]
=NETSPOC=
--router
route inside 10.20.0.0 255.255.255.0 10.1.2.3
access-list inside_in extended permit tcp 10.1.1.0 255.255.255.252 10.9.9.0 255.255.255.0 range 80 90
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
--ipv6/router
ipv6 route inside 10::3:0/120 10::2:2
access-list inside_in extended permit tcp host 1000::abcd:1:12 1000::abcd:9:0/112 range 80 90
access-list inside_in extended deny ip any6 any6
access-group inside_in in interface inside
--router.raw
route inside 10.22.0.0 255.255.0.0 10.1.2.4
ipv6 route inside 10::4:0/120 10::2:2
access-list inside_in extended permit tcp 10.2.2.0 255.255.255.252 10.9.9.0 255.255.255.0 range 80 90
access-list inside_in extended permit tcp 1000::abcd:2:0/112 1000::abcd:9:0/112 range 80 90
access-group inside_in in interface inside
=OUTPUT=
access-list inside_in-DRC-0 extended permit tcp 10.2.2.0 255.255.255.252 10.9.9.0 255.255.255.0 range 80 90
access-list inside_in-DRC-0 extended permit tcp 1000::abcd:2:0/112 1000::abcd:9:0/112 range 80 90
access-list inside_in-DRC-0 extended permit tcp host 1000::abcd:1:12 1000::abcd:9:0/112 range 80 90
access-list inside_in-DRC-0 extended permit tcp 10.1.1.0 255.255.255.252 10.9.9.0 255.255.255.0 range 80 90
access-list inside_in-DRC-0 extended deny ip any4 any4
access-list inside_in-DRC-0 extended deny ip any6 any6
access-group inside_in-DRC-0 in interface inside
ipv6 route inside 10::3:0/120 10::2:2
ipv6 route inside 10::4:0/120 10::2:2
route inside 10.20.0.0 255.255.255.0 10.1.2.3
route inside 10.22.0.0 255.255.0.0 10.1.2.4
=END=

############################################################
=TITLE=ipv4 config and raw with ipv6
=DEVICE=[[minimal_device1]]
=NETSPOC=
--router
route inside 10.20.0.0 255.255.255.0 10.1.2.3
access-list inside_in extended permit tcp 10.1.1.0 255.255.255.252 10.9.9.0 255.255.255.0 range 80 90
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
--router.raw
ipv6 route inside 10::4:0/120 10::2:2
access-list inside_in extended permit tcp 1000::abcd:2:0/112 1000::abcd:9:0/112 range 80 90
access-group inside_in in interface inside
=OUTPUT=
access-list inside_in-DRC-0 extended permit tcp 1000::abcd:2:0/112 1000::abcd:9:0/112 range 80 90
access-list inside_in-DRC-0 extended permit tcp 10.1.1.0 255.255.255.252 10.9.9.0 255.255.255.0 range 80 90
access-list inside_in-DRC-0 extended deny ip any4 any4
access-group inside_in-DRC-0 in interface inside
ipv6 route inside 10::4:0/120 10::2:2
route inside 10.20.0.0 255.255.255.0 10.1.2.3
=END=

############################################################
=TITLE=ipv6 config and raw with ipv4
=DEVICE=[[minimal_device1]]
=NETSPOC=
--router.raw
route inside 10.22.0.0 255.255.0.0 10.1.2.4
access-list inside_in extended permit tcp 10.2.2.0 255.255.255.252 10.9.9.0 255.255.255.0 range 80 90
access-group inside_in in interface inside
--ipv6/router
ipv6 route inside 10::3:0/120 10::2:2
access-list inside_in extended permit tcp 1000::abcd:1:0/112 1000::abcd:9:0/112 range 80 90
access-list inside_in extended deny ip any6 any6
access-group inside_in in interface inside
=OUTPUT=
access-list inside_in-DRC-0 extended permit tcp 10.2.2.0 255.255.255.252 10.9.9.0 255.255.255.0 range 80 90
access-list inside_in-DRC-0 extended permit tcp 1000::abcd:1:0/112 1000::abcd:9:0/112 range 80 90
access-list inside_in-DRC-0 extended deny ip any6 any6
access-group inside_in-DRC-0 in interface inside
ipv6 route inside 10::3:0/120 10::2:2
route inside 10.22.0.0 255.255.0.0 10.1.2.4
=END=

############################################################
=TITLE=merge ACL
=DEVICE=[[minimal_device]]
=NETSPOC=
--router
access-list inside_in extended permit tcp 10.1.1.0 255.255.255.252 10.2.2.0 255.255.255.0 range 80 90
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside

access-list outside_in extended deny ip any4 any4
access-group outside_in in interface outside
--ipv6/router
access-list inside_in extended permit tcp 1000::abcd:1:0/96 1000::abcd:2:0/96 range 80 90
access-list inside_in extended deny ip any6 any6
access-group inside_in in interface inside

access-list outside_in extended deny ip any6 any6
access-group outside_in in interface outside
=OUTPUT=
access-list inside_in-DRC-0 extended permit tcp 1000::abcd:1:0/96 1000::abcd:2:0/96 range 80 90
access-list inside_in-DRC-0 extended permit tcp 10.1.1.0 255.255.255.252 10.2.2.0 255.255.255.0 range 80 90
access-list inside_in-DRC-0 extended deny ip any4 any4
access-list inside_in-DRC-0 extended deny ip any6 any6
access-group inside_in-DRC-0 in interface inside
access-list outside_in-DRC-0 extended deny ip any4 any4
access-list outside_in-DRC-0 extended deny ip any6 any6
access-group outside_in-DRC-0 in interface outside
=END=

############################################################
=TITLE=ipv6 interface unknown in ipv4
=DEVICE=[[minimal_device]]
=NETSPOC=
--router
access-list outside_in extended deny ip any4 any4
access-group outside_in in interface outside
--ipv6/router
access-list inside_in extended deny ip any6 any6
access-group inside_in in interface inside
=OUTPUT=
access-list outside_in-DRC-0 extended deny ip any4 any4
access-group outside_in-DRC-0 in interface outside
access-list inside_in-DRC-0 extended deny ip any6 any6
access-group inside_in-DRC-0 in interface inside
=END=
