=TEMPL=minimal_device
interface Ethernet0/0
 nameif inside
=TEMPL=minimal_device2
interface Ethernet0/0
 nameif inside
interface Ethernet0/1
 nameif outside
=END=


############################################################
=TITLE=Add ACL entries
############################################################
=DEVICE=
[[minimal_device]]
access-list inside extended permit ip host 1.1.1.1 any4
access-list inside extended permit ip host 5.5.5.5 any4
access-group inside in interface inside
=NETSPOC=
access-list inside extended permit ip host 2.2.2.2 any4
access-list inside extended permit ip host 3.3.3.3 any4
access-list inside extended permit ip host 1.1.1.1 any4
access-list inside extended permit ip host 4.4.4.4 any4
access-list inside extended permit ip host 5.5.5.5 any4
access-list inside extended permit ip host 6.6.6.6 any4
access-group inside in interface inside
=OUTPUT=
access-list inside line 1 extended permit ip host 2.2.2.2 any4
access-list inside line 2 extended permit ip host 3.3.3.3 any4
access-list inside line 4 extended permit ip host 4.4.4.4 any4
access-list inside line 6 extended permit ip host 6.6.6.6 any4
=END=

############################################################
=TITLE=Delete ACL entries
=DEVICE=
[[minimal_device]]
access-list inside extended permit ip host 1.1.1.1 any4
access-list inside extended permit ip host 2.2.2.2 any4
access-list inside extended permit ip host 3.3.3.3 any4
access-list inside extended permit ip host 4.4.4.4 any4
access-list inside extended permit ip host 5.5.5.5 any4
access-group inside in interface inside
=NETSPOC=
access-list inside extended permit ip host 2.2.2.2 any4
access-list inside extended permit ip host 3.3.3.3 any4
access-list inside extended permit ip host 5.5.5.5 any4
access-group inside in interface inside
=OUTPUT=
no access-list inside line 4 extended permit ip host 4.4.4.4 any4
no access-list inside line 1 extended permit ip host 1.1.1.1 any4
=END=

############################################################
=TITLE=Move ACL entries upwards
=DEVICE=
[[minimal_device]]
access-list inside extended permit ip host 1.1.1.1 any4
access-list inside extended permit ip host 2.2.2.2 any4
access-list inside extended permit ip host 3.3.3.3 any4
access-list inside extended permit ip host 4.4.4.4 any4
access-list inside extended permit ip host 5.5.5.5 any4
access-list inside extended permit ip host 6.6.6.6 any4
access-group inside in interface inside
=NETSPOC=
access-list inside extended permit ip host 1.1.1.1 any4
access-list inside extended permit ip host 6.6.6.6 any4
access-list inside extended permit ip host 4.4.4.4 any4
access-list inside extended permit ip host 2.2.2.2 any4
access-list inside extended permit ip host 3.3.3.3 any4
access-list inside extended permit ip host 5.5.5.5 any4
access-group inside in interface inside
=OUTPUT=
no access-list inside line 6 extended permit ip host 6.6.6.6 any4\N access-list inside line 2 extended permit ip host 6.6.6.6 any4
no access-list inside line 5 extended permit ip host 4.4.4.4 any4\N access-list inside line 3 extended permit ip host 4.4.4.4 any4
=END=

############################################################
=TITLE=Move ACL entries downwards
############################################################
=DEVICE=
[[minimal_device]]
access-list inside extended permit ip host 1.1.1.1 any4
access-list inside extended permit ip host 2.2.2.2 any4
access-list inside extended permit ip host 3.3.3.3 any4
access-list inside extended permit ip host 4.4.4.4 any4
access-list inside extended permit ip host 5.5.5.5 any4
access-list inside extended permit ip host 6.6.6.6 any4
access-group inside in interface inside
=NETSPOC=
access-list inside extended permit ip host 1.1.1.1 any4
access-list inside extended permit ip host 4.4.4.4 any4
access-list inside extended permit ip host 2.2.2.2 any4
access-list inside extended permit ip host 5.5.5.5 any4
access-list inside extended permit ip host 6.6.6.6 any4
access-list inside extended permit ip host 3.3.3.3 any4
access-group inside in interface inside
=OUTPUT=
no access-list inside line 2 extended permit ip host 2.2.2.2 any4\N access-list inside line 4 extended permit ip host 2.2.2.2 any4
no access-list inside line 2 extended permit ip host 3.3.3.3 any4\N access-list inside line 6 extended permit ip host 3.3.3.3 any4
=END=

############################################################
=TITLE=Move successive ACL entries downwards
=DEVICE=
[[minimal_device]]
access-list inside extended permit ip host 1.1.1.1 any4
access-list inside extended permit ip host 2.2.2.2 any4
access-list inside extended permit ip host 3.3.3.3 any4
access-list inside extended permit ip host 4.4.4.4 any4
access-list inside extended permit ip host 5.5.5.5 any4
access-list inside extended permit ip host 6.6.6.6 any4
access-group inside in interface inside
=NETSPOC=
access-list inside extended permit ip host 3.3.3.3 any4
access-list inside extended permit ip host 4.4.4.4 any4
access-list inside extended permit ip host 5.5.5.5 any4
access-list inside extended permit ip host 1.1.1.1 any4
access-list inside extended permit ip host 2.2.2.2 any4
access-list inside extended permit ip host 7.7.7.7 any4
access-list inside extended permit ip host 6.6.6.6 any4
access-group inside in interface inside
=OUTPUT=
no access-list inside line 1 extended permit ip host 1.1.1.1 any4\N access-list inside line 5 extended permit ip host 1.1.1.1 any4
no access-list inside line 1 extended permit ip host 2.2.2.2 any4\N access-list inside line 5 extended permit ip host 2.2.2.2 any4
access-list inside line 6 extended permit ip host 7.7.7.7 any4
=END=

############################################################
=TITLE=Change standard ACL non incrementally
=DEVICE=
[[minimal_device]]
access-list inside remark r1
access-list inside standard permit host 1.1.1.1
access-group inside in interface inside
=NETSPOC=
access-list inside remark r1
access-list inside standard permit host 1.1.1.1
access-list inside standard permit 2.2.2.2 255.255.255.254
access-group inside in interface inside
=OUTPUT=
access-list inside-DRC-0 remark r1
access-list inside-DRC-0 standard permit host 1.1.1.1
access-list inside-DRC-0 standard permit 2.2.2.2 255.255.255.254
access-group inside-DRC-0 in interface inside
clear configure access-list inside
=END=

############################################################
=TITLE=Add object-group
=DEVICE=
[[minimal_device]]
access-list inside extended permit ip host 1.1.1.1 any4
access-group inside in interface inside
=NETSPOC=
object-group network g1
 network-object host 2.2.2.2
 network-object host 3.3.3.3
access-list inside extended permit ip object-group g1 any4
access-list inside extended permit ip host 1.1.1.1 any4
access-group inside in interface inside
=OUTPUT=
object-group network g1-DRC-0
network-object host 2.2.2.2
network-object host 3.3.3.3
access-list inside line 1 extended permit ip object-group g1-DRC-0 any4
=END=

############################################################
=TITLE=Remove object-group
=DEVICE=
[[minimal_device]]
object-group network g1
 network-object host 2.2.2.2
 network-object host 3.3.3.3
access-list inside extended permit ip object-group g1 any4
access-list inside extended permit ip host 1.1.1.1 any4
access-group inside in interface inside
=NETSPOC=
access-list inside extended permit ip host 1.1.1.1 any4
access-group inside in interface inside
=OUTPUT=
no access-list inside line 1 extended permit ip object-group g1 any4
no object-group network g1
=END=

############################################################
=TITLE=Add elements to object-group
=DEVICE=
[[minimal_device]]
object-group network g1
 network-object host 2.2.2.2
 network-object host 3.3.3.3
access-list inside extended permit ip object-group g1 any4
access-group inside in interface inside
=NETSPOC=
object-group network g1
 network-object host 1.1.1.1
 network-object host 2.2.2.2
 network-object host 4.4.4.4
 network-object host 3.3.3.3
access-list inside extended permit ip object-group g1 any4
access-group inside in interface inside
=OUTPUT=
object-group network g1
network-object host 1.1.1.1
network-object host 4.4.4.4
=END=

############################################################
=TITLE=Add and delete elements from object-group
=DEVICE=
[[minimal_device]]
object-group network g1
 network-object host 2.2.2.2
 network-object host 3.3.3.3
access-list inside extended permit ip object-group g1 any4
access-group inside in interface inside
=NETSPOC=
object-group network g1
 network-object host 1.1.1.1
 network-object host 2.2.2.2
 network-object host 4.4.4.4
access-list inside extended permit ip object-group g1 any4
access-group inside in interface inside
=OUTPUT=
object-group network g1
network-object host 1.1.1.1
no network-object host 3.3.3.3
network-object host 4.4.4.4
=END=

############################################################
=TITLE=Transfer new object-group if modified too much
=DEVICE=
[[minimal_device]]
object-group network g1
 network-object host 2.2.2.2
 network-object host 3.3.3.3
 network-object host 4.4.4.4
access-list inside extended permit ip object-group g1 any4
access-group inside in interface inside
=NETSPOC=
object-group network g1
 network-object host 1.1.1.1
 network-object host 2.2.2.2
 network-object host 5.5.5.5
access-list inside extended permit ip object-group g1 any4
access-group inside in interface inside
=OUTPUT=
object-group network g1-DRC-0
network-object host 1.1.1.1
network-object host 2.2.2.2
network-object host 5.5.5.5
access-list inside line 1 extended permit ip object-group g1-DRC-0 any4
no access-list inside line 2 extended permit ip object-group g1 any4
no object-group network g1
=END=

############################################################
=TITLE=Modify type of object-group
=DEVICE=
[[minimal_device]]
object-group service g1
 service-object tcp destination range 135 139

access-list inside_in extended permit object-group g1 any4 host 10.0.1.11
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
=NETSPOC=
object-group protocol g1
 protocol-object udp
 protocol-object tcp

access-list inside_in extended permit object-group g1 any4 host 10.0.1.11
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
=OUTPUT=
object-group protocol g1-DRC-0
protocol-object tcp
protocol-object udp
access-list inside_in line 1 extended permit object-group g1-DRC-0 any4 host 10.0.1.11
no access-list inside_in line 2 extended permit object-group g1 any4 host 10.0.1.11
no object-group service g1
=END=

############################################################
=TITLE=Element of object-group with named port is not recognized as equal
=DEVICE=
[[minimal_device]]
object-group service g1 tcp
 port-object eq 53
 port-object eq 79
 port-object eq www
 port-object eq 81
 port-object range 135 netbios-ssn

access-list inside_in extended permit tcp any4 host 10.0.1.11 object-group g1
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
=NETSPOC=
object-group service g1 tcp
 port-object eq 53
 port-object eq 79
 port-object eq 80
 port-object eq 81
 port-object range 135 139

access-list inside_in extended permit tcp any4 host 10.0.1.11 object-group g1
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
=OUTPUT=
object-group service g1 tcp
port-object eq 80
no port-object eq www
no port-object range 135 netbios-ssn
port-object range 135 139
=END=

############################################################
=TITLE=Must also check type of object-group when finding on device
=DEVICE=
[[minimal_device]]
object-group service g1 udp
 port-object eq 53
 port-object eq 135

access-list inside_in extended permit udp any4 host 10.0.1.11 object-group g1
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
=NETSPOC=
object-group service g1 tcp
 port-object eq 53
 port-object eq 135

access-list inside_in extended permit tcp any4 host 10.0.1.11 object-group g1
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
=OUTPUT=
object-group service g1-DRC-0 tcp
port-object eq 135
port-object eq 53
access-list inside_in line 2 extended permit tcp any4 host 10.0.1.11 object-group g1-DRC-0
no access-list inside_in line 1 extended permit udp any4 host 10.0.1.11 object-group g1
no object-group service g1 udp
=END=

############################################################
=TITLE=Modify object-group referenced twice
=DEVICE=
[[minimal_device]]
object-group network g1
 network-object host 1.1.1.1
!network-object host 2.2.2.2
 network-object host 3.3.3.3
 network-object host 4.4.4.4
 network-object host 5.5.5.5
 network-object host 6.6.6.6
 network-object host 7.7.7.7
access-list inside extended permit ip object-group g1 host 10.0.1.1
access-list inside extended permit ip object-group g1 host 10.0.1.2
access-group inside in interface inside
=NETSPOC=
object-group network g1
 network-object host 1.1.1.1
 network-object host 2.2.2.2
 network-object host 3.3.3.3
!network-object host 4.4.4.4
 network-object host 5.5.5.5
!! Order of lines doesn't matter
 network-object host 7.7.7.7
 network-object host 6.6.6.6
access-list inside extended permit ip object-group g1 host 10.0.1.1
access-list inside extended permit ip object-group g1 host 10.0.1.2
access-group inside in interface inside
=OUTPUT=
object-group network g1
network-object host 2.2.2.2
no network-object host 4.4.4.4
=END=

############################################################
=TITLE=Modify object-group once if referenced twice (1)
=DEVICE=
[[minimal_device]]
object-group network g1
 network-object host 2.2.2.2
 network-object host 3.3.3.3
 network-object host 4.4.4.4
access-list inside extended permit ip object-group g1 host 10.0.1.1
access-list inside extended permit ip object-group g1 host 10.0.1.2
access-group inside in interface inside
=NETSPOC=
object-group network g1a
 network-object host 1.1.1.1
 network-object host 2.2.2.2
 network-object host 3.3.3.3
 network-object host 4.4.4.4
object-group network g1b
 network-object host 2.2.2.2
 network-object host 3.3.3.3
 network-object host 4.4.4.4
 network-object host 5.5.5.5
access-list inside extended permit ip object-group g1a host 10.0.1.1
access-list inside extended permit ip object-group g1b host 10.0.1.2
access-group inside in interface inside
=OUTPUT=
object-group network g1
network-object host 1.1.1.1
object-group network g1b-DRC-0
network-object host 2.2.2.2
network-object host 3.3.3.3
network-object host 4.4.4.4
network-object host 5.5.5.5
access-list inside line 2 extended permit ip object-group g1b-DRC-0 host 10.0.1.2
no access-list inside line 3 extended permit ip object-group g1 host 10.0.1.2
=END=

############################################################
=TITLE=Modify object-group once if referenced twice (2)
=DEVICE=
[[minimal_device]]
object-group network g1
 network-object host 2.2.2.2
 network-object host 3.3.3.3
 network-object host 4.4.4.4
object-group network g2
 network-object host 2.2.2.2
 network-object host 3.3.3.3
 network-object host 4.4.4.4
 network-object host 5.5.5.5
access-list inside extended permit ip object-group g1 host 10.0.1.1
access-list inside extended permit ip object-group g1 host 10.0.1.2
access-list inside extended permit ip object-group g2 host 10.0.1.3
access-group inside in interface inside
=NETSPOC=
object-group network g1a
 network-object host 1.1.1.1
 network-object host 2.2.2.2
 network-object host 3.3.3.3
 network-object host 4.4.4.4
object-group network g1b
 network-object host 2.2.2.2
 network-object host 3.3.3.3
 network-object host 4.4.4.4
 network-object host 5.5.5.5
access-list inside extended permit ip object-group g1a host 10.0.1.1
access-list inside extended permit ip object-group g1b host 10.0.1.2
access-group inside in interface inside
=OUTPUT=
object-group network g1
network-object host 1.1.1.1
access-list inside line 2 extended permit ip object-group g2 host 10.0.1.2
no access-list inside line 4 extended permit ip object-group g2 host 10.0.1.3
no access-list inside line 3 extended permit ip object-group g1 host 10.0.1.2
=END=

############################################################
=TITLE=object-group referenced twice but only equal once
=DEVICE=
[[minimal_device]]
object-group network g1
 network-object host 1.1.1.1
 network-object host 2.2.2.2
 network-object host 3.3.3.3
 network-object host 4.4.4.4
access-list inside extended permit ip object-group g1 host 10.0.1.1
access-list inside extended permit ip object-group g1 host 10.0.1.2
access-group inside in interface inside
=NETSPOC=
object-group network g1a
 network-object host 1.1.1.1
 network-object host 2.2.2.2
 network-object host 3.3.3.3
 network-object host 4.4.4.4
object-group network g1b
 network-object host 2.2.2.2
 network-object host 3.3.3.3
 network-object host 4.4.4.4
access-list inside extended permit ip object-group g1a host 10.0.1.1
access-list inside extended permit ip object-group g1b host 10.0.1.2
access-group inside in interface inside
=OUTPUT=
object-group network g1b-DRC-0
network-object host 2.2.2.2
network-object host 3.3.3.3
network-object host 4.4.4.4
access-list inside line 2 extended permit ip object-group g1b-DRC-0 host 10.0.1.2
no access-list inside line 3 extended permit ip object-group g1 host 10.0.1.2
=END=

############################################################
=TITLE=Add object-group referenced twice in ACL
=DEVICE=
[[minimal_device]]
access-list inside extended deny ip any4 any4
access-group inside in interface inside
=NETSPOC=
object-group network g1
 network-object host 1.1.1.1
access-list inside extended permit ip object-group g1 object-group g1
access-group inside in interface inside
=OUTPUT=
object-group network g1-DRC-0
network-object host 1.1.1.1
access-list inside-DRC-0 extended permit ip object-group g1-DRC-0 object-group g1-DRC-0
access-group inside-DRC-0 in interface inside
clear configure access-list inside
=END=

############################################################
=TITLE=Object group used in two ACLs; 1. occurrence new, 2. unchanged
=DEVICE=
[[minimal_device2]]
object-group network g1-0
 network-object host 2.2.2.2
access-list inside extended permit ip host 1.1.1.1 any4
access-group inside in interface inside
access-list outside extended permit ip object-group g1-0 any4
access-group outside in interface outside
=NETSPOC=
object-group network g1
 network-object host 2.2.2.2
access-list inside extended permit ip object-group g1 any4
access-list inside extended permit ip host 1.1.1.1 any4
access-group inside in interface inside
access-list outside extended permit ip object-group g1 any4
access-group outside in interface outside
=OUTPUT=
access-list inside line 1 extended permit ip object-group g1-0 any4
=END=

############################################################
=TITLE=Similar object group is not found on device
=DEVICE=
[[minimal_device2]]
object-group network g1-0
 network-object host 2.2.2.2
 network-object host 3.3.3.3
access-list inside extended permit ip host 1.1.1.1 any4
access-group inside in interface inside
access-list outside extended permit ip object-group g1-0 any4
access-group outside in interface outside
=NETSPOC=
object-group network g1
 network-object host 2.2.2.2
 network-object host 3.3.3.3
 network-object host 4.4.4.4
access-list inside extended permit ip object-group g1 any4
access-list inside extended permit ip host 1.1.1.1 any4
access-group inside in interface inside
access-list outside extended permit ip object-group g1 any4
access-group outside in interface outside
=OUTPUT=
object-group network g1-DRC-0
network-object host 2.2.2.2
network-object host 3.3.3.3
network-object host 4.4.4.4
access-list inside line 1 extended permit ip object-group g1-DRC-0 any4
access-list outside line 1 extended permit ip object-group g1-DRC-0 any4
no access-list outside line 2 extended permit ip object-group g1-0 any4
no object-group network g1-0
=END=

############################################################
=TITLE=Move ACL line with object-groups
=DEVICE=
[[minimal_device2]]
object-group network g1
 network-object host 1.1.1.1
object-group network g2
 network-object host 2.2.2.2
object-group network g3
 network-object host 3.3.3.3
object-group network g4
 network-object host 4.4.4.4
access-list inside extended permit tcp object-group g1 object-group g2
access-list inside extended permit tcp object-group g2 object-group g3
access-list inside extended permit tcp object-group g3 object-group g4
access-group inside in interface inside
access-list outside extended permit ip object-group g1 any4
access-group outside in interface outside
=NETSPOC=
object-group network g1
 network-object host 1.1.1.1
object-group network g2
 network-object host 2.2.2.2
object-group network g3
 network-object host 3.3.3.3
object-group network g4
 network-object host 4.4.4.4
access-list inside extended permit tcp object-group g3 object-group g4
access-list inside extended permit tcp object-group g2 object-group g3
access-list inside extended permit tcp object-group g1 object-group g2
access-group inside in interface inside
access-list outside extended permit ip object-group g1 any4
access-group outside in interface outside
=OUTPUT=
no access-list inside line 3 extended permit tcp object-group g3 object-group g4\N access-list inside line 1 extended permit tcp object-group g3 object-group g4
no access-list inside line 2 extended permit tcp object-group g1 object-group g2\N access-list inside line 3 extended permit tcp object-group g1 object-group g2
=END=

############################################################
=TITLE=Two matching lines with object-groups
=TEMPL=groups
object-group network g1
 network-object host 10.1.1.1
 network-object host 10.1.2.1
object-group network g2
 network-object host 10.1.1.2
 network-object host 10.1.2.2
=DEVICE=
[[groups]]
access-list a1 extended permit tcp any4 any4 eq 80
access-list a1 extended permit tcp object-group g1 any4 eq 81
access-list a1 extended permit tcp any4 any4 eq 82
access-list a1 extended permit tcp any4 any4 eq 90
access-group a1 in interface outside
=NETSPOC=
[[groups]]
access-list a1 extended permit tcp object-group g2 any4 eq 81
access-list a1 extended permit tcp object-group g1 any4 eq 81
access-list a1 extended permit tcp any4 any4 eq 82
access-group a1 in interface outside
=OUTPUT=
access-list a1 line 2 extended permit tcp object-group g2 any4 eq 81
no access-list a1 line 3 extended permit tcp object-group g1 any4 eq 81\N access-list a1 line 3 extended permit tcp object-group g1 any4 eq 81
no access-list a1 line 5 extended permit tcp any4 any4 eq 90
no access-list a1 line 1 extended permit tcp any4 any4 eq 80
=END=

############################################################
=TITLE=Object-group with identical names from netspoc and from device
# Must not mix up name 'g26' from netspoc and from device.
=DEVICE=
[[minimal_device2]]
object-group network g2
 network-object host 10.2.4.6
object-group network g26
 network-object host 10.3.3.3
access-list in extended permit tcp object-group g2 object-group g26
access-list out extended permit tcp object-group g2 object-group g26 eq 25
access-group in in interface inside
access-group out in interface outside
=NETSPOC=
object-group network g26
 network-object host 10.2.4.6
object-group network g1
 network-object host 10.3.3.3
access-list in extended permit tcp object-group g26 object-group g1
access-list out extended permit tcp object-group g1 object-group g26 eq 25
access-group in in interface inside
access-group out in interface outside
=OUTPUT=
access-list out line 1 extended permit tcp object-group g26 object-group g2 eq 25
no access-list out line 2 extended permit tcp object-group g2 object-group g26 eq 25
=END=

############################################################
=TITLE=Delete description in object-group
=DEVICE=
[[minimal_device]]
object-group network g0
 description test123 ###
 network-object 10.0.3.0 255.255.255.0
 network-object 10.0.4.0 255.255.255.0
 network-object 10.0.5.0 255.255.255.0
 network-object 10.0.6.0 255.255.255.0

access-list inside_in extended permit udp object-group g0 host 10.0.1.11 eq sip
access-group inside_in in interface inside
=NETSPOC=
object-group network g0
 network-object 10.0.4.0 255.255.255.0
 network-object 10.0.5.0 255.255.255.0
 network-object 10.0.6.0 255.255.255.0
 network-object 10.0.7.0 255.255.255.0

access-list inside_in extended permit udp object-group g0 host 10.0.1.11 eq sip
access-group inside_in in interface inside
=OUTPUT=
object-group network g0
no description test123 ###
no network-object 10.0.3.0 255.255.255.0
network-object 10.0.7.0 255.255.255.0
=END=

############################################################
=TITLE=Move ACL entry with log
############################################################
=DEVICE=
[[minimal_device]]
access-list inside extended permit ip host 1.1.1.1 any4 log
access-list inside extended permit ip host 2.2.2.2 any4 log 5 interval 30
access-list inside extended permit ip host 3.3.3.3 any4
access-list inside extended permit ip host 4.4.4.4 any4
access-list inside extended permit ip host 5.5.5.5 any4 log disable
access-list inside extended permit ip host 6.6.6.6 any4
access-list inside extended deny ip any4 any4 log warnings
access-group inside in interface inside
=NETSPOC=
access-list inside extended permit ip host 2.2.2.2 any4 log interval 30
access-list inside extended permit ip host 1.1.1.1 any4 log errors
access-list inside extended permit ip host 3.3.3.3 any4
access-list inside extended permit ip host 4.4.4.4 any4 log default
access-list inside extended permit ip host 5.5.5.5 any4
access-list inside extended permit ip host 6.6.6.6 any4 time-range log
access-list inside extended deny ip any4 any4
access-group inside in interface inside
=OUTPUT=
no access-list inside line 2 extended permit ip host 2.2.2.2 any4 log 5 interval 30\N access-list inside line 2 extended permit ip host 2.2.2.2 any4 log interval 30
no access-list inside line 1 extended permit ip host 1.1.1.1 any4 log\N access-list inside line 2 extended permit ip host 1.1.1.1 any4 log 3
no access-list inside line 4 extended permit ip host 4.4.4.4 any4\N access-list inside line 7 extended permit ip host 4.4.4.4 any4 log default
no access-list inside line 4 extended permit ip host 5.5.5.5 any4 log disable\N access-list inside line 7 extended permit ip host 5.5.5.5 any4
access-list inside line 8 extended permit ip host 6.6.6.6 any4 time-range log
no access-list inside line 5 extended deny ip any4 any4 log warnings\N access-list inside line 8 extended deny ip any4 any4
no access-list inside line 4 extended permit ip host 6.6.6.6 any4
=END=

############################################################
=TITLE=log informational is default
=DEVICE=
[[minimal_device]]
access-list inside extended permit ip host 1.1.1.1 any4 log
access-list inside extended permit ip host 2.2.2.2 any4 log
access-group inside in interface inside
=NETSPOC=
access-list inside extended permit ip host 1.1.1.1 any4 log 6
access-list inside extended permit ip host 2.2.2.2 any4 log informational
access-group inside in interface inside
=OUTPUT=NONE

############################################################
=TITLE=Recognize named kerberos port
=DEVICE=
[[minimal_device]]
access-list inside extended permit tcp host 2.2.2.2 any4 eq kerberos
access-list inside extended permit udp host 2.2.2.2 any4 eq kerberos
access-group inside in interface inside
=NETSPOC=
access-list inside extended permit udp host 2.2.2.2 any4 eq 750
access-list inside extended permit tcp host 2.2.2.2 any4 eq 750
access-group inside in interface inside
=OUTPUT=
no access-list inside line 1 extended permit tcp host 2.2.2.2 any4 eq kerberos\N access-list inside line 2 extended permit tcp host 2.2.2.2 any4 eq 750
=END=

############################################################
=TITLE=Ignore spare ACL
# ACL 'foo' is silently ignored
=DEVICE=
access-list foo extended permit tcp host 2.2.2.2 any4 eq 80
access-list foo-DRC-1 extended permit tcp host 2.2.2.2 any4 eq 80
=NETSPOC=NONE
=OUTPUT=
clear configure access-list foo-DRC-1
=END=

############################################################
=TITLE=Handle ACL line with remark
=DEVICE=
[[minimal_device]]
access-list inside remark Test1
access-list inside extended permit ip host 1.1.1.1 any4
access-list inside extended permit ip host 2.2.2.2 any4
access-list inside remark Test2
access-list inside extended permit ip host 4.4.4.4 any4
access-group inside in interface inside
=NETSPOC=
access-list inside extended permit ip host 1.1.1.1 any4
access-list inside remark Test1
access-list inside extended permit ip host 4.4.4.4 any4
access-list inside extended permit ip host 5.5.5.5 any4
access-list inside remark Test3
access-group inside in interface inside
=OUTPUT=
no access-list inside line 1 remark Test1\N access-list inside line 4 remark Test1
access-list inside line 6 extended permit ip host 5.5.5.5 any4
access-list inside line 7 remark Test3
no access-list inside line 3 remark Test2
no access-list inside line 2 extended permit ip host 2.2.2.2 any4
=END=

############################################################
=TITLE=Remove incoming, add outgoing ACL
=DEVICE=
[[minimal_device]]
object-group network g0
 network-object host 1.1.1.1
access-list inside extended permit ip object-group g0 any4
access-group inside in interface inside
=NETSPOC=
access-list outside extended permit ip host 1.1.1.1 any4
access-group outside out interface inside
=OUTPUT=
access-list outside-DRC-0 extended permit ip host 1.1.1.1 any4
access-group outside-DRC-0 out interface inside
no access-group inside in interface inside
clear configure access-list inside
no object-group network g0
=END=

############################################################
=TITLE=Remove outgoing, add incoming ACL
=DEVICE=
[[minimal_device]]
object-group network g0
 network-object host 1.1.1.1
access-list outside extended permit ip object-group g0 any4
access-group outside out interface inside
=NETSPOC=
access-list inside extended permit ip host 1.1.1.1 any4
access-group inside in interface inside
=OUTPUT=
access-list inside-DRC-0 extended permit ip host 1.1.1.1 any4
access-group inside-DRC-0 in interface inside
no access-group outside out interface inside
clear configure access-list outside
no object-group network g0
=END=
