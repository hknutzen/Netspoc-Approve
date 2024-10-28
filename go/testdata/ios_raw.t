
############################################################
=TITLE=Merge routing
=DEVICE=NONE
=NETSPOC=
--router
ip route 10.20.0.0 255.248.0.0 10.1.2.3
ip route 10.23.0.0 255.255.0.0 10.1.2.5
--router.raw
ip route 10.22.0.0 255.255.0.0 10.1.2.4
ip route 10.0.0.0 255.0.0.0 10.1.2.2
=OUTPUT=
ip route 10.22.0.0 255.255.0.0 10.1.2.4
ip route 10.23.0.0 255.255.0.0 10.1.2.5
ip route 10.20.0.0 255.248.0.0 10.1.2.3
ip route 10.0.0.0 255.0.0.0 10.1.2.2
=END=

############################################################
=TITLE=Different next hop
=DEVICE=NONE
=NETSPOC=
--router
ip route 10.20.0.0 255.255.0.0 10.1.2.3
--router.raw
ip route 10.20.0.0 255.255.0.0 10.1.2.4
=OUTPUT=
ip route 10.20.0.0 255.255.0.0 10.1.2.3
ip route 10.20.0.0 255.255.0.0 10.1.2.4
=END=

############################################################
=TITLE=Duplicate route from raw
=DEVICE=NONE
=NETSPOC=
--router
ip route 10.20.0.0 255.255.0.0 10.1.2.3
--router.raw
ip route 10.20.0.0 255.255.0.0 10.1.2.3
=OUTPUT=
ip route 10.20.0.0 255.255.0.0 10.1.2.3
=END=

############################################################
=TITLE=Merge ACL using [APPEND]
=DEVICE=
interface Ethernet1
 ip address 10.0.6.1 255.255.255.0
=NETSPOC=
--router
ip access-list extended Ethernet1_in
 permit udp 10.0.6.0 0.0.0.255 host 10.0.1.11 eq 123
 deny ip any any
interface Ethernet1
 ip address 10.0.6.1 255.255.255.0
 ip access-group Ethernet1_in in
--router.raw
ip access-list extended Ethernet1x
 permit udp 10.0.6.0 0.0.0.255 host 224.0.1.1 eq 123
[APPEND]
 deny ip any host 224.0.1.1 log
interface Ethernet1
 ip access-group Ethernet1x in
=OUTPUT=
ip access-list extended Ethernet1_in-DRC-0
permit udp 10.0.6.0 0.0.0.255 host 224.0.1.1 eq 123
permit udp 10.0.6.0 0.0.0.255 host 10.0.1.11 eq 123
deny ip any host 224.0.1.1 log
deny ip any any
exit
interface Ethernet1
ip access-group Ethernet1_in-DRC-0 in
=END=

############################################################
=TITLE=ADD ACL
=DEVICE=
interface Ethernet1
 ip address 10.0.6.1 255.255.255.0
=NETSPOC=
--router
ip access-list extended Ethernet1_in
 permit udp 10.0.6.0 0.0.0.255 host 10.0.1.11 eq 123
 deny ip any any
interface Ethernet1
 ip address 10.0.6.1 255.255.255.0
 ip access-group Ethernet1_in in
--router.raw
ip access-list extended Ethernet1_out
 deny ip host 10.0.6.1 any
interface Ethernet1
 ip access-group Ethernet1_out out
=OUTPUT=
ip access-list extended Ethernet1_in-DRC-0
permit udp 10.0.6.0 0.0.0.255 host 10.0.1.11 eq 123
deny ip any any
exit
interface Ethernet1
ip access-group Ethernet1_in-DRC-0 in
ip access-list extended Ethernet1_out-DRC-0
deny ip host 10.0.6.1 any
exit
interface Ethernet1
ip access-group Ethernet1_out-DRC-0 out
=END=

############################################################
=TITLE=Interface from raw has no address
=DEVICE=
interface Ethernet0
 ip address 10.0.5.1 255.255.255.0
interface Ethernet1
 ip address 10.0.6.1 255.255.255.0
END
=NETSPOC=
--router
ip access-list extended Ethernet1_in
 permit udp 10.0.6.0 0.0.0.255 host 10.0.1.11 eq 123
interface Ethernet1
 ip address 10.0.6.1 255.255.255.0
 ip access-group Ethernet1_in in
--router.raw
ip access-list extended Ethernet0_in
 deny ip host 10.0.6.1 any
interface Ethernet0
 ip access-group Ethernet0_in out
=WARNING=
WARNING>>> Different address defined for interface Ethernet0: Device: "10.0.5.1 255.255.255.0", Netspoc: ""
=END=

############################################################
=TITLE=Name clash with IOS ACL
=DEVICE=
interface Ethernet1
 ip address 10.0.6.1 255.255.255.0
=NETSPOC=
--router
ip access-list extended Ethernet1_in
 permit udp 10.0.6.0 0.0.0.255 host 10.0.1.11 eq 123
 deny ip any any
interface Ethernet1
 ip access-group Ethernet1_in in
--router.raw
ip access-list extended Ethernet1_in
 deny ip host 10.0.6.1 any
interface Ethernet1
 ip access-group Ethernet1_in out
=ERROR=
ERROR>>> Name clash for 'ip access-list extended Ethernet1_in' from raw
=END=

############################################################
=TITLE=Must not bind same ACL multiple times
=DEVICE=
interface Ethernet1
 ip address 10.0.6.1 255.255.255.0
=NETSPOC=
--router
interface Ethernet1
 ip address 10.1.1.1 255.255.255.0
--router.raw
ip access-list extended in_out
 permit ip any host 10.0.6.1
interface Ethernet1
 ip access-group in_out in
 ip access-group in_out out
=ERROR=
ERROR>>> Name clash for 'ip access-list extended in_out' from raw
=END=

############################################################
=TITLE=Must not bind same ACL at different interfaces
=DEVICE=
interface Ethernet1
 ip address 10.0.1.1 255.255.255.0
interface Ethernet2
 ip address 10.0.2.1 255.255.255.0
=NETSPOC=
--router
ip access-list extended acl1
 permit ip any host 10.0.1.1
interface Ethernet1
 ip address 10.0.1.1 255.255.255.0
 ip access-group acl1 in
ip access-list extended acl2
 permit ip any host 10.0.1.1
interface Ethernet2
 ip address 10.0.2.1 255.255.255.0
 ip access-group acl2 in
--router.raw
ip access-list extended foo
 permit ip any host 10.0.1.2
interface Ethernet1
 ip access-group foo in
interface Ethernet2
 ip access-group foo in
=ERROR=
ERROR>>> Must reference 'ip access-list extended foo' only once in raw
=END=

############################################################
=TITLE=Unknown ACL in raw, IOS
=DEVICE=
interface Ethernet1
 ip address 10.0.6.1 255.255.255.0
=NETSPOC=
--router
ip access-list extended Ethernet1_in
 permit udp 10.0.6.0 0.0.0.255 host 10.0.1.11 eq 123
 deny ip any any
interface Ethernet1
 ip access-group Ethernet1_in in
--router.raw
interface Ethernet1
 ip access-group Ethernet1_in in
=ERROR=
ERROR>>> While reading file router.raw: 'ip access-group Ethernet1_in in' references unknown 'ip access-list extended Ethernet1_in'
=END=

############################################################
=TITLE=Unbound ACLs in raw, IOS
=DEVICE=
interface Ethernet1
 ip address 10.0.6.1 255.255.255.0
=NETSPOC=
--router
ip access-list extended Ethernet1_in
 permit udp 10.0.6.0 0.0.0.255 host 10.0.1.11 eq 123
 deny ip any any
interface Ethernet1
 ip address 10.0.6.1 255.255.255.0
 ip access-group Ethernet1_in in
--router.raw
ip access-list extended Ethernet1_in
 deny ip host 10.0.6.1 any
ip access-list extended Ethernet0_in
 deny ip host 10.0.6.0 any
=WARNING=
WARNING>>> Ignoring unused 'ip access-list extended Ethernet0_in' in raw
WARNING>>> Ignoring unused 'ip access-list extended Ethernet1_in' in raw
=END=
