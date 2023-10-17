#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Approve;

my $crypto_ASA = <<END;
interface Ethernet0/1
 nameif outside
END

# Input from Netspoc, from raw, output from approve.
my($spoc, $device, $out, $warn);
my $title;

############################################################
$title = "Only known command allowed in raw";
############################################################
$spoc = {
spoc4 => <<END
route inside 10.20.0.0 255.248.0.0 10.1.2.3
END
,
raw => <<END
unexpected foo
END
};

$out = <<END;
ERROR>>> While reading router.raw: Unexpected command:
>>unexpected foo<<
END

test_err($title, 'ASA', '', $spoc , $out);

############################################################
$title = "Merge routing IOS";
############################################################
$spoc = {
spoc4 => <<END
ip route 10.20.0.0 255.248.0.0 10.1.2.3
ip route 10.23.0.0 255.255.0.0 10.1.2.5
END
,
raw => <<END
ip route 10.22.0.0 255.255.0.0 10.1.2.4
ip route 10.0.0.0 255.0.0.0 10.1.2.2
END
};

$out = <<END;
ip route 10.22.0.0 255.255.0.0 10.1.2.4
ip route 10.23.0.0 255.255.0.0 10.1.2.5
ip route 10.20.0.0 255.248.0.0 10.1.2.3
ip route 10.0.0.0 255.0.0.0 10.1.2.2
END

test_run($title, 'IOS', '', $spoc, $out);

############################################################
$title = "Merge routing ASA";
############################################################
$spoc = {
spoc4 => <<END
route inside 10.20.0.0 255.248.0.0 10.1.2.3
route inside 10.23.0.0 255.255.0.0 10.1.2.5
END
,
raw => <<END
route inside 10.22.0.0 255.255.0.0 10.1.2.4
route inside 10.0.0.0 255.0.0.0 10.1.2.2
END
};

$out = <<END;
route inside 10.22.0.0 255.255.0.0 10.1.2.4
route inside 10.23.0.0 255.255.0.0 10.1.2.5
route inside 10.20.0.0 255.248.0.0 10.1.2.3
route inside 10.0.0.0 255.0.0.0 10.1.2.2
END

test_run($title, 'ASA', '', $spoc , $out);

############################################################
$title = "Merge routing NX-OS";
############################################################
$spoc = {
spoc4 => <<END
vrf context one
 ip route 10.20.0.0/19 10.1.2.3
ip route 10.23.0.0/16 10.1.2.5
END
,
raw => <<END
ip route 10.22.0.0/16 10.1.2.4
vrf context two
 ip route 10.0.0.0/8 10.1.2.2
END
};

$out = <<END;
ip route 10.22.0.0/16 10.1.2.4
ip route 10.23.0.0/16 10.1.2.5
vrf context one
ip route 10.20.0.0/19 10.1.2.3
vrf context two
ip route 10.0.0.0/8 10.1.2.2
END

test_run($title, 'NX-OS', '', $spoc, $out);

############################################################
$title = "Merge routing Linux";
############################################################
$spoc = {
spoc4 => <<END
ip route add 10.20.0.0/19 via 10.1.2.3
ip route add 10.23.0.0/16 via 10.1.2.5
END
,
raw => <<END
ip route add 10.22.0.0/16 via 10.1.2.4
ip route add 10.0.0.0/8 via 10.1.2.2
END
};

$out = <<END;
ip route add 10.20.0.0/19 via 10.1.2.3
ip route add 10.22.0.0/16 via 10.1.2.4
ip route add 10.23.0.0/16 via 10.1.2.5
ip route add 10.0.0.0/8 via 10.1.2.2
END

test_run($title, 'Linux', '', $spoc, $out);

############################################################
$title = "Different next hop, IOS";
############################################################
$spoc = {
spoc4 => <<END
ip route 10.20.0.0 255.255.0.0 10.1.2.3
END
,
raw => <<END
ip route 10.20.0.0 255.255.0.0 10.1.2.4
END
};

$out = <<END;
ip route 10.20.0.0 255.255.0.0 10.1.2.4
ip route 10.20.0.0 255.255.0.0 10.1.2.3
END

test_run($title, 'IOS', '', $spoc, $out);

############################################################
$title = "Different next hop, ASA";
############################################################
$spoc = {
spoc4 => <<END
route inside 10.20.0.0 255.255.0.0 10.1.2.3
END
,
raw => <<END
route inside 10.20.0.0 255.255.0.0 10.1.2.4
END
};

$out = <<END;
route inside 10.20.0.0 255.255.0.0 10.1.2.3
route inside 10.20.0.0 255.255.0.0 10.1.2.4
END

test_run($title, 'ASA', '', $spoc, $out);

############################################################
$title = "Duplicate route from raw, IOS";
############################################################
$spoc = {
spoc4 => <<END
ip route 10.20.0.0 255.255.0.0 10.1.2.3
END
,
raw => <<END
ip route 10.20.0.0 255.255.0.0 10.1.2.3
END
};

$out = <<END;
ip route 10.20.0.0 255.255.0.0 10.1.2.3
END

$warn = <<END;
WARNING>>> Ignoring duplicate route from raw: ip route 10.20.0.0 255.255.0.0 10.1.2.3
END

test_warn($title, 'IOS', '', $spoc, $warn, $out);

############################################################
$title = "Duplicate route from raw, ASA";
############################################################
$spoc = {
spoc4 => <<END
route inside 10.20.0.0 255.255.0.0 10.1.2.3
END
,
raw => <<END
route inside 10.20.0.0 255.255.0.0 10.1.2.3
END
};

$out = <<END;
route inside 10.20.0.0 255.255.0.0 10.1.2.3
END

$warn = '';

test_warn($title, 'ASA', '', $spoc, $warn, $out);

############################################################
$title = "No routing in [APPEND] part";
############################################################
$spoc = {
spoc4 => '',

raw => <<END
[APPEND]
ip route 10.22.0.0/16 10.1.2.4
END
};

$out = <<END;
ERROR>>> Must only use ACLs in [APPEND] part, but found ROUTING_VRF
END

test_err($title, 'NX-OS', '', $spoc, $out);

############################################################
$title = "Routing in [APPEND] part ok for ASA";
############################################################
$spoc = {
spoc4 => '',

raw => <<END
[APPEND]
route inside 10.22.0.0 255.255.0.0 10.1.2.4
END
};

$out = <<END;
route inside 10.22.0.0 255.255.0.0 10.1.2.4
END

test_run($title, 'ASA', '', $spoc, $out);

############################################################
$title = "Merge IOS ACL";
############################################################
$device = <<END;
interface Ethernet1
 ip address 10.0.6.1 255.255.255.0
END

$spoc = {
spoc4 => <<END
ip access-list extended Ethernet1_in
 permit udp 10.0.6.0 0.0.0.255 host 10.0.1.11 eq 123
 deny ip any any
interface Ethernet1
 ip address 10.0.6.1 255.255.255.0
 ip access-group Ethernet1_in in
END
,
raw => <<END
ip access-list extended Ethernet1_in
 permit udp 10.0.6.0 0.0.0.255 host 224.0.1.1 eq 123
interface Ethernet1
 ip access-group Ethernet1_in in
[APPEND]
ip access-list extended Ethernet1_in
 deny ip any host 224.0.1.1 log
interface Ethernet1
 ip access-group Ethernet1_in in
END
};

$out = <<END;
ip access-list extended Ethernet1_in-DRC-0
permit udp 10.0.6.0 0.0.0.255 host 224.0.1.1 eq 123
permit udp 10.0.6.0 0.0.0.255 host 10.0.1.11 eq 123
deny ip any host 224.0.1.1 log
deny ip any any
interface Ethernet1
ip access-group Ethernet1_in-DRC-0 in
END

test_run($title, 'IOS', $device, $spoc, $out);

############################################################
$title = "Merge ASA ACL, duplicate access-group in raw";
############################################################
$device = <<END;
interface Ethernet0/1
 nameif inside
END

$spoc = {
spoc4 => <<END
access-list inside_in extended permit udp 10.0.6.0 0.0.0.255 host 10.0.1.11 eq 123
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
END
,
raw => <<END
access-list inside_in extended permit udp 10.0.6.0 0.0.0.255 host 224.0.1.1 eq 123
access-group inside_in in interface inside
[APPEND]
access-list inside_in extended deny ip any4 host 224.0.1.1 log
access-group inside_in in interface inside
END
};

$out = <<END;
access-list inside_in-DRC-0 extended permit udp 10.0.6.0 0.0.0.255 host 224.0.1.1 eq 123
access-list inside_in-DRC-0 extended permit udp 10.0.6.0 0.0.0.255 host 10.0.1.11 eq 123
access-list inside_in-DRC-0 extended deny ip any4 host 224.0.1.1 log
access-list inside_in-DRC-0 extended deny ip any4 any4
access-group inside_in-DRC-0 in interface inside
END

test_run($title, 'ASA', $device, $spoc, $out);

############################################################
$title = "Host written as IP MASK is recognized as host";
############################################################
$device = <<END;
interface Ethernet0/1
 nameif inside
access-list inside_in-DRC-0 extended permit udp host 10.0.6.1 host 224.0.1.1 eq 123
access-list inside_in-DRC-0 extended permit tcp host 1000::abcd:1:1 host 1000::abcd:2:1 range 80 90
access-list inside_in-DRC-0 extended permit udp host 10.0.6.1 host 10.0.1.11 eq 123
access-list inside_in-DRC-0 extended deny ip any4 any4
access-group inside_in-DRC-0 in interface inside
END

$spoc = {
spoc4 => <<END
access-list inside_in extended permit udp host 10.0.6.1 host 10.0.1.11 eq 123
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
END
,
raw => <<END
access-list inside_in extended permit udp 10.0.6.1 255.255.255.255 224.0.1.1 255.255.255.255 eq 123
access-list inside_in extended permit tcp 1000::abcd:1:1/128 1000::abcd:2:1/128 range 80 90
access-group inside_in in interface inside
END
};

$out = <<END;
END

test_run($title, 'ASA', $device, $spoc, $out);

############################################################
$title = "Recognize mask 0.0.0.0 as any4";
############################################################
$device = <<'END';
interface Ethernet0/1
 nameif inside
access-list inside extended permit ip host 1.1.1.1 any4
access-group inside in interface inside
END

$spoc = {
spoc4 => <<END
END
,
raw => <<END
access-list inside extended permit ip host 1.1.1.1 0.0.0.0 0.0.0.0
access-group inside in interface inside
END
};

$out = <<'END';
END
test_run($title, 'ASA', $device, $spoc, $out);

############################################################
$title = "Add IOS ACL";
############################################################
$device = <<END;
interface Ethernet1
 ip address 10.0.6.1 255.255.255.0
END

$spoc = {
spoc4 => <<END
ip access-list extended Ethernet1_in
 permit udp 10.0.6.0 0.0.0.255 host 10.0.1.11 eq 123
 deny ip any any
interface Ethernet1
 ip address 10.0.6.1 255.255.255.0
 ip access-group Ethernet1_in in
END
,
raw => <<END
ip access-list extended Ethernet1_out
 deny ip host 10.0.6.1 any
interface Ethernet1
 ip access-group Ethernet1_out out
END
};

$out = <<END;
ip access-list extended Ethernet1_in-DRC-0
permit udp 10.0.6.0 0.0.0.255 host 10.0.1.11 eq 123
deny ip any any
interface Ethernet1
ip access-group Ethernet1_in-DRC-0 in
ip access-list extended Ethernet1_out-DRC-0
deny ip host 10.0.6.1 any
interface Ethernet1
ip access-group Ethernet1_out-DRC-0 out
END

test_run($title, 'IOS', $device, $spoc, $out);

############################################################
$title = "Implicitly defined interface from raw has no address";
############################################################
$device = <<END;
interface Ethernet0
 ip address 10.0.5.1 255.255.255.0
interface Ethernet1
 ip address 10.0.6.1 255.255.255.0
END

$spoc = {
spoc4 => <<END
ip access-list extended Ethernet1_in
 permit udp 10.0.6.0 0.0.0.255 host 10.0.1.11 eq 123
interface Ethernet1
 ip address 10.0.6.1 255.255.255.0
 ip access-group Ethernet1_in in
END
,
raw => <<END
ip access-list extended Ethernet0_in
 deny ip host 10.0.6.1 any
interface Ethernet0
 ip address 10.0.5.1 255.255.255.0
 ip access-group Ethernet0_in out
END
};

$out = <<'END';
WARNING>>> Different address defined for interface Ethernet0: Conf: 10.0.5.1 255.255.255.0, Netspoc: missing
END

test_err($title, 'IOS', $device, $spoc, $out);

############################################################
$title = "Name clash with IOS ACL";
############################################################
$device = <<END;
interface Ethernet1
 ip address 10.0.6.1 255.255.255.0
END

$spoc = {
spoc4 => <<END
ip access-list extended Ethernet1_in
 permit udp 10.0.6.0 0.0.0.255 host 10.0.1.11 eq 123
 deny ip any any
interface Ethernet1
 ip access-group Ethernet1_in in
END
,
raw => <<END
ip access-list extended Ethernet1_in
 deny ip host 10.0.6.1 any
interface Ethernet1
 ip access-group Ethernet1_in out
END
};

$out = <<END;
ERROR>>> Name clash for 'Ethernet1_in' of ACCESS_LIST from raw
END

test_err($title, 'IOS', $device, $spoc, $out);

############################################################
$title = "Name clash with ASA ACL";
############################################################
$device = <<END;
interface Ethernet1
 ip address 10.0.6.1 255.255.255.0
END

$spoc = {
spoc4 => <<END
access-list inside_in extended permit udp 10.0.6.0 0.0.0.255 host 10.0.1.11 eq 123
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
END
,
raw => <<END
access-list inside_in extended deny ip host 10.0.6.1 any4
access-group inside_in out interface inside
END
};

$out = <<END;
ERROR>>> Name clash for 'access-list inside_in' from raw
END

test_err($title, 'ASA', $device, $spoc, $out);

############################################################
$title = "Must not bind same ACL multiple times, IOS";
############################################################

$device = <<END;
interface Ethernet1
 ip address 10.0.6.1 255.255.255.0
END

$spoc = {
spoc4 => <<END
interface Ethernet1
 ip address 10.1.1.1 255.255.255.0
END
,
raw => <<END
ip access-list extended in_out
 permit ip any host 10.0.6.1
interface Ethernet1
 ip access-group in_out in
 ip access-group in_out out
END
};

$out = <<END;
ERROR>>> ACL 'in_out' must not be referenced multiple times in raw
END

test_err($title, 'IOS', $device, $spoc, $out);

############################################################
$title = "Must not bind same ACL multiple times, ASA";
############################################################

$device = <<END;
interface Ethernet0/1
 nameif inside
END

$spoc = {
spoc4 => <<END
END
,
raw => <<END
access-list in_out extended permit ip any4 host 10.0.6.1
access-group in_out in interface inside
access-group in_out out interface inside
END
};

$out = <<END;
ERROR>>> Name clash for 'access-list in_out' from raw
END

test_err($title, 'ASA', $device, $spoc, $out);

############################################################
$title = "Must not bind same ACL at different interfaces";
############################################################

$device = <<END;
interface Ethernet1
 ip address 10.0.1.1 255.255.255.0
interface Ethernet2
 ip address 10.0.2.1 255.255.255.0
END

$spoc = {
spoc4 => <<END
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
END
,
raw => <<END
ip access-list extended foo
 permit ip any host 10.0.1.2
interface Ethernet1
 ip access-group foo in
interface Ethernet2
 ip access-group foo in
END
};

$out = <<END;
ERROR>>> ACL 'foo' must not be referenced multiple times in raw
END

test_err($title, 'IOS', $device, $spoc, $out);

############################################################
$title = "Unknown ACL in raw, IOS";
############################################################
$device = <<END;
interface Ethernet1
 ip address 10.0.6.1 255.255.255.0
END

$spoc = {
spoc4 => <<END
ip access-list extended Ethernet1_in
 permit udp 10.0.6.0 0.0.0.255 host 10.0.1.11 eq 123
 deny ip any any
interface Ethernet1
 ip access-group Ethernet1_in in
END
,
raw => <<END
interface Ethernet1
 ip access-group Ethernet1_in in
END
};

$out = <<END;
ERROR>>> ACL Ethernet1_in referenced at 'Ethernet1' does not exist
END

test_err($title, 'IOS', $device, $spoc, $out);

############################################################
$title = "Unknown ACL in raw, ASA";
############################################################
$device = <<END;
interface Ethernet0/1
 nameif inside
END

$spoc = {
spoc4 => <<END
access-list inside_in extended permit udp 10.0.6.0 0.0.0.255 host 10.0.1.11 eq 123
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
END
,
raw => <<END
access-group inside_in in interface inside
END
};

$out = <<END;
ERROR>>> While reading router.raw: 'access-group inside_in in interface inside' references unknown 'access-list inside_in'
END

test_err($title, 'ASA', $device, $spoc, $out);

############################################################
$title = "Unbound ACLs in raw, IOS";
############################################################
$device = <<END;
interface Ethernet1
 ip address 10.0.6.1 255.255.255.0
END

$spoc = {
spoc4 => <<END
ip access-list extended Ethernet1_in
 permit udp 10.0.6.0 0.0.0.255 host 10.0.1.11 eq 123
 deny ip any any
interface Ethernet1
 ip access-group Ethernet1_in in
END
,
raw => <<END
ip access-list extended Ethernet1_in
 deny ip host 10.0.6.1 any
ip access-list extended Ethernet0_in
 deny ip host 10.0.6.0 any
END
};

$out = <<END;
ERROR>>> Found unbound ACCESS_LIST in raw: Ethernet0_in, Ethernet1_in
END

test_err($title, 'IOS', $device, $spoc, $out);

############################################################
$title = "Unbound ACLs in raw, ASA";
############################################################
$device = <<END;
interface Ethernet0/1
 nameif inside
END

$spoc = {
spoc4 => <<END
access-list inside_in extended permit udp 10.0.6.0 0.0.0.255 host 10.0.1.11 eq 123
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
END
,
raw => <<END
access-list inside_in extended deny ip host 10.0.6.1 any4
access-list outside_in extended deny ip host 10.0.6.0 any4
END
};

$out = <<END;
WARNING>>> Ignoring unused 'access-list inside_in' in raw
WARNING>>> Ignoring unused 'access-list outside_in' in raw
END

test_err($title, 'ASA', $device, $spoc, $out);

############################################################
$title = "Name clash with object-group";
############################################################

$device = <<'END';
interface Ethernet0/1
 nameif inside
END

$spoc = {
spoc4 => <<END
object-group network g1
 network-object host 2.2.2.2
access-list inside extended permit ip object-group g1 any4
access-group inside in interface inside
interface Ethernet0/1
 nameif inside
END
,
raw => <<END
object-group network g1
 network-object host 1.1.1.1
access-list inside extended permit ip object-group g1 any4
access-group inside in interface inside
END
};

$out = <<'END';
ERROR>>> Name clash for 'object-group g1' from raw
END

test_err($title, 'ASA', $device, $spoc, $out);

############################################################
$title = "Merge Linux chains";
############################################################

$spoc = {
spoc4 => <<END
*filter
:INPUT DROP
-A INPUT -i eth0 -s 10.0.6.0/24 -d 10.0.1.11/32 -p udp --dport 123 -j ACCEPT
-A INPUT -j DROP
END
,
raw => <<END
*mangle
:PREROUTING ACCEPT
-A PREROUTING -j MARK --set-xmark 0x01 -p TCP --dport 80
*filter
:INPUT DROP
:c1 -
-A c1 -s 10.0.6.0/24 -j ACCEPT
-A INPUT -i eth0 -p udp -d 224.0.1.1/32 --dport 123 -j c1
[APPEND]
*filter
:INPUT DROP
-A INPUT -i eth0 -p udp -d 224.0.1.1/32 --dport 123 -j DROP
END
};

$out = <<'END';
iptables differs at [keys: <->filter,mangle]
#!/sbin/iptables-restore
# Generated by NetSPoC
*filter
:INPUT DROP
:c1 -
-A INPUT -i eth0 -p udp -d 224.0.1.1/32 --dport 123 -j c1
-A INPUT -i eth0 -s 10.0.6.0/24 -d 10.0.1.11/32 -p udp --dport 123 -j ACCEPT
-A INPUT -i eth0 -p udp -d 224.0.1.1/32 --dport 123 -j DROP
-A INPUT -j DROP
-A c1 -s 10.0.6.0/24 -j ACCEPT
COMMIT
*mangle
:PREROUTING ACCEPT
-A PREROUTING -j MARK --set-xmark 0x01 -p TCP --dport 80
COMMIT
END

test_run($title, 'Linux', '', $spoc, $out);

############################################################
$title = "Must not reference Netspoc generated chain";
############################################################

$spoc = {
spoc4 => <<END
*filter
:INPUT DROP
:c1 -
-A c1 -s 10.0.6.0/24 -j ACCEPT
-A INPUT -i eth0 -p udp -d 224.0.1.1/32 --dport 123 -j c1
END
,
raw => <<END
*filter
:c1 -
-A c1 -s 10.0.7.0/24 -j ACCEPT
END
};

$out = <<'END';
ERROR>>> Must not redefine chain 'c1' from rawdata
END

test_err($title, 'Linux', '', $spoc, $out);

############################################################
$title = "Add crypto";
############################################################

$device = $crypto_ASA;

$spoc = {
spoc4 => <<END
crypto ipsec ikev1 transform-set abc esp-3des esp-sha-hmac
crypto dynamic-map outside_dyn_map 1 set pfs group19
crypto dynamic-map outside_dyn_map 1 set ikev1 transform-set abc
crypto map outside_map 2 ipsec-isakmp dynamic outside_dyn_map
crypto map outside_map interface outside
END
,
raw => <<END
crypto ipsec ikev1 transform-set ESP-3DES-MD5 esp-3des esp-md5-hmac
crypto ipsec ikev1 transform-set ESP-AES-256-SHA esp-aes-256 esp-sha-hmac
crypto dynamic-map raw_dyn_map 1 set pfs group21
crypto dynamic-map raw_dyn_map 1 set ikev1 transform-set ESP-AES-256-SHA ESP-3DES-MD5
crypto dynamic-map raw_dyn_map 1 set reverse-route
crypto map outside_map 2 ipsec-isakmp dynamic raw_dyn_map
crypto map outside_map interface outside

group-policy DfltGrpPolicy attributes
 vpn-tunnel-protocol ikev1
 smartcard-removal-disconnect enable
 pfs enable
 ip-comp enable
END
};

$out = <<'END';
crypto dynamic-map outside_dyn_map 1 set pfs group19
crypto ipsec ikev1 transform-set abc-DRC-0 esp-3des esp-sha-hmac
crypto dynamic-map outside_dyn_map 1 set ikev1 transform-set abc-DRC-0
crypto map outside_map 2 ipsec-isakmp dynamic outside_dyn_map
crypto dynamic-map raw_dyn_map 1 set pfs group21
crypto ipsec ikev1 transform-set ESP-AES-256-SHA-DRC-0 esp-aes-256 esp-sha-hmac
crypto ipsec ikev1 transform-set ESP-3DES-MD5-DRC-0 esp-3des esp-md5-hmac
crypto dynamic-map raw_dyn_map 1 set ikev1 transform-set ESP-AES-256-SHA-DRC-0 ESP-3DES-MD5-DRC-0
crypto dynamic-map raw_dyn_map 1 set reverse-route
crypto map outside_map 1 ipsec-isakmp dynamic raw_dyn_map
crypto map outside_map interface outside
group-policy DfltGrpPolicy attributes
vpn-tunnel-protocol ikev1
smartcard-removal-disconnect enable
pfs enable
ip-comp enable
END

test_run($title, 'ASA', $device, $spoc, $out);

############################################################
$title = "Add crypto to empty crypto";
############################################################

$device = $crypto_ASA;

$spoc = {
spoc4 => '',
raw => <<END
crypto map outside_map 2 set peer 1.2.3.4
crypto map outside_map 2 set pfs group21
crypto map outside_map interface outside
END
};

$out = <<'END';
crypto map outside_map 1 set peer 1.2.3.4
crypto map outside_map 1 set pfs group21
crypto map outside_map interface outside
END

test_run($title, 'ASA', $device, $spoc, $out);

############################################################
$title = "Merge crypto dynamic-map";
############################################################

$device = $crypto_ASA;

$spoc = {
spoc4 => <<'END'
access-list crypto-vpn1@example.com extended permit ip any4 10.99.1.0 255.255.255.0
crypto ipsec ikev1 transform-set abc esp-3des esp-sha-hmac
crypto dynamic-map vpn1@example.com 1 set pfs group19
crypto dynamic-map vpn1@example.com 1 set ikev1 transform-set abc
crypto dynamic-map vpn1@example.com 1 match address crypto-vpn1@example.com
crypto map outside_map 1 ipsec-isakmp dynamic vpn1@example.com
crypto map outside_map interface outside
END
,
raw => <<'END'
access-list extra extended permit ip any4 10.99.2.0 255.255.255.0
crypto ipsec ikev1 transform-set ESP-3DES-MD5 esp-3des esp-md5-hmac
crypto ipsec ikev1 transform-set ESP-AES-256-SHA esp-aes-256 esp-sha-hmac
crypto dynamic-map vpn1@example.com 2 set pfs group21
crypto dynamic-map vpn1@example.com 2 set ikev1 transform-set ESP-AES-256-SHA ESP-3DES-MD5
crypto dynamic-map vpn1@example.com 2 match address extra
crypto dynamic-map vpn1@example.com 2 set reverse-route
crypto map outside_map 2 ipsec-isakmp dynamic vpn1@example.com
crypto map outside_map interface outside
END
};

$out = <<'END';
crypto dynamic-map vpn1@example.com 1 set pfs group21
crypto ipsec ikev1 transform-set ESP-AES-256-SHA-DRC-0 esp-aes-256 esp-sha-hmac
crypto ipsec ikev1 transform-set ESP-3DES-MD5-DRC-0 esp-3des esp-md5-hmac
crypto dynamic-map vpn1@example.com 1 set ikev1 transform-set ESP-AES-256-SHA-DRC-0 ESP-3DES-MD5-DRC-0
access-list crypto-vpn1@example.com-DRC-0 extended permit ip any4 10.99.2.0 255.255.255.0
access-list crypto-vpn1@example.com-DRC-0 extended permit ip any4 10.99.1.0 255.255.255.0
crypto dynamic-map vpn1@example.com 1 match address crypto-vpn1@example.com-DRC-0
crypto dynamic-map vpn1@example.com 1 set reverse-route
crypto map outside_map 1 ipsec-isakmp dynamic vpn1@example.com
crypto map outside_map interface outside
END

test_run($title, 'ASA', $device, $spoc, $out);

############################################################
$title = "Prepend and append crypto filter ACL";
############################################################

$device = $crypto_ASA;

$spoc = {
spoc4 => <<END
access-list crypto-1.2.3.4 extended permit ip host 10.1.1.10 10.1.2.0 255.255.255.240
crypto map crypto-outside 1 set peer 1.2.3.4
crypto map crypto-outside 1 match address crypto-1.2.3.4
crypto map crypto-outside interface outside
END
,
raw => <<END
access-list acl extended permit ip host 10.1.1.10 10.1.7.0 255.255.255.240
[APPEND]
access-list acl extended deny ip any4 host 224.0.1.1 log
crypto map crypto-outside 1 set peer 1.2.3.4
crypto map crypto-outside 1 match address acl
crypto map crypto-outside interface outside
END
};

$out = <<'END';
crypto map crypto-outside 1 set peer 1.2.3.4
access-list crypto-1.2.3.4-DRC-0 extended permit ip host 10.1.1.10 10.1.7.0 255.255.255.240
access-list crypto-1.2.3.4-DRC-0 extended permit ip host 10.1.1.10 10.1.2.0 255.255.255.240
access-list crypto-1.2.3.4-DRC-0 extended deny ip any4 host 224.0.1.1 log
crypto map crypto-outside 1 match address crypto-1.2.3.4-DRC-0
crypto map crypto-outside interface outside
END

test_run($title, 'ASA', $device, $spoc, $out);

############################################################
$title = "Change crypto map attributes";
############################################################

$device = $crypto_ASA;

$spoc = {
spoc4 => <<END
crypto ipsec ikev2 ipsec-proposal Trans2
 protocol esp encryption aes-256
 protocol esp integrity sha-384
access-list crypto-1.2.3.4 extended permit ip host 10.1.1.10 10.1.2.0 255.255.255.240
crypto map crypto-outside 9 set peer 1.2.3.4
crypto map crypto-outside 9 match address crypto-1.2.3.4
crypto map crypto-outside 9 set ikev2 ipsec-proposal Trans2
crypto map crypto-outside 9 set pfs group19
crypto map crypto-outside 9 set security-association lifetime seconds 3600
crypto map crypto-outside interface outside
tunnel-group 1.2.3.4 type ipsec-l2l
tunnel-group 1.2.3.4 ipsec-attributes
 peer-id-validate nocheck
END
,
raw => <<END
crypto ipsec ikev2 ipsec-proposal Trans1
 protocol esp encryption 3des
 protocol esp integrity sha-1
crypto map crypto-outside 1 set peer 1.2.3.4
crypto map crypto-outside 1 set ikev2 ipsec-proposal Trans1
crypto map crypto-outside interface outside
END
};

$out = <<'END';
crypto map crypto-outside 9 set peer 1.2.3.4
access-list crypto-1.2.3.4-DRC-0 extended permit ip host 10.1.1.10 10.1.2.0 255.255.255.240
crypto map crypto-outside 9 match address crypto-1.2.3.4-DRC-0
crypto ipsec ikev2 ipsec-proposal Trans1-DRC-0
protocol esp encryption 3des
protocol esp integrity sha-1
crypto map crypto-outside 9 set ikev2 ipsec-proposal Trans1-DRC-0
crypto map crypto-outside 9 set pfs group19
crypto map crypto-outside 9 set security-association lifetime seconds 3600
crypto map crypto-outside interface outside
tunnel-group 1.2.3.4 type ipsec-l2l
tunnel-group 1.2.3.4 ipsec-attributes
peer-id-validate nocheck
END

test_run($title, 'ASA', $device, $spoc, $out);

############################################################
$title = "Add crypto map entry (1)";
############################################################

$device = $crypto_ASA;

$spoc = {
spoc4 => <<END
crypto ipsec ikev2 ipsec-proposal Trans2
 protocol esp encryption aes-256
 protocol esp integrity sha-384
access-list crypto-1.2.3.4 extended permit ip host 10.1.1.14 10.1.2.0 255.255.255.240
crypto map crypto-outside 1 set peer 1.2.3.4
crypto map crypto-outside 1 match address crypto-1.2.3.4
crypto map crypto-outside 1 set ikev2 ipsec-proposal Trans2
crypto map crypto-outside 1 set pfs group19
crypto map crypto-outside 1 set security-association lifetime seconds 3600
tunnel-group 1.2.3.4 type ipsec-l2l
tunnel-group 1.2.3.4 ipsec-attributes
 peer-id-validate nocheck
crypto map crypto-outside 2 set peer 1.2.3.10
crypto map crypto-outside 2 set ikev2 ipsec-proposal Trans2
crypto map crypto-outside 2 set pfs group19
crypto map crypto-outside interface outside
tunnel-group 1.2.3.10 type ipsec-l2l
tunnel-group 1.2.3.10 ipsec-attributes
 peer-id-validate nocheck
END
,
raw => <<END
crypto ipsec ikev2 ipsec-proposal Trans2x
 protocol esp encryption aes-256
 protocol esp integrity sha-384
access-list crypto-1.2.3.9 extended permit ip host 10.1.1.19 10.1.2.0 255.255.255.240
crypto map crypto-outside 1 set peer 1.2.3.9
crypto map crypto-outside 1 match address crypto-1.2.3.9
crypto map crypto-outside 1 set ikev2 ipsec-proposal Trans2x
crypto map crypto-outside 1 set pfs group19
crypto map crypto-outside 1 set security-association lifetime seconds 3600
access-list crypto-1.2.3.3 extended permit ip host 10.1.1.13 10.1.2.0 255.255.255.240
crypto map crypto-outside 2 set peer 1.2.3.3
crypto map crypto-outside 2 match address crypto-1.2.3.3
crypto map crypto-outside 2 set ikev2 ipsec-proposal Trans2x
crypto map crypto-outside interface outside
tunnel-group 1.2.3.9 type ipsec-l2l
tunnel-group 1.2.3.9 ipsec-attributes
 peer-id-validate nocheck
tunnel-group 1.2.3.3 type ipsec-l2l
tunnel-group 1.2.3.3 ipsec-attributes
 peer-id-validate nocheck
END
};

$out = <<'END';
crypto map crypto-outside 1 set peer 1.2.3.4
access-list crypto-1.2.3.4-DRC-0 extended permit ip host 10.1.1.14 10.1.2.0 255.255.255.240
crypto map crypto-outside 1 match address crypto-1.2.3.4-DRC-0
crypto ipsec ikev2 ipsec-proposal Trans2-DRC-0
protocol esp encryption aes-256
protocol esp integrity sha-384
crypto map crypto-outside 1 set ikev2 ipsec-proposal Trans2-DRC-0
crypto map crypto-outside 1 set pfs group19
crypto map crypto-outside 1 set security-association lifetime seconds 3600
crypto map crypto-outside 2 set peer 1.2.3.10
crypto map crypto-outside 2 set ikev2 ipsec-proposal Trans2-DRC-0
crypto map crypto-outside 2 set pfs group19
crypto map crypto-outside 3 set peer 1.2.3.9
access-list crypto-1.2.3.9-DRC-0 extended permit ip host 10.1.1.19 10.1.2.0 255.255.255.240
crypto map crypto-outside 3 match address crypto-1.2.3.9-DRC-0
crypto map crypto-outside 3 set ikev2 ipsec-proposal Trans2-DRC-0
crypto map crypto-outside 3 set pfs group19
crypto map crypto-outside 3 set security-association lifetime seconds 3600
crypto map crypto-outside 4 set peer 1.2.3.3
access-list crypto-1.2.3.3-DRC-0 extended permit ip host 10.1.1.13 10.1.2.0 255.255.255.240
crypto map crypto-outside 4 match address crypto-1.2.3.3-DRC-0
crypto map crypto-outside 4 set ikev2 ipsec-proposal Trans2-DRC-0
crypto map crypto-outside interface outside
tunnel-group 1.2.3.10 type ipsec-l2l
tunnel-group 1.2.3.10 ipsec-attributes
peer-id-validate nocheck
tunnel-group 1.2.3.3 type ipsec-l2l
tunnel-group 1.2.3.3 ipsec-attributes
peer-id-validate nocheck
tunnel-group 1.2.3.4 type ipsec-l2l
tunnel-group 1.2.3.4 ipsec-attributes
peer-id-validate nocheck
tunnel-group 1.2.3.9 type ipsec-l2l
tunnel-group 1.2.3.9 ipsec-attributes
peer-id-validate nocheck
END

test_run($title, 'ASA', $device, $spoc, $out);

############################################################
$title = "Add crypto map entry (2)";
############################################################

$device = $crypto_ASA;

$spoc = {
spoc4 => <<END
crypto ipsec ikev2 ipsec-proposal Trans2
 protocol esp encryption aes-256
 protocol esp integrity sha-384
crypto map crypto-outside 1 set peer 1.2.3.4
crypto map crypto-outside 1 set ikev2 ipsec-proposal Trans2
tunnel-group 1.2.3.4 type ipsec-l2l
tunnel-group 1.2.3.4 ipsec-attributes
 peer-id-validate nocheck
crypto map crypto-outside 2 set peer 1.2.3.10
crypto map crypto-outside 2 set ikev2 ipsec-proposal Trans2
crypto map crypto-outside interface outside
tunnel-group 1.2.3.10 type ipsec-l2l
tunnel-group 1.2.3.10 ipsec-attributes
 peer-id-validate nocheck
END
,
raw => <<END
crypto ipsec ikev2 ipsec-proposal Trans2
 protocol esp encryption aes-256
 protocol esp integrity sha-384
crypto map crypto-outside 1 set peer 1.2.3.9
crypto map crypto-outside 1 set ikev2 ipsec-proposal Trans2
crypto map crypto-outside interface outside
tunnel-group 1.2.3.9 type ipsec-l2l
tunnel-group 1.2.3.9 ipsec-attributes
 peer-id-validate nocheck
END
};

$out = <<'END';
crypto map crypto-outside 1 set peer 1.2.3.4
crypto ipsec ikev2 ipsec-proposal Trans2-DRC-0
protocol esp encryption aes-256
protocol esp integrity sha-384
crypto map crypto-outside 1 set ikev2 ipsec-proposal Trans2-DRC-0
crypto map crypto-outside 2 set peer 1.2.3.10
crypto map crypto-outside 2 set ikev2 ipsec-proposal Trans2-DRC-0
crypto map crypto-outside 3 set peer 1.2.3.9
crypto map crypto-outside 3 set ikev2 ipsec-proposal Trans2-DRC-0
crypto map crypto-outside interface outside
tunnel-group 1.2.3.10 type ipsec-l2l
tunnel-group 1.2.3.10 ipsec-attributes
peer-id-validate nocheck
tunnel-group 1.2.3.4 type ipsec-l2l
tunnel-group 1.2.3.4 ipsec-attributes
peer-id-validate nocheck
tunnel-group 1.2.3.9 type ipsec-l2l
tunnel-group 1.2.3.9 ipsec-attributes
peer-id-validate nocheck
END

test_run($title, 'ASA', $device, $spoc, $out);

############################################################
done_testing;
