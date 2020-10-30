#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Approve;

# Minimal configuration of device.
my $minimal_ASA = <<END;
interface Ethernet0/0
 nameif inside
interface Ethernet0/1
 nameif outside
END

# Input from Netspoc, from raw, output from approve.
my($spoc, $device, $out);
my $title;

############################################################
$title = "Merge routing IOS";
############################################################
$spoc = {
spoc4 => <<END
ip route 10.20.0.0 255.248.0.0 10.1.2.3
ip route 10.22.0.0 255.255.0.0 10.1.2.4
END
,
raw4 => <<END
ip route 10.22.0.0 255.255.0.0 10.1.2.4
ip route 10.0.0.0 255.0.0.0 10.1.2.2
END
};

$out = <<END;
ip route 10.22.0.0 255.255.0.0 10.1.2.4
ip route 10.22.0.0 255.255.0.0 10.1.2.4
ip route 10.20.0.0 255.248.0.0 10.1.2.3
ip route 10.0.0.0 255.0.0.0 10.1.2.2
END

eq_or_diff( approve('IOS', '', $spoc), $out, $title );

############################################################
$title = "Merge routing ASA";
############################################################
$spoc = {
spoc4 => <<END
route inside 10.20.0.0 255.248.0.0 10.1.2.3
route inside 10.22.0.0 255.255.0.0 10.1.2.4
END
,
raw4 => <<END
route inside 10.22.0.0 255.255.0.0 10.1.2.4
route inside 10.0.0.0 255.0.0.0 10.1.2.2
END
};

$out = <<END;
route inside 10.22.0.0 255.255.0.0 10.1.2.4
route inside 10.22.0.0 255.255.0.0 10.1.2.4
route inside 10.20.0.0 255.248.0.0 10.1.2.3
route inside 10.0.0.0 255.0.0.0 10.1.2.2
END

eq_or_diff( approve('ASA', '', $spoc ), $out, $title );

############################################################
$title = "Merge routing NX-OS";
############################################################
$spoc = {
spoc4 => <<END
vrf context one
 ip route 10.20.0.0/19 10.1.2.3
ip route 10.22.0.0/16 10.1.2.4
END
,
raw4 => <<END
ip route 10.22.0.0/16 10.1.2.4
vrf context two
 ip route 10.0.0.0/8 10.1.2.2
END
};

$out = <<END;
ip route 10.22.0.0/16 10.1.2.4
ip route 10.22.0.0/16 10.1.2.4
vrf context one
ip route 10.20.0.0/19 10.1.2.3
vrf context two
ip route 10.0.0.0/8 10.1.2.2
END

eq_or_diff( approve('NX-OS', '', $spoc), $out, $title );

############################################################
$title = "Merge routing Linux";
############################################################
$spoc = {
spoc4 => <<END
ip route add 10.20.0.0/19 via 10.1.2.3
ip route add 10.22.0.0/16 via 10.1.2.4
END
,
raw4 => <<END
ip route add 10.22.0.0/16 via 10.1.2.4
ip route add 10.0.0.0/8 via 10.1.2.2
END
};

$out = <<END;
ip route add 10.20.0.0/19 via 10.1.2.3
ip route add 10.22.0.0/16 via 10.1.2.4
ip route add 10.22.0.0/16 via 10.1.2.4
ip route add 10.0.0.0/8 via 10.1.2.2
END

eq_or_diff( approve('Linux', '', $spoc), $out, $title );

############################################################
$title = "Different next hop";
############################################################
$spoc = {
spoc4 => <<END
ip route 10.20.0.0 255.255.0.0 10.1.2.3
END
,
raw4 => <<END
ip route 10.20.0.0 255.255.0.0 10.1.2.4
END
};

$out = <<END;
ip route 10.20.0.0 255.255.0.0 10.1.2.4
ip route 10.20.0.0 255.255.0.0 10.1.2.3
END

eq_or_diff( approve('IOS', '', $spoc), $out, $title );

############################################################
$title = "No routing in [APPEND] part";
############################################################
$spoc = {
spoc4 => '',

raw4 => <<END
[APPEND]
ip route 10.22.0.0/16 10.1.2.4
END
};

$out = <<END;
ERROR>>> Must only use ACLs in [APPEND] part, but found ROUTING_VRF
END

eq_or_diff( approve_err('NX-OS', '', $spoc), $out, $title );

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
raw4 => <<END
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

eq_or_diff( approve('IOS', $device, $spoc), $out, $title );

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
raw4 => <<END
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

eq_or_diff( approve('IOS', $device, $spoc), $out, $title );

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
raw4 => <<END
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

eq_or_diff( approve_err('IOS', $device, $spoc), $out, $title );

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
raw4 => <<END
ip access-list extended Ethernet1_in
 deny ip host 10.0.6.1 any
interface Ethernet1
 ip access-group Ethernet1_in out
END
};

$out = <<END;
ERROR>>> Name clash for 'Ethernet1_in' of ACCESS_LIST from raw
END

eq_or_diff( approve_err('IOS', $device, $spoc), $out, $title );

############################################################
$title = "Must not bind same ACL multiple times";
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
raw4 => <<END
ip access-list extended in_out
 permit ip any host 10.0.6.1
interface Ethernet1
 ip access-group in_out in
 ip access-group in_out out
END
};

$out = <<END;
ERROR>>> ACL in_out is referenced from two places:
 Ethernet1 and Ethernet1
END

eq_or_diff( approve_err('IOS', $device, $spoc), $out, $title );

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
raw4 => <<END
ip access-list extended foo
 permit ip any host 10.0.1.2
interface Ethernet1
 ip access-group foo in
interface Ethernet2
 ip access-group foo in
END
};

$out = <<END;
ERROR>>> ACL foo is referenced from two places:
 Ethernet1 and Ethernet2
END

eq_or_diff( approve_err('IOS', $device, $spoc), $out, $title );

############################################################
$title = "Unknown ACL in raw";
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
raw4 => <<END
interface Ethernet1
 ip access-group Ethernet1_in in
END
};

$out = <<END;
ERROR>>> ACL Ethernet1_in referenced at 'Ethernet1' does not exist
END

eq_or_diff( approve_err('IOS', $device, $spoc), $out, $title );

############################################################
$title = "Unbound ACLs in raw";
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
raw4 => <<END
ip access-list extended Ethernet1_in
 deny ip host 10.0.6.1 any
ip access-list extended Ethernet0_in
 deny ip host 10.0.6.0 any
END
};

$out = <<END;
ERROR>>> Found unbound ACCESS_LIST in raw: Ethernet0_in, Ethernet1_in
END

eq_or_diff( approve_err('IOS', $device, $spoc), $out, $title );

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
access-list inside extended permit ip object-group g1 any
access-group inside in interface inside
interface Ethernet0/1
 nameif inside
END
,
raw4 => <<END
object-group network g1
 network-object host 1.1.1.1
END
};

$out = <<'END';
ERROR>>> Name clash for 'g1' of OBJECT_GROUP from raw
END

eq_or_diff(approve_err('ASA', $device, $spoc), $out, $title);

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
raw4 => <<END
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

eq_or_diff( approve('Linux', '', $spoc), $out, $title );

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
raw4 => <<END
*filter
:c1 -
-A c1 -s 10.0.7.0/24 -j ACCEPT
END
};

$out = <<'END';
ERROR>>> Must not redefine chain 'c1' from rawdata
END

eq_or_diff( approve_err('Linux', '', $spoc), $out, $title );

############################################################
$title = "Add crypto";
############################################################

$device = <<'END';
interface Ethernet0/1
 nameif outside
END

$spoc = {
spoc4 => <<END
END
,
raw4 => <<END
crypto ipsec ikev1 transform-set ESP-3DES-MD5 esp-3des esp-md5-hmac
crypto ipsec ikev1 transform-set ESP-AES-256-SHA esp-aes-256 esp-sha-hmac
crypto ipsec ikev1 transform-set ESP-3DES-SHA esp-3des esp-sha-hmac
crypto ipsec ikev1 transform-set ESP-AES-256-MD5 esp-aes-256 esp-md5-hmac

crypto dynamic-map outside_dyn_map 20 set pfs
crypto dynamic-map outside_dyn_map 20 set ikev1 transform-set ESP-AES-256-SHA ESP-3DES-MD5
crypto dynamic-map outside_dyn_map 20 set reverse-route
crypto map outside_map 65535 ipsec-isakmp dynamic outside_dyn_map
crypto map outside_map interface outside

group-policy DfltGrpPolicy attributes
 vpn-tunnel-protocol ikev1
 password-storage enable
 pfs enable
 nem enable
END
};

$out = <<'END';
crypto ipsec ikev1 transform-set ESP-AES-256-SHA-DRC-0 esp-aes-256 esp-sha-hmac
crypto ipsec ikev1 transform-set ESP-3DES-MD5-DRC-0 esp-3des esp-md5-hmac
crypto dynamic-map outside_dyn_map 20 set pfs group2
crypto dynamic-map outside_dyn_map 20 set reverse-route
no crypto dynamic-map outside_dyn_map 20 set ikev1 transform-set
crypto dynamic-map outside_dyn_map 20 set ikev1 transform-set ESP-AES-256-SHA-DRC-0 ESP-3DES-MD5-DRC-0
crypto map outside_map 65535 ipsec-isakmp dynamic outside_dyn_map
group-policy DfltGrpPolicy attributes
nem enable
password-storage enable
pfs enable
vpn-tunnel-protocol ikev1
END

eq_or_diff( approve('ASA', $device, $spoc), $out, $title );

############################################################
$title = "Prepend and append crypto filter ACL";
############################################################

$device = <<'END';
interface Ethernet0/1
 nameif outside
END

$spoc = {
spoc4 => <<END
access-list crypto-1.2.3.4 extended permit ip host 10.1.1.10 10.1.2.0 255.255.255.240
crypto map crypto-outside 1 set peer 1.2.3.4
crypto map crypto-outside 1 match address crypto-1.2.3.4
END
,
raw4 => <<END
access-list prepend extended permit ip host 10.1.1.10 10.1.7.0 255.255.255.240
crypto map crypto-outside 1 set peer 1.2.3.4
crypto map crypto-outside 1 match address prepend
[APPEND]
access-list append extended deny ip any host 224.0.1.1 log
crypto map crypto-outside 1 set peer 1.2.3.4
crypto map crypto-outside 1 match address append
END
};

$out = <<'END';
access-list crypto-1.2.3.4-DRC-0 extended permit ip host 10.1.1.10 10.1.7.0 255.255.255.240
access-list crypto-1.2.3.4-DRC-0 extended permit ip host 10.1.1.10 10.1.2.0 255.255.255.240
access-list crypto-1.2.3.4-DRC-0 extended deny ip any host 224.0.1.1 log
crypto map crypto-outside 1 set peer 1.2.3.4
crypto map crypto-outside 1 match address crypto-1.2.3.4-DRC-0
END

eq_or_diff( approve('ASA', $device, $spoc), $out, $title );

############################################################
$title = "Change crypto map attributes";
############################################################

$device = <<'END';
interface Ethernet0/1
 nameif outside
END

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
tunnel-group 1.2.3.4 type ipsec-l2l
tunnel-group 1.2.3.4 ipsec-attributes
 peer-id-validate nocheck
END
,
raw4 => <<END
crypto ipsec ikev2 ipsec-proposal Trans1
 protocol esp encryption 3des
 protocol esp integrity sha-1
crypto map crypto-outside 1 set peer 1.2.3.4
crypto map crypto-outside 1 set ikev2 ipsec-proposal Trans1
END
};

$out = <<'END';
access-list crypto-1.2.3.4-DRC-0 extended permit ip host 10.1.1.10 10.1.2.0 255.255.255.240
crypto ipsec ikev2 ipsec-proposal Trans1-DRC-0
protocol esp encryption 3des
protocol esp integrity sha-1
crypto map crypto-outside 9 set peer 1.2.3.4
crypto map crypto-outside 9 set pfs group19
crypto map crypto-outside 9 set security-association lifetime seconds 3600
no crypto map crypto-outside 9 set ikev2 ipsec-proposal
crypto map crypto-outside 9 set ikev2 ipsec-proposal Trans1-DRC-0
crypto map crypto-outside 9 match address crypto-1.2.3.4-DRC-0
tunnel-group 1.2.3.4 type ipsec-l2l
tunnel-group 1.2.3.4 ipsec-attributes
peer-id-validate nocheck
END

eq_or_diff( approve('ASA', $device, $spoc), $out, $title );

############################################################
$title = "Add crypto map entry";
############################################################

$device = <<'END';
interface Ethernet0/1
 nameif outside
END

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
END
,
raw4 => <<END
crypto ipsec ikev2 ipsec-proposal Trans2x
 protocol esp encryption aes-256
 protocol esp integrity sha-384
interface Ethernet0/1
 nameif outside
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
tunnel-group 1.2.3.9 type ipsec-l2l
tunnel-group 1.2.3.9 ipsec-attributes
 peer-id-validate nocheck
tunnel-group 1.2.3.3 type ipsec-l2l
tunnel-group 1.2.3.3 ipsec-attributes
 peer-id-validate nocheck
END
};

$out = <<'END';
access-list crypto-1.2.3.4-DRC-0 extended permit ip host 10.1.1.14 10.1.2.0 255.255.255.240
crypto ipsec ikev2 ipsec-proposal Trans2-DRC-0
protocol esp encryption aes-256
protocol esp integrity sha-384
crypto map crypto-outside 1 set peer 1.2.3.4
crypto map crypto-outside 1 set pfs group19
crypto map crypto-outside 1 set security-association lifetime seconds 3600
no crypto map crypto-outside 1 set ikev2 ipsec-proposal
crypto map crypto-outside 1 set ikev2 ipsec-proposal Trans2-DRC-0
crypto map crypto-outside 1 match address crypto-1.2.3.4-DRC-0
access-list crypto-1.2.3.9-DRC-0 extended permit ip host 10.1.1.19 10.1.2.0 255.255.255.240
crypto ipsec ikev2 ipsec-proposal Trans2x-DRC-0
protocol esp encryption aes-256
protocol esp integrity sha-384
crypto map crypto-outside 2 set peer 1.2.3.9
crypto map crypto-outside 2 set pfs group19
crypto map crypto-outside 2 set security-association lifetime seconds 3600
no crypto map crypto-outside 2 set ikev2 ipsec-proposal
crypto map crypto-outside 2 set ikev2 ipsec-proposal Trans2x-DRC-0
crypto map crypto-outside 2 match address crypto-1.2.3.9-DRC-0
access-list crypto-1.2.3.3-DRC-0 extended permit ip host 10.1.1.13 10.1.2.0 255.255.255.240
crypto map crypto-outside 3 set peer 1.2.3.3
no crypto map crypto-outside 3 set ikev2 ipsec-proposal
crypto map crypto-outside 3 set ikev2 ipsec-proposal Trans2x-DRC-0
crypto map crypto-outside 3 match address crypto-1.2.3.3-DRC-0
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

eq_or_diff( approve('ASA', $device, $spoc), $out, $title );

############################################################
done_testing;
