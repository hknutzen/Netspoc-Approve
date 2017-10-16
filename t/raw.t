#!/usr/bin/perl

use strict;
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
my($spoc, $raw, $device, $out);
my $title;

############################################################
$title = "Merge routing IOS";
############################################################
$spoc = <<END;
ip route 10.20.0.0 255.248.0.0 10.1.2.3
ip route 10.22.0.0 255.255.0.0 10.1.2.4
END

$raw = <<END;
ip route 10.22.0.0 255.255.0.0 10.1.2.4
ip route 10.0.0.0 255.0.0.0 10.1.2.2
END

$out = <<END;
ip route 10.22.0.0 255.255.0.0 10.1.2.4
ip route 10.22.0.0 255.255.0.0 10.1.2.4
ip route 10.20.0.0 255.248.0.0 10.1.2.3
ip route 10.0.0.0 255.0.0.0 10.1.2.2
END

eq_or_diff( approve('IOS', '', $spoc, $raw ), $out, $title );

############################################################
$title = "Merge routing ASA";
############################################################
$spoc = <<END;
route inside 10.20.0.0 255.248.0.0 10.1.2.3
route inside 10.22.0.0 255.255.0.0 10.1.2.4
END

$raw = <<END;
route inside 10.22.0.0 255.255.0.0 10.1.2.4
route inside 10.0.0.0 255.0.0.0 10.1.2.2
END

$out = <<END;
route inside 10.22.0.0 255.255.0.0 10.1.2.4
route inside 10.22.0.0 255.255.0.0 10.1.2.4
route inside 10.20.0.0 255.248.0.0 10.1.2.3
route inside 10.0.0.0 255.0.0.0 10.1.2.2
END

eq_or_diff( approve('ASA', '', $spoc, $raw ), $out, $title );

############################################################
$title = "Merge routing NX-OS";
############################################################
$spoc = <<END;
vrf context one
 ip route 10.20.0.0/19 10.1.2.3
ip route 10.22.0.0/16 10.1.2.4
END

$raw = <<END;
ip route 10.22.0.0/16 10.1.2.4
vrf context two
 ip route 10.0.0.0/8 10.1.2.2
END

$out = <<END;
ip route 10.22.0.0/16 10.1.2.4
ip route 10.22.0.0/16 10.1.2.4
vrf context one
 ip route 10.20.0.0/19 10.1.2.3
vrf context two
 ip route 10.0.0.0/8 10.1.2.2
END

eq_or_diff( approve('NX-OS', '', $spoc, $raw ), $out, $title );

############################################################
$title = "Merge routing Linux";
############################################################
$spoc = <<END;
ip route add 10.20.0.0/19 via 10.1.2.3
ip route add 10.22.0.0/16 via 10.1.2.4
END

$raw = <<END;
ip route add 10.22.0.0/16 via 10.1.2.4
ip route add 10.0.0.0/8 via 10.1.2.2
END

$out = <<END;
ip route add 10.20.0.0/19 via 10.1.2.3
ip route add 10.22.0.0/16 via 10.1.2.4
ip route add 10.22.0.0/16 via 10.1.2.4
ip route add 10.0.0.0/8 via 10.1.2.2
END

eq_or_diff( approve('Linux', '', $spoc, $raw ), $out, $title );

############################################################
$title = "Different next hop";
############################################################
$spoc = <<END;
ip route 10.20.0.0 255.255.0.0 10.1.2.3
END

$raw = <<END;
ip route 10.20.0.0 255.255.0.0 10.1.2.4
END

$out = <<END;
ip route 10.20.0.0 255.255.0.0 10.1.2.4
ip route 10.20.0.0 255.255.0.0 10.1.2.3
END

eq_or_diff( approve('IOS', '', $spoc, $raw ), $out, $title );

############################################################
$title = "No routing in [APPEND] part";
############################################################

$raw = <<END;
[APPEND]
ip route 10.22.0.0/16 10.1.2.4
END

$out = <<END;
ERROR>>> Must only use ACLs in [APPEND] part, but found ROUTING_VRF
END

eq_or_diff( approve_err('NX-OS', '', '', $raw ), $out, $title );

############################################################
$title = "Merge IOS ACL";
############################################################
$device = <<END;
interface Ethernet1
 ip address 10.0.6.1 255.255.255.0
END

$spoc = <<END;
ip access-list extended Ethernet1_in
 permit udp 10.0.6.0 0.0.0.255 host 10.0.1.11 eq 123
 deny ip any any
interface Ethernet1
 ip access-group Ethernet1_in in
END

$raw = <<END;
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

$out = <<END;
ip access-list extended Ethernet1_in-DRC-0
permit udp 10.0.6.0 0.0.0.255 host 224.0.1.1 eq 123
permit udp 10.0.6.0 0.0.0.255 host 10.0.1.11 eq 123
deny ip any host 224.0.1.1 log
deny ip any any
interface Ethernet1
ip access-group Ethernet1_in-DRC-0 in
END

eq_or_diff( approve('IOS', $device, $spoc, $raw ), $out, $title );

############################################################
$title = "Add IOS ACL";
############################################################
$device = <<END;
interface Ethernet1
 ip address 10.0.6.1 255.255.255.0
END

$spoc = <<END;
ip access-list extended Ethernet1_in
 permit udp 10.0.6.0 0.0.0.255 host 10.0.1.11 eq 123
 deny ip any any
interface Ethernet1
 ip access-group Ethernet1_in in
END

$raw = <<END;
ip access-list extended Ethernet1_out
 deny ip host 10.0.6.1 any
interface Ethernet1
 ip access-group Ethernet1_out out
END

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

eq_or_diff( approve('IOS', $device, $spoc, $raw ), $out, $title );

############################################################
$title = "Name clash with IOS ACL";
############################################################
$device = <<END;
interface Ethernet0
 ip address 10.0.5.1 255.255.255.0
interface Ethernet1
 ip address 10.0.6.1 255.255.255.0
END

$spoc = <<END;
interface Ethernet1
 ip access-group Ethernet1_in in
END

$raw = <<END;
ip access-list extended Ethernet0_in
 deny ip host 10.0.6.1 any
interface Ethernet0
 ip access-group Ethernet0_in out
END

$out = <<'END';
WARNING>>> Interface Ethernet0 referenced in raw doesn't exist in Netspoc
END

eq_or_diff( approve_err('IOS', $device, $spoc, $raw ), $out, $title );

############################################################
$title = "Name clash with IOS ACL";
############################################################
$device = <<END;
interface Ethernet1
 ip address 10.0.6.1 255.255.255.0
END

$spoc = <<END;
ip access-list extended Ethernet1_in
 permit udp 10.0.6.0 0.0.0.255 host 10.0.1.11 eq 123
 deny ip any any
interface Ethernet1
 ip access-group Ethernet1_in in
END

$raw = <<END;
ip access-list extended Ethernet1_in
 deny ip host 10.0.6.1 any
interface Ethernet1
 ip access-group Ethernet1_in out
END

$out = <<END;
ERROR>>> Name clash for 'Ethernet1_in' of ACCESS_LIST from raw
END

eq_or_diff( approve_err('IOS', $device, $spoc, $raw ), $out, $title );

############################################################
$title = "Merge Linux chains";
############################################################

$spoc = <<END;
*filter
:INPUT DROP
-A INPUT -i eth0 -s 10.0.6.0/24 -d 10.0.1.11/32 -p udp --dport 123 -j ACCEPT
-A INPUT -j DROP
END

$raw = <<END;
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

eq_or_diff( approve('Linux', '', $spoc, $raw ), $out, $title );

############################################################
$title = "Must not reference Netspoc generated chain";
############################################################

$spoc = <<END;
*filter
:INPUT DROP
:c1 -
-A c1 -s 10.0.6.0/24 -j ACCEPT
-A INPUT -i eth0 -p udp -d 224.0.1.1/32 --dport 123 -j c1
END

$raw = <<END;
*filter
:c1 -
-A c1 -s 10.0.7.0/24 -j ACCEPT
END

$out = <<'END';
ERROR>>> Must not redefine chain 'c1' from rawdata
END

eq_or_diff( approve_err('Linux', '', $spoc, $raw ), $out, $title );


############################################################
$title = "Add crypto";
############################################################

$device = <<'END';
interface Ethernet0/1
 nameif outside
END

$spoc = <<'END';
interface Ethernet0/1
 nameif outside
END

$raw = <<'END';
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

eq_or_diff( approve('ASA', $device, $spoc, $raw ), $out, $title );

############################################################
done_testing;
