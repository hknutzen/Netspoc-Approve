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
$title = "Merging IOS ACL";
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
$title = "Merging Linux chains";
############################################################

$spoc = <<END;
*filter
:INPUT DROP
-A INPUT -i eth0 -s 10.0.6.0/24 -d 10.0.1.11/32 -p udp --dport 123 -j ACCEPT
-A INPUT -j DROP
END

$raw = <<END;
*filter
:INPUT DROP
-A INPUT -i eth0 -p udp -s 10.0.6.0/24 -d 224.0.1.1/32 --dport 123 -j ACCEPT
[APPEND]
*filter
:INPUT DROP
-A INPUT -i eth0 -p udp -d 224.0.1.1/32 --dport 123 -j DROP
END

# Currently we don't see any output in compare mode,
# because iptables rules are always fully transferred, not incementally.
$out = '';

eq_or_diff( approve('Linux', '', $spoc, $raw ), $out, $title );

############################################################
done_testing;
