#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Approve;

# Input from Netspoc, from raw, output from approve.
my($spoc, $device, $out, $warn);
my $title;

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
done_testing;
