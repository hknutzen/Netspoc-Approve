#!/usr/bin/perl
# $id:$

use strict;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Approve;

# Minimal configuration of device.
my $minimal_device = <<END;
interface Ethernet0/0
 ip address 10.1.8.0/29
interface Ethernet0/1
 ip address 10.1.32.0/28
END

# Input from Netspoc.
# Input from device.
# Output from approve.
my($in, $device, $out);
my $device_type = 'NX-OS';
my $title;

############################################################
$title = "Parse routing and ACL with object-groups";
############################################################
$in = <<END;

ip route 10.20.0.0/16 10.1.2.3

ip access-list inside_in
 10 deny ip any any

interface Ethernet0/0
 ip access-group inside_in in

object-group ip port p0
 10 eq 80
 20 eq 88
 30 range 7937 8999

object-group ip address g0
 10 10.0.6.0/24
 20 10.0.5.0/24
 30 host 10.0.12.3

ip access-list outside_in
 10 permit udp addrgroup g0 host 10.0.1.11 eq sip
 20 permit tcp any host 10.0.1.11 portgroup p0
 30 deny ip any any

interface Ethernet0/1
 ip access-group outside_in in
END

$out = <<END;
object-group ip address g0-DRC-0
10.0.6.0/24
10.0.5.0/24
host 10.0.12.3
object-group ip port p0-DRC-0
eq 80
eq 88
range 7937 8999
ip access-list inside_in-DRC-0
deny ip any any
interface Ethernet0/0
ip access-group inside_in-DRC-0 in
ip access-list outside_in-DRC-0
permit udp addrgroup g0-DRC-0 host 10.0.1.11 eq sip
permit tcp any host 10.0.1.11 portgroup p0-DRC-0
deny ip any any
interface Ethernet0/1
ip access-group outside_in-DRC-0 in
ip route 10.20.0.0/16 10.1.2.3
END

# Check whether output is as expected with given input
# AND whether output is empty for identical input.
check_parse_and_unchanged( $device_type, $minimal_device, $in, $out, $title );

############################################################
$title = "Move ACL entries";
############################################################

$device = <<'END';
ip access-list outside_in
 10 permit ip host 1.1.1.1 any
 20 permit ip host 2.2.2.2 any
 30 permit ip host 3.3.3.3 any
 40 permit ip host 4.4.4.4 any
interface Ethernet0/1
 ip access-group outside_in in
END

$in = <<'END';
ip access-list outside_in
 10 permit ip host 1.1.1.1 any
 20 permit ip host 4.4.4.4 any
 30 permit ip host 2.2.2.2 any
 40 permit ip host 3.3.3.3 any
interface Ethernet0/1
 ip access-group outside_in in
END

$out = <<'END';
resequence ip access-list outside_in 10000 10000
ip access-list outside_in
no 40000\N 10001 permit ip host 4.4.4.4 any
resequence ip access-list outside_in 10 10
END
eq_or_diff(approve($device_type, $device, $in), $out, $title);

############################################################
$title = "Object group used in two ACLs; 1. occurrence new, 2. unchanged";
############################################################
$device = <<'END';
object-group ip address g1-0
 10 host 2.2.2.2
ip access-list inside
 10 permit ip host 1.1.1.1 any
interface Ethernet0/0
 ip access-group inside in
ip access-list outside
 10 permit ip addrgroup g1-0 any
interface Ethernet0/1
 ip access-group outside in
END

$in = <<'END';
object-group ip address g1
 10 host 2.2.2.2
 20 host 3.3.3.3
ip access-list inside
 10 permit ip addrgroup g1 any
 20 permit ip host 1.1.1.1 any
interface Ethernet0/0
 ip access-group inside in
ip access-list outside
 10 permit ip addrgroup g1 any
interface Ethernet0/1
 ip access-group outside in
END

$out = <<'END';
object-group ip address g1-0
host 3.3.3.3
resequence ip access-list inside 10000 10000
ip access-list inside
1 permit ip addrgroup g1-0 any
resequence ip access-list inside 10 10
END
eq_or_diff(approve('NX-OS', $device, $in), $out, $title);

############################################################
$title = "Remove in ACL with object-group, add out ACL";
############################################################

$device = <<'END';
object-group ip address g1
 10 host 1.1.1.1
ip access-list inside
 10 permit ip addrgroup g1 any
interface Ethernet0/0
 ip address 10.1.0.1/24
 ip access-group inside in
interface Ethernet0/1
 ip address 10.1.1.1/24
END

$in = <<'END';
interface Ethernet0/0
 ip address 10.1.0.1/24
ip access-list outside
 10 permit ip host 1.1.1.1 any
interface Ethernet0/1
 ip access-group outside out
END

$out = <<'END';
ip access-list outside-DRC-0
permit ip host 1.1.1.1 any
interface Ethernet0/1
ip access-group outside-DRC-0 out
interface Ethernet0/0
no ip access-group inside in
no ip access-list inside
no object-group ip address g1
END
eq_or_diff(approve('NX-OS', $device, $in), $out, $title);

############################################################
$title = "Ignore ACL line with remark";
############################################################
$device = <<'END';
ip access-list inside
 10 remark Test1
 20 permit ip host 1.1.1.1 any
 30 permit ip host 2.2.2.2 any
 40 remark Test2
 50 permit ip host 4.4.4.4 any
interface Ethernet0/0
 ip access-group inside in
END

$in = <<'END';
ip access-list inside
 10 permit ip host 1.1.1.1 any
 20 permit ip host 4.4.4.4 any
interface Ethernet0/0
 ip access-group inside in
END

$out = <<'END';
resequence ip access-list inside 10000 10000
ip access-list inside
no 40000
no 30000
no 10000
resequence ip access-list inside 10 10
END
eq_or_diff(approve('NX-OS', $device, $in), $out, $title);

############################################################
$title = "Managed and unmanaged VRF in one device; add VRF route";
############################################################
$device = <<END;
ip route 10.20.0.0/16 10.1.2.3
ip access-list acl1
 10 permit ip any host 10.0.1.1
interface Ethernet1
 ip address 10.0.9.1/24
 ip access-group acl1 in
vrf context 013
 ip route 10.30.0.0/16 10.1.2.3
ip access-list acl2
 10 permit ip any host 10.0.1.1
interface Ethernet2
 ip address 10.0.0.1/24
 vrf member 013
 ip access-group acl2 in
END

$in = <<END;
vrf context 013
 ip route 10.30.0.0/16 10.1.2.3
 ip route 10.40.0.0/16 10.1.2.4
ip access-list acl2
 10 permit ip any host 10.0.1.1
interface Ethernet2
 ip address 10.0.0.1/24
 vrf member 013
 ip access-group acl2 in
END

$out = <<END;
vrf context 013
ip route 10.40.0.0/16 10.1.2.4
END

eq_or_diff(approve('NX-OS', $device, $in), $out, $title);

############################################################
$title = "Ignore pseudo mpls interface from netspoc";
############################################################
$device = <<END;
interface Ethernet2
 ip address 10.0.0.1/24
 vrf member 013
interface Po1
 mpls ip
END

$in = <<END;
interface Ethernet2
 ip address 10.0.0.1/24
 vrf member 013
interface mpls1
 ip unnumbered X
 vrf member 013
END

$out = '';

eq_or_diff(approve('NX-OS', $device, $in), $out, $title);

############################################################
$title = "Interface mgmt0 is located in management VRF by default";
############################################################
$device = <<END;
interface mgmt0
 ip address 10.0.0.1/24
END

$in = <<END;
interface mgmt0
 vrf member management
END

$out = '';

eq_or_diff(approve('NX-OS', $device, $in), $out, $title);

############################################################
done_testing;
