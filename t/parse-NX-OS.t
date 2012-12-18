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

object-group ip address g0
 10 10.0.6.0/24
 20 10.0.5.0/24
 30 host 10.0.12.3

ip access-list outside_in
 10 permit udp addrgroup g0 host 10.0.1.11 eq sip
 20 permit tcp any host 10.0.1.11 range 7937 8999
 30 deny ip any any

interface Ethernet0/1
 ip access-group outside_in in
END

$out = <<END;
object-group ip address g0-DRC-0
10.0.6.0/24
10.0.5.0/24
host 10.0.12.3
ip access-list inside_in-DRC-0
deny ip any any
interface Ethernet0/0
ip access-group inside_in-DRC-0 in
ip access-list outside_in-DRC-0
permit udp addrgroup g0-DRC-0 host 10.0.1.11 eq sip
permit tcp any host 10.0.1.11 range 7937 8999
deny ip any any
interface Ethernet0/1
ip access-group outside_in-DRC-0 in
ip route 10.20.0.0/16 10.1.2.3
END

# Check whether output is as expected with given input
# AND whether output is empty for identical input.
check_parse_and_unchanged( $device_type, $minimal_device, $in, $out, $title );

############################################################
$title = "Object group used in two ACLs; 1. occurence new, 2. unchanged";
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
done_testing;
