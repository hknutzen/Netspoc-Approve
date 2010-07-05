#!/usr/bin/perl
# $id:$

use strict;
use Test::More qw(no_plan);
use lib 't';
use Test_Approve;

# Minimal configuration of device.
my $empty_device = <<END;
interface Ethernet0/0
 nameif inside
interface Ethernet0/1
 nameif outside
END

# Input from Netspoc.
# Input from device.
# Output from approve.
my($in, $all_in, $device, $out);

my $title;

############################################################
$title = "Parse routing and ACL with object-groups";
############################################################
$in = <<END;

route outside 10.20.0.0 255.255.0.0 10.1.2.3

access-list inside_in extended deny ip any any
access-group inside_in in interface inside

object-group network g0
 network-object 10.0.6.0 255.255.255.0
 network-object 10.0.5.0 255.255.255.0
 network-object host 10.0.12.3

access-list outside_in extended permit udp object-group g0 host 10.0.1.11 eq 7938
access-list outside_in extended permit tcp any host 10.0.1.11 range 7937 8999
access-list outside_in extended deny ip any any
access-group outside_in in interface outside
END

$out = <<END;
route outside 10.20.0.0 255.255.0.0 10.1.2.3
object-group network g0-DRC-0
network-object 10.0.6.0 255.255.255.0
network-object 10.0.5.0 255.255.255.0
network-object host 10.0.12.3
access-list inside_in-DRC-0 extended deny ip any any
access-list outside_in-DRC-0 extended permit udp object-group g0-DRC-0 host 10.0.1.11 eq 7938
access-list outside_in-DRC-0 extended permit tcp any host 10.0.1.11 range 7937 8999
access-list outside_in-DRC-0 extended deny ip any any
access-group inside_in-DRC-0 in interface inside
access-group outside_in-DRC-0 in interface outside
END
is_deeply(approve('ASA', $empty_device, $in), $out, $title);

$all_in .= $in;

############################################################
$title = "Parse static, global, nat";
############################################################
$in = <<END;
global (outside) 1 10.48.56.5 netmask 255.255.255.255
nat (inside) 1 10.48.48.0 255.255.248.0
static (outside,inside) 10.9.0.0 172.31.0.0 netmask 255.255.0.0
END

$out = <<END;
static (outside,inside) 10.9.0.0 172.31.0.0 netmask 255.255.0.0
global (outside) 1 10.48.56.5 netmask 255.255.255.255
nat (inside) 1 10.48.48.0 255.255.248.0
END
is_deeply(approve('ASA', $empty_device, $in), $out, $title);

$all_in .= $in;

############################################################
$title = "Parse crypto map";
############################################################
$in = <<END;
access-list crypto-acl permit ip 10.1.2.0 255.255.240.0 host 10.3.4.5

crypto ipsec transform-set trans esp-3des esp-sha-hmac 

crypto map map-outside 10 ipsec-isakmp
crypto map map-outside 10 match address crypto-acl
crypto map map-outside 10 set pfs group2
crypto map map-outside 10 set peer 97.98.99.100
crypto map map-outside 10 set transform-set trans
crypto map map-outside 10 set security-association lifetime seconds 43200 kilobytes 4608000
crypto map map-outside interface outside
END

$out = <<END;
access-list crypto-acl-DRC-0 permit ip 10.1.2.0 255.255.240.0 host 10.3.4.5
crypto map map-outside 10 set peer 97.98.99.100
crypto map map-outside 10 set pfs group2
crypto map map-outside 10 set security-association lifetime seconds 43200
crypto map map-outside 10 set security-association lifetime kilobytes 4608000
crypto map map-outside 10 set transform-set trans
crypto map map-outside 10 match address crypto-acl-DRC-0
END
is_deeply(approve('ASA', $empty_device, $in), $out, $title);

$all_in .= $in;

############################################################
$title = "Parse username, group-policy";
############################################################
$in = <<'END';
access-list split-tunnel standard permit 10.2.42.0 255.255.255.224
access-list vpn-filter extended permit ip host 10.1.1.67 10.2.42.0 255.255.255.224
access-list vpn-filter extended deny ip any any
group-policy VPN-group internal
group-policy VPN-group attributes
 banner value Willkommen!
 dns-server 10.1.2.3 10.44.55.66
 split-tunnel-network-list value split-tunnel
 split-tunnel-policy tunnelspecified
 vpn-idle-timeout 60
username jon.doe@token.example.com nopassword
username jon.doe@token.example.com attributes
 vpn-framed-ip-address 10.1.1.67 255.255.254.0
 service-type remote-access
 vpn-filter value vpn-filter
 vpn-group-policy VPN-group
END

$out = <<'END';
access-list split-tunnel-DRC-0 standard permit 10.2.42.0 255.255.255.224
group-policy VPN-group-DRC-0 internal
group-policy VPN-group-DRC-0 attributes
banner value Willkommen!
dns-server 10.1.2.3 10.44.55.66
split-tunnel-policy tunnelspecified
vpn-idle-timeout 60
access-list vpn-filter-DRC-0 extended permit ip host 10.1.1.67 10.2.42.0 255.255.255.224
access-list vpn-filter-DRC-0 extended deny ip any any
username jon.doe@token.example.com nopassword
username jon.doe@token.example.com attributes
service-type remote-access
vpn-framed-ip-address 10.1.1.67 255.255.254.0
username jon.doe@token.example.com attributes
vpn-group-policy VPN-group-DRC-0
vpn-filter value vpn-filter-DRC-0
group-policy VPN-group-DRC-0 attributes
split-tunnel-network-list value split-tunnel-DRC-0
END
is_deeply(approve('ASA', $empty_device, $in), $out, $title);

$all_in .= $in;

############################################################
$title = "Modify username attributes";
############################################################
$device = $empty_device;
$device .= <<'END';
username jon.doe@token.example.com nopassword
username jon.doe@token.example.com attributes
 service-type remote-access
 vpn-framed-ip-address 10.1.2.3 255.0.0.0
 vpn-simultaneous-logins 4
 password-storage enable
END

$in = <<'END';
username jon.doe@token.example.com nopassword
username jon.doe@token.example.com attributes
 service-type remote-access
 vpn-framed-ip-address 10.11.22.33 255.255.0.0
 vpn-idle-timeout 60
END

$out = <<'END';
username jon.doe@token.example.com attributes
vpn-framed-ip-address 10.11.22.33 255.255.0.0
vpn-idle-timeout 60
username jon.doe@token.example.com attributes
no password-storage
no vpn-simultaneous-logins
END
is_deeply(approve('ASA', $device, $in), $out, $title);

# username already added before, so it is not necessary
# to append input to $all_in.

############################################################
$title = "Modify group-policy attributes";
############################################################
$device = $empty_device;
$device .= <<'END';
group-policy VPN-group internal
group-policy VPN-group attributes
 banner value Welcome!
 dns-server value 10.1.2.3 10.44.55.66
 split-tunnel-policy tunnelspecified
 vpn-idle-timeout 60
 pfs
username jon.doe@token.example.com nopassword
username jon.doe@token.example.com attributes
 vpn-group-policy VPN-group
END

$in = <<'END';
group-policy VPN-group internal
group-policy VPN-group attributes
 banner value Willkommen!
 dns-server value 10.1.2.3
 split-tunnel-policy tunnelall
 vpn-session-timeout 40
username jon.doe@token.example.com nopassword
username jon.doe@token.example.com attributes
 vpn-group-policy VPN-group
END

$out = <<'END';
group-policy VPN-group attributes
no banner
banner value Willkommen!
dns-server value 10.1.2.3
split-tunnel-policy tunnelall
vpn-session-timeout 40
group-policy VPN-group attributes
no pfs
no vpn-idle-timeout
END
is_deeply(approve('ASA', $device, $in), $out, $title);

# group-policy already added before, so it is not necessary
# to append input to $all_in.

############################################################
$title = "Parse tunnel-group, group-policy, ca cert map, pool";
############################################################
$in = <<'END';
access-list split-tunnel standard permit 10.1.0.0 255.255.255.0
access-list vpn-filter extended permit ip 10.1.2.192 255.255.255.192 10.1.0.0 255.255.255.0
access-list vpn-filter extended deny ip any any
crypto ca certificate map ca-map 10
 subject-name attr ea co @sub.example.com
ip local pool pool 10.1.219.192-10.1.219.255 mask 0.0.0.63
group-policy VPN-group internal
group-policy VPN-group attributes
 address-pools value pool
 banner value Willkommen beim Zugang per VPN
 split-tunnel-network-list value split-tunnel
 split-tunnel-policy tunnelspecified
 vpn-filter value vpn-filter
 vpn-idle-timeout 60
tunnel-group VPN-tunnel type remote-access
tunnel-group VPN-tunnel general-attributes
 default-group-policy VPN-group
tunnel-group VPN-tunnel ipsec-attributes
 peer-id-validate req
 isakmp ikev1-user-authentication none
 isakmp keepalive threshold 15 retry 3
 trust-point ASDM_TrustPoint4
! TODO: parse sequence number
tunnel-group-map ca-map 20 VPN-tunnel
END

$out = <<'END';
access-list vpn-filter-DRC-0 extended permit ip 10.1.2.192 255.255.255.192 10.1.0.0 255.255.255.0
access-list vpn-filter-DRC-0 extended deny ip any any
access-list split-tunnel-DRC-0 standard permit 10.1.0.0 255.255.255.0
ip local pool pool-DRC-0 10.1.219.192-10.1.219.255 mask 0.0.0.63
group-policy VPN-group-DRC-0 internal
group-policy VPN-group-DRC-0 attributes
banner value Willkommen beim Zugang per VPN
split-tunnel-policy tunnelspecified
vpn-idle-timeout 60
tunnel-group VPN-tunnel-DRC-0 type remote-access
tunnel-group VPN-tunnel-DRC-0 general-attributes
tunnel-group VPN-tunnel-DRC-0 ipsec-attributes
isakmp ikev1-user-authentication none
isakmp keepalive threshold 15 retry 3
peer-id-validate req
trust-point ASDM_TrustPoint4
crypto ca certificate map ca-map-DRC-0 10
subject-name attr ea co @sub.example.com
tunnel-group-map ca-map-DRC-0 10 VPN-tunnel-DRC-0
tunnel-group VPN-tunnel-DRC-0 general-attributes
default-group-policy VPN-group-DRC-0
group-policy VPN-group-DRC-0 attributes
address-pools value pool-DRC-0
split-tunnel-network-list value split-tunnel-DRC-0
vpn-filter value vpn-filter-DRC-0
END
is_deeply(approve('ASA', $empty_device, $in), $out, $title);


############################################################
$title = "Modify tunnel-group ipsec-attributes";
############################################################
$device = $empty_device;
$device .= <<'END';
tunnel-group VPN-tunnel type remote-access
tunnel-group VPN-tunnel general-attributes
tunnel-group VPN-tunnel ipsec-attributes
 trust-point ASDM_TrustPoint4
crypto ca certificate map ca-map 10
 subject-name attr ea co @sub.example.com
tunnel-group-map ca-map 20 VPN-tunnel
END

$in = <<'END';
tunnel-group VPN-tunnel general-attributes
tunnel-group VPN-tunnel ipsec-attributes
 trust-point ASDM_TrustPoint5
crypto ca certificate map ca-map 10
 subject-name attr ea co @sub.example.com
tunnel-group-map ca-map 20 VPN-tunnel
END

$out = <<'END';
tunnel-group VPN-tunnel ipsec-attributes
trust-point ASDM_TrustPoint5
END
is_deeply(approve('ASA', $device, $in), $out, $title);

$all_in .= <<'END';
tunnel-group VPN-tunnel type remote-access
END

$all_in .= $in;

############################################################
$title = "Add tunnel-group of type ipsec-l2l (with IP as name)";
############################################################

$in = <<'END';
tunnel-group 193.155.130.20 type ipsec-l2l
tunnel-group 193.155.130.20 ipsec-attributes
 pre-shared-key *
 peer-id-validate nocheck
END

$out = <<'END';
tunnel-group 193.155.130.20 type ipsec-l2l
tunnel-group 193.155.130.20 ipsec-attributes
peer-id-validate nocheck
pre-shared-key *
END
is_deeply(approve('ASA', $empty_device, $in), $out, $title);

$all_in .= $in;

############################################################
$title = "Delete tunnel-group";
############################################################
$device  = $empty_device;
$device .= <<'END';
tunnel-group 193.155.130.20 type ipsec-l2l
tunnel-group 193.155.130.20 ipsec-attributes
 pre-shared-key *
 peer-id-validate nocheck
END

$in = <<'END';
END

$out = <<'END';
no tunnel-group 193.155.130.20
END
is_deeply(approve('ASA', $device, $in), $out, $title);


############################################################
# This test should always be the last test. When new tests 
# are added and new objects are involved in that test,
# the (relevant part of the) test-input should be appended
# to $all_in.
############################################################
$title = "Test empty output for identical input";
############################################################

$out = '';
is_deeply(approve('ASA', $all_in, $all_in), $out, $title);









