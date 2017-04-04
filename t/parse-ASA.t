#!/usr/bin/perl

use strict;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Approve;

# Minimal configuration of device.
my $minimal_device = <<END;
interface Ethernet0/0
 nameif inside
interface Ethernet0/1
 nameif outside
END

# Input from Netspoc.
# Input from device.
# Output from approve.
my($in, $device, $out);
my $device_type = 'ASA';
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

access-list outside_in extended permit udp object-group g0 host 10.0.1.11 eq sip
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
access-group inside_in-DRC-0 in interface inside
access-list outside_in-DRC-0 extended permit udp object-group g0-DRC-0 host 10.0.1.11 eq sip
access-list outside_in-DRC-0 extended permit tcp any host 10.0.1.11 range 7937 8999
access-list outside_in-DRC-0 extended deny ip any any
access-group outside_in-DRC-0 in interface outside
END

# Check whether output is as expected with given input
# AND whether output is empty for identical input.
check_parse_and_unchanged( $device_type, $minimal_device, $in, $out, $title );

############################################################
$title = "Abort on unknown sub command of object-group";
############################################################

$device = $minimal_device . <<'END';
object-group network g0
 network-object 10.0.3.0 255.255.255.0
 unknown command
access-list outside_in extended permit udp object-group g0 host 10.0.1.11 eq sip
access-group outside_in in interface ethernet0
END

$in = <<'END';
END

$out = <<END;
ERROR>>> Unexpected command in line 7:
>>unknown command<<
END

eq_or_diff(approve_err('ASA', $device, $in), $out, $title);

############################################################
$title = "Ignore ASA pre 8.4 static, global, nat";
############################################################
# Differences are ignored.

$device = $minimal_device;
$device .= <<'END';
global (outside) 1 10.48.56.5 netmask 255.255.255.255
nat (inside) 1 10.48.48.0 255.255.248.0
static (outside,inside) 10.9.0.0 172.31.0.0 netmask 255.255.0.0
END
$in = <<END;
global (outside) 1 10.4.56.5 netmask 255.255.255.255
nat (inside) 1 10.4.8.0 255.255.248.0
static (outside,inside) 10.1.0.0 172.1.0.0 netmask 255.255.0.0
END

$out = <<END;
END

eq_or_diff(approve('ASA', $device, $in), $out, $title);

############################################################
$title = "Parse crypto map, dynamic map with tunnel-group";
############################################################
$in = <<END;
access-list crypto-acl1 permit ip 10.1.2.0 255.255.240.0 host 10.3.4.5
access-list crypto-acl2 permit ip 10.1.3.0 255.255.240.0 host 10.3.4.5

crypto ipsec ikev1 transform-set trans esp-3des esp-sha-hmac
crypto dynamic-map some-name 10 match address crypto-acl2
crypto map map-outside 10 match address crypto-acl1
crypto map map-outside 10 set pfs group2
crypto map map-outside 10 set peer 97.98.99.100
crypto map map-outside 10 set ikev1 transform-set trans
crypto map map-outside 10 set security-association lifetime seconds 43200 kilobytes 4608000
crypto map map-outside 65000 ipsec-isakmp dynamic some-name
crypto map map-outside interface outside
crypto ca certificate map some-name 10
 subject-name attr ea eq some-name
tunnel-group some-name type ipsec-l2l
tunnel-group some-name ipsec-attributes
 peer-id-validate nocheck
 ikev2 local-authentication certificate Trustpoint2
 ikev2 remote-authentication certificate
tunnel-group-map some-name 10 some-name
END

$out = <<END;
tunnel-group some-name type ipsec-l2l
tunnel-group some-name ipsec-attributes
ikev2 local-authentication certificate Trustpoint2
ikev2 remote-authentication certificate
peer-id-validate nocheck
crypto ca certificate map some-name-DRC-0 10
subject-name attr ea eq some-name
tunnel-group-map some-name-DRC-0 10 some-name
access-list crypto-acl1-DRC-0 permit ip 10.1.2.0 255.255.240.0 host 10.3.4.5
crypto ipsec ikev1 transform-set trans-DRC-0 esp-3des esp-sha-hmac
crypto map map-outside 10 set peer 97.98.99.100
crypto map map-outside 10 set pfs group2
crypto map map-outside 10 set security-association lifetime seconds 43200
crypto map map-outside 10 set security-association lifetime kilobytes 4608000
crypto map map-outside 10 match address crypto-acl1-DRC-0
no crypto map map-outside 10 set ikev1 transform-set
crypto map map-outside 10 set ikev1 transform-set trans-DRC-0
access-list crypto-acl2-DRC-0 permit ip 10.1.3.0 255.255.240.0 host 10.3.4.5
crypto dynamic-map some-name 10 match address crypto-acl2-DRC-0
crypto map map-outside 65000 ipsec-isakmp dynamic some-name
END
check_parse_and_unchanged( $device_type, $minimal_device, $in, $out, $title );

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
group-policy VPN-group-DRC-0 attributes
split-tunnel-network-list value split-tunnel-DRC-0
access-list vpn-filter-DRC-0 extended permit ip host 10.1.1.67 10.2.42.0 255.255.255.224
access-list vpn-filter-DRC-0 extended deny ip any any
username jon.doe@token.example.com nopassword
username jon.doe@token.example.com attributes
service-type remote-access
vpn-framed-ip-address 10.1.1.67 255.255.254.0
username jon.doe@token.example.com attributes
vpn-filter value vpn-filter-DRC-0
vpn-group-policy VPN-group-DRC-0
END
check_parse_and_unchanged( $device_type, $minimal_device, $in, $out, $title );


############################################################
$title = "Parse tunnel-group of type ipsec-l2l (IP as name)";
############################################################

# Ignore pre-shared keys shown as '******'
$in = <<'END';
tunnel-group 193.155.130.1 type ipsec-l2l
tunnel-group 193.155.130.1 ipsec-attributes
 peer-id-validate nocheck
tunnel-group 193.155.130.2 type ipsec-l2l
tunnel-group 193.155.130.2 ipsec-attributes
 ikev2 local-authentication pre-shared-key ***
 ikev2 remote-authentication pre-shared-key ****
tunnel-group 193.155.130.3 type ipsec-l2l
tunnel-group 193.155.130.3 ipsec-attributes
 peer-id-validate nocheck
 ikev2 local-authentication certificate ASDM_TrustPoint1
 ikev2 remote-authentication certificate
crypto ca certificate map cert-map 10
 subject-name attr ea eq cert@example.com
tunnel-group-map cert-map 10 193.155.130.3
crypto map crypto-outside interface outside
END

$out = <<'END';
tunnel-group 193.155.130.3 type ipsec-l2l
tunnel-group 193.155.130.3 ipsec-attributes
ikev2 local-authentication certificate ASDM_TrustPoint1
ikev2 remote-authentication certificate
peer-id-validate nocheck
crypto ca certificate map cert-map-DRC-0 10
subject-name attr ea eq cert@example.com
tunnel-group-map cert-map-DRC-0 10 193.155.130.3
tunnel-group 193.155.130.1 type ipsec-l2l
tunnel-group 193.155.130.1 ipsec-attributes
peer-id-validate nocheck
tunnel-group 193.155.130.2 type ipsec-l2l
END
check_parse_and_unchanged( $device_type, $minimal_device, $in, $out, $title );


############################################################
$title = "Modify username attributes";
############################################################
$device = $minimal_device;
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
eq_or_diff(approve('ASA', $device, $in), $out, $title);


############################################################
$title = "Modify group-policy attributes";
############################################################
$device = $minimal_device;
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
eq_or_diff(approve('ASA', $device, $in), $out, $title);

############################################################
$title = "Remove group-policy and username";
############################################################
$device = $minimal_device;
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
END

$out = <<'END';
clear configure username jon.doe@token.example.com
clear configure group-policy VPN-group
END

eq_or_diff(approve('ASA', $device, $in), $out, $title);

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
tunnel-group VPN-tunnel webvpn-attributes
 authentication aaa certificate
! TODO: parse sequence number
tunnel-group-map ca-map 20 VPN-tunnel
webvpn
 certificate-group-map ca-map 20 VPN-tunnel
END

$out = <<'END';
tunnel-group VPN-tunnel-DRC-0 type remote-access
access-list vpn-filter-DRC-0 extended permit ip 10.1.2.192 255.255.255.192 10.1.0.0 255.255.255.0
access-list vpn-filter-DRC-0 extended deny ip any any
access-list split-tunnel-DRC-0 standard permit 10.1.0.0 255.255.255.0
ip local pool pool-DRC-0 10.1.219.192-10.1.219.255 mask 0.0.0.63
group-policy VPN-group-DRC-0 internal
group-policy VPN-group-DRC-0 attributes
banner value Willkommen beim Zugang per VPN
split-tunnel-policy tunnelspecified
vpn-idle-timeout 60
group-policy VPN-group-DRC-0 attributes
address-pools value pool-DRC-0
split-tunnel-network-list value split-tunnel-DRC-0
vpn-filter value vpn-filter-DRC-0
tunnel-group VPN-tunnel-DRC-0 general-attributes
tunnel-group VPN-tunnel-DRC-0 general-attributes
default-group-policy VPN-group-DRC-0
tunnel-group VPN-tunnel-DRC-0 ipsec-attributes
isakmp ikev1-user-authentication none
isakmp keepalive threshold 15 retry 3
peer-id-validate req
trust-point ASDM_TrustPoint4
tunnel-group VPN-tunnel-DRC-0 webvpn-attributes
authentication aaa certificate
crypto ca certificate map ca-map-DRC-0 10
subject-name attr ea co @sub.example.com
tunnel-group-map ca-map-DRC-0 10 VPN-tunnel-DRC-0
webvpn
certificate-group-map ca-map-DRC-0 10 VPN-tunnel-DRC-0
END
check_parse_and_unchanged('ASA', $minimal_device, $in, $out, $title);

############################################################
$title = "Modify tunnel-group ipsec-attributes";
############################################################
$device = $minimal_device;
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
tunnel-group VPN-tunnel type remote-access
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
eq_or_diff(approve('ASA', $device, $in), $out, $title);

############################################################
$title = "Modify tunnel-group l2l ipsec-attributes";
############################################################
$device = $minimal_device;
$device .= <<'END';
tunnel-group 193.155.130.20 type ipsec-l2l
tunnel-group 193.155.130.20 ipsec-attributes
 pre-shared-key *
 peer-id-validate nocheck
END

$in = <<'END';
tunnel-group 193.155.130.20 type ipsec-l2l
tunnel-group 193.155.130.20 ipsec-attributes
 trust-point ASDM_TrustPoint5
 ikev2 local-authentication certificate Trustpoint2
 ikev2 remote-authentication certificate
crypto ca certificate map ca-map 10
 subject-name attr ea eq some@example.com
tunnel-group-map ca-map 20 193.155.130.20
END

$out = <<'END';
tunnel-group 193.155.130.20 ipsec-attributes
ikev2 local-authentication certificate Trustpoint2
ikev2 remote-authentication certificate
trust-point ASDM_TrustPoint5
crypto ca certificate map ca-map-DRC-0 10
subject-name attr ea eq some@example.com
tunnel-group-map ca-map-DRC-0 10 193.155.130.20
tunnel-group 193.155.130.20 ipsec-attributes
no peer-id-validate
END
eq_or_diff(approve('ASA', $device, $in), $out, $title);

############################################################
$title = "Modify ip local pool";
############################################################
$device = $minimal_device;
$device .= <<'END';
ip local pool pool 10.1.219.192-10.1.219.255 mask 0.0.0.63
group-policy VPN-group internal
group-policy VPN-group attributes
 address-pools value pool
tunnel-group VPN-tunnel type remote-access
tunnel-group VPN-tunnel general-attributes
 default-group-policy VPN-group
crypto ca certificate map ca-map 10
 subject-name attr ea co @sub.example.com
tunnel-group-map ca-map 20 VPN-tunnel
END

$in = <<'END';
ip local pool pool 10.1.219.192-10.1.219.208 mask 0.0.0.15
group-policy VPN-group internal
group-policy VPN-group attributes
 address-pools value pool
tunnel-group VPN-tunnel type remote-access
tunnel-group VPN-tunnel general-attributes
 default-group-policy VPN-group
crypto ca certificate map ca-map 10
 subject-name attr ea co @sub.example.com
tunnel-group-map ca-map 20 VPN-tunnel
END

$out = <<'END';
ip local pool pool-DRC-0 10.1.219.192-10.1.219.208 mask 0.0.0.15
group-policy VPN-group attributes
address-pools value pool-DRC-0
no ip local pool pool 10.1.219.192-10.1.219.255 mask 0.0.0.63
END
eq_or_diff(approve('ASA', $device, $in), $out, $title);

############################################################
$title = "Add webvpn-attributes, delete ipsec-attributes";
############################################################
$device = $minimal_device;
$device .= <<'END';
tunnel-group NAME type remote-access
tunnel-group NAME ipsec-attributes
 trust-point ASDM_TrustPoint5
crypto ca certificate map ca-map 10
 subject-name attr ea co @sub.example.com
tunnel-group-map ca-map 20 NAME
END

$in = <<'END';
tunnel-group VPN-tunnel type remote-access
tunnel-group VPN-tunnel webvpn-attributes
 authentication aaa
crypto ca certificate map ca-map 10
 subject-name attr ea co @sub.example.com
tunnel-group-map ca-map 20 VPN-tunnel
END

$out = <<'END';
tunnel-group NAME webvpn-attributes
authentication aaa
no tunnel-group NAME ipsec-attributes
END
eq_or_diff(approve('ASA', $device, $in), $out, $title);

############################################################
$title = "Add certificate-group-map";
############################################################
$device = $minimal_device;
$device .= <<'END';
tunnel-group NAME type remote-access
tunnel-group NAME ipsec-attributes
 trust-point ASDM_TrustPoint5
crypto ca certificate map ca-map 10
 subject-name attr ea co @sub.example.com
tunnel-group-map ca-map 20 NAME
END

$in = <<'END';
tunnel-group VPN-tunnel type remote-access
tunnel-group VPN-tunnel ipsec-attributes
 trust-point ASDM_TrustPoint5
crypto ca certificate map ca-map 10
 subject-name attr ea co @sub.example.com
tunnel-group-map ca-map 20 VPN-tunnel
webvpn
 certificate-group-map ca-map 20 VPN-tunnel
END

$out = <<'END';
webvpn
certificate-group-map ca-map 10 NAME
END
eq_or_diff(approve('ASA', $device, $in), $out, $title);

############################################################
$title = "Delete tunnel-group";
############################################################
$device  = $minimal_device;
$device .= <<'END';
tunnel-group 193.155.130.20 type ipsec-l2l
tunnel-group 193.155.130.20 ipsec-attributes
 pre-shared-key *
 peer-id-validate nocheck
END

$in = <<'END';
END

$out = <<'END';
no tunnel-group 193.155.130.20 ipsec-attributes
clear configure tunnel-group 193.155.130.20
END
eq_or_diff(approve('ASA', $device, $in), $out, $title);

############################################################
$title = "Insert and delete entries from crypto map sequence";
############################################################
$device = $minimal_device;
$device .= <<'END';
crypto ipsec ikev1 transform-set Trans1a esp-3des esp-md5-hmac
crypto ipsec ikev1 transform-set Trans1b esp-3des esp-md5-hmac
crypto ipsec ikev1 transform-set Trans2 esp-aes-192 esp-sha-hmac
crypto ipsec ikev2 ipsec-proposal Proposal1
 protocol esp encryption aes192
 protocol esp integrity  sha
access-list crypto-outside-1 extended permit ip any 10.0.1.0 255.255.255.0
crypto map crypto-outside 1 match address crypto-outside-1
crypto map crypto-outside 1 set peer 10.0.0.1
crypto map crypto-outside 1 set ikev1 transform-set Trans1b
crypto map crypto-outside 1 set pfs group2
access-list crypto-outside-3 extended permit ip any 10.0.3.0 255.255.255.0
crypto map crypto-outside 3 match address crypto-outside-3
crypto map crypto-outside 3 set peer 10.0.0.3
crypto map crypto-outside 3 set ikev2 ipsec-proposal Proposal1
crypto map crypto-outside 3 set pfs group2
END

$in = <<'END';
crypto ipsec ikev1 transform-set Trans1 esp-3des esp-md5-hmac
crypto ipsec ikev2 ipsec-proposal Proposal1
 protocol esp encryption aes256
 protocol esp integrity  sha
access-list crypto-outside-1 extended permit ip any 10.0.2.0 255.255.255.0
crypto map crypto-outside 1 match address crypto-outside-1
crypto map crypto-outside 1 set peer 10.0.0.2
crypto map crypto-outside 1 set ikev1 transform-set Trans1
crypto map crypto-outside 1 set pfs group2
access-list crypto-outside-3 extended permit ip any 10.0.3.0 255.255.255.0
crypto map crypto-outside 3 match address crypto-outside-3
crypto map crypto-outside 3 set peer 10.0.0.3
crypto map crypto-outside 3 set ikev2 ipsec-proposal Proposal1
crypto map crypto-outside 3 set pfs group1
END

$out = <<'END';
access-list crypto-outside-1-DRC-0 extended permit ip any 10.0.2.0 255.255.255.0
crypto map crypto-outside 2 set peer 10.0.0.2
crypto map crypto-outside 2 set pfs group2
crypto map crypto-outside 2 match address crypto-outside-1-DRC-0
no crypto map crypto-outside 2 set ikev1 transform-set
crypto map crypto-outside 2 set ikev1 transform-set Trans1a
crypto ipsec ikev2 ipsec-proposal Proposal1-DRC-0
protocol esp encryption aes256
protocol esp integrity sha
no crypto map crypto-outside 3 set ikev2 ipsec-proposal
crypto map crypto-outside 3 set ikev2 ipsec-proposal Proposal1-DRC-0
crypto map crypto-outside 3 set pfs group1
clear configure crypto map crypto-outside 1
no crypto ipsec ikev1 transform-set Trans1b esp-3des esp-md5-hmac
no crypto ipsec ikev2 ipsec-proposal Proposal1
clear configure access-list crypto-outside-1
END

eq_or_diff(approve('ASA', $device, $in), $out, $title);

############################################################
$title = "Insert, change and delete dynamic crypto map";
############################################################
$device = $minimal_device;
$device .= <<'END';
crypto ipsec ikev1 transform-set Trans1a esp-3des esp-md5-hmac
crypto ipsec ikev1 transform-set Trans1b esp-3des esp-sha-hmac
crypto ipsec ikev1 transform-set Trans3 esp-aes-256 esp-md5-hmac
access-list crypto-outside-65535 extended permit ip 10.1.1.0 255.255.255.0 10.99.2.0 255.255.255.0
access-list crypto-outside-65534 extended permit ip 10.1.3.0 255.255.255.0 10.99.2.0 255.255.255.0
access-list crypto-outside-65533 extended permit ip 10.1.4.0 255.255.255.0 10.99.2.0 255.255.255.0
crypto dynamic-map name1@example.com 20 match address crypto-outside-65535
crypto dynamic-map name1@example.com 20 set ikev1 transform-set Trans1a Trans3
crypto dynamic-map name1@example.com 20 set pfs group2
crypto dynamic-map name3@example.com 20 match address crypto-outside-65534
crypto dynamic-map name4@example.com 40 match address crypto-outside-65533
crypto dynamic-map name4@example.com 40 set ikev1 transform-set Trans1a Trans1b
crypto map crypto-outside 65535 ipsec-isakmp dynamic name1@example.com
crypto map crypto-outside 65534 ipsec-isakmp dynamic name3@example.com
crypto map crypto-outside 65533 ipsec-isakmp dynamic name4@example.com
END

$in = <<'END';
crypto ipsec ikev1 transform-set Trans1 esp-3des esp-md5-hmac
crypto ipsec ikev1 transform-set Trans2 esp-aes esp-md5-hmac
access-list crypto-outside-1 extended permit ip 10.1.1.0 255.255.255.0 10.99.2.0 255.255.255.0
access-list crypto-outside-2 extended permit ip 10.1.2.0 255.255.255.0 10.99.2.0 255.255.255.0
access-list crypto-outside-3 extended permit ip 10.1.3.0 255.255.255.0 10.99.2.0 255.255.255.0
crypto dynamic-map name1@example.com 20 match address crypto-outside-1
crypto dynamic-map name1@example.com 20 set security-association lifetime seconds 3600
crypto dynamic-map name2@example.com 20 match address crypto-outside-2
crypto dynamic-map name3@example.com 20 match address crypto-outside-3
crypto dynamic-map name3@example.com 20 set ikev1 transform-set Trans1 Trans2
crypto map crypto-outside 65534 ipsec-isakmp dynamic name1@example.com
crypto map crypto-outside 65533 ipsec-isakmp dynamic name2@example.com
crypto map crypto-outside 65532 ipsec-isakmp dynamic name3@example.com
END

$out = <<'END';
crypto ipsec ikev1 transform-set Trans2-DRC-0 esp-aes esp-md5-hmac
no crypto dynamic-map name3@example.com 20 set ikev1 transform-set
crypto dynamic-map name3@example.com 20 set ikev1 transform-set Trans1a Trans2-DRC-0
access-list crypto-outside-2-DRC-0 extended permit ip 10.1.2.0 255.255.255.0 10.99.2.0 255.255.255.0
crypto dynamic-map name2@example.com 20 match address crypto-outside-2-DRC-0
crypto map crypto-outside 65532 ipsec-isakmp dynamic name2@example.com
crypto dynamic-map name1@example.com 20 set security-association lifetime seconds 3600
clear configure crypto map crypto-outside 65533
no crypto dynamic-map name1@example.com 20 set pfs group2
no crypto dynamic-map name1@example.com 20 set ikev1 transform-set Trans1a Trans3
clear configure crypto dynamic-map name4@example.com 40
no crypto ipsec ikev1 transform-set Trans1b esp-3des esp-sha-hmac
no crypto ipsec ikev1 transform-set Trans3 esp-aes-256 esp-md5-hmac
clear configure access-list crypto-outside-65533
END

eq_or_diff(approve('ASA', $device, $in), $out, $title);

############################################################
done_testing;
