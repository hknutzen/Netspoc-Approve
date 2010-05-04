#!/usr/bin/perl
# parse-IOS.t

use strict;
use Test::More qw(no_plan);
use lib 't';
use Test_Approve;

# Minimal configuration of device.
my $empty_device = <<END;
interface Ethernet0
 ip address 10.1.1.1 255.255.255.0
interface Ethernet1
 ip address 10.2.2.2 255.255.255.128
END

# Input from Netspoc.
# Input from device.
# Output from approve.
my($in, $device, $out);

my $title;

############################################################
$title = "Parse routing and ACL";
############################################################
$device = <<END;

ip route 10.20.0.0 255.255.0.0 10.1.2.3
ip route 0.0.0.0 0.0.0.0 10.1.2.3

ip access-list extended Ethernet0_in
 deny ip any any
interface Ethernet0
 ip access-group Ethernet0_in in

ip access-list extended Ethernet1_in 
 permit udp 10.0.6.0 0.0.0.255 host 10.0.1.11 eq 123
 permit 50 10.0.5.0 0.0.0.255 host 10.0.1.11
 permit udp host 10.0.12.3 host 10.0.1.11 eq 7938
 permit tcp any host 10.0.1.11 range 7937 8999
 permit icmp any host 10.0.1.11 3 3
 deny ip any any
interface Ethernet1
 ip access-group Ethernet1_in in
END

$out = '';

is_deeply(approve('IOS', $device, $device), $out, $title);

############################################################
$title = "Parse crypto EZVPN";
############################################################
$device = <<END;

crypto ipsec client ezvpn vpn
 connect auto
 mode network-extension
 peer 141.91.129.163
 acl ACL-Split-Tunnel
 virtual-interface 1
 username test pass test
 xauth userid mode local

ip access-list extended ACL-Split-Tunnel
 permit ip 10.0.100.16 0.0.0.15 any
ip access-list extended ACL-crypto-filter
 permit tcp 10.1.11.0 0.0.0.255 host 10.0.100.17 range 22 23
 deny ip any any

interface Virtual-Template1 type tunnel
 ip access-group ACL-crypto-filter in

ip access-list extended Dialer1_in
 permit 50 host 141.91.129.163 any
 deny ip any any

ip access-list extended Ethernet0_in
 permit icmp any host 10.0.100.17 8
 permit icmp any host 10.0.100.17 0
 deny ip any any

interface Dialer1
 crypto ipsec client ezvpn vpn
 ip address negotiated
 ip access-group Dialer1_in in
interface Ethernet0
 crypto ipsec client ezvpn vpn inside
 ip access-group Ethernet0_in in
END

$out = '';

is_deeply(approve('IOS', $device, $device), $out, $title);


############################################################
$title = "Parse crypto map";
############################################################
$device = <<'END';

crypto isakmp policy 1
 encryption 3des
 hash md5
 group 2

crypto ipsec transform-set Trans esp-3des esp-md5-hmac

ip access-list extended crypto-Dialer1-1
 permit ip 10.156.9.128 0.0.0.7 any

ip access-list extended crypto-filter-Dialer1-1
 permit udp 10.1.11.0 0.0.0.255 host 10.156.9.129 gt 1023
 deny ip any any

crypto map crypto-Dialer1 1 ipsec-isakmp
 match address crypto-Dialer1-1
 set ip access-group crypto-filter-Dialer1-1 in
 set peer 193.101.67.17
 set peer 193.101.67.20
 set transform-set Trans
 set pfs group2

ip access-list extended Dialer1_in
 permit 50 host 193.101.67.17 any
 permit 50 host 193.101.67.20 any
 deny ip any any
ip access-list extended Vlan10_in
 permit tcp 10.156.9.128 0.0.0.7 10.1.45.10 0.0.0.1 range 950 969
 deny ip any any

interface Dialer1
 crypto map crypto-Dialer1
 ip address negotiated
 ip access-group Dialer1_in in
interface Vlan10
 ip address 10.156.9.129 255.255.255.248
 ip access-group Vlan10_in in
END

$out = '';

is_deeply(approve('IOS', $device, $device), $out, $title);

############################################################
$title = "Change routing";
############################################################
$in = <<END;
ip route 10.10.0.0 255.255.0.0 10.1.2.3
ip route 10.20.0.0 255.255.0.0 10.1.2.3
ip route 10.40.0.0 255.255.0.0 10.1.2.4
END

$device = <<END;
ip route 10.20.0.0 255.255.0.0 10.1.2.3
ip route 10.30.0.0 255.255.0.0 10.1.2.3
ip route 10.40.0.0 255.255.0.0 10.1.2.3
END

$out = <<END;
ip route 10.10.0.0 255.255.0.0 10.1.2.3
no ip route 10.40.0.0 255.255.0.0 10.1.2.3
ip route 10.40.0.0 255.255.0.0 10.1.2.4
no ip route 10.30.0.0 255.255.0.0 10.1.2.3
END

is_deeply(approve('IOS', $device, $in), $out, $title);

############################################################
$title = "Change ACL";
############################################################
$in = <<END;
ip access-list extended test
 permit icmp any host 10.0.1.11 3 3
 permit udp 10.0.6.0 0.0.0.255 host 10.0.1.11 eq 123
 permit 50 10.0.5.0 0.0.0.255 host 10.0.1.11
 permit udp host 10.0.12.3 host 10.0.1.11 eq 7938
 permit udp host 10.0.12.3 host 10.0.1.11 eq 80
! permit tcp any host 10.0.1.11 range 7937 8999
 permit ah 10.0.5.0 0.0.0.255 host 10.0.1.11
 deny ip any any

interface Ethernet1
 ip access-group test in
END

$device = <<END;
ip access-list extended test
 permit udp 10.0.6.0 0.0.0.255 host 10.0.1.11 eq ntp
 permit esp 10.0.5.0 0.0.0.255 host 10.0.1.11
 permit ah 10.0.5.0 0.0.0.255 host 10.0.1.11
 permit udp host 10.0.12.3 host 10.0.1.11 eq 7938
! permit udp host 10.0.12.3 host 10.0.1.11 eq 80
 permit tcp any host 10.0.1.11 range 7937 8999
 permit icmp any host 10.0.1.11 3 3
 deny ip any any

interface Ethernet1
 ip access-group test in
END

$out = <<END;
ip access-list resequence test 10000 10000
ip access-list extended test
40001 permit udp host 10.0.12.3 host 10.0.1.11 eq 80
no 30000\\N 40002 permit ah 10.0.5.0 0.0.0.255 host 10.0.1.11
no 50000
no 60000\\N 1 permit icmp any host 10.0.1.11 3 3
exit
ip access-list resequence test 10 10
END

is_deeply(approve('IOS', $device, $in), $out, $title);
