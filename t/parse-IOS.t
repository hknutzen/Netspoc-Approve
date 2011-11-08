#!/usr/bin/perl
# parse-IOS.t

use strict;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Approve;

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
 deny ip any any log
interface Ethernet1
 ip access-group Ethernet1_in in
END

$out = '';

eq_or_diff(approve('IOS', $device, $device), $out, $title);

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

eq_or_diff(approve('IOS', $device, $device), $out, $title);


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

crypto map crypto-Dialer1 local-address Loopback1

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

eq_or_diff(approve('IOS', $device, $device), $out, $title);

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

eq_or_diff(approve('IOS', $device, $in), $out, $title);

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
 deny ip any any log-input

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
no 60000\\N 1 permit icmp any host 10.0.1.11 3 3
40001 permit udp host 10.0.12.3 host 10.0.1.11 eq 80
40003 deny ip any any log-input
no 70000
no 50000
no 30000\\N 40002 permit ah 10.0.5.0 0.0.0.255 host 10.0.1.11
exit
ip access-list resequence test 10 10
END

eq_or_diff(approve('IOS', $device, $in), $out, $title);

############################################################
$title = "Add lines at end of ACL";
############################################################
$in = <<END;
ip access-list extended test
 permit ip any host 10.0.1.1
 permit ip any host 10.0.1.2
 permit ip any host 10.0.1.3

interface Ethernet1
 ip access-group test in
END

$device = <<END;
ip access-list extended test
 permit ip any host 10.0.1.1

interface Ethernet1
 ip access-group test in
END

$out = <<END;
ip access-list resequence test 10000 10000
ip access-list extended test
10001 permit ip any host 10.0.1.2
10002 permit ip any host 10.0.1.3
exit
ip access-list resequence test 10 10
END

eq_or_diff(approve('IOS', $device, $in), $out, $title);

############################################################
$title = "Change ACL, prevent lockout";
#
# ACL lines must be deleted in reversed order,
# otherwise Netspoc server would be locked out.
############################################################
$in = <<END;
ip access-list extended test
 permit tcp host 10.2.3.4 host 10.3.4.5
! Network management to interface of device
 permit ip 10.0.11.0 0.0.0.255 host 10.9.9.1
 deny ip any any

interface Ethernet1
 ip access-group test in
END

$device = <<END;
ip access-list extended test
! Netspoc server to interface of device
 permit ip host 10.0.11.111 host 10.9.9.1
 deny ip any host 10.9.9.1
 permit tcp host 10.2.3.4 host 10.3.4.5
 deny ip any any

interface Ethernet1
 ip access-group test in
END

$out = <<END;
ip access-list resequence test 10000 10000
ip access-list extended test
30001 permit ip 10.0.11.0 0.0.0.255 host 10.9.9.1
no 20000
no 10000
exit
ip access-list resequence test 10 10
END

eq_or_diff(approve('IOS', $device, $in), $out, $title);

############################################################
$title = "Change ACL, prevent ephemeral permit";
#
# Handle moves of ACL lines differently depending on the direction.
# Upward moves are handled together with added lines.
# Downward moves are handled together with deleted lines.
############################################################
$in = <<END;
ip access-list extended test
 deny ip host 10.1.2.3 host 10.1.1.1
 permit udp host 10.2.3.4 host 10.3.4.5
 permit ip any host 10.1.1.1
 permit tcp host 10.2.3.4 host 10.3.4.5
 permit ip any any

interface Ethernet1
 ip access-group test in
END

$device = <<END;
ip access-list extended test
 permit udp host 10.2.3.4 host 10.3.4.5
 permit tcp host 10.2.3.4 host 10.3.4.5
 deny ip host 10.1.2.3 host 10.1.1.1
 permit ip any any

interface Ethernet1
 ip access-group test in
END

$out = <<END;
ip access-list resequence test 10000 10000
ip access-list extended test
no 30000\\N 1 deny ip host 10.1.2.3 host 10.1.1.1
10001 permit ip any host 10.1.1.1
exit
ip access-list resequence test 10 10
END

eq_or_diff(approve('IOS', $device, $in), $out, $title);

############################################################
$title = "Don't change ACL line which permit administrative access";
############################################################
$in = <<END;
ip access-list extended test
 permit tcp any host 10.1.13.33
 permit tcp any host 10.1.13.31
 permit tcp any host 10.1.13.32
 deny ip any any

interface Ethernet1
 ip access-group test in
END

$device = <<END;
ip access-list extended test
 permit tcp any host 10.1.13.31
 permit tcp any host 10.1.13.32
 permit tcp any host 10.1.13.33
 deny ip any any

interface Ethernet1
 ip access-group test in
END

$out = <<END;
no ip access-list extended test-DRC-0
ip access-list extended test-DRC-0
permit tcp any host 10.1.13.33
permit tcp any host 10.1.13.31
permit tcp any host 10.1.13.32
deny ip any any
interface Ethernet1
ip access-group test-DRC-0 in
no ip access-list extended test
END

eq_or_diff(approve('IOS', $device, $in), $out, $title);

############################################################
$title = "Change incoming crypto filter ACL";
############################################################
$in = <<END;
crypto ipsec transform-set Trans esp-3des esp-sha-hmac
ip access-list extended crypto-Ethernet1-1
 permit ip any 10.127.18.0 0.0.0.255
ip access-list extended crypto-filter-Ethernet1-1
! permit tcp host 10.127.18.1 host 10.1.11.40 eq 48
 permit tcp host 10.127.18.1 host 10.1.11.40 eq 49
 deny ip any any
crypto map crypto-Ethernet1 1 ipsec-isakmp
 match address crypto-Ethernet1-1
 set ip access-group crypto-filter-Ethernet1-1 in
 set peer 10.156.4.206
 set transform-set Trans

interface Ethernet1
 crypto map crypto-Ethernet1
END

$device = <<END;
crypto ipsec transform-set Trans esp-3des esp-sha-hmac
ip access-list extended crypto-Ethernet1-1
 permit ip any 10.127.18.0 0.0.0.255
ip access-list extended crypto-filter-Ethernet1-1
 permit tcp host 10.127.18.1 host 10.1.11.40 eq 48
! permit tcp host 10.127.18.1 host 10.1.11.40 eq 49
 deny ip any any
crypto map crypto-Ethernet1 1 ipsec-isakmp
 match address crypto-Ethernet1-1
 set ip access-group crypto-filter-Ethernet1-1 in
 set peer 10.156.4.206
 set transform-set Trans

interface Ethernet1
 crypto map crypto-Ethernet1
END

$out = <<END;
no ip access-list extended crypto-filter-Ethernet1-1-DRC-0
ip access-list extended crypto-filter-Ethernet1-1-DRC-0
permit tcp host 10.127.18.1 host 10.1.11.40 eq 49
deny ip any any
crypto map crypto-Ethernet1 1
set ip access-group crypto-filter-Ethernet1-1-DRC-0 in
no ip access-list extended crypto-filter-Ethernet1-1
END

eq_or_diff(approve('IOS', $device, $in), $out, $title);

############################################################
$title = "Move incoming to outgoing crypto filter ACL";
############################################################
$in = <<END;
crypto ipsec transform-set Trans esp-3des esp-sha-hmac
ip access-list extended crypto-Ethernet1-1
 permit ip any 10.127.18.0 0.0.0.255
ip access-list extended crypto-out-filter-Ethernet1-1
 permit tcp host 10.127.18.1 host 10.1.11.40 eq 48
 permit tcp host 10.127.18.1 host 10.1.11.40 eq 49
 deny ip any any
crypto map crypto-Ethernet1 1 ipsec-isakmp
 match address crypto-Ethernet1-1
 set ip access-group crypto-out-filter-Ethernet1-1 out
 set peer 10.156.4.206
 set transform-set Trans

interface Ethernet1
 crypto map crypto-Ethernet1
END

$device = <<END;
crypto ipsec transform-set Trans esp-3des esp-sha-hmac
ip access-list extended crypto-Ethernet1-1
 permit ip any 10.127.18.0 0.0.0.255
ip access-list extended crypto-in-filter-Ethernet1-1
 permit tcp host 10.127.18.1 host 10.1.11.40 eq 48
! permit tcp host 10.127.18.1 host 10.1.11.40 eq 49
 deny ip any any
crypto map crypto-Ethernet1 1 ipsec-isakmp
 match address crypto-Ethernet1-1
 set ip access-group crypto-in-filter-Ethernet1-1 in
 set peer 10.156.4.206
 set transform-set Trans

interface Ethernet1
 crypto map crypto-Ethernet1
END

$out = <<END;
no ip access-list extended crypto-out-filter-Ethernet1-1-DRC-0
ip access-list extended crypto-out-filter-Ethernet1-1-DRC-0
permit tcp host 10.127.18.1 host 10.1.11.40 eq 48
permit tcp host 10.127.18.1 host 10.1.11.40 eq 49
deny ip any any
crypto map crypto-Ethernet1 1
set ip access-group crypto-out-filter-Ethernet1-1-DRC-0 out
no set ip access-group crypto-in-filter-Ethernet1-1 in
no ip access-list extended crypto-in-filter-Ethernet1-1
END

eq_or_diff(approve('IOS', $device, $in), $out, $title);


############################################################
$title = "Find differences in transform-set";
############################################################
$in = <<END;
crypto ipsec transform-set Trans esp-des esp-sha-hmac
END

$device = <<END;
crypto ipsec transform-set Trans esp-3des esp-md5-hmac
END

$out = <<END;
ERROR>>> severe diffs in crypto ipsec detected
END

#eq_or_diff(approve('IOS', $device, $in), $out, $title);


############################################################
done_testing;
