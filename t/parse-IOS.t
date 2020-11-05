#!/usr/bin/perl
# parse-IOS.t

use strict;
use warnings;
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
$title = "Ignore commands in banner";
############################################################
$device = <<END;
banner motd ^CCC
ip route 0.0.0.0 0.0.0.0 10.1.1.1
^C
ip route 0.0.0.0 0.0.0.0 10.2.2.2
END

$in = << 'END';
ip route 0.0.0.0 0.0.0.0 10.3.3.3
END

$out = <<'END';
no ip route 0.0.0.0 0.0.0.0 10.2.2.2\N ip route 0.0.0.0 0.0.0.0 10.3.3.3
END

eq_or_diff(approve('IOS', $device, $in), $out, $title);

############################################################
$title = "Bad indentation after first subcommand";
############################################################
$device = <<END;
object-group network g1
 host 10.0.1.11
  10.0.2.0 0.0.0.255
END

$out = <<'END';
ERROR>>> Expected indentation '1' but got '2' at line 3:
ERROR>>> >>  10.0.2.0 0.0.0.255<<
END

eq_or_diff(approve_err('IOS', $device, $device), $out, $title);

############################################################
$title = "Higher indentation of subcommands";
############################################################
$device = <<END;
object-group network g1
  host 10.0.1.11
  10.0.2.0 0.0.0.255
END

$out = '';

eq_or_diff(approve('IOS', $device, $device), $out, $title);

############################################################
$title = "Higher indentation of unknown subcommands";
############################################################
$device = <<END;
policy-map type inspect dns preset_dns_map
  parameters
   message-length maximum client auto
   message-length maximum 512
policy-map global_policy
 class inspection_default
   inspect dns preset_dns_map
      inspect ftp
   ! ignore interface command as sub command
   interface e0
    ip address 10.1.1.1 255.255.255.0
   inspect h323 h225
interface e0
 ip address 10.1.1.1 255.255.255.0
END

$in = <<"END";
interface e0
 ip address 10.1.1.1 255.255.255.0
END

$out = '';

eq_or_diff(approve('IOS', $device, $in), $out, $title);

############################################################
$title = "Device file with CRLF";
############################################################
$device = <<'END';
interface Loopback1
 vrf forwarding 001
 ip address 10.1.1.1 255.255.255.255
END

$in  = <<'END';
interface Loopback1
 vrf forwarding 001
 ip address 10.1.1.1 255.255.255.255
END

$device =~ s/\n/\r\n/g;

$out = <<'END';
END
eq_or_diff(approve('IOS', $device, $in), $out, $title);

############################################################
$title = "Multiple occurrences of command";
############################################################
$device = <<END;
interface e0
 ip address 10.1.1.1 255.255.255.0
interface e0
 ip address 10.1.1.1 255.255.255.0
END

$out = <<"END";
ERROR>>> Multiple occurrences of command not allowed
ERROR>>>  at line 3, pos 2:
ERROR>>> >>interface e0<<
END

eq_or_diff(approve_err('IOS', $device, $device), $out, $title);

############################################################
$title = "Bad indentation after subcommands";
############################################################
$device = <<END;
object-group network g1
  host 10.0.1.11
  10.0.2.0 0.0.0.255
 object-group network g2
END

$out = <<'END';
ERROR>>> Expected indentation '0' but got '1' at line 4:
ERROR>>> >> object-group network g2<<
END

eq_or_diff(approve_err('IOS', $device, $device), $out, $title);

############################################################
$title = "Certificate chain";
############################################################
$device = <<'END';
crypto pki certificate chain VPND012345
 certificate 6D0002F1B7E1307AF07D82AEEF00000002F1B7
  00000000 11111111 22222222 33333333 44444444 55555555 66666666 77777777
  88888888 99999999 AAAAAAAA BBBBBBBB CCCCCCCC DDDDDDDD EEEEEEEE FFFFFFFF
  ABCDEFAB EEEEFFFF EE
  	quit
ip route 0.0.0.0 0.0.0.0 10.2.2.2
END

$in = << 'END';
ip route 0.0.0.0 0.0.0.0 10.2.2.2
END

$out = '';

eq_or_diff(approve('IOS', $device, $in), $out, $title);

############################################################
$title = "Parse routing, object-group and ACL";
############################################################
$device = <<END;

ip route 10.20.0.0 255.255.0.0 10.1.2.3
ip route 0.0.0.0 0.0.0.0 10.1.2.3

ip access-list extended Ethernet0_in
 deny ip any any
interface Ethernet0
 ip access-group Ethernet0_in in

object-group network g1
 host 10.0.1.11
 10.0.2.0 0.0.0.255

ip access-list extended Ethernet1_in
 permit udp 10.0.6.0 0.0.0.255 object-group g1 eq 123
 permit 50 10.0.5.0 0.0.0.255 host 10.0.1.11
 permit udp host 10.0.12.3 host 10.0.1.11 eq 7938
 permit tcp any host 10.0.1.11 range 7937 8999
 permit icmp any host 10.0.1.11 3 4
 deny ip any any log
interface Ethernet1
 ip access-group Ethernet1_in in
END

$out = '';

eq_or_diff(approve('IOS', $device, $device), $out, $title);

############################################################
$title = "point-to-point interface";
############################################################
$device = <<END;
interface ATM0
 no ip address
 no atm ilmi-keepalive
!
interface ATM0.7 point-to-point
 pvc 1/32
  bridge-dot1q encap 7
  pppoe-client dial-pool-number 1
!
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
$device = <<END;
ip route 10.20.0.0 255.255.0.0 10.1.2.3
ip route 10.30.0.0 255.255.0.0 10.1.2.3
ip route 10.40.0.0 255.255.0.0 10.1.2.3
END

$in = <<END;
ip route 10.10.0.0 255.255.0.0 10.1.2.3
ip route 10.20.0.0 255.255.0.0 10.1.2.3
ip route 10.40.0.0 255.255.0.0 10.1.2.4
END

$out = <<END;
ip route 10.10.0.0 255.255.0.0 10.1.2.3
no ip route 10.40.0.0 255.255.0.0 10.1.2.3\\N ip route 10.40.0.0 255.255.0.0 10.1.2.4
no ip route 10.30.0.0 255.255.0.0 10.1.2.3
END

eq_or_diff(approve('IOS', $device, $in), $out, $title);

############################################################
$title = "Leave routing unchanged";
############################################################

# Routes and ACL in global VRF
$device = <<END;
ip route 10.20.0.0 255.255.0.0 10.1.2.3
ip route 10.30.0.0 255.255.0.0 10.1.2.3
ip route 10.40.0.0 255.255.0.0 10.1.2.3
ip access-list extended acl2
 permit ip any host 10.0.1.1
interface Ethernet2
 ip access-group acl2 in
END

# Only ACL is configured from Netspoc, routes are left unchanged
$in = <<END;
ip access-list extended acl2
 permit ip any host 10.0.1.1
interface Ethernet2
 ip access-group acl2 in
END

$out = <<END;
END

eq_or_diff(approve('IOS', $device, $in), $out, $title);

############################################################
$title = "Route with interface name";
############################################################
$device = <<END;
ip route 10.10.0.0 255.255.0.0 serial0 10.1.2.3
ip route 10.20.0.0 255.255.0.0 10.1.2.3
END

$in = <<END;
ip route 10.10.0.0 255.255.0.0 10.1.2.3
ip route 10.20.0.0 255.255.0.0 serial1 10.1.2.3
END

$out = <<'END';
no ip route 10.10.0.0 255.255.0.0 serial0 10.1.2.3\N ip route 10.10.0.0 255.255.0.0 10.1.2.3
no ip route 10.20.0.0 255.255.0.0 10.1.2.3\N ip route 10.20.0.0 255.255.0.0 serial1 10.1.2.3
END

eq_or_diff(approve('IOS', $device, $in), $out, $title);

############################################################
$title = "Named static route";
############################################################
$device = <<END;
ip route 10.10.0.0 255.255.0.0 10.1.2.3 name x
ip route 10.20.0.0 255.255.0.0 10.1.2.3
END

$in = <<END;
ip route 10.20.0.0 255.255.0.0 10.1.2.3
ip route 10.10.0.0 255.255.0.0 10.1.2.3 name y
END

$out = <<END;
END

eq_or_diff(approve('IOS', $device, $in), $out, $title);

############################################################
$title = "Tagged static route";
############################################################
$device = <<END;
ip route 10.10.0.0 255.255.0.0 10.1.2.3 tag 10
ip route 10.20.0.0 255.255.0.0 10.1.2.3 tag 20
END

$in = <<END;
ip route 10.10.0.0 255.255.0.0 10.1.2.3
ip route 10.20.0.0 255.255.0.0 10.1.2.3 tag 30
END

$out = <<END;
no ip route 10.10.0.0 255.255.0.0 10.1.2.3 tag 10\\N ip route 10.10.0.0 255.255.0.0 10.1.2.3
no ip route 10.20.0.0 255.255.0.0 10.1.2.3 tag 20\\N ip route 10.20.0.0 255.255.0.0 10.1.2.3 tag 30
END

eq_or_diff(approve('IOS', $device, $in), $out, $title);

############################################################
$title = "Change ACL";
############################################################
$device = <<END;
ip access-list extended test-DRC-0
 permit udp 10.0.6.0 0.0.0.255 host 10.0.1.11 eq ntp
 permit gre 10.0.5.0 0.0.0.255 host 10.0.1.11
 permit igmp 10.0.5.0 0.0.0.255 host 10.0.1.11
 permit udp host 10.0.12.3 host 10.0.1.11 eq 7938
! permit udp host 10.0.12.3 host 10.0.1.11 eq 80
 permit tcp any host 10.0.1.11 range 7937 8999
 permit icmp any host 10.0.1.11 packet-too-big
 deny ip any any

interface Serial1
 ip unnumbered Ethernet1
 ip access-group test-DRC-0 in
END

$in = <<END;
ip access-list extended test
 permit icmp any host 10.0.1.11 3 1
 permit udp 10.0.6.0 0.0.0.255 host 10.0.1.11 eq 123
 permit 47 10.0.5.0 0.0.0.255 host 10.0.1.11
 permit udp host 10.0.12.3 host 10.0.1.11 eq 7938
 permit udp host 10.0.12.3 host 10.0.1.11 eq 80
! permit tcp any host 10.0.1.11 range 7937 8999
 permit igmp 10.0.5.0 0.0.0.255 host 10.0.1.11
 deny ip any any log-input

interface Serial1
 ip unnumbered Ethernet1
 ip access-group test in
END

$out = <<END;
ip access-list resequence test-DRC-0 10000 10000
ip access-list extended test-DRC-0
1 permit icmp any host 10.0.1.11 3 1
40001 permit udp host 10.0.12.3 host 10.0.1.11 eq 80
no 70000\\N 40003 deny ip any any log-input
no 60000
no 50000
no 30000\\N 40002 permit igmp 10.0.5.0 0.0.0.255 host 10.0.1.11
ip access-list resequence test-DRC-0 10 10
END

eq_or_diff(approve('IOS', $device, $in), $out, $title);

############################################################
$title = "Unknown ACL on device";
############################################################
$device = <<END;
interface Serial1
 ip unnumbered Ethernet1
 ip access-group test-DRC-0 in
END

$out = <<'END';
ERROR>>> ACL test-DRC-0 referenced at 'Serial1' does not exist
END

eq_or_diff(approve_err('IOS', $device, $device), $out, $title);

############################################################
$title = "Reference same ACL from two interfaces";
############################################################
$device = <<END;
ip access-list extended test-DRC-0
 permit udp 10.0.6.0 0.0.0.255 host 10.0.1.11 eq ntp
interface Serial1
 ip unnumbered Ethernet1
 ip access-group test-DRC-0 in
interface Serial2
 ip unnumbered Ethernet1
 ip access-group test-DRC-0 in
END

$out = <<'END';
ERROR>>> ACL test-DRC-0 is referenced from two places:
 Serial1 and Serial2
END

eq_or_diff(approve_err('IOS', $device, $device), $out, $title);

############################################################
$title = "Reference same ACL two times";
############################################################
$device = <<END;
ip access-list extended test-DRC-0
 permit udp 10.0.6.0 0.0.0.255 host 10.0.1.11 eq ntp
interface Serial1
 ip unnumbered Ethernet1
 ip access-group test-DRC-0 in
 ip access-group test-DRC-0 out
END

$out = <<'END';
ERROR>>> ACL test-DRC-0 is referenced from two places:
 Serial1 and Serial1
END

eq_or_diff(approve_err('IOS', $device, $device), $out, $title);

############################################################
$title = "Change object-group";
############################################################
$device = <<END;
object-group network g1-DRC-0
 host 10.0.1.11
 host 10.0.1.12
 host 10.0.1.13
object-group network g2-DRC-0
 10.0.6.0 0.0.0.255

ip access-list extended test-DRC-0
 permit udp object-group g2-DRC-0 object-group g1-DRC-0 eq ntp
 deny ip any any

interface Serial1
 ip unnumbered Ethernet1
 ip access-group test-DRC-0 in
END

$in = <<END;
object-group network g1
 host 10.0.1.11
 host 10.0.1.13
object-group network g2
 10.0.5.0 0.0.0.128
 10.0.6.0 0.0.0.255

ip access-list extended test
 permit udp object-group g2 object-group g1 eq ntp
 deny ip any any

interface Serial1
 ip unnumbered Ethernet1
 ip access-group test in
END

$out = <<END;
object-group network g1-DRC-0
no host 10.0.1.12
object-group network g2-DRC-0
10.0.5.0 0.0.0.128
END

eq_or_diff(approve('IOS', $device, $in), $out, $title);

############################################################
$title = "Remove and add object-group";
############################################################
$device = <<END;
object-group network g1-DRC-0
 host 10.0.1.11
ip access-list extended test-DRC-0
 permit udp any object-group g1-DRC-0 eq ntp

interface Serial1
 ip unnumbered Ethernet1
 ip access-group test-DRC-0 in
END

$in = <<END;
object-group network g2
 10.0.5.0 0.0.0.128
 10.0.6.0 0.0.0.255

ip access-list extended test
 permit udp object-group g2 any eq ntp

interface Serial1
 ip unnumbered Ethernet1
 ip access-group test in
END

$out = <<END;
object-group network g2-DRC-0
10.0.5.0 0.0.0.128
10.0.6.0 0.0.0.255
ip access-list resequence test-DRC-0 10000 10000
ip access-list extended test-DRC-0
1 permit udp object-group g2-DRC-0 any eq ntp
no 10000
ip access-list resequence test-DRC-0 10 10
no object-group network g1-DRC-0
END

eq_or_diff(approve('IOS', $device, $in), $out, $title);

############################################################
$title = "Unknown object-group";
############################################################
$device = <<END;
ip access-list extended test-DRC-0
 permit udp object-group g1-DRC-0 host 10.0.1.11 eq ntp
 deny ip any any

interface Serial1
 ip unnumbered Ethernet1
 ip access-group test-DRC-0 in
END

$out = <<'END';
ERROR>>> Can't find OBJECT_GROUP g1-DRC-0 referenced by test-DRC-0
END

eq_or_diff(approve_err('IOS', $device, $device), $out, $title);

############################################################
$title = "Nested object-group";
############################################################
$device = <<END;
object-group network g1
 10.0.5.0 0.0.0.128
object-group network g2
 10.0.1.0 0.0.0.255
 group-object g1
END

$out = <<'END';
ERROR>>> Nested object group not supported
ERROR>>>  at line 5, pos 0:
ERROR>>> >>group-object g1<<
END

eq_or_diff(approve_err('IOS', $device, $device), $out, $title);

############################################################
$title = "Compare unchanged ACL and non-existant outgoing ACL";
############################################################
$device = <<END;
ip access-list extended test-DRC-0
 deny ip any any

interface Serial1
 ip unnumbered Ethernet1
 ip access-group test-DRC-0 in
END

$in = <<END;
ip access-list extended test
 deny ip any any

interface Serial1
 ip unnumbered Ethernet1
 ip access-group test in
END

$out = <<END;
END

my $status = approve_status('IOS', $device, $in);
ok($status == 0, $title);

############################################################
$title = "Handle ACL line with remark";
############################################################
$device = <<'END';
ip access-list extended inside
 remark Test1
 permit ip host 1.1.1.1 any
 permit ip host 2.2.2.2 any
 remark Test2
 permit ip host 4.4.4.4 any
interface Ethernet0/0
 ip access-group inside in
END

$in = <<'END';
ip access-list extended inside
 permit ip host 1.1.1.1 any
 remark Test1
 permit ip host 4.4.4.4 any
 permit ip host 5.5.5.5 any
 remark Test3
interface Ethernet0/0
 ip access-group inside in
END

$out = <<'END';
ip access-list resequence inside 10000 10000
ip access-list extended inside
20001 remark Test1
50001 permit ip host 5.5.5.5 any
50002 remark Test3
no 40000
no 30000
no 10000
ip access-list resequence inside 10 10
END

eq_or_diff(approve('IOS', $device, $in), $out, $title);

############################################################
$title = "Add lines at end of ACL";
############################################################
$device = <<END;
ip access-list extended test
 permit ip any host 10.0.1.1

interface Ethernet1
 ip access-group test in
END

$in = <<END;
ip access-list extended test
 permit ip any host 10.0.1.1
 permit ip any host 10.0.1.2
 permit icmp any any 0
 permit ip any host 10.0.1.3

interface Ethernet1
 ip access-group test in
END

$out = <<END;
ip access-list resequence test 10000 10000
ip access-list extended test
10001 permit ip any host 10.0.1.2
10002 permit icmp any any 0
10003 permit ip any host 10.0.1.3
ip access-list resequence test 10 10
END

eq_or_diff(approve('IOS', $device, $in), $out, $title);

############################################################
$title = "Remove incoming, add outgoing ACL";
############################################################
$device = <<END;
ip access-list extended test
 permit ip any host 10.0.1.1
interface Ethernet1
 ip access-group test in
END

$in = <<END;
ip access-list extended test
 permit ip host 10.0.1.1 any
interface Ethernet1
 ip access-group test out
END

$out = <<END;
ip access-list extended test-DRC-0
permit ip host 10.0.1.1 any
interface Ethernet1
ip access-group test-DRC-0 out
interface Ethernet1
no ip access-group test in
no ip access-list extended test
END

eq_or_diff(approve('IOS', $device, $in), $out, $title);

############################################################
$title = "ACL with unknown keyword";
############################################################
$device = <<END;
ip access-list extended test
 permit ip any host 10.0.1.1 fragments

interface Ethernet1
 ip access-group test in
END

$in = <<END;
ip access-list extended test
 permit ip any host 10.0.1.1

interface Ethernet1
 ip access-group test in
END

$out = <<'END';
ERROR>>> Can't compare ACL with unknown attribute:
 permit ip any host 10.0.1.1 fragments
END

eq_or_diff(approve_err('IOS', $device, $in), $out, $title);

############################################################
$title = "Can't change ACL with more than 9999 lines";
############################################################
$device = <<END;
interface Ethernet1
 ip access-group test in

ip access-list extended test
END

for my $port (1 .. 10000) {
   $device .= " permit tcp any host 10.0.1.1 eq $port\n";
}

$in = $device . " permit tcp any host 10.0.1.1 eq 60000\n";

$out = <<END;
ERROR>>> Can\'t handle ACL test with 10000 or more entries
END

eq_or_diff(approve_err('IOS', $device, $in), $out, $title);

############################################################
$title = "Change ACL, prevent lockout";
#
# ACL lines must be deleted in reversed order,
# otherwise Netspoc server would be locked out.
############################################################
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

$in = <<END;
ip access-list extended test
 permit tcp host 10.2.3.4 host 10.3.4.5
! Network management to interface of device
 permit ip 10.0.11.0 0.0.0.255 host 10.9.9.1
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
$device = <<END;
ip access-list extended test
 permit udp host 10.2.3.4 host 10.3.4.5
 permit tcp host 10.2.3.4 host 10.3.4.5
 deny ip host 10.1.2.3 host 10.1.1.1
 permit ip any any

interface Ethernet1
 ip access-group test in
END

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

$out = <<END;
ip access-list resequence test 10000 10000
ip access-list extended test
no 30000\\N 1 deny ip host 10.1.2.3 host 10.1.1.1
10001 permit ip any host 10.1.1.1
ip access-list resequence test 10 10
END

eq_or_diff(approve('IOS', $device, $in), $out, $title);

############################################################
$title = "Move successive ACL entries downwards";
############################################################
$device = <<END;
ip access-list extended test
 permit ip any host 1.1.1.1
 permit ip any host 2.2.2.2
 permit ip any host 3.3.3.3
 permit ip any host 4.4.4.4
 permit ip any host 5.5.5.5
 permit ip any host 6.6.6.6

interface Ethernet1
 ip access-group test in
END

$in = <<END;
ip access-list extended test
 permit ip any host 3.3.3.3
 permit ip any host 4.4.4.4
 permit ip any host 5.5.5.5
 permit ip any host 1.1.1.1
 permit ip any host 2.2.2.2
 permit ip any host 7.7.7.7
 permit ip any host 6.6.6.6

interface Ethernet1
 ip access-group test in
END

$out = <<END;
ip access-list resequence test 10000 10000
ip access-list extended test
50003 permit ip any host 7.7.7.7
no 20000\\N 50002 permit ip any host 2.2.2.2
no 10000\\N 50001 permit ip any host 1.1.1.1
ip access-list resequence test 10 10
END

eq_or_diff(approve('IOS', $device, $in), $out, $title);

############################################################
$title = "Don't change ACL line which permit administrative access";
############################################################
# Device IP is 10.1.13.33

$device = <<END;
ip access-list extended test-DRC-0
 permit tcp any host 10.1.13.31
 permit tcp any host 10.1.13.32
 permit tcp any host 10.1.13.33
 deny ip any any

interface Ethernet1
 ip access-group test-DRC-0 in
END

$in = <<END;
ip access-list extended test
 permit tcp any host 10.1.13.33
 permit tcp any host 10.1.13.31
 permit tcp any host 10.1.13.32
 deny ip any any

interface Ethernet1
 ip access-group test in
END

$out = <<END;
ip access-list extended test-DRC-1
permit tcp any host 10.1.13.33
permit tcp any host 10.1.13.31
permit tcp any host 10.1.13.32
deny ip any any
interface Ethernet1
ip access-group test-DRC-1 in
no ip access-list extended test-DRC-0
END

eq_or_diff(approve('IOS', $device, $in), $out, $title);

############################################################
$title = "Don't change ACL where ESP/AH may permit administrative access";
############################################################
$device = <<END;
ip access-list extended test-DRC-0
 permit icmp any host 10.1.13.31
 permit icmp any host 10.1.13.32
 permit esp any host 10.1.13.31
 permit tcp any host 10.1.13.33
 deny ip any any

interface Ethernet1
 ip access-group test-DRC-0 in
END

$in = <<END;
ip access-list extended test
 permit esp any host 10.1.13.31
 permit icmp any host 10.1.13.31
 permit icmp any host 10.1.13.32
 permit tcp any host 10.1.13.33
 deny ip any any

interface Ethernet1
 ip access-group test in
END

$out = <<END;
ip access-list extended test-DRC-1
permit esp any host 10.1.13.31
permit icmp any host 10.1.13.31
permit icmp any host 10.1.13.32
permit tcp any host 10.1.13.33
deny ip any any
interface Ethernet1
ip access-group test-DRC-1 in
no ip access-list extended test-DRC-0
END

eq_or_diff(approve('IOS', $device, $in), $out, $title);

############################################################
$title = "Change incoming crypto filter ACL";
############################################################
$device = <<END;
ip access-list extended crypto-Ethernet1-1
 permit ip any 10.127.18.0 0.0.0.255
ip access-list extended crypto-filter-Ethernet1-1
 permit tcp host 10.127.18.1 host 10.1.11.40 eq 48
! permit tcp host 10.127.18.1 host 10.1.11.40 eq 49
 deny ip any any
crypto map VPN 1 ipsec-isakmp
 match address crypto-Ethernet1-1
 set ip access-group crypto-filter-Ethernet1-1 in
 set peer 10.156.4.206

interface Ethernet1
 crypto map VPN
END

$in = <<END;
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

interface Ethernet1
 crypto map crypto-Ethernet1
END

$out = <<END;
ip access-list resequence crypto-filter-Ethernet1-1 10000 10000
ip access-list extended crypto-filter-Ethernet1-1
1 permit tcp host 10.127.18.1 host 10.1.11.40 eq 49
no 10000
ip access-list resequence crypto-filter-Ethernet1-1 10 10
END

eq_or_diff(approve('IOS', $device, $in), $out, $title);

############################################################
$title = "Crypto maps differ in size";
############################################################
$device .= <<'END';
crypto map VPN 2 ipsec-isakmp
 set peer 10.156.4.2
END

$out = <<END;
ERROR>>> Crypto maps differ for interface Ethernet1
END

eq_or_diff(approve_err('IOS', $device, $in), $out, $title);

############################################################
$title = "Crypto map only from device";
############################################################
$device .= <<'END';
interface Ethernet2
 ip unnumbered x
END

$in = <<END;
interface Ethernet1
 ip unnumbered x
ip access-list extended crypto-filter-Ethernet2
 permit tcp host 10.127.18.1 host 10.1.11.40 eq 49
crypto map crypto-Ethernet2 1 ipsec-isakmp
 match address crypto-Ethernet1-1
 set ip access-group crypto-filter-Ethernet2 in
 set peer 10.156.4.206
interface Ethernet2
 crypto map crypto-Ethernet2
END

$out = <<END;
ERROR>>> Missing crypto map at interface Ethernet1 from Netspoc
ERROR>>> Missing crypto map at interface Ethernet2 from device
END

eq_or_diff(approve_err('IOS', $device, $in), $out, $title);

############################################################
$title = "Don't change crypto filter ACL which permit administrative access";
############################################################
# Device IP is 10.1.13.33

$device = <<END;
ip access-list extended crypto-Ethernet1-1-DRC-0
 permit ip any 10.127.18.0 0.0.0.255
ip access-list extended crypto-filter-Ethernet1-1-DRC-0
 permit tcp any host 10.1.13.31
 permit tcp any host 10.1.13.32
 permit tcp any host 10.1.13.33
 deny ip any any
crypto map crypto-Ethernet1 1 ipsec-isakmp
 match address crypto-Ethernet1-1-DRC-0
 set ip access-group crypto-filter-Ethernet1-1-DRC-0 in
 set peer 10.156.4.206

interface Ethernet1
 crypto map crypto-Ethernet1
END

$in = <<END;
ip access-list extended crypto-Ethernet1-1
 permit ip any 10.127.18.0 0.0.0.255
ip access-list extended crypto-filter-Ethernet1-1
 permit tcp any host 10.1.13.33
 permit tcp any host 10.1.13.31
 permit tcp any host 10.1.13.32
 deny ip any any
crypto map crypto-Ethernet1 1 ipsec-isakmp
 match address crypto-Ethernet1-1
 set ip access-group crypto-filter-Ethernet1-1 in
 set peer 10.156.4.206

interface Ethernet1
 crypto map crypto-Ethernet1
END

$out = <<END;
ip access-list extended crypto-filter-Ethernet1-1-DRC-1
permit tcp any host 10.1.13.33
permit tcp any host 10.1.13.31
permit tcp any host 10.1.13.32
deny ip any any
crypto map crypto-Ethernet1 1
set ip access-group crypto-filter-Ethernet1-1-DRC-1 in
no ip access-list extended crypto-filter-Ethernet1-1-DRC-0
END

eq_or_diff(approve('IOS', $device, $in), $out, $title);

############################################################
$title = "Change outgoing crypto filter ACL";
############################################################
$device = <<END;
ip access-list extended crypto-Ethernet1-1
 permit ip any 10.127.18.0 0.0.0.255
ip access-list extended crypto-filter-Ethernet1-1
 permit tcp host 10.127.18.1 host 10.1.11.40 eq 48
! permit tcp host 10.127.18.1 host 10.1.11.40 eq 49
 deny ip any any
crypto map crypto-Ethernet1 1 ipsec-isakmp
 match address crypto-Ethernet1-1
 set ip access-group crypto-filter-Ethernet1-1 out
 set peer 10.156.4.206

interface Ethernet1
 crypto map crypto-Ethernet1
END

$in = <<END;
ip access-list extended crypto-Ethernet1-1
 permit ip any 10.127.18.0 0.0.0.255
ip access-list extended crypto-filter-Ethernet1-1
! permit tcp host 10.127.18.1 host 10.1.11.40 eq 48
 permit tcp host 10.127.18.1 host 10.1.11.40 eq 49
 deny ip any any
crypto map crypto-Ethernet1 1 ipsec-isakmp
 match address crypto-Ethernet1-1
 set ip access-group crypto-filter-Ethernet1-1 out
 set peer 10.156.4.206

interface Ethernet1
 crypto map crypto-Ethernet1
END

$out = <<END;
ip access-list resequence crypto-filter-Ethernet1-1 10000 10000
ip access-list extended crypto-filter-Ethernet1-1
1 permit tcp host 10.127.18.1 host 10.1.11.40 eq 49
no 10000
ip access-list resequence crypto-filter-Ethernet1-1 10 10
END

eq_or_diff(approve('IOS', $device, $in), $out, $title);

############################################################
$title = "Move incoming to outgoing crypto filter ACL";
############################################################
$device = <<END;
ip access-list extended crypto-Ethernet1-1
 permit ip any 10.127.18.0 0.0.0.255
ip access-list extended crypto-filter-Ethernet1-1-DRC-0
 permit tcp host 10.127.18.1 host 10.1.11.40 eq 48
! permit tcp host 10.127.18.1 host 10.1.11.40 eq 49
 deny ip any any
crypto map crypto-Ethernet1 1 ipsec-isakmp
 match address crypto-Ethernet1-1
 set ip access-group crypto-filter-Ethernet1-1-DRC-0 in
 set peer 10.156.4.206

interface Ethernet1
 crypto map crypto-Ethernet1
END

$in = <<END;
ip access-list extended crypto-Ethernet1-1
 permit ip any 10.127.18.0 0.0.0.255
ip access-list extended crypto-filter-Ethernet1-1
 permit tcp host 10.127.18.1 host 10.1.11.40 eq 48
 permit tcp host 10.127.18.1 host 10.1.11.40 eq 49
 deny ip any any
crypto map crypto-Ethernet1 1 ipsec-isakmp
 match address crypto-Ethernet1-1
 set ip access-group crypto-filter-Ethernet1-1 out
 set peer 10.156.4.206

interface Ethernet1
 crypto map crypto-Ethernet1
END

$out = <<END;
ip access-list extended crypto-filter-Ethernet1-1-DRC-1
permit tcp host 10.127.18.1 host 10.1.11.40 eq 48
permit tcp host 10.127.18.1 host 10.1.11.40 eq 49
deny ip any any
crypto map crypto-Ethernet1 1
set ip access-group crypto-filter-Ethernet1-1-DRC-1 out
crypto map crypto-Ethernet1 1
no set ip access-group crypto-filter-Ethernet1-1-DRC-0 in
no ip access-list extended crypto-filter-Ethernet1-1-DRC-0
END

eq_or_diff(approve('IOS', $device, $in), $out, $title);

############################################################
$title = "Interface with dhcp address ";
############################################################
$device = <<END;
interface Ethernet1
 ip address dhcp
interface Ethernet2
 ip address 10.0.0.1 255.255.255.0
END

$in = <<END;
interface Ethernet1
 ip address negotiated
interface Ethernet2
 ip address 10.0.0.1 255.255.255.0
END

$out = <<END;
END

eq_or_diff(approve_err('IOS', $device, $in), $out, $title);

############################################################
$title = "Check Netspoc interfaces";
############################################################
$device = <<END;
interface Serial1
 ip address 10.1.1.1 255.255.255.0
interface Serial2
 ip address 10.1.2.1 255.255.255.0
END

$in = <<'END';
interface Serial1
 ip address 10.1.1.1 255.255.255.0
interface Serial3
 ip address 10.1.3.1 255.255.255.0
END

$out = <<'END';
ERROR>>> Interface 'Serial3' from Netspoc not known on device
END

eq_or_diff(approve_err('IOS', $device, $in), $out, $title);

############################################################
$title = "Check device interfaces";
############################################################
# Device interfaces are checked, if ACL or Crypto config is present.
# 'secondary' attribute is ignored when comparing IP addresses.

$device = <<END;
interface Serial1
 ip address 10.1.1.1 255.255.255.0
interface Serial2
 ip address 10.1.2.1 255.255.255.0
 ip address 10.1.2.250 255.255.255.0 secondary
 ip address 1.1.1.1 255.255.255.0 secondary
interface Serial3
 ip address 10.1.3.1 255.255.255.0
END

$in = <<'END';
ip access-list extended test1
 permit ip any 10.127.18.0 0.0.0.255
interface Serial1
 ip address 1.1.1.1 255.0.0.0
 ip address 10.1.2.1 255.255.255.0 secondary
 ip address 10.1.2.250 255.255.255.0 secondary
 ip access-group test1 in
ip access-list extended test2
 permit ip any 10.127.18.0 0.0.0.255
interface Serial2
 ip address 10.1.2.1 255.255.255.0 secondary
 ip address 10.1.2.250 255.255.255.0
 ip address 1.1.1.1 255.255.255.0 secondary
 ip access-group test2 in
ip access-list extended test
 deny ip any any log-input
END

$out = <<'END';
WARNING>>> Interface 'Serial3' on device is not known by Netspoc
WARNING>>> Different address defined for interface Serial1: Conf: 10.1.1.1 255.255.255.0, Netspoc: 1.1.1.1 255.0.0.0,10.1.2.1 255.255.255.0,10.1.2.250 255.255.255.0
END

eq_or_diff(approve_err('IOS', $device, $in), $out, $title);

############################################################
$title = "Check 'ip inspect'";
############################################################
# Device interfaces are checked, if ACL or Crypto config is present.

$device = <<END;
interface Serial1
 ip address 10.1.1.1 255.255.255.0
 ip inspect NAME in
interface Serial2
 ip address 10.1.2.1 255.255.255.0
END

$in = <<'END';
interface Serial1
 ip address 10.1.2.1 255.255.255.0
interface Serial2
 ip address 10.1.2.1 255.255.255.0
 ip inspect NAME in
 ip access-group test in
ip access-list extended test
 deny ip any any log-input
END

$out = <<'END';
ERROR>>> Different 'ip inspect' defined for interface Serial1: Conf: enabled, Netspoc: disabled
ERROR>>> Different 'ip inspect' defined for interface Serial2: Conf: disabled, Netspoc: enabled
END

eq_or_diff(approve_err('IOS', $device, $in), $out, $title);

############################################################
$title = "Only change VRFs mentioned in Netspoc";
############################################################
$device = <<END;
ip route 10.20.0.0 255.255.0.0 10.2.2.2
ip access-list extended acl2-DRC-0
 permit ip any host 10.0.1.1
interface Ethernet1
 ip address 10.0.0.1 255.255.255.0
 ip vrf forwarding 001
 ip access-group acl2-DRC-0 in
interface Ethernet2
 ip address 10.0.0.1 255.255.255.0
 ip vrf forwarding 002
END

$in = <<END;
ip route vrf 013 10.30.0.0 255.255.0.0 10.3.3.3
ip access-list extended acl2
 permit ip any host 10.0.1.1
interface Ethernet2
 ip address 10.0.0.1 255.255.255.0
 ip vrf forwarding 002
 ip access-group acl2 in
END

$out = <<END;
ip access-list extended acl2-DRC-1
permit ip any host 10.0.1.1
interface Ethernet2
ip access-group acl2-DRC-1 in
ip route vrf 013 10.30.0.0 255.255.0.0 10.3.3.3
END

eq_or_diff(approve('IOS', $device, $in), $out, $title);

############################################################
$title = "Check VRF of interfaces";
############################################################
$device = <<END;
interface Serial1
 ip address 10.1.1.1 255.255.255.0
interface Serial2
 ip address 10.1.2.1 255.255.255.0
 ip vrf forwarding 014
interface Serial3
 ip address 10.1.3.1 255.255.255.0
 ip vrf forwarding 013
END

$in = <<'END';
interface Serial1
 ip address 10.1.1.1 255.255.255.0
 ip vrf forwarding 013
interface Serial2
 ip address 10.1.2.1 255.255.255.0
 ip vrf forwarding 014
interface Serial3
 ip address 10.1.3.1 255.255.255.0
END

$out = <<'END';
ERROR>>> Different VRFs defined for interface Serial1: Conf: -, Netspoc: 013
ERROR>>> Different VRFs defined for interface Serial3: Conf: 013, Netspoc: -
END

eq_or_diff(approve_err('IOS', $device, $in), $out, $title);

############################################################
$title = "Unknown interface in VRF";
############################################################
$device = <<END;
ip route 10.20.0.0 255.255.0.0 10.1.2.3
ip access-list extended acl1
 permit ip any host 10.0.1.1
interface Ethernet1
 ip address 10.0.9.1 255.255.255.0
 ip access-group acl1 in
ip route vrf 013 10.30.0.0 255.255.0.0 10.1.2.3
ip access-list extended acl2
 permit ip any host 10.0.1.1
interface Ethernet2
 ip address 10.0.0.1 255.255.255.0
 ip vrf forwarding 013
 ip access-group acl2 in
END

$in = <<END;
ip route 10.20.0.0 255.255.0.0 10.1.2.3
ip route vrf 013 10.30.0.0 255.255.0.0 10.1.2.3
ip access-list extended acl2
 permit ip any host 10.0.1.1
interface Ethernet2
 ip address 10.0.0.1 255.255.255.0
 ip vrf forwarding 013
 ip access-group acl2 in
END

$out = <<END;
WARNING>>> Interface 'Ethernet1' on device is not known by Netspoc
END
eq_or_diff(approve_err('IOS', $device, $in), $out, $title);

############################################################
$title = "Managed and unmanaged VRF in one device";
############################################################

$in =~ s/ip route 10.20.0.0 255.255.0.0 10.1.2.3//msg;
$out = '';
eq_or_diff(approve('IOS', $device, $in), $out, $title);

############################################################
$title = "Crypto of unmanaged VRF is left unchanged";
############################################################
$device = <<'END';
ip access-list extended crypto-filter2
 permit tcp host 10.1.1.1 host 10.2.2.2 eq 80
ip access-list extended crypto-filter-Ethernet1-1-DRC-0
 permit tcp host 10.127.18.1 host 10.1.11.40 eq 48
 deny ip any any
crypto map crypto-Ethernet1 1 ipsec-isakmp
 set ip access-group crypto-filter-Ethernet1-1-DRC-0 in
 set peer 10.156.4.206
crypto map crypto-Ethernet2 1 ipsec-isakmp
 set ip access-group crypto-filter2 in
 set peer 10.156.1.2

interface Ethernet1
 crypto map crypto-Ethernet1
interface Ethernet2
 ip vrf forwarding 013
 crypto map crypto-Ethernet2
END

$in = <<'END';
ip access-list extended crypto-filter-Ethernet1-1-DRC-0
 permit tcp host 10.127.18.1 host 10.1.11.40 eq 49
 deny ip any any
crypto map crypto-Ethernet1 1 ipsec-isakmp
 set ip access-group crypto-filter-Ethernet1-1-DRC-0 in
 set peer 10.156.4.206

interface Ethernet1
 crypto map crypto-Ethernet1
END

$out = <<'END';
ip access-list resequence crypto-filter-Ethernet1-1-DRC-0 10000 10000
ip access-list extended crypto-filter-Ethernet1-1-DRC-0
1 permit tcp host 10.127.18.1 host 10.1.11.40 eq 49
no 10000
ip access-list resequence crypto-filter-Ethernet1-1-DRC-0 10 10
END
eq_or_diff(approve('IOS', $device, $in), $out, $title);

############################################################
done_testing;
