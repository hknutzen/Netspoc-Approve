#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Approve;

# Minimal configuration of device.
my $minimal_device = <<END;
interface Ethernet0/0
 nameif inside
END
my $minimal_device2 = <<END;
interface Ethernet0/0
 nameif inside
interface Ethernet0/1
 nameif outside
END

# Input from Netspoc.
# Input from device.
# Output from approve.
my($in, $device, $out);
my $title;

############################################################
$title = "Add ACL entries";
############################################################
$device = $minimal_device;
$device .= <<'END';
access-list inside extended permit ip host 1.1.1.1 any4
access-list inside extended permit ip host 5.5.5.5 any4
access-group inside in interface inside
END

$in = <<'END';
access-list inside extended permit ip host 2.2.2.2 any4
access-list inside extended permit ip host 3.3.3.3 any4
access-list inside extended permit ip host 1.1.1.1 any4
access-list inside extended permit ip host 4.4.4.4 any4
access-list inside extended permit ip host 5.5.5.5 any4
access-list inside extended permit ip host 6.6.6.6 any4
access-group inside in interface inside
END

$out = <<'END';
access-list inside line 1 extended permit ip host 2.2.2.2 any4
access-list inside line 2 extended permit ip host 3.3.3.3 any4
access-list inside line 4 extended permit ip host 4.4.4.4 any4
access-list inside line 6 extended permit ip host 6.6.6.6 any4
END
test_run($title, 'ASA', $device, $in, $out);

############################################################
$title = "Delete ACL entries";
############################################################
$device = $minimal_device;
$device .= <<'END';
access-list inside extended permit ip host 1.1.1.1 any4
access-list inside extended permit ip host 2.2.2.2 any4
access-list inside extended permit ip host 3.3.3.3 any4
access-list inside extended permit ip host 4.4.4.4 any4
access-list inside extended permit ip host 5.5.5.5 any4
access-group inside in interface inside
END

$in = <<'END';
access-list inside extended permit ip host 2.2.2.2 any4
access-list inside extended permit ip host 3.3.3.3 any4
access-list inside extended permit ip host 5.5.5.5 any4
access-group inside in interface inside
END

$out = <<'END';
no access-list inside line 4 extended permit ip host 4.4.4.4 any4
no access-list inside line 1 extended permit ip host 1.1.1.1 any4
END
test_run($title, 'ASA', $device, $in, $out);

############################################################
$title = "Move ACL entries upwards";
############################################################
$device = $minimal_device;
$device .= <<'END';
access-list inside extended permit ip host 1.1.1.1 any4
access-list inside extended permit ip host 2.2.2.2 any4
access-list inside extended permit ip host 3.3.3.3 any4
access-list inside extended permit ip host 4.4.4.4 any4
access-list inside extended permit ip host 5.5.5.5 any4
access-list inside extended permit ip host 6.6.6.6 any4
access-group inside in interface inside
END

$in = <<'END';
access-list inside extended permit ip host 1.1.1.1 any4
access-list inside extended permit ip host 6.6.6.6 any4
access-list inside extended permit ip host 4.4.4.4 any4
access-list inside extended permit ip host 2.2.2.2 any4
access-list inside extended permit ip host 3.3.3.3 any4
access-list inside extended permit ip host 5.5.5.5 any4
access-group inside in interface inside
END

$out = <<'END';
no access-list inside line 6 extended permit ip host 6.6.6.6 any4\N access-list inside line 2 extended permit ip host 6.6.6.6 any4
no access-list inside line 5 extended permit ip host 4.4.4.4 any4\N access-list inside line 3 extended permit ip host 4.4.4.4 any4
END
test_run($title, 'ASA', $device, $in, $out);

############################################################
$title = "Move ACL entries downwards";
############################################################
$device = $minimal_device;
$device .= <<'END';
access-list inside extended permit ip host 1.1.1.1 any4
access-list inside extended permit ip host 2.2.2.2 any4
access-list inside extended permit ip host 3.3.3.3 any4
access-list inside extended permit ip host 4.4.4.4 any4
access-list inside extended permit ip host 5.5.5.5 any4
access-list inside extended permit ip host 6.6.6.6 any4
access-group inside in interface inside
END

$in = <<'END';
access-list inside extended permit ip host 1.1.1.1 any4
access-list inside extended permit ip host 4.4.4.4 any4
access-list inside extended permit ip host 2.2.2.2 any4
access-list inside extended permit ip host 5.5.5.5 any4
access-list inside extended permit ip host 6.6.6.6 any4
access-list inside extended permit ip host 3.3.3.3 any4
access-group inside in interface inside
END

$out = <<'END';
no access-list inside line 2 extended permit ip host 2.2.2.2 any4\N access-list inside line 4 extended permit ip host 2.2.2.2 any4
no access-list inside line 2 extended permit ip host 3.3.3.3 any4\N access-list inside line 6 extended permit ip host 3.3.3.3 any4
END
test_run($title, 'ASA', $device, $in, $out);

############################################################
$title = "Move successive ACL entries downwards";
############################################################
$device = $minimal_device;
$device .= <<'END';
access-list inside extended permit ip host 1.1.1.1 any4
access-list inside extended permit ip host 2.2.2.2 any4
access-list inside extended permit ip host 3.3.3.3 any4
access-list inside extended permit ip host 4.4.4.4 any4
access-list inside extended permit ip host 5.5.5.5 any4
access-list inside extended permit ip host 6.6.6.6 any4
access-group inside in interface inside
END

$in = <<'END';
access-list inside extended permit ip host 3.3.3.3 any4
access-list inside extended permit ip host 4.4.4.4 any4
access-list inside extended permit ip host 5.5.5.5 any4
access-list inside extended permit ip host 1.1.1.1 any4
access-list inside extended permit ip host 2.2.2.2 any4
access-list inside extended permit ip host 7.7.7.7 any4
access-list inside extended permit ip host 6.6.6.6 any4
access-group inside in interface inside
END

$out = <<'END';
no access-list inside line 1 extended permit ip host 1.1.1.1 any4\N access-list inside line 5 extended permit ip host 1.1.1.1 any4
no access-list inside line 1 extended permit ip host 2.2.2.2 any4\N access-list inside line 5 extended permit ip host 2.2.2.2 any4
access-list inside line 6 extended permit ip host 7.7.7.7 any4
END
test_run($title, 'ASA', $device, $in, $out);

############################################################
$title = "Change standard ACL non incrementally";
############################################################
$device = $minimal_device;
$device .= <<'END';
access-list inside remark r1
access-list inside standard permit host 1.1.1.1
access-group inside in interface inside
END

$in = <<'END';
access-list inside remark r1
access-list inside standard permit host 1.1.1.1
access-list inside standard permit 2.2.2.2 255.255.255.254
access-group inside in interface inside
END

$out = <<'END';
access-list inside-DRC-0 remark r1
access-list inside-DRC-0 standard permit host 1.1.1.1
access-list inside-DRC-0 standard permit 2.2.2.2 255.255.255.254
access-group inside-DRC-0 in interface inside
clear configure access-list inside
END
test_run($title, 'ASA', $device, $in, $out);

############################################################
$title = "Add object-group";
############################################################
$device = $minimal_device . <<'END';
access-list inside extended permit ip host 1.1.1.1 any4
access-group inside in interface inside
END

$in = $minimal_device . <<'END';
object-group network g1
 network-object host 2.2.2.2
 network-object host 3.3.3.3
access-list inside extended permit ip object-group g1 any4
access-list inside extended permit ip host 1.1.1.1 any4
access-group inside in interface inside
END

$out = <<'END';
object-group network g1-DRC-0
network-object host 2.2.2.2
network-object host 3.3.3.3
access-list inside line 1 extended permit ip object-group g1-DRC-0 any4
END
test_run($title, 'ASA', $device, $in, $out);

############################################################
$title = "Remove object-group";
############################################################

$out = <<'END';
no access-list inside line 1 extended permit ip object-group g1 any4
no object-group network g1
END

test_run($title, 'ASA', $in, $device, $out);

############################################################
$title = "Modify type of object-group";
############################################################
$device = $minimal_device;
$device .= <<'END';
object-group service g1 tcp
 port-object range 135 139

access-list inside_in extended permit tcp any4 host 10.0.1.11 object-group g1
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
END

$in = <<'END';
object-group service g1 udp
 port-object range 135 139

access-list inside_in extended permit udp any4 host 10.0.1.11 object-group g1
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
END

$out = <<'END';
object-group service g1-DRC-0 udp
port-object range 135 139
access-list inside_in line 2 extended permit udp any4 host 10.0.1.11 object-group g1-DRC-0
no access-list inside_in line 1 extended permit tcp any4 host 10.0.1.11 object-group g1
no object-group service g1 tcp
END
test_run($title, 'ASA', $device, $in, $out);

############################################################
$title = "object-group with named port is not recognized as equal";
############################################################
$device = $minimal_device . <<'END';
object-group service g1-DRC-0 tcp
 port-object range 135 netbios-ssn

access-list inside_in-DRC-0 extended permit tcp any4 host 10.0.1.11 object-group g1-DRC-0
access-list inside_in-DRC-0 extended deny ip any4 any4
END

$in = <<'END';
object-group service g1 tcp
 port-object range 135 139

access-list inside_in extended permit tcp any4 host 10.0.1.11 object-group g1
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
END

$out = <<'END';
object-group service g1-DRC-1 tcp
port-object range 135 139
access-list inside_in-DRC-1 extended permit tcp any4 host 10.0.1.11 object-group g1-DRC-1
access-list inside_in-DRC-1 extended deny ip any4 any4
access-group inside_in-DRC-1 in interface inside
clear configure access-list inside_in-DRC-0
no object-group service g1-DRC-0 tcp
END

test_run($title, 'ASA', $device, $in, $out);

############################################################
$title = "Modify object-group; referenced multiple times";
############################################################
$device = $minimal_device . <<'END';
object-group network g1
 network-object host 1.1.1.1
!network-object host 2.2.2.2
 network-object host 3.3.3.3
 network-object host 4.4.4.4
 network-object host 5.5.5.5
 network-object host 6.6.6.6
 network-object host 7.7.7.7
access-list inside extended permit ip object-group g1 host 10.0.1.1
access-list inside extended permit ip object-group g1 host 10.0.1.2
access-group inside in interface inside
END

$in = <<'END';
object-group network g1
 network-object host 1.1.1.1
 network-object host 2.2.2.2
 network-object host 3.3.3.3
!network-object host 4.4.4.4
 network-object host 5.5.5.5
!! Order of lines doesn't matter
 network-object host 7.7.7.7
 network-object host 6.6.6.6
access-list inside extended permit ip object-group g1 host 10.0.1.1
access-list inside extended permit ip object-group g1 host 10.0.1.2
access-group inside in interface inside
END

$out = <<'END';
object-group network g1
network-object host 2.2.2.2
no network-object host 4.4.4.4
END
test_run($title, 'ASA', $device, $in, $out);

############################################################
$title = "Add object-group referenced twice in ACL";
############################################################
$device = $minimal_device;
$device .= <<'END';
access-list inside extended deny ip any4 any4
access-group inside in interface inside
END

$in = <<'END';
object-group network g1
 network-object host 1.1.1.1
access-list inside extended permit ip object-group g1 object-group g1
access-group inside in interface inside
END

$out = <<'END';
object-group network g1-DRC-0
network-object host 1.1.1.1
access-list inside-DRC-0 extended permit ip object-group g1-DRC-0 object-group g1-DRC-0
access-group inside-DRC-0 in interface inside
clear configure access-list inside
END

test_run($title, 'ASA', $device, $in, $out);

############################################################
$title = "Object group used in two ACLs; 1. occurrence new, 2. unchanged";
############################################################
$device = $minimal_device2;
$device .= <<'END';
object-group network g1-0
 network-object host 2.2.2.2
access-list inside extended permit ip host 1.1.1.1 any4
access-group inside in interface inside
access-list outside extended permit ip object-group g1-0 any4
access-group outside in interface outside
END

$in = <<'END';
object-group network g1
 network-object host 2.2.2.2
access-list inside extended permit ip object-group g1 any4
access-list inside extended permit ip host 1.1.1.1 any4
access-group inside in interface inside
access-list outside extended permit ip object-group g1 any4
access-group outside in interface outside
END

$out = <<'END';
access-list inside line 1 extended permit ip object-group g1-0 any4
END
test_run($title, 'ASA', $device, $in, $out);

############################################################
$title = "Similar object group is not transferred and not changed ";
############################################################
$device = $minimal_device2;
$device .= <<'END';
object-group network g1-0
 network-object host 2.2.2.2
 network-object host 3.3.3.3
access-list inside extended permit ip host 1.1.1.1 any4
access-group inside in interface inside
access-list outside extended permit ip object-group g1-0 any4
access-group outside in interface outside
END

$in = <<'END';
object-group network g1
 network-object host 2.2.2.2
 network-object host 3.3.3.3
 network-object host 4.4.4.4
access-list inside extended permit ip object-group g1 any4
access-list inside extended permit ip host 1.1.1.1 any4
access-group inside in interface inside
access-list outside extended permit ip object-group g1 any4
access-group outside in interface outside
END

$out = <<'END';
object-group network g1-DRC-0
network-object host 2.2.2.2
network-object host 3.3.3.3
network-object host 4.4.4.4
access-list inside line 1 extended permit ip object-group g1-DRC-0 any4
access-list outside line 1 extended permit ip object-group g1-DRC-0 any4
no access-list outside line 2 extended permit ip object-group g1-0 any4
no object-group network g1-0
END
test_run($title, 'ASA', $device, $in, $out);

############################################################
$title = "Move ACL line with object-groups";
############################################################
$device = $minimal_device2;
$device .= <<'END';
object-group network g1
 network-object host 1.1.1.1
object-group network g2
 network-object host 2.2.2.2
object-group network g3
 network-object host 3.3.3.3
object-group network g4
 network-object host 4.4.4.4
access-list inside extended permit tcp object-group g1 object-group g2
access-list inside extended permit tcp object-group g2 object-group g3
access-list inside extended permit tcp object-group g3 object-group g4
access-group inside in interface inside
access-list outside extended permit ip object-group g1 any4
access-group outside in interface outside
END

$in = <<'END';
object-group network g1
 network-object host 1.1.1.1
object-group network g2
 network-object host 2.2.2.2
object-group network g3
 network-object host 3.3.3.3
object-group network g4
 network-object host 4.4.4.4
access-list inside extended permit tcp object-group g3 object-group g4
access-list inside extended permit tcp object-group g2 object-group g3
access-list inside extended permit tcp object-group g1 object-group g2
access-group inside in interface inside
access-list outside extended permit ip object-group g1 any4
access-group outside in interface outside
END

$out = <<'END';
no access-list inside line 3 extended permit tcp object-group g3 object-group g4\N access-list inside line 1 extended permit tcp object-group g3 object-group g4
no access-list inside line 2 extended permit tcp object-group g1 object-group g2\N access-list inside line 3 extended permit tcp object-group g1 object-group g2
END

test_run($title, 'ASA', $device, $in, $out);

############################################################
$title = "Object-group with identical names from netspoc and from device";
############################################################

# Must not mix up name 'g26' from netspoc and from device.

$device = $minimal_device2;
$device .= <<'END';
object-group network g2
 network-object host 10.2.4.6
object-group network g26
 network-object host 10.3.3.3
access-list in extended permit tcp object-group g2 object-group g26
access-list out extended permit tcp object-group g2 object-group g26 eq 25
access-group in in interface inside
access-group out in interface outside
END

$in = <<'END';
object-group network g26
 network-object host 10.2.4.6
object-group network g1
 network-object host 10.3.3.3
access-list in extended permit tcp object-group g26 object-group g1
access-list out extended permit tcp object-group g1 object-group g26 eq 25
access-group in in interface inside
access-group out in interface outside
END

$out = <<'END';
access-list out line 1 extended permit tcp object-group g26 object-group g2 eq 25
no access-list out line 2 extended permit tcp object-group g2 object-group g26 eq 25
END
test_run($title, 'ASA', $device, $in, $out);

############################################################
$title = "Delete description in object-group";
############################################################
$device = $minimal_device . <<'END';
object-group network g0
 description test123 ###
 network-object 10.0.3.0 255.255.255.0
 network-object 10.0.4.0 255.255.255.0
 network-object 10.0.5.0 255.255.255.0
 network-object 10.0.6.0 255.255.255.0

access-list inside_in extended permit udp object-group g0 host 10.0.1.11 eq sip
access-group inside_in in interface inside
END

$in = $minimal_device . <<'END';
object-group network g0
 network-object 10.0.4.0 255.255.255.0
 network-object 10.0.5.0 255.255.255.0
 network-object 10.0.6.0 255.255.255.0
 network-object 10.0.7.0 255.255.255.0

access-list inside_in extended permit udp object-group g0 host 10.0.1.11 eq sip
access-group inside_in in interface inside
END

$out = <<'END';
object-group network g0
no description test123 ###
no network-object 10.0.3.0 255.255.255.0
network-object 10.0.7.0 255.255.255.0
END

test_run($title, 'ASA', $device, $in, $out);

############################################################
$title = "Move ACL entry with log";
############################################################
$device = $minimal_device;
$device .= <<'END';
access-list inside extended permit ip host 1.1.1.1 any4 log
access-list inside extended permit ip host 2.2.2.2 any4 log 5 interval 30
access-list inside extended permit ip host 3.3.3.3 any4
access-list inside extended permit ip host 4.4.4.4 any4
access-list inside extended permit ip host 5.5.5.5 any4 log disable
access-list inside extended permit ip host 6.6.6.6 any4
access-list inside extended deny ip any4 any4 log warnings
access-group inside in interface inside
END

$in = <<'END';
access-list inside extended permit ip host 2.2.2.2 any4 log interval 30
access-list inside extended permit ip host 1.1.1.1 any4 log errors
access-list inside extended permit ip host 3.3.3.3 any4
access-list inside extended permit ip host 4.4.4.4 any4 log default
access-list inside extended permit ip host 5.5.5.5 any4
access-list inside extended permit ip host 6.6.6.6 any4 time-range log
access-list inside extended deny ip any4 any4
access-group inside in interface inside
END

$out = <<'END';
no access-list inside line 2 extended permit ip host 2.2.2.2 any4 log 5 interval 30\N access-list inside line 2 extended permit ip host 2.2.2.2 any4 log interval 30
no access-list inside line 1 extended permit ip host 1.1.1.1 any4 log\N access-list inside line 2 extended permit ip host 1.1.1.1 any4 log 3
no access-list inside line 4 extended permit ip host 4.4.4.4 any4\N access-list inside line 7 extended permit ip host 4.4.4.4 any4 log default
no access-list inside line 4 extended permit ip host 5.5.5.5 any4 log disable\N access-list inside line 7 extended permit ip host 5.5.5.5 any4
access-list inside line 8 extended permit ip host 6.6.6.6 any4 time-range log
no access-list inside line 5 extended deny ip any4 any4 log warnings\N access-list inside line 8 extended deny ip any4 any4
no access-list inside line 4 extended permit ip host 6.6.6.6 any4
END
test_run($title, 'ASA', $device, $in, $out);

############################################################
$title = "log informational is default";
############################################################
$device = $minimal_device;
$device .= <<'END';
access-list inside extended permit ip host 1.1.1.1 any4 log
access-list inside extended permit ip host 2.2.2.2 any4 log
access-group inside in interface inside
END

$in = <<'END';
access-list inside extended permit ip host 1.1.1.1 any4 log 6
access-list inside extended permit ip host 2.2.2.2 any4 log informational
access-group inside in interface inside
END

$out = <<'END';
END
test_run($title, 'ASA', $device, $in, $out);

############################################################
$title = "Recognize named kerberos port";
############################################################
$device = $minimal_device;
$device .= <<'END';
access-list inside extended permit tcp host 2.2.2.2 any4 eq kerberos
access-list inside extended permit udp host 2.2.2.2 any4 eq kerberos
access-group inside in interface inside
END

$in = <<'END';
access-list inside extended permit udp host 2.2.2.2 any4 eq 750
access-list inside extended permit tcp host 2.2.2.2 any4 eq 750
access-group inside in interface inside
END

$out = <<'END';
no access-list inside line 1 extended permit tcp host 2.2.2.2 any4 eq kerberos\N access-list inside line 2 extended permit tcp host 2.2.2.2 any4 eq 750
END
test_run($title, 'ASA', $device, $in, $out);

############################################################
$title = "Ignore spare ACL";
############################################################
# ACL foo is silently ignored

$device = <<'END';
access-list foo extended permit tcp host 2.2.2.2 any4 eq 80
access-list foo-DRC-1 extended permit tcp host 2.2.2.2 any4 eq 80
END

$in = <<'END';
END

$out = <<'END';
END

test_err($title, 'ASA', $device, $in, $out);

############################################################
$title = "Handle ACL line with remark";
############################################################
$device = $minimal_device;
$device .= <<'END';
access-list inside remark Test1
access-list inside extended permit ip host 1.1.1.1 any4
access-list inside extended permit ip host 2.2.2.2 any4
access-list inside remark Test2
access-list inside extended permit ip host 4.4.4.4 any4
access-group inside in interface inside
END

$in = <<'END';
access-list inside extended permit ip host 1.1.1.1 any4
access-list inside remark Test1
access-list inside extended permit ip host 4.4.4.4 any4
access-list inside extended permit ip host 5.5.5.5 any4
access-list inside remark Test3
access-group inside in interface inside
END

$out = <<'END';
no access-list inside line 1 remark Test1\N access-list inside line 4 remark Test1
access-list inside line 6 extended permit ip host 5.5.5.5 any4
access-list inside line 7 remark Test3
no access-list inside line 3 remark Test2
no access-list inside line 2 extended permit ip host 2.2.2.2 any4
END

test_run($title, 'ASA', $device, $in, $out);

############################################################
$title = "Remove incoming, add outgoing ACL";
############################################################
$device = $minimal_device;
$device .= <<'END';
object-group network g0
 network-object host 1.1.1.1
access-list inside extended permit ip object-group g0 any4
access-group inside in interface inside
END

$in = <<'END';
access-list outside extended permit ip host 1.1.1.1 any4
access-group outside out interface inside
END

$out = <<'END';
access-list outside-DRC-0 extended permit ip host 1.1.1.1 any4
access-group outside-DRC-0 out interface inside
no access-group inside in interface inside
clear configure access-list inside
no object-group network g0
END

test_run($title, 'ASA', $device, $in, $out);

############################################################
$title = "Remove outgoing, add incoming ACL";
############################################################
$device = $minimal_device;
$device .= <<'END';
object-group network g0
 network-object host 1.1.1.1
access-list outside extended permit ip object-group g0 any4
access-group outside out interface inside
END

$in = <<'END';
access-list inside extended permit ip host 1.1.1.1 any4
access-group inside in interface inside
END

$out = <<'END';
access-list inside-DRC-0 extended permit ip host 1.1.1.1 any4
access-group inside-DRC-0 in interface inside
no access-group outside out interface inside
clear configure access-list outside
no object-group network g0
END

test_run($title, 'ASA', $device, $in, $out);

############################################################
done_testing;
