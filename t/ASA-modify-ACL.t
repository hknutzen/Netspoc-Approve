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
my $device_type = 'ASA';
my $title;

############################################################
$title = "Add ACL entries";
############################################################
$device = $minimal_device;
$device .= <<'END';
access-list inside extended permit ip host 1.1.1.1 any
access-list inside extended permit ip host 5.5.5.5 any
access-group inside in interface inside
END

$in = <<'END';
access-list inside extended permit ip host 2.2.2.2 any
access-list inside extended permit ip host 3.3.3.3 any
access-list inside extended permit ip host 1.1.1.1 any
access-list inside extended permit ip host 4.4.4.4 any
access-list inside extended permit ip host 5.5.5.5 any
access-list inside extended permit ip host 6.6.6.6 any
access-group inside in interface inside
END

$out = <<'END';
access-list inside line 1 extended permit ip host 2.2.2.2 any
access-list inside line 2 extended permit ip host 3.3.3.3 any
access-list inside line 4 extended permit ip host 4.4.4.4 any
access-list inside line 6 extended permit ip host 6.6.6.6 any
END
eq_or_diff(approve('ASA', $device, $in), $out, $title);

############################################################
$title = "Delete ACL entries";
############################################################
$device = $minimal_device;
$device .= <<'END';
access-list inside extended permit ip host 1.1.1.1 any
access-list inside extended permit ip host 2.2.2.2 any
access-list inside extended permit ip host 3.3.3.3 any
access-list inside extended permit ip host 4.4.4.4 any
access-list inside extended permit ip host 5.5.5.5 any
access-group inside in interface inside
END

$in = <<'END';
access-list inside extended permit ip host 2.2.2.2 any
access-list inside extended permit ip host 3.3.3.3 any
access-list inside extended permit ip host 5.5.5.5 any
access-group inside in interface inside
END

$out = <<'END';
no access-list inside line 4 extended permit ip host 4.4.4.4 any
no access-list inside line 1 extended permit ip host 1.1.1.1 any
END
eq_or_diff(approve('ASA', $device, $in), $out, $title);

############################################################
$title = "Move ACL entries upwards";
############################################################
$device = $minimal_device;
$device .= <<'END';
access-list inside extended permit ip host 1.1.1.1 any
access-list inside extended permit ip host 2.2.2.2 any
access-list inside extended permit ip host 3.3.3.3 any
access-list inside extended permit ip host 4.4.4.4 any
access-list inside extended permit ip host 5.5.5.5 any
access-list inside extended permit ip host 6.6.6.6 any
access-group inside in interface inside
END

$in = <<'END';
access-list inside extended permit ip host 1.1.1.1 any
access-list inside extended permit ip host 6.6.6.6 any
access-list inside extended permit ip host 4.4.4.4 any
access-list inside extended permit ip host 2.2.2.2 any
access-list inside extended permit ip host 3.3.3.3 any
access-list inside extended permit ip host 5.5.5.5 any
access-group inside in interface inside
END

$out = <<'END';
no access-list inside line 6 extended permit ip host 6.6.6.6 any\N access-list inside line 2 extended permit ip host 6.6.6.6 any
no access-list inside line 5 extended permit ip host 4.4.4.4 any\N access-list inside line 3 extended permit ip host 4.4.4.4 any
END
eq_or_diff(approve('ASA', $device, $in), $out, $title);

############################################################
$title = "Move ACL entries downwards";
############################################################
$device = $minimal_device;
$device .= <<'END';
access-list inside extended permit ip host 1.1.1.1 any
access-list inside extended permit ip host 2.2.2.2 any
access-list inside extended permit ip host 3.3.3.3 any
access-list inside extended permit ip host 4.4.4.4 any
access-list inside extended permit ip host 5.5.5.5 any
access-list inside extended permit ip host 6.6.6.6 any
access-group inside in interface inside
END

$in = <<'END';
access-list inside extended permit ip host 1.1.1.1 any
access-list inside extended permit ip host 4.4.4.4 any
access-list inside extended permit ip host 2.2.2.2 any
access-list inside extended permit ip host 5.5.5.5 any
access-list inside extended permit ip host 6.6.6.6 any
access-list inside extended permit ip host 3.3.3.3 any
access-group inside in interface inside
END

$out = <<'END';
no access-list inside line 3 extended permit ip host 3.3.3.3 any\N access-list inside line 6 extended permit ip host 3.3.3.3 any
no access-list inside line 2 extended permit ip host 2.2.2.2 any\N access-list inside line 3 extended permit ip host 2.2.2.2 any
END
eq_or_diff(approve('ASA', $device, $in), $out, $title);

############################################################
$title = "Move successive ACL entries downwards";
############################################################
$device = $minimal_device;
$device .= <<'END';
access-list inside extended permit ip host 1.1.1.1 any
access-list inside extended permit ip host 2.2.2.2 any
access-list inside extended permit ip host 3.3.3.3 any
access-list inside extended permit ip host 4.4.4.4 any
access-list inside extended permit ip host 5.5.5.5 any
access-list inside extended permit ip host 6.6.6.6 any
access-group inside in interface inside
END

$in = <<'END';
access-list inside extended permit ip host 3.3.3.3 any
access-list inside extended permit ip host 4.4.4.4 any
access-list inside extended permit ip host 5.5.5.5 any
access-list inside extended permit ip host 1.1.1.1 any
access-list inside extended permit ip host 2.2.2.2 any
access-list inside extended permit ip host 7.7.7.7 any
access-list inside extended permit ip host 6.6.6.6 any
access-group inside in interface inside
END

$out = <<'END';
access-list inside line 6 extended permit ip host 7.7.7.7 any
no access-list inside line 2 extended permit ip host 2.2.2.2 any\N access-list inside line 5 extended permit ip host 2.2.2.2 any
no access-list inside line 1 extended permit ip host 1.1.1.1 any\N access-list inside line 4 extended permit ip host 1.1.1.1 any
END
eq_or_diff(approve('ASA', $device, $in), $out, $title);

############################################################
$title = "Add object-group";
############################################################
$device = $minimal_device;
$device .= <<'END';
access-list inside extended permit ip host 1.1.1.1 any
access-group inside in interface inside
END

$in = <<'END';
object-group network g1
 network-object host 2.2.2.2
 network-object host 3.3.3.3
access-list inside extended permit ip object-group g1 any
access-list inside extended permit ip host 1.1.1.1 any
access-group inside in interface inside
END

$out = <<'END';
object-group network g1-DRC-0
network-object host 2.2.2.2
network-object host 3.3.3.3
access-list inside line 1 extended permit ip object-group g1-DRC-0 any
END
eq_or_diff(approve('ASA', $device, $in), $out, $title);

############################################################
$title = "Object group used in two ACLs; 1. occurence new, 2. unchanged";
############################################################
$device = $minimal_device2;
$device .= <<'END';
object-group network g1-0
 network-object host 2.2.2.2
access-list inside extended permit ip host 1.1.1.1 any
access-group inside in interface inside
access-list outside extended permit ip object-group g1-0 any
access-group outside in interface outside
END

$in = <<'END';
object-group network g1
 network-object host 2.2.2.2
access-list inside extended permit ip object-group g1 any
access-list inside extended permit ip host 1.1.1.1 any
access-group inside in interface inside
access-list outside extended permit ip object-group g1 any
access-group outside in interface outside
END

$out = <<'END';
access-list inside line 1 extended permit ip object-group g1-0 any
END
eq_or_diff(approve('ASA', $device, $in), $out, $title);

############################################################
$title = "Multiple ACL lines, nearly identical except for object groups";
############################################################
$device = $minimal_device2;
$device .= <<'END';
object-group network g1-0
 network-object host 2.2.2.2
access-list inside extended permit ip host 1.1.1.1 any
access-group inside in interface inside
access-list outside extended permit ip object-group g1-0 any
access-group outside in interface outside
END

$in = <<'END';
object-group network g1
 network-object host 2.2.2.2
access-list inside extended permit ip object-group g1 any
access-list inside extended permit ip host 1.1.1.1 any
access-group inside in interface inside
access-list outside extended permit ip object-group g1 any
access-group outside in interface outside
END

$out = <<'END';
access-list inside line 1 extended permit ip object-group g1-0 any
END
eq_or_diff(approve('ASA', $device, $in), $out, $title);

############################################################
$title = "Move ACL line with object-groups, name of group changes";
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
access-list outside extended permit ip object-group g1 any
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
access-list outside extended permit ip object-group g1 any
access-group outside in interface outside
END

$out = <<'END';
object-group network g1-DRC-0
network-object host 1.1.1.1
object-group network g4-DRC-0
network-object host 4.4.4.4
access-list inside line 1 extended permit tcp object-group g3 object-group g4-DRC-0
access-list inside line 4 extended permit tcp object-group g1-DRC-0 object-group g2
no access-list inside line 5 extended permit tcp object-group g3 object-group g4
no access-list inside line 2 extended permit tcp object-group g1 object-group g2
access-list outside line 1 extended permit ip object-group g1-DRC-0 any
no access-list outside line 2 extended permit ip object-group g1 any
no object-group network g1
no object-group network g4
END

eq_or_diff(approve('ASA', $device, $in), $out, $title);

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
eq_or_diff(approve('ASA', $device, $in), $out, $title);

############################################################
$title = "Move ACL entry with log";
############################################################
$device = $minimal_device;
$device .= <<'END';
access-list inside extended permit ip host 1.1.1.1 any log
access-list inside extended permit ip host 2.2.2.2 any
access-list inside extended deny ip any any log warnings
access-group inside in interface inside
END

$in = <<'END';
access-list inside extended permit ip host 2.2.2.2 any
access-list inside extended permit ip host 1.1.1.1 any 
access-list inside extended deny ip any any
access-group inside in interface inside
END

$out = <<'END';
no access-list inside line 3 extended deny ip any any log warnings\N access-list inside line 3 extended deny ip any any
no access-list inside line 1 extended permit ip host 1.1.1.1 any log\N access-list inside line 2 extended permit ip host 1.1.1.1 any
END
eq_or_diff(approve('ASA', $device, $in), $out, $title);

############################################################
$title = "Recognize named kerberos port";
############################################################
$device = $minimal_device;
$device .= <<'END';
access-list inside extended permit tcp host 2.2.2.2 any eq kerberos
access-list inside extended permit udp host 2.2.2.2 any eq kerberos
access-group inside in interface inside
END

$in = <<'END';
access-list inside extended permit udp host 2.2.2.2 any eq 750
access-list inside extended permit tcp host 2.2.2.2 any eq 750
access-group inside in interface inside
END

$out = <<'END';
no access-list inside line 1 extended permit tcp host 2.2.2.2 any eq kerberos\N access-list inside line 2 extended permit tcp host 2.2.2.2 any eq 750
END
eq_or_diff(approve('ASA', $device, $in), $out, $title);

############################################################
done_testing;
