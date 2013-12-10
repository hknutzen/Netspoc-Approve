#!/usr/bin/perl

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
$title = "Recognize named kerberos port";
############################################################

# ACE uses other number than ASA.

$device = <<'END';
access-list inside extended permit tcp host 2.2.2.2 any eq kerberos
access-list inside extended permit udp host 2.2.2.2 any eq kerberos
interface vlan 7
 ip address 10.1.1.1 255.255.255.240
 access-group input inside
END

$in = <<'END';
access-list side extended permit udp host 2.2.2.2 any eq 88
access-list side extended permit tcp host 2.2.2.2 any eq 88
interface vlan 7
 ip address 10.1.1.1 255.255.255.240
 access-group input side
END

$out = <<'END';
access-list inside resequence 10000 10000
no access-list inside line 10000 extended permit tcp host 2.2.2.2 any eq kerberos\N access-list inside line 20001 extended permit tcp host 2.2.2.2 any eq 88
access-list inside resequence 10 10
END
eq_or_diff(approve('ACE', $device, $in), $out, $title);

############################################################
done_testing;
