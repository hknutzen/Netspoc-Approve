#!/usr/bin/perl

use strict;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Approve;

# Minimal configuration of device.
my $minimal_ASA = <<END;
interface Ethernet0/0
 nameif inside
interface Ethernet0/1
 nameif outside
END

# Input from Netspoc IPv4 and IPv6, output from approve.
my($spoc4, $spoc6, $raw4, $raw6, $device, $out);
my $title;

############################################################
$title = "ASA - merge routing";
############################################################
$spoc4 = <<END;
route inside 10.20.0.0 255.255.255.0 10.1.2.3
route inside 10.22.0.0 255.255.0.0 10.1.2.4
END

$spoc6 = <<END;
ipv6 route inside 10::3:0/120 10::2:2
ipv6 route inside 10::2:0/1 10::2:5
END

$out = <<END;
ipv6 route inside 10::3:0/120 10::2:2
ipv6 route inside 10::2:0/1 10::2:5
route inside 10.20.0.0 255.255.255.0 10.1.2.3
route inside 10.22.0.0 255.255.0.0 10.1.2.4
END

eq_or_diff( approve('ASA', $minimal_ASA, $spoc4, $spoc6), $out, $title );

############################################################
$title = "ASA - ipv4 but no ipv6 config";
############################################################
$spoc4 = <<END;
route inside 10.20.0.0 255.255.255.0 10.1.2.3
route inside 10.22.0.0 255.255.0.0 10.1.2.4
END

$out = <<END;
route inside 10.20.0.0 255.255.255.0 10.1.2.3
route inside 10.22.0.0 255.255.0.0 10.1.2.4
END

eq_or_diff( approve('ASA', $minimal_ASA, $spoc4, undef), $out, $title );

############################################################
$title = "ASA - ipv6 but no ipv4 config";
############################################################
$spoc6 = <<END;
ipv6 route inside 10::3:0/120 10::2:2
ipv6 route inside 10::2:0/1 10::2:5
END

$out = <<END;
ipv6 route inside 10::3:0/120 10::2:2
ipv6 route inside 10::2:0/1 10::2:5
END

eq_or_diff( approve('ASA', $minimal_ASA, undef, $spoc6), $out, $title );

############################################################
$title = "ASA - ipv4 and ipv6 configs and raws";
############################################################
$spoc4 = <<END;
route inside 10.20.0.0 255.255.255.0 10.1.2.3
access-list inside_in extended permit tcp 10.1.1.0 255.255.255.252 10.9.9.0 255.255.255.0 range 80 90
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
END

$raw4 = <<END;
route inside 10.22.0.0 255.255.0.0 10.1.2.4
access-list inside_in extended permit tcp 10.2.2.0 255.255.255.252 10.9.9.0 255.255.255.0 range 80 90
access-group inside_in in interface inside
END

$spoc6 = <<END;
ipv6 route inside 10::3:0/120 10::2:2
access-list inside_in extended permit tcp 1000::abcd:1:0/112 1000::abcd:9:0/112 range 80 90
access-list inside_in extended deny ip any6 any6
access-group inside_in in interface inside
END

$raw6 = <<END;
ipv6 route inside 10::4:0/120 10::2:2
access-list inside_in extended permit tcp 1000::abcd:2:0/112 1000::abcd:9:0/112 range 80 90
access-group inside_in in interface inside
END

$out = <<END;
ipv6 route inside 10::4:0/120 10::2:2
ipv6 route inside 10::3:0/120 10::2:2
route inside 10.20.0.0 255.255.255.0 10.1.2.3
route inside 10.22.0.0 255.255.0.0 10.1.2.4
access-list inside_in-DRC-0 extended permit tcp 1000::abcd:2:0/112 1000::abcd:9:0/112 range 80 90
access-list inside_in-DRC-0 extended permit tcp 1000::abcd:1:0/112 1000::abcd:9:0/112 range 80 90
access-list inside_in-DRC-0 extended deny ip any6 any6
access-list inside_in-DRC-0 extended permit tcp 10.2.2.0 255.255.255.252 10.9.9.0 255.255.255.0 range 80 90
access-list inside_in-DRC-0 extended permit tcp 10.1.1.0 255.255.255.252 10.9.9.0 255.255.255.0 range 80 90
access-list inside_in-DRC-0 extended deny ip any4 any4
access-group inside_in-DRC-0 in interface inside
END

eq_or_diff( approve('ASA', $minimal_ASA, $spoc4, $spoc6, $raw4, $raw6), $out, $title );

############################################################
$title = "ASA - ipv4 config and ipv6 raw only";
############################################################
$spoc4 = <<END;
route inside 10.20.0.0 255.255.255.0 10.1.2.3
access-list inside_in extended permit tcp 10.1.1.0 255.255.255.252 10.9.9.0 255.255.255.0 range 80 90
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
END

$raw6 = <<END;
ipv6 route inside 10::4:0/120 10::2:2
access-list inside_in extended permit tcp 1000::abcd:2:0/112 1000::abcd:9:0/112 range 80 90
access-group inside_in in interface inside
END

$out = <<END;
ipv6 route inside 10::4:0/120 10::2:2
route inside 10.20.0.0 255.255.255.0 10.1.2.3
access-list inside_in-DRC-0 extended permit tcp 1000::abcd:2:0/112 1000::abcd:9:0/112 range 80 90
access-list inside_in-DRC-0 extended permit tcp 10.1.1.0 255.255.255.252 10.9.9.0 255.255.255.0 range 80 90
access-list inside_in-DRC-0 extended deny ip any4 any4
access-group inside_in-DRC-0 in interface inside
END

eq_or_diff( approve('ASA', $minimal_ASA, $spoc4, undef, undef, $raw6), $out, $title );

############################################################
$title = "ASA - ipv6 config and ipv4 raw only";
############################################################
$raw4 = <<END;
route inside 10.22.0.0 255.255.0.0 10.1.2.4
access-list inside_in extended permit tcp 10.2.2.0 255.255.255.252 10.9.9.0 255.255.255.0 range 80 90
access-group inside_in in interface inside
END

$spoc6 = <<END;
ipv6 route inside 10::3:0/120 10::2:2
access-list inside_in extended permit tcp 1000::abcd:1:0/112 1000::abcd:9:0/112 range 80 90
access-list inside_in extended deny ip any6 any6
access-group inside_in in interface inside
END

$out = <<END;
ipv6 route inside 10::3:0/120 10::2:2
route inside 10.22.0.0 255.255.0.0 10.1.2.4
access-list inside_in-DRC-0 extended permit tcp 1000::abcd:1:0/112 1000::abcd:9:0/112 range 80 90
access-list inside_in-DRC-0 extended deny ip any6 any6
access-list inside_in-DRC-0 extended permit tcp 10.2.2.0 255.255.255.252 10.9.9.0 255.255.255.0 range 80 90
access-group inside_in-DRC-0 in interface inside
END

eq_or_diff( approve('ASA', $minimal_ASA, undef, $spoc6, $raw4), $out, $title );

############################################################
$title = "ASA - any allowed in ipv4 raw with ipv4 config";
############################################################
# Any will never be generated by Netspoc compiler.
# It can only appear within a raw file.

$spoc4 = <<END;
route inside 10.20.0.0 255.255.255.0 10.1.2.3
access-list inside_in extended permit tcp 10.1.1.0 255.255.255.252 10.9.9.0 255.255.255.0 range 80 90
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
END


$raw4 = <<END;
access-list inside_in extended permit ip any any
access-group inside_in in interface inside
END

$out = <<END;
route inside 10.20.0.0 255.255.255.0 10.1.2.3
access-list inside_in-DRC-0 extended permit ip any any
access-list inside_in-DRC-0 extended permit tcp 10.1.1.0 255.255.255.252 10.9.9.0 255.255.255.0 range 80 90
access-list inside_in-DRC-0 extended deny ip any4 any4
access-group inside_in-DRC-0 in interface inside
END

eq_or_diff( approve('ASA', $minimal_ASA, $spoc4, undef, $raw4), $out, $title );

############################################################
$title = "ASA - any allowed in ipv6 raw with ipv6 config";
############################################################
$spoc6 = <<END;
access-list inside_in extended permit tcp 1000::abcd:2:0/112 1000::abcd:9:0/112 range 80 90
access-list inside_in extended deny ip any6 any6
access-group inside_in in interface inside
END

$raw6 = <<END;
access-list inside_in extended permit ip any any
access-group inside_in in interface inside
END

$out = <<END;
access-list inside_in-DRC-0 extended permit ip any any
access-list inside_in-DRC-0 extended permit tcp 1000::abcd:2:0/112 1000::abcd:9:0/112 range 80 90
access-list inside_in-DRC-0 extended deny ip any6 any6
access-group inside_in-DRC-0 in interface inside
END

eq_or_diff( approve('ASA', $minimal_ASA, undef, $spoc6, undef, $raw6), $out, $title );

############################################################
$title = "ASA - any not allowed in ipv4 raw with ipv6 config";
############################################################
$spoc6 = <<END;
access-list inside_in extended permit tcp 1000::abcd:2:0/112 1000::abcd:9:0/112 range 80 90
access-list inside_in extended deny ip any6 any6
access-group inside_in in interface inside
END

$raw4 = <<END;
access-list inside_in extended permit ip any any
access-group inside_in in interface inside
END

$out = <<END;
ERROR>>> Usage of bare any in test.raw line 1 is not allowed for dual stack device.
END

eq_or_diff( approve_err('ASA', $minimal_ASA, undef, $spoc6, $raw4, undef), $out, $title );

############################################################
$title = "ASA - any not allowed in ipv6 raw with ipv4 config";
############################################################
$spoc4 = <<END;
route inside 10.20.0.0 255.255.255.0 10.1.2.3
access-list inside_in extended permit tcp 10.1.1.0 255.255.255.252 10.9.9.0 255.255.255.0 range 80 90
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
END

$raw6 = <<END;
access-list inside_in extended permit ip any any
access-group inside_in in interface inside
END

$out = <<END;
ERROR>>> Usage of bare any in ipv6/test.raw line 1 is not allowed for dual stack device.
END

eq_or_diff( approve_err('ASA', $minimal_ASA, $spoc4, undef, undef, $raw6), $out, $title );

############################################################
$title = "ASA - any not allowed in ipv6 raw with ipv4 and ipv6 config";
############################################################
$spoc4 = <<END;
route inside 10.20.0.0 255.255.255.0 10.1.2.3
END

$spoc6 = <<END;
access-list inside_in extended permit tcp 1000::abcd:2:0/112 1000::abcd:9:0/112 range 80 90
access-list inside_in extended deny ip any6 any6
access-group inside_in in interface inside
END

$raw6 = <<END;
access-list inside_in extended permit ip any any
access-group inside_in in interface inside
END

$out = <<END;
ERROR>>> Usage of bare any in ipv6/test.raw line 1 is not allowed for dual stack device.
END

eq_or_diff( approve_err('ASA', $minimal_ASA, $spoc4, undef, undef, $raw6), $out, $title );

############################################################
$title = "ASA - any not allowed in ipv4 raw with ipv4 and ipv6 config";
############################################################
$spoc4 = <<END;
route inside 10.20.0.0 255.255.255.0 10.1.2.3
END

$spoc6 = <<END;
access-list inside_in extended permit tcp 1000::abcd:2:0/112 1000::abcd:9:0/112 range 80 90
access-list inside_in extended deny ip any6 any6
access-group inside_in in interface inside
END

$raw4 = <<END;
access-list inside_in extended permit ip any any
access-group inside_in in interface inside
END

$out = <<END;
ERROR>>> Usage of bare any in test.raw line 1 is not allowed for dual stack device.
END

eq_or_diff( approve_err('ASA', $minimal_ASA, undef, $spoc6, $raw4, undef), $out, $title );

############################################################
$title = "ASA - any within comments in ipv6 raw with ipv4 config";
############################################################
$spoc4 = <<END;
route inside 10.20.0.0 255.255.255.0 10.1.2.3
END

$raw6 = <<END;
! no any allowed here, use any6 instead
access-list inside_in extended permit ip any6 any6
access-group inside_in in interface inside
END

$out = <<END;
route inside 10.20.0.0 255.255.255.0 10.1.2.3
access-list inside_in-DRC-0 extended permit ip any6 any6
access-group inside_in-DRC-0 in interface inside
END

eq_or_diff( approve('ASA', $minimal_ASA, $spoc4, undef, undef, $raw6), $out, $title );

############################################################
$title = "ASA - any allowed on device";
############################################################
$device = $minimal_ASA;
$device .= <<END;
access-list inside_in extended permit ip any any
access-group inside_in in interface inside
END

$spoc4 = <<END;
access-list inside_in extended permit ip any4 any4
access-group inside_in in interface inside
END

$spoc6 = <<END;
access-list inside_in extended permit ip any6 any6
access-group inside_in in interface inside
END

$out = <<END;
access-list inside_in line 1 extended permit ip any6 any6
access-list inside_in line 2 extended permit ip any4 any4
no access-list inside_in line 3 extended permit ip any any
END

eq_or_diff( approve('ASA', $device, $spoc4, $spoc6), $out, $title );

############################################################
$title = "ASA - merge ACL";
############################################################

$spoc4 = <<END;
access-list inside_in extended permit tcp 10.1.1.0 255.255.255.252 10.2.2.0 255.255.255.0 range 80 90
access-list inside_in extended deny ip any any
access-group inside_in in interface inside

access-list outside_in extended deny ip any any
access-group outside_in in interface outside
END

$spoc6 = <<END;
access-list inside_in extended permit tcp 1000::abcd:1:0/96 1000::abcd:2:0/96 range 80 90
access-list inside_in extended deny ip any6 any6
access-group inside_in in interface inside

access-list outside_in extended deny ip any6 any6
access-group outside_in in interface outside
END

$out = <<END;
access-list inside_in-DRC-0 extended permit tcp 1000::abcd:1:0/96 1000::abcd:2:0/96 range 80 90
access-list inside_in-DRC-0 extended deny ip any6 any6
access-list inside_in-DRC-0 extended permit tcp 10.1.1.0 255.255.255.252 10.2.2.0 255.255.255.0 range 80 90
access-list inside_in-DRC-0 extended deny ip any any
access-group inside_in-DRC-0 in interface inside
access-list outside_in-DRC-0 extended deny ip any6 any6
access-list outside_in-DRC-0 extended deny ip any any
access-group outside_in-DRC-0 in interface outside
END

eq_or_diff( approve('ASA', $minimal_ASA, $spoc4, $spoc6), $out, $title );

############################################################
$title = "ASA - ipv6 interface unknown in ipv4";
############################################################
$spoc4 = <<END;
access-list outside_in extended deny ip any any
access-group outside_in in interface outside
END

$spoc6 = <<END;
access-list inside_in extended deny ip any6 any6
access-group inside_in in interface inside
END

$out = <<END;
access-list inside_in-DRC-0 extended deny ip any6 any6
access-group inside_in-DRC-0 in interface inside
access-list outside_in-DRC-0 extended deny ip any any
access-group outside_in-DRC-0 in interface outside
END

eq_or_diff( approve('ASA', $minimal_ASA, $spoc4, $spoc6), $out, $title );

############################################################
$title = "Unknown IP address for device";
############################################################

$spoc4 = <<END;
route inside 10.20.0.0 255.255.255.0 10.1.2.3
route inside 10.22.0.0 255.255.0.0 10.1.2.4
END

$spoc6 = <<END;
ipv6 route inside 10::3:0/120 10::2:2
ipv6 route inside 10::2:0/1 10::2:5
END

my $header4 = <<END;
! [ BEGIN router:r1 ]
! [ Model = ASA ]

END

my $header6 = <<END;
! [ BEGIN router:r1 ]
! [ Model = ASA ]

END

$out = <<END;
ERROR>>> Can not get IP from test or ipv6/test.
END

eq_or_diff( approve_err('ASA', $minimal_ASA, $spoc4, $spoc6, undef, undef, $header4, $header6), $out, $title);

############################################################
$title = "Only IPv6 address known for device";
############################################################

$spoc4 = <<END;
route inside 10.20.0.0 255.255.255.0 10.1.2.3
route inside 10.22.0.0 255.255.0.0 10.1.2.4
END

$spoc6 = <<END;
ipv6 route inside 10::3:0/120 10::2:2
ipv6 route inside 10::2:0/1 10::2:5
END

my $header4 = <<END;
! [ BEGIN router:r1 ]
! [ Model = ASA ]

END

my $header6 = <<END;
! [ BEGIN router:r1 ]
! [ Model = ASA ]
! [ IP = 10::33 ]

END

$out = <<END;
ipv6 route inside 10::3:0/120 10::2:2
ipv6 route inside 10::2:0/1 10::2:5
route inside 10.20.0.0 255.255.255.0 10.1.2.3
route inside 10.22.0.0 255.255.0.0 10.1.2.4
END

eq_or_diff( approve('ASA', $minimal_ASA, $spoc4, $spoc6, undef, undef, $header4, $header6), $out, $title);

############################################################
$title = "Different device types for same device";
############################################################

$spoc4 = <<END;
route inside 10.20.0.0 255.255.255.0 10.1.2.3
route inside 10.22.0.0 255.255.0.0 10.1.2.4
END

$spoc6 = <<END;
ipv6 route inside 10::3:0/120 10::2:2
ipv6 route inside 10::2:0/1 10::2:5
END

my $header4 = <<END;
! [ BEGIN router:r1 ]
! [ Model = ASA ]
! [ IP = 10.12.13.14 ]

END

my $header6 = <<END;
! [ BEGIN router:r1 ]
! [ Model = IOS ]
! [ IP = 10::13 ]

END

$out = <<END;
ERROR>>> Ambiguous model specification for device test: ASA, IOS.
END

eq_or_diff( approve_err('ASA', $minimal_ASA, $spoc4, $spoc6, undef, undef, $header4, $header6), $out, $title);

############################################################
done_testing;
