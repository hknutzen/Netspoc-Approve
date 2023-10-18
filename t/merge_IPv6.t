#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Approve;

# Minimal configuration of device.
my $minimal_ASA = <<END;
interface Ethernet0/0
 nameif inside
END
my $minimal_ASA2 = <<END;
interface Ethernet0/0
 nameif inside
interface Ethernet0/1
 nameif outside
END

# Input from Netspoc IPv4 and IPv6, output from approve.
my ($spoc, $device, $out);
my $title;

############################################################
$title = "ASA - merge routing";
############################################################
$spoc = {

spoc4 => <<END
route inside 10.20.0.0 255.255.255.0 10.1.2.3
route inside 10.22.0.0 255.255.0.0 10.1.2.4
END
,
spoc6 => <<END
ipv6 route inside 10::3:0/120 10::2:2
ipv6 route inside 10::2:0/1 10::2:5
END
};

$out = <<END;
route inside 10.20.0.0 255.255.255.0 10.1.2.3
route inside 10.22.0.0 255.255.0.0 10.1.2.4
ipv6 route inside 10::3:0/120 10::2:2
ipv6 route inside 10::2:0/1 10::2:5
END

test_run($title, 'ASA', '', $spoc, $out);

############################################################
$title = "ASA - alter IPv6 routing, leaving IPv4 routing untouched";
############################################################
$device = $minimal_ASA;
$device .= <<END;
ipv6 route outside 10::3:0/112 10::2:2
route inside 10.20.0.0 255.255.255.0 10.1.2.3
route inside 10.22.0.0 255.255.0.0 10.1.2.4
END

$spoc = {

spoc4 => <<END
access-list inside_in extended permit tcp 10.1.1.0 255.255.255.252 10.9.9.0 255.255.255.0 range 80 90
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
END
,
spoc6 => <<END
ipv6 route E2 1000::abcd:3:0/120 1000::abcd:2:2
END
};

$out = <<END;
ipv6 route E2 1000::abcd:3:0/120 1000::abcd:2:2
no ipv6 route outside 10::3:0/112 10::2:2
access-list inside_in-DRC-0 extended permit tcp 10.1.1.0 255.255.255.252 10.9.9.0 255.255.255.0 range 80 90
access-list inside_in-DRC-0 extended deny ip any4 any4
access-group inside_in-DRC-0 in interface inside
END

test_run($title, 'ASA', $device, $spoc, $out);

############################################################
$title = "ASA - ipv4 but no ipv6 config";
############################################################
$spoc = {

spoc4 => <<END
route inside 10.20.0.0 255.255.255.0 10.1.2.3
route inside 10.22.0.0 255.255.0.0 10.1.2.4
END
};

$out = <<END;
route inside 10.20.0.0 255.255.255.0 10.1.2.3
route inside 10.22.0.0 255.255.0.0 10.1.2.4
END

test_run($title, 'ASA', '', $spoc, $out);

############################################################
$title = "ASA - ipv6 but no ipv4 config";
############################################################
$spoc = {

spoc6 => <<END
ipv6 route inside 10::3:0/120 10::2:2
ipv6 route inside 10::2:0/1 10::2:5
END
};

$out = <<END;
ipv6 route inside 10::3:0/120 10::2:2
ipv6 route inside 10::2:0/1 10::2:5
END

test_run($title, 'ASA', '', $spoc, $out);

############################################################
$title = "ASA - ipv4 and ipv6 configs and raw with ipv4 and ipv6";
############################################################
$spoc = {

spoc4 => <<END
route inside 10.20.0.0 255.255.255.0 10.1.2.3
access-list inside_in extended permit tcp 10.1.1.0 255.255.255.252 10.9.9.0 255.255.255.0 range 80 90
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
END
,
spoc6 => <<END
ipv6 route inside 10::3:0/120 10::2:2
access-list inside_in extended permit tcp host 1000::abcd:1:12 1000::abcd:9:0/112 range 80 90
access-list inside_in extended deny ip any6 any6
access-group inside_in in interface inside
END
,
raw => <<END
route inside 10.22.0.0 255.255.0.0 10.1.2.4
ipv6 route inside 10::4:0/120 10::2:2
access-list inside_in extended permit tcp 10.2.2.0 255.255.255.252 10.9.9.0 255.255.255.0 range 80 90
access-list inside_in extended permit tcp 1000::abcd:2:0/112 1000::abcd:9:0/112 range 80 90
access-group inside_in in interface inside
END
};

$out = <<END;
route inside 10.20.0.0 255.255.255.0 10.1.2.3
route inside 10.22.0.0 255.255.0.0 10.1.2.4
ipv6 route inside 10::3:0/120 10::2:2
ipv6 route inside 10::4:0/120 10::2:2
access-list inside_in-DRC-0 extended permit tcp 10.2.2.0 255.255.255.252 10.9.9.0 255.255.255.0 range 80 90
access-list inside_in-DRC-0 extended permit tcp 1000::abcd:2:0/112 1000::abcd:9:0/112 range 80 90
access-list inside_in-DRC-0 extended permit tcp host 1000::abcd:1:12 1000::abcd:9:0/112 range 80 90
access-list inside_in-DRC-0 extended permit tcp 10.1.1.0 255.255.255.252 10.9.9.0 255.255.255.0 range 80 90
access-list inside_in-DRC-0 extended deny ip any4 any4
access-list inside_in-DRC-0 extended deny ip any6 any6
access-group inside_in-DRC-0 in interface inside
END

test_run($title, 'ASA', $minimal_ASA, $spoc, $out);

############################################################
$title = "ASA - ipv4 config and raw with ipv6 ";
############################################################
$spoc = {
spoc4 => <<END
route inside 10.20.0.0 255.255.255.0 10.1.2.3
access-list inside_in extended permit tcp 10.1.1.0 255.255.255.252 10.9.9.0 255.255.255.0 range 80 90
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
END
,
raw => <<END
ipv6 route inside 10::4:0/120 10::2:2
access-list inside_in extended permit tcp 1000::abcd:2:0/112 1000::abcd:9:0/112 range 80 90
access-group inside_in in interface inside
END
};

$out = <<END;
route inside 10.20.0.0 255.255.255.0 10.1.2.3
ipv6 route inside 10::4:0/120 10::2:2
access-list inside_in-DRC-0 extended permit tcp 1000::abcd:2:0/112 1000::abcd:9:0/112 range 80 90
access-list inside_in-DRC-0 extended permit tcp 10.1.1.0 255.255.255.252 10.9.9.0 255.255.255.0 range 80 90
access-list inside_in-DRC-0 extended deny ip any4 any4
access-group inside_in-DRC-0 in interface inside
END

test_run($title, 'ASA', $minimal_ASA, $spoc, $out);

############################################################
$title = "ASA - ipv6 config and raw with ipv4";
############################################################
$spoc = {
raw => <<END
route inside 10.22.0.0 255.255.0.0 10.1.2.4
access-list inside_in extended permit tcp 10.2.2.0 255.255.255.252 10.9.9.0 255.255.255.0 range 80 90
access-group inside_in in interface inside
END
,
spoc6 => <<END
ipv6 route inside 10::3:0/120 10::2:2
access-list inside_in extended permit tcp 1000::abcd:1:0/112 1000::abcd:9:0/112 range 80 90
access-list inside_in extended deny ip any6 any6
access-group inside_in in interface inside
END
};

$out = <<END;
route inside 10.22.0.0 255.255.0.0 10.1.2.4
ipv6 route inside 10::3:0/120 10::2:2
access-list inside_in-DRC-0 extended permit tcp 10.2.2.0 255.255.255.252 10.9.9.0 255.255.255.0 range 80 90
access-list inside_in-DRC-0 extended permit tcp 1000::abcd:1:0/112 1000::abcd:9:0/112 range 80 90
access-list inside_in-DRC-0 extended deny ip any6 any6
access-group inside_in-DRC-0 in interface inside
END

test_run($title, 'ASA', $minimal_ASA, $spoc, $out);

############################################################
$title = "ASA - any allowed in raw with ipv4 config";
############################################################

$spoc = {
spoc4 => <<END
route inside 10.20.0.0 255.255.255.0 10.1.2.3
access-list inside_in extended permit tcp 10.1.1.0 255.255.255.252 10.9.9.0 255.255.255.0 range 80 90
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
END
,
raw => <<END
access-list inside_in extended permit ip any any
access-group inside_in in interface inside
END
};

$out = <<END;
route inside 10.20.0.0 255.255.255.0 10.1.2.3
access-list inside_in-DRC-0 extended permit ip any any
access-list inside_in-DRC-0 extended permit tcp 10.1.1.0 255.255.255.252 10.9.9.0 255.255.255.0 range 80 90
access-list inside_in-DRC-0 extended deny ip any4 any4
access-group inside_in-DRC-0 in interface inside
END

test_run($title, 'ASA', $minimal_ASA, $spoc, $out);

############################################################
$title = "ASA - any allowed in raw with ipv6 config";
############################################################
$spoc = {
spoc6 => <<END
access-list inside_in extended permit tcp 1000::abcd:2:0/112 1000::abcd:9:0/112 range 80 90
access-list inside_in extended deny ip any6 any6
access-group inside_in in interface inside
END
,
raw => <<END
access-list inside_in extended permit ip any any
access-group inside_in in interface inside
END
};

$out = <<END;
access-list inside_in-DRC-0 extended permit ip any any
access-list inside_in-DRC-0 extended permit tcp 1000::abcd:2:0/112 1000::abcd:9:0/112 range 80 90
access-list inside_in-DRC-0 extended deny ip any6 any6
access-group inside_in-DRC-0 in interface inside
END

test_run($title, 'ASA', $minimal_ASA, $spoc, $out);

############################################################
$title = "ASA - alter any to any4 + any6";
############################################################
$device = $minimal_ASA;
$device .= <<END;
access-list inside_in extended permit ip any any
access-group inside_in in interface inside
END

$spoc = {
spoc4 => <<END
access-list inside_in extended permit ip any4 any4
access-group inside_in in interface inside
END
,
spoc6 => <<END
access-list inside_in extended permit ip any6 any6
access-group inside_in in interface inside
END
};

$out = <<END;
access-list inside_in-DRC-0 extended permit ip any6 any6
access-list inside_in-DRC-0 extended permit ip any4 any4
access-group inside_in-DRC-0 in interface inside
clear configure access-list inside_in
END

test_run($title, 'ASA', $device, $spoc, $out);

############################################################
$title = "ASA - alter any on device even if only ipv4 input exists";
############################################################
$device = $minimal_ASA;
$device .= <<END;
access-list inside_in extended permit ip any any
access-group inside_in in interface inside
END

$spoc = {
spoc4 => <<'END'
access-list inside_in extended permit ip any4 any4
access-group inside_in in interface inside
END
};

$out = <<END;
access-list inside_in-DRC-0 extended permit ip any4 any4
access-group inside_in-DRC-0 in interface inside
clear configure access-list inside_in
END

test_run($title, 'ASA', $device, $spoc, $out);

############################################################
$title = "ASA - alter any to any4 ";
############################################################
$device = $minimal_ASA;
$device .= <<END;
access-list inside_in extended permit ip any any
access-group inside_in in interface inside
END

$spoc = {
spoc4 => <<END
access-list inside_in extended permit ip any4 any4
access-group inside_in in interface inside
END
,
spoc6 => <<END
ipv6 route inside 10::3:0/120 10::2:2
END
};

$out = <<END;
ipv6 route inside 10::3:0/120 10::2:2
access-list inside_in-DRC-0 extended permit ip any4 any4
access-group inside_in-DRC-0 in interface inside
clear configure access-list inside_in
END

test_run($title, 'ASA', $device, $spoc, $out);

############################################################
$title = "ASA - merge ACL";
############################################################
$spoc = {
spoc4 => <<END
access-list inside_in extended permit tcp 10.1.1.0 255.255.255.252 10.2.2.0 255.255.255.0 range 80 90
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside

access-list outside_in extended deny ip any4 any4
access-group outside_in in interface outside
END
,
spoc6 => <<END
access-list inside_in extended permit tcp 1000::abcd:1:0/96 1000::abcd:2:0/96 range 80 90
access-list inside_in extended deny ip any6 any6
access-group inside_in in interface inside

access-list outside_in extended deny ip any6 any6
access-group outside_in in interface outside
END
};

$out = <<END;
access-list inside_in-DRC-0 extended permit tcp 1000::abcd:1:0/96 1000::abcd:2:0/96 range 80 90
access-list inside_in-DRC-0 extended permit tcp 10.1.1.0 255.255.255.252 10.2.2.0 255.255.255.0 range 80 90
access-list inside_in-DRC-0 extended deny ip any4 any4
access-list inside_in-DRC-0 extended deny ip any6 any6
access-group inside_in-DRC-0 in interface inside
access-list outside_in-DRC-0 extended deny ip any4 any4
access-list outside_in-DRC-0 extended deny ip any6 any6
access-group outside_in-DRC-0 in interface outside
END

test_run($title, 'ASA', $minimal_ASA2, $spoc, $out);

############################################################
$title = "ASA - ipv6 interface unknown in ipv4";
############################################################
$spoc = {
spoc4 => <<END
access-list outside_in extended deny ip any any
access-group outside_in in interface outside
END
,
spoc6 => <<END
access-list inside_in extended deny ip any6 any6
access-group inside_in in interface inside
END
};

$out = <<END;
access-list outside_in-DRC-0 extended deny ip any any
access-group outside_in-DRC-0 in interface outside
access-list inside_in-DRC-0 extended deny ip any6 any6
access-group inside_in-DRC-0 in interface inside
END

test_run($title, 'ASA', $minimal_ASA2, $spoc, $out);

############################################################
$title = "Only IPv6 address known for device";
############################################################

$spoc = {
spoc4 => <<END
route inside 10.20.0.0 255.255.255.0 10.1.2.3
route inside 10.22.0.0 255.255.0.0 10.1.2.4
END
,
spoc6 => <<END
ipv6 route inside 10::3:0/120 10::2:2
ipv6 route inside 10::2:0/1 10::2:5
END
,
info4 => <<END
{ "model": "ASA" }
END
,
info6 => <<END
{
 "model": "ASA",
 "ip_list": ["10::33"]
}
END
};

$out = <<END;
route inside 10.20.0.0 255.255.255.0 10.1.2.3
route inside 10.22.0.0 255.255.0.0 10.1.2.4
ipv6 route inside 10::3:0/120 10::2:2
ipv6 route inside 10::2:0/1 10::2:5
END

test_run($title, 'ASA', '', $spoc, $out);

############################################################
done_testing;
