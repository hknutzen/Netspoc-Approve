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

# Input from Netspoc, from raw, output from approve.
my($spoc, $raw, $out);
my $title;

############################################################
$title = "Merge routing IOS";
############################################################
$spoc = <<END;
ip route 10.20.0.0 255.248.0.0 10.1.2.3
END

$raw = <<END;
ip route 10.22.0.0 255.255.0.0 10.1.2.4
ip route 10.0.0.0 255.0.0.0 10.1.2.2
END

$out = <<END;
ip route 10.22.0.0 255.255.0.0 10.1.2.4
ip route 10.20.0.0 255.248.0.0 10.1.2.3
ip route 10.0.0.0 255.0.0.0 10.1.2.2
END

eq_or_diff( approve('IOS', '', $spoc, $raw ), $out, $title );

############################################################
$title = "Merge routing ASA";
############################################################
$spoc = <<END;
route inside 10.20.0.0 255.248.0.0 10.1.2.3
END

$raw = <<END;
route inside 10.22.0.0 255.255.0.0 10.1.2.4
route inside 10.0.0.0 255.0.0.0 10.1.2.2
END

$out = <<END;
route inside 10.22.0.0 255.255.0.0 10.1.2.4
route inside 10.20.0.0 255.248.0.0 10.1.2.3
route inside 10.0.0.0 255.0.0.0 10.1.2.2
END

eq_or_diff( approve('ASA', '', $spoc, $raw ), $out, $title );

############################################################
$title = "Duplicate routing IOS";
############################################################
$spoc = <<END;
ip route 10.20.0.0 255.255.0.0 10.1.2.3
END

$raw = <<END;
ip route 10.20.0.0 255.255.0.0 10.1.2.3
END

$out = <<END;
WARNING>>> RAW: double RE 'ip route 10.20.0.0 255.255.0.0 10.1.2.3' scheduled for remove from spocconf.
ip route 10.20.0.0 255.255.0.0 10.1.2.3
END

eq_or_diff( approve('IOS', '', $spoc, $raw ), $out, $title );

############################################################
$title = "Duplicate routing ASA";
############################################################
$spoc = <<END;
route inside 10.20.0.0 255.248.0.0 10.1.2.3
END

$raw = <<END;
route inside 10.20.0.0 255.248.0.0 10.1.2.3
END

$out = <<END;
route inside 10.20.0.0 255.248.0.0 10.1.2.3
route inside 10.20.0.0 255.248.0.0 10.1.2.3
END

eq_or_diff( approve('ASA', '', $spoc, $raw ), $out, $title );

############################################################
$title = "Different next hop";
############################################################
$spoc = <<END;
ip route 10.20.0.0 255.255.0.0 10.1.2.3
END

$raw = <<END;
ip route 10.20.0.0 255.255.0.0 10.1.2.4
END

$out = <<END;
WARNING>>> RAW: inconsistent NEXT HOP in routing entries:
WARNING>>>      spoc: ip route 10.20.0.0 255.255.0.0 10.1.2.3 (scheduled for remove)
WARNING>>>      raw:  ip route 10.20.0.0 255.255.0.0 10.1.2.4 
ip route 10.20.0.0 255.255.0.0 10.1.2.4
END

eq_or_diff( approve('IOS', '', $spoc, $raw ), $out, $title );

############################################################
$title = "Duplicate static";
############################################################
$spoc = <<END;
static (outside,inside) 10.9.0.0 172.31.0.0 netmask 255.255.0.0
END

$raw = <<END;
static (outside,inside) 10.9.0.0 172.31.0.0 netmask 255.255.0.0
END

$out = <<END;
WARNING>>> RAW: ignoring useless: 'static (outside,inside) 10.9.0.0 172.31.0.0 netmask 255.255.0.0'
static (outside,inside) 10.9.0.0 172.31.0.0 netmask 255.255.0.0
END

eq_or_diff( approve('ASA', '', $spoc, $raw ), $out, $title );

############################################################
$title = "Replacing static";
############################################################
$spoc = <<END;
static (outside,inside) 10.7.0.0 172.29.0.0 netmask 255.255.0.0
static (outside,inside) 10.9.0.0 172.31.0.0 netmask 255.255.0.0
END

$raw = <<END;
static (outside,inside) 10.8.0.0 172.30.0.0 netmask 255.255.0.0
static (outside,inside) 10.0.0.0 172.0.0.0 netmask 255.0.0.0
END

$out = <<END;
static (outside,inside) 10.8.0.0 172.30.0.0 netmask 255.255.0.0
static (outside,inside) 10.0.0.0 172.0.0.0 netmask 255.0.0.0
END

eq_or_diff( approve('ASA', '', $spoc, $raw ), $out, $title );

############################################################
done_testing;
