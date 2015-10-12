#!/usr/bin/perl

use strict;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Approve;

# Minimal configuration of device.
my $minimal_device = <<END;
nameif Ethernet0/0 inside 100
nameif Ethernet0/1 outside 0
END

# Input from Netspoc.
# Input from device.
# Output from approve.
my($in, $device, $out);
my $device_type = 'PIX';
my $title;

############################################################
$title = "Parse PIX static, global, nat";
############################################################
$in = <<END;
global (outside) 1 10.48.56.5 netmask 255.255.255.255
nat (inside) 1 10.48.48.0 255.255.248.0
static (outside,inside) 10.9.0.0 172.31.0.0 netmask 255.255.0.0
END

$out = <<END;
static (outside,inside) 10.9.0.0 172.31.0.0 netmask 255.255.0.0
global (outside) 1 10.48.56.5 netmask 255.255.255.255
nat (inside) 1 10.48.48.0 255.255.248.0
END

check_parse_and_unchanged( $device_type, $minimal_device, $in, $out, $title );

############################################################
done_testing;
