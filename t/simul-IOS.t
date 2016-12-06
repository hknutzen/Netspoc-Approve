#!/usr/bin/perl

use strict;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Approve;

my($scenario, $in, $out, $title);

############################################################
$title = "SSH timeout";
############################################################
$scenario = '';
$in = '';

$out = <<'END';
ERROR>>> TIMEOUT
END

simul_err($title, 'IOS', $scenario, $in, $out);

############################################################
$title = "SSH, setup, get config, but no change";
############################################################
$scenario = <<'END';
Enter Password:<!>
>
# sh ver
Cisco IOS Software, C2900 Software (C2900-UNIVERSALK9-M), Version 15.1(4)M4, RELEASE SOFTWARE (fc1)
# sh run
ip route 0.0.0.0 0.0.0.0 10.1.2.3
END

$in = << 'END';
ip route 0.0.0.0 0.0.0.0 10.1.2.3
END

$out = <<'END';
--router.login
Enter Password:secret

>
enable
router#
router#term len 0
router#term width 512
router#sh ver
Cisco IOS Software, C2900 Software (C2900-UNIVERSALK9-M), Version 15.1(4)M4, RELEASE SOFTWARE (fc1)
router#
router#configure terminal
router#no logging console
router#line vty 0 15
router#logging synchronous level all
router#ip subnet-zero
router#ip classless
router#end
router#
--router.change
configure terminal
router#end
router#
END

simul_run($title, 'IOS', $scenario, $in, $out);

############################################################
done_testing;
