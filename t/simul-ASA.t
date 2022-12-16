#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::Differences;

use lib 't';
use Test_Approve;

my($login_scenario, $scenario, $in, $out, $title);

$login_scenario = <<'END';
***********************************************************
**                 managed by NetSPoC                    **
***********************************************************
netspoc@10.1.2.3's password: <!>
Type help or '?' for a list of available commands.
router>
# sh pager
pager lines 24

# sh term

Width = 80, no monitor
terminal interactive
# sh ver
Cisco Adaptive Security Appliance Software Version 9.4(4)5
Hardware:   ASA5550, 4096 MB RAM, CPU Pentium 4 3000 MHz
Configuration last modified by netspoc at 10:40:44.291 CEDT Thu Oct 19 2017
# show hostname
router
END

############################################################
$title = "Login, set terminal, empty config";
############################################################
$scenario = $login_scenario;

$in = '';

$out = <<'END';
--router.login
***********************************************************
**                 managed by NetSPoC                    **
***********************************************************
netspoc@10.1.2.3's password: secret

Type help or '?' for a list of available commands.
router>enable
router#
router#sh pager
pager lines 24

router#terminal pager 0
router#sh term

Width = 80, no monitor
terminal interactive
router#configure terminal
router#terminal width 511
router#end
router#sh ver
Cisco Adaptive Security Appliance Software Version 9.4(4)5
Hardware:   ASA5550, 4096 MB RAM, CPU Pentium 4 3000 MHz
Configuration last modified by netspoc at 10:40:44.291 CEDT Thu Oct 19 2017
router#show hostname
router
router#
--router.config
write term
router#
END

simul_run($title, 'ASA', $scenario, $in, $out);

############################################################
$title = "Change routing, move ACL with two commands in one line";
############################################################
$scenario = $login_scenario . <<'END';
# write term
route inside 0.0.0.0 0.0.0.0 10.1.2.3
access-list inside extended permit ip host 1.1.1.1 any
access-list inside extended permit ip host 2.2.2.2 any
access-list inside extended permit ip host 3.3.3.3 any
access-list inside extended permit ip host 4.4.4.4 any
access-group inside in interface inside
# write memory
Building configuration...
Cryptochecksum: abcdef01 44444444 12345678 98765432

123456 bytes copied in 0.330 secs
[OK]
END

$in = <<'END';
route inside 0.0.0.0 0.0.0.0 10.1.2.4
access-list inside extended permit ip host 1.1.1.1 any
access-list inside extended permit ip host 4.4.4.4 any
access-list inside extended permit ip host 2.2.2.2 any
access-list inside extended permit ip host 3.3.3.3 any
access-group inside in interface inside
END

# Two commands to change route and access-list
# are send in one packet.
# This results in two prompts received in one packet.
# Expect library is expected to stop on first prompt
# (see Bug #100342 for Expect). Otherwise this test should fail.
$out = <<'END';
--router.config
write term
route inside 0.0.0.0 0.0.0.0 10.1.2.3
access-list inside extended permit ip host 1.1.1.1 any
access-list inside extended permit ip host 2.2.2.2 any
access-list inside extended permit ip host 3.3.3.3 any
access-list inside extended permit ip host 4.4.4.4 any
access-group inside in interface inside
router#
--router.change
configure terminal
router#no route inside 0.0.0.0 0.0.0.0 10.1.2.3
router#route inside 0.0.0.0 0.0.0.0 10.1.2.4
router#end
router#configure terminal
router#no access-list inside line 4 extended permit ip host 4.4.4.4 any
router#access-list inside line 2 extended permit ip host 4.4.4.4 any
router#end
router#write memory
Building configuration...
Cryptochecksum: abcdef01 44444444 12345678 98765432

123456 bytes copied in 0.330 secs
[OK]
router#
END

simul_run($title, 'ASA', $scenario, $in, $out);

############################################################
$title = "Expected command output";
############################################################
$scenario = $login_scenario . <<'END';
# write term
access-list inside extended deny ip any any
access-group inside in interface inside
# access-list inside line 1 extended permit ip object-group g1-DRC-0 object-group g1-DRC-0
WARNING: Same object-group is used more than once in one config line. This config is redundant. Please use seperate object-groups
END

$in = <<'END';
object-group network g1
 network-object host 1.1.1.1
access-list inside extended permit ip object-group g1 object-group g1
access-group inside in interface inside
END

$out = <<'END';
--router.change
configure terminal
router#object-group network g1-DRC-0
router#network-object host 1.1.1.1
router#access-list inside line 1 extended permit ip object-group g1-DRC-0 object-group g1-DRC-0
WARNING: Same object-group is used more than once in one config line. This config is redundant. Please use seperate object-groups
router#no access-list inside line 2 extended deny ip any any
router#end
router#write memory
router#
END

simul_run($title, 'ASA', $scenario, $in, $out);

############################################################
$title = "Unexpected warning";
############################################################
$scenario = $login_scenario . <<'END';
# route inside 0.0.0.0 0.0.0.0 10.1.2.4
WARNING: foo
END

$in = <<'END';
route inside 0.0.0.0 0.0.0.0 10.1.2.4
END

$out = <<'END';
WARNING>>> WARNING: foo
END

simul_run($title, 'ASA', $scenario, $in, $out);

############################################################
$title = "Unexpected command output";
############################################################
$scenario = $login_scenario . <<'END';
# configure terminal
foo
END

$in = <<'END';
route inside 0.0.0.0 0.0.0.0 10.1.2.4
END

$out = <<'END';
ERROR>>> Unexpected output of 'configure terminal'
ERROR>>> foo
END

simul_err($title, 'ASA', $scenario, $in, $out);

############################################################
done_testing;
