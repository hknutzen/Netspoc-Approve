#!/usr/bin/perl

use strict;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Approve;

my($scenario, $scenario2, $in, $out, $title);

############################################################
$title = "Login, set terminal, empty config";
############################################################
$scenario = <<'END';
***********************************************************
**                 managed by NetSPoC                    **
***********************************************************
netspoc@10.1.2.3's password: <!>
Type help or '?' for a list of available commands.
router>
# sh pager
pager lines 24
# terminal pager 0
# sh term

Width = 80, no monitor
terminal interactive
# sh ver
Cisco Adaptive Security Appliance Software Version 9.4(4)5 <context>
Hardware:   ASA5585-SSP-40
Configuration last modified by netspoc at 10:40:44.291 CEDT Thu Oct 19 2017
# show hostname
router
END

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
Cisco Adaptive Security Appliance Software Version 9.4(4)5 <context>
Hardware:   ASA5585-SSP-40
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
$title = "Login, set terminal, empty config";
############################################################
$scenario = <<'END';
managed by NetSPoC
netspoc@10.1.2.3's password: <!>
router>
# sh pager
pager lines 24
# sh term

Width = 511, no monitor
terminal interactive
# sh ver
Cisco Adaptive Security Appliance Software Version 9.4(4)5 <context>
Hardware:   ASA5585-SSP-40
# show hostname
router
# write term
route inside 0.0.0.0 0.0.0.0 10.1.2.3
# write memory
Building configuration...
Cryptochecksum: abcdef01 44444444 12345678 98765432

123456 bytes copied in 0.330 secs
[OK]
END

$in = <<'END';
route inside 0.0.0.0 0.0.0.0 10.1.2.4
END

$out = <<'END';
--router.config
write term
route inside 0.0.0.0 0.0.0.0 10.1.2.3
router#
--router.change
configure terminal
router#no route inside 0.0.0.0 0.0.0.0 10.1.2.3
router#route inside 0.0.0.0 0.0.0.0 10.1.2.4
router#end
router#configure terminal
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
done_testing;
