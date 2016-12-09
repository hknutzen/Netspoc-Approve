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
$title = "Login with unknown SSH key + enable";
############################################################
$scenario = <<'END';
The authenticity of host 'router (10.1.1.1)' can't be established.
ECDSA key fingerprint is ee:6e:ee:00:33:aa:22:88:44:66:44:33:aa:77:42:f5.
Are you sure you want to continue connecting (yes/no)? <!>
Enter Password:<!>
banner motd managed by NetSPoC
>
# sh ver
Cisco IOS Software, C2900 Software (C2900-UNIVERSALK9-M), Version 15.1(4)M4, RELEASE SOFTWARE (fc1)
END

$in = '';

$out = <<'END';
--router.login
The authenticity of host 'router (10.1.1.1)' can't be established.
ECDSA key fingerprint is ee:6e:ee:00:33:aa:22:88:44:66:44:33:aa:77:42:f5.
Are you sure you want to continue connecting (yes/no)? yes

Enter Password:secret

banner motd managed by NetSPoC
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
END

simul_run($title, 'IOS', $scenario, $in, $out);

############################################################
$title = "SSH login without enable";
############################################################
$scenario = <<'END';
Enter Password:<!>
banner motd managed by NetSPoC
(router)#
# sh ver
Cisco IOS Software, C2900 Software (C2900-UNIVERSALK9-M), Version 15.1(4)M4, RELEASE SOFTWARE (fc1)
END

$in = '';

$out = <<'END';
--router.login
Enter Password:secret

banner motd managed by NetSPoC
(router)#

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
END

simul_run($title, 'IOS', $scenario, $in, $out);

############################################################
$title = "Unknown device version";
############################################################
$scenario = <<'END';
Enter Password:<!>
>
END

$in = '';

$out = <<'END';
ERROR>>> Can't identify device version
END

simul_err($title, 'IOS', $scenario, $in, $out);

############################################################
$title = "Missing banner";
############################################################
$scenario = <<'END';
Enter Password:<!>
>
# sh ver
Cisco IOS Software, C2900 Software (C2900-UNIVERSALK9-M), Version 15.1(4)M4, RELEASE SOFTWARE (fc1)
END

$in = '';

$out = <<'END';
ERROR>>> Missing banner at NetSPoC managed device
END

simul_err($title, 'IOS', $scenario, $in, $out);

############################################################
$title = "Check banner";
############################################################
$scenario = <<'END';
Enter Password:<!>
banner motd =================================================================
banner motd ===                                                           ===
banner motd ===              -----  managed by NetSPoC  ----              ===
banner motd ===                                                           ===
banner motd =================================================================
>
# sh ver
Cisco IOS Software, C2900 Software (C2900-UNIVERSALK9-M), Version 15.1(4)M4, RELEASE SOFTWARE (fc1)
END

$in = '';

$out = <<'END';
--router.login
Enter Password:secret

banner motd =================================================================
banner motd ===                                                           ===
banner motd ===              -----  managed by NetSPoC  ----              ===
banner motd ===                                                           ===
banner motd =================================================================
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
