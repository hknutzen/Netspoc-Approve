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
Cisco IOS Software, C800 Software (C800-UNIVERSALK9-M), Version 15.4(3)M4, RELEASE SOFTWARE (fc1)
Technical Support: http://www.cisco.com/techsupport
Cisco C886VA-K9 (revision 1.0) with 488524K/35763K bytes of memory.
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
Cisco IOS Software, C800 Software (C800-UNIVERSALK9-M), Version 15.4(3)M4, RELEASE SOFTWARE (fc1)
Technical Support: http://www.cisco.com/techsupport
Cisco C886VA-K9 (revision 1.0) with 488524K/35763K bytes of memory.
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
$title = "Conf mode, reload banner, small change, write mem";
############################################################
$scenario = <<'END';
Enter Password:<!>
banner motd  managed by NetSPoC
>
# sh ver
Cisco IOS Software, C2900 Software (C2900-UNIVERSALK9-M), Version 15.1(4)M4,
# sh run
ip route 10.0.0.0 255.0.0.0 10.1.2.3
# configure terminal
Enter configuration commands, one per line.  End with CNTL/Z.
# \BANNER5/



***
*** --- SHUTDOWN in 00:05:00 ---
***
# \BANNER1/



***
*** --- SHUTDOWN in 00:01:00 ---
***
# reload in 5

System configuration has been modified. Save? [yes/no]: <!>
Reload reason: Reload Command
Proceed with reload? [confirm]<!>
# reload in 2
Proceed with reload? [confirm]<!>
# reload cancel


***
*** --- SHUTDOWN ABORTED ---
***
# no ip route 10.0.0.0 25\BANNER5/5.0.0.0 10.1.2.3
# ip \BANNER1/route 10.0.0.0 255.0.0.0 10.11.22.33
# write memory
Building configuration...
  Compressed configuration from 106098 bytes to 30504 bytes[OK]
END

$in = <<'END';
ip route 10.0.0.0 255.0.0.0 10.11.22.33
END

$out = <<'END';
------ router.login
Enter Password:secret

banner motd  managed by NetSPoC
>
enable
router#
router#term len 0
router#term width 512
router#sh ver
Cisco IOS Software, C2900 Software (C2900-UNIVERSALK9-M), Version 15.1(4)M4,
router#
router#configure terminal
Enter configuration commands, one per line.  End with CNTL/Z.
router#no logging console
router#line vty 0 15
router#logging synchronous level all
router#ip subnet-zero
router#ip classless
router#end
router#
------ router.change
configure terminal
Enter configuration commands, one per line.  End with CNTL/Z.
router#end
router#reload in 5

System configuration has been modified. Save? [yes/no]: n

Reload reason: Reload Command
Proceed with reload? [confirm]

router#configure terminal
Enter configuration commands, one per line.  End with CNTL/Z.
router#no ip route 10.0.0.0 25


***
*** --- SHUTDOWN in 00:05:00 ---
***
5.0.0.0 10.1.2.3
router#ip 


***
*** --- SHUTDOWN in 00:01:00 ---
***
route 10.0.0.0 255.0.0.0 10.11.22.33
router#do reload in 2
Proceed with reload? [confirm]

router#end
router#reload cancel


***
*** --- SHUTDOWN ABORTED ---
***
router#
router#write memory
Building configuration...
  Compressed configuration from 106098 bytes to 30504 bytes[OK]
router#
END

simul_run($title, 'IOS', $scenario, $in, $out);

############################################################
done_testing;
