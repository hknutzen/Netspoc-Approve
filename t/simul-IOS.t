#!/usr/bin/perl

use strict;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Approve;

my($scenario, $scenario2, $in, $out, $title);

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
>enable
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
>enable
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
# ip\BANNER1/ route 10.0.0.0 255.0.0.0 10.11.22.33
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
>enable
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
$title = "write mem: overwrite previous NVRAM";
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
# reload in 5

System configuration has been modified. Save? [yes/no]: <!>
Reload reason: Reload Command
Proceed with reload? [confirm]<!>
# reload cancel


***
*** --- SHUTDOWN ABORTED ---
***
# write memory
Warning: Attempting to overwrite an NVRAM configuration previously written by a different version of the system image.
Overwrite the previous NVRAM configuration?[confirm]<!>
Building configuration...
  Compressed configuration from 10194 bytes to 5372 bytes[OK]
END

$in = <<'END';
ip route 10.0.0.0 255.0.0.0 10.11.22.33
END

$out = <<'END';
------ router.login
Enter Password:secret

banner motd  managed by NetSPoC
>enable
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
router#no ip route 10.0.0.0 255.0.0.0 10.1.2.3
router#ip route 10.0.0.0 255.0.0.0 10.11.22.33
router#end
router#reload cancel


***
*** --- SHUTDOWN ABORTED ---
***
router#
router#write memory
Warning: Attempting to overwrite an NVRAM configuration previously written by a different version of the system image.
Overwrite the previous NVRAM configuration?[confirm]

Building configuration...
  Compressed configuration from 10194 bytes to 5372 bytes[OK]
router#
END

simul_run($title, 'IOS', $scenario, $in, $out);

############################################################
$title = "write mem: abort on too large config";
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
# reload in 5

System configuration has been modified. Save? [yes/no]: <!>
Reload reason: Reload Command
Proceed with reload? [confirm]<!>
# reload cancel


***
*** --- SHUTDOWN ABORTED ---
***
# write memory
Building configuration...
Compressed configuration is too large for nvram
Truncate config?? [no]:
END

$in = <<'END';
ip route 10.0.0.0 255.0.0.0 10.11.22.33
END

$out = <<'END';
ERROR>>> write mem: failed, config may be truncated
END

simul_err($title, 'IOS', $scenario, $in, $out);

############################################################
$title = "write mem: retry if startup-config open failed";
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
# reload in 5

System configuration has been modified. Save? [yes/no]: <!>
Reload reason: Reload Command
Proceed with reload? [confirm]<!>
# reload cancel


***
*** --- SHUTDOWN ABORTED ---
***
# write memory
startup-config file open failed (Device or resource busy)
END

$in = <<'END';
ip route 10.0.0.0 255.0.0.0 10.11.22.33
END

$out = <<'END';
WARNING>>> write mem: startup-config open failed - trying again
WARNING>>> write mem: startup-config open failed - trying again
ERROR>>> write mem: startup-config open failed - giving up
END

simul_err($title, 'IOS', $scenario, $in, $out);

############################################################
$title = "write mem: unexpected output";
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
# reload in 5

System configuration has been modified. Save? [yes/no]: <!>
Reload reason: Reload Command
Proceed with reload? [confirm]<!>
# reload cancel


***
*** --- SHUTDOWN ABORTED ---
***
# write memory
foo
END

$in = <<'END';
ip route 10.0.0.0 255.0.0.0 10.11.22.33
END

$out = <<'END';
ERROR>>> write mem: unexpected result:
ERROR>>> foo
END

simul_err($title, 'IOS', $scenario, $in, $out);

############################################################
$title = "Unexpected command output";
############################################################
$scenario = <<'END';
Enter Password:<!>
banner motd  managed by NetSPoC
>
# sh ver
Cisco IOS Software, C2900 Software (C2900-UNIVERSALK9-M), Version 15.1(4)M4,
# configure terminal
Enter configuration commands, one per line.  End with CNTL/Z.
foo
END

$in = '';

$out = <<'END';
ERROR>>> Unexpected output of 'configure terminal'
ERROR>>> Enter configuration commands, one per line.  End with CNTL/Z.
ERROR>>> foo
END

simul_err($title, 'IOS', $scenario, $in, $out);

############################################################
$title = "Must not move ACL line permitting device access";
############################################################
$scenario = <<'END';
Enter Password:<!>
banner motd  managed by NetSPoC
>
# sh ver
Cisco IOS Software, C2900 Software (C2900-UNIVERSALK9-M), Version 15.1(4)M4,
# sh run
ip access-list extended Ethernet0_in
 permit ip host 10.1.1.1 host 10.2.2.1
 permit tcp 10.0.6.0 0.0.0.255 host 10.0.1.11 eq 22
 permit ip host 10.1.1.1 host 10.2.2.2
 permit ip host 10.1.1.1 host 10.2.2.3
 deny ip any any
interface Ethernet0
 ip access-group Ethernet0_in in
# sh users | incl ^\*
*  7 vty 1     router   idle                 00:00:00 10.0.6.11
# sh tcp 7 | incl Local host:
Local host: 10.0.1.11, Local port: 22
# configure terminal
Enter configuration commands, one per line.  End with CNTL/Z.
# reload in 5

System configuration has been modified. Save? [yes/no]: <!>
Reload reason: Reload Command
Proceed with reload? [confirm]<!>
# reload cancel


***
*** --- SHUTDOWN ABORTED ---
***
# write memory
Building configuration...
  Compressed configuration from 106098 bytes to 30504 bytes[OK]
END

# This router is accessed at address 10.0.1.11
# and ACL line premitting this access would be moved.
# But this situation is recognized and hence the whole ACL
# defined again.
$in = <<'END';
ip access-list extended Ethernet0_in
 permit ip host 10.1.1.1 host 10.2.2.1
 permit ip host 10.1.1.1 host 10.2.2.2
 permit tcp 10.0.6.0 0.0.0.255 host 10.0.1.11 eq 22
 permit ip host 10.1.1.1 host 10.2.2.3
 deny ip any any
interface Ethernet0
 ip access-group Ethernet0_in in
 deny ip any any
END

$out = <<'END';
------ router.login
Enter Password:secret

banner motd  managed by NetSPoC
>enable
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
router#do sh users | incl ^\*
*  7 vty 1     router   idle                 00:00:00 10.0.6.11
router#do sh tcp 7 | incl Local host:
Local host: 10.0.1.11, Local port: 22
router#do reload in 5

System configuration has been modified. Save? [yes/no]: n

Reload reason: Reload Command
Proceed with reload? [confirm]

router#ip access-list extended Ethernet0_in-DRC-0
router#permit ip host 10.1.1.1 host 10.2.2.1
router#permit ip host 10.1.1.1 host 10.2.2.2
router#permit tcp 10.0.6.0 0.0.0.255 host 10.0.1.11 eq 22
router#permit ip host 10.1.1.1 host 10.2.2.3
router#deny ip any any
router#interface Ethernet0
router#ip access-group Ethernet0_in-DRC-0 in
router#do reload cancel


***
*** --- SHUTDOWN ABORTED ---
***
router#
router#no ip access-list extended Ethernet0_in
router#end
router#write memory
Building configuration...
  Compressed configuration from 106098 bytes to 30504 bytes[OK]
router#
END

simul_run($title, 'IOS', $scenario, $in, $out);

############################################################
$title = "Unknown vty";
############################################################
($scenario2 = $scenario) =~ s/[*]  7 vty.*//;

$out = <<'END';
ERROR>>> Can't determine my vty
END

simul_err($title, 'IOS', $scenario2, $in, $out);

############################################################
$title = "Unknown source IP of vty";
############################################################
($scenario2 = $scenario) =~ s/00:00:00 10\.0\.6\.11/00:00:00 10.0../;

$out = <<'END';
ERROR>>> Can't parse src ip: 10.0..
END

simul_err($title, 'IOS', $scenario2, $in, $out);

############################################################
$title = "Unknown tcp connection for vty";
############################################################
($scenario2 = $scenario) =~ s/Local host: .*, Local port: .*//;

$out = <<'END';
ERROR>>> Can't determine remote ip and port of my TCP session
END

simul_err($title, 'IOS', $scenario2, $in, $out);

############################################################
$title = "Unknown router IP from tcp connection";
############################################################
($scenario2 = $scenario) =~ s/Local host: 10\.0\.1\.11/Local host: 10.0../;

$out = <<'END';
ERROR>>> Can't parse remote ip: 10.0..
END

simul_err($title, 'IOS', $scenario2, $in, $out);

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
done_testing;
