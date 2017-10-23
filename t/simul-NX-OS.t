#!/usr/bin/perl

use strict;
use Test::More;
use Test::Differences;

use lib 't';
use Test_Approve;

my($login_scenario, $scenario, $scenario2, $in, $out, $title);

############################################################
$title = "Login, set terminal, empty config";
############################################################
$login_scenario = <<'END';
=============================================================================
===                 -----  managed by NetSPoC  ----                       ===
=============================================================================
Password: <!>
Cisco Nexus Operating System (NX-OS) Software
router#
# show version
Software
  system:    version 6.2(16)
Hardware
  cisco Nexus7000 C7010 (10 Slot) Chassis
# show hostname
router.example.com
END

$in = '';

$out = <<'END';
--router.login
=============================================================================
===                 -----  managed by NetSPoC  ----                       ===
=============================================================================
Password: secret

Cisco Nexus Operating System (NX-OS) Software
router#
router#terminal length 0
router#terminal width 511
router#show version
Software
  system:    version 6.2(16)
Hardware
  cisco Nexus7000 C7010 (10 Slot) Chassis
router#show hostname
router.example.com
router#
--router.config
show running-config
router#
END

simul_run($title, 'NX-OS', $login_scenario, $in, $out);

############################################################
$title = "Change routing and ACL";
############################################################
$scenario = $login_scenario . <<'END';

# show running-config
vrf context sh
 ip route 10.1.1.0/24 10.1.2.3
ip access-list inside_in
 10 permit tcp any host 10.0.1.11 eq 22
interface Ethernet0/0
 ip access-group inside_in in
# configure session Netspoc
Config Session started, Session ID is 1
Enter configuration commands, one per line.  End with CNTL/Z.
# verify
Verification Successful
# commit
Commit Successful
# copy running-config startup-config
[#############] 100%
Copy complete.
END

$in = <<'END';
vrf context sh
 ip route 10.1.1.0/24 10.1.2.4
ip access-list inside_in
 10 permit tcp 10.1.1.0/24 host 10.0.1.11 eq 22
interface Ethernet0/0
 ip access-group inside_in in
END

$out = <<'END';
--router.config
show running-config
vrf context sh
 ip route 10.1.1.0/24 10.1.2.3
ip access-list inside_in
 10 permit tcp any host 10.0.1.11 eq 22
interface Ethernet0/0
 ip access-group inside_in in
router#
--router.change
show configuration session
router#configure session Netspoc
Config Session started, Session ID is 1
Enter configuration commands, one per line.  End with CNTL/Z.
router#resequence ip access-list inside_in 10000 10000
router#ip access-list inside_in
router#1 permit tcp 10.1.1.0/24 host 10.0.1.11 eq 22
router#no 10000
router#resequence ip access-list inside_in 10 10
router#verify
Verification Successful
router#commit
Commit Successful
router#configure terminal
router#vrf context sh
router#no ip route 10.1.1.0/24 10.1.2.3
router#ip route 10.1.1.0/24 10.1.2.4
router#end
router#copy running-config startup-config
[#############] 100%
Copy complete.
router#
END

simul_run($title, 'NX-OS', $scenario, $in, $out);

############################################################
$title = "Unexpected open config session";
############################################################

$scenario2 = $scenario . <<'END';
# show configuration session
Name                    Session Owner           Creation Time
--------------------------------------------------------------------
myACLS                  admin                   21:34:39 UTC Apr 27 2008
Number of active configuration sessions = 1
END

$out = <<'END';
ERROR>>> There already is an open configuration session
ERROR>>> Name                    Session Owner           Creation Time
ERROR>>> --------------------------------------------------------------------
ERROR>>> myACLS                  admin                   21:34:39 UTC Apr 27 2008
ERROR>>> Number of active configuration sessions = 1
END

simul_err($title, 'NX-OS', $scenario2, $in, $out);

############################################################
$title = "Ignore other config session output";
############################################################

$scenario2 = $scenario . <<'END';
# show configuration session
Name                    Session Owner           Creation Time
END

$out = <<'END';
--router.change
show configuration session
Name                    Session Owner           Creation Time
router#configure session Netspoc
Config Session started, Session ID is 1
Enter configuration commands, one per line.  End with CNTL/Z.
router#resequence ip access-list inside_in 10000 10000
router#ip access-list inside_in
router#1 permit tcp 10.1.1.0/24 host 10.0.1.11 eq 22
router#no 10000
router#resequence ip access-list inside_in 10 10
router#verify
Verification Successful
router#commit
Commit Successful
router#configure terminal
router#vrf context sh
router#no ip route 10.1.1.0/24 10.1.2.3
router#ip route 10.1.1.0/24 10.1.2.4
router#end
router#copy running-config startup-config
[#############] 100%
Copy complete.
router#
END

simul_run($title, 'NX-OS', $scenario2, $in, $out);

############################################################
$title = "Can't verify config session";
############################################################

($scenario2 = $scenario) =~ s/Verification Successful/Verification Failed/;

$out = <<'END';
ERROR>>> Can't 'verify' configuration session
ERROR>>> Verification Failed
END

simul_err($title, 'NX-OS', $scenario2, $in, $out);

############################################################
$title = "Unexpected command output";
############################################################
$scenario = $login_scenario . <<'END';

# show running-config
vrf context sh
 ip route 10.1.1.0/24 10.1.2.3
# configure session Netspoc
foo
END

$in = <<'END';
vrf context sh
 ip route 10.1.1.0/24 10.1.2.4
END

$out = <<'END';
ERROR>>> Unexpected output of 'configure session Netspoc'
ERROR>>> foo
END

simul_err($title, 'NX-OS', $scenario, $in, $out);

############################################################
done_testing;
