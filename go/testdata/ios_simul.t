=TEMPL=std_scenario
Enter Password:<!>
banner motd  managed by NetSPoC
router>
# sh ver
Cisco IOS Software, C2900 Software (C2900-UNIVERSALK9-M), Version 15.1(4)M4,
# configure terminal
Enter configuration commands, one per line.  End with CNTL/Z.
# reload in 2

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
=END=

############################################################
=TITLE=Login with unknown SSH key + enable
=SCENARIO=
The authenticity of host 'router (10.1.1.1)' can't be established.
ECDSA key fingerprint is ee:6e:ee:00:33:aa:22:88:44:66:44:33:aa:77:42:f5.
Are you sure you want to continue connecting (yes/no)? <!>
Enter Password:<!>
banner motd managed by NetSPoC
router>
# sh ver
Cisco IOS Software, C800 Software (C800-UNIVERSALK9-M), Version 15.4(3)M4, RELEASE SOFTWARE (fc1)
Technical Support: http://www.cisco.com/techsupport
Cisco C886VA-K9 (revision 1.0) with 488524K/35763K bytes of memory.
=NETSPOC=NONE
=OUTPUT=
--router.login
The authenticity of host 'router (10.1.1.1)' can't be established.
ECDSA key fingerprint is ee:6e:ee:00:33:aa:22:88:44:66:44:33:aa:77:42:f5.
Are you sure you want to continue connecting (yes/no)? yes

Enter Password:secret

banner motd managed by NetSPoC
router>enable
router#
router#term len 0
router#term width 512
router#sh ver
Cisco IOS Software, C800 Software (C800-UNIVERSALK9-M), Version 15.4(3)M4, RELEASE SOFTWARE (fc1)
Technical Support: http://www.cisco.com/techsupport
Cisco C886VA-K9 (revision 1.0) with 488524K/35763K bytes of memory.
router#
router#
--router.config
sh run
router#
--router.change
No changes applied
=END=

############################################################
=TITLE=SSH login failed
=SCENARIO=
Enter Password:<!>
Enter Password:<!>
=NETSPOC=NONE
=ERROR=
ERROR>>> Authentication failed
=END=

############################################################
=TITLE=Enable password fails
=SCENARIO=
Enter Password:<!>
banner motd managed by NetSPoC
router>
# enable
Password:<!>
Password:<!>
=NETSPOC=NONE
=ERROR=
ERROR>>> Authentication for enable mode failed
=END=

############################################################
=TITLE=SSH login without enable
=SCENARIO=
Enter Password:<!>
banner motd managed by NetSPoC
router#
# sh ver
Cisco IOS Software, C2900 Software (C2900-UNIVERSALK9-M), Version 15.1(4)M4, RELEASE SOFTWARE (fc1)
=NETSPOC=NONE
=OUTPUT=
--router.login
Enter Password:secret

banner motd managed by NetSPoC
router#
router#term len 0
router#term width 512
router#sh ver
Cisco IOS Software, C2900 Software (C2900-UNIVERSALK9-M), Version 15.1(4)M4, RELEASE SOFTWARE (fc1)
router#
router#
=END=

############################################################
=TITLE=Approve unchanged
=SCENARIO=
[[std_scenario]]
# sh run
ip route 10.20.0.0 255.255.0.0 10.1.2.3
END
=NETSPOC=
ip route 10.20.0.0 255.255.0.0 10.1.2.3
=OUTPUT=
--router.change
No changes applied
=END=

############################################################
=TITLE=Compare unchanged with logfile
=SCENARIO=
[[std_scenario]]
# sh run
ip route 10.20.0.0 255.255.0.0 10.1.2.3
END
=NETSPOC=
ip route 10.20.0.0 255.255.0.0 10.1.2.3
=OUTPUT=
--router.compare
Requesting device config
Got device config
Parsed device config
comp: device unchanged
=OPTIONS=-C -q=0 --LOGFILE router.compare

############################################################
=TITLE=Compare unchanged with logfile in new directory
=SCENARIO=
[[std_scenario]]
# sh run
ip route 10.20.0.0 255.255.0.0 10.1.2.3
END
=NETSPOC=
ip route 10.20.0.0 255.255.0.0 10.1.2.3
=OUTPUT=
--d/file
Requesting device config
Got device config
Parsed device config
comp: device unchanged
=OPTIONS=-C -q=0 --LOGFILE d/file

############################################################
=TITLE=Can't create log directory
=SCENARIO=
[[std_scenario]]
# sh run
ip route 10.20.0.0 255.255.0.0 10.1.2.3
END
=NETSPOC=
ip route 10.20.0.0 255.255.0.0 10.1.2.3
=ERROR=
ERROR>>> Can't mkdir code/router: not a directory
=OPTIONS=-C -q=0 --LOGFILE code/router/log

############################################################
=TITLE=Compare changed
=SCENARIO=
[[std_scenario]]
# sh run
ip route 10.20.0.0 255.255.0.0 10.1.2.3
=NETSPOC=
ip route 10.20.0.0 255.255.0.0 10.1.2.99
=OUTPUT=
--router.cmp
no ip route 10.20.0.0 255.255.0.0 10.1.2.3\N ip route 10.20.0.0 255.255.0.0 10.1.2.99
=OPTIONS=-C

############################################################
=TITLE=Compare with missing banner
=SCENARIO=
Enter Password:<!>
router#
# sh ver
Cisco IOS Software, C2900 Software (C2900-UNIVERSALK9-M), Version 15.1(4)M4, RELEASE SOFTWARE (fc1)
=NETSPOC=NONE
=WARNING=
WARNING>>> Missing banner at NetSPoC managed device
=OPTIONS=-C

############################################################
=TITLE=Missing banner
=SCENARIO=
Enter Password:<!>
router>
# sh ver
Cisco IOS Software, C2900 Software (C2900-UNIVERSALK9-M), Version 15.1(4)M4, RELEASE SOFTWARE (fc1)
=NETSPOC=NONE
=ERROR=
ERROR>>> Missing banner at NetSPoC managed device
=END=

############################################################
=TITLE=Check banner
=SCENARIO=
Enter Password:<!>
banner motd =================================================================
banner motd ===                                                           ===
banner motd ===              -----  managed by NetSPoC  ----              ===
banner motd ===                                                           ===
banner motd =================================================================
router>
# sh ver
Cisco IOS Software, C2900 Software (C2900-UNIVERSALK9-M), Version 15.1(4)M4, RELEASE SOFTWARE (fc1)
=NETSPOC=NONE
=OUTPUT=
--router.login
Enter Password:secret

banner motd =================================================================
banner motd ===                                                           ===
banner motd ===              -----  managed by NetSPoC  ----              ===
banner motd ===                                                           ===
banner motd =================================================================
router>enable
router#
router#term len 0
router#term width 512
router#sh ver
Cisco IOS Software, C2900 Software (C2900-UNIVERSALK9-M), Version 15.1(4)M4, RELEASE SOFTWARE (fc1)
router#
router#
--router.change
No changes applied
=END=

############################################################
=TITLE=Banner contains prompt character
=SCENARIO=
 ###################################
 # Login for authorized users only #
 ###################################
Password:<!>
router>
# enable
Password:<!>
 ###########################
 # All commands are logged #
 # managed by NetSPoC      #
 ###########################
# sh ver
Cisco IOS Software, C2900 Software (C2900-UNIVERSALK9-M), Version 15.1(4)M4, RELEASE SOFTWARE (fc1)
=NETSPOC=NONE
=OUTPUT=
--router.login
 ###################################
 # Login for authorized users only #
 ###################################
Password:secret

router>enable
Password:secret

 ###########################
 # All commands are logged #
 # managed by NetSPoC      #
 ###########################
router#
router#term len 0
router#term width 512
router#sh ver
Cisco IOS Software, C2900 Software (C2900-UNIVERSALK9-M), Version 15.1(4)M4, RELEASE SOFTWARE (fc1)
router#
router#
=END=

############################################################
=TITLE=Conf mode, reload banner, small change, write mem
=SCENARIO=
[[std_scenario]]
# sh run
ip route 10.0.0.0 255.0.0.0 10.1.2.3
# \BANNER2/



***
*** --- SHUTDOWN in 0:02:00 ---
***
# \BANNER2_prompt/





***
*** --- SHUTDOWN in 0:02:00 ---
***

router#
# \BANNER1/



***
*** --- SHUTDOWN in 0:01:00 ---
***
# \BANNER2_prompt/ip route 10.1.1.0 255.255.255.0 10.1.2.3
# ip route 10.1.2.0 255.255.255.0 10.2.3.4\BANNER2_prompt/
# ip route 10.1.3.0 255.255.255.0 10.2.3.5\BANNER2/
# no ip route 10.0.0.0 25\BANNER2/5.0.0.0 10.1.2.3
# ip\BANNER1/ route 10.0.0.0 255.0.0.0 10.11.22.33
# write memory
Building configuration...
  Compressed configuration from 106098 bytes to 30504 bytes[OK]
=NETSPOC=
ip route 10.0.0.0 255.0.0.0 10.11.22.33
ip route 10.1.1.0 255.255.255.0 10.1.2.3
ip route 10.1.2.0 255.255.255.0 10.2.3.4
ip route 10.1.3.0 255.255.255.0 10.2.3.5
=OUTPUT=
------ router.login
Enter Password:secret

banner motd  managed by NetSPoC
router>enable
router#
router#term len 0
router#term width 512
router#sh ver
Cisco IOS Software, C2900 Software (C2900-UNIVERSALK9-M), Version 15.1(4)M4,
router#
router#
------ router.change
configure terminal
Enter configuration commands, one per line.  End with CNTL/Z.
router#no logging console
router#line vty 0 15
router#logging synchronous level all
router#ip subnet-zero
router#ip classless
router#end
router#reload in 2

System configuration has been modified. Save? [yes/no]: n

Reload reason: Reload Command
Proceed with reload? [confirm]

router#configure terminal
Enter configuration commands, one per line.  End with CNTL/Z.
router#




***
*** --- SHUTDOWN in 0:02:00 ---
***

router#ip route 10.1.1.0 255.255.255.0 10.1.2.3
router#ip route 10.1.2.0 255.255.255.0 10.2.3.4




***
*** --- SHUTDOWN in 0:02:00 ---
***

router#
router#ip route 10.1.3.0 255.255.255.0 10.2.3.5


***
*** --- SHUTDOWN in 0:02:00 ---
***

router#no ip route 10.0.0.0 25


***
*** --- SHUTDOWN in 0:02:00 ---
***
5.0.0.0 10.1.2.3
router#ip


***
*** --- SHUTDOWN in 0:01:00 ---
***
 route 10.0.0.0 255.0.0.0 10.11.22.33
router#do reload in 2

System configuration has been modified. Save? [yes/no]: n

Reload reason: Reload Command
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
=END=

############################################################
=TITLE=Unexpected command output while reload is scheduled
=SCENARIO=
[[std_scenario]]
# ip route 10.0.0.0 255.0.0.0 10.1.2.4
failed
=NETSPOC=
ip route 10.0.0.0 255.0.0.0 10.1.2.4
=ERROR=
ERROR>>> Got unexpected output from 'ip route 10.0.0.0 255.0.0.0 10.1.2.4':
ERROR>>> failed
=OUTPUT=
--router.change
configure terminal
Enter configuration commands, one per line.  End with CNTL/Z.
router#no logging console
router#line vty 0 15
router#logging synchronous level all
router#ip subnet-zero
router#ip classless
router#end
router#reload in 2

System configuration has been modified. Save? [yes/no]: n

Reload reason: Reload Command
Proceed with reload? [confirm]

router#configure terminal
Enter configuration commands, one per line.  End with CNTL/Z.
router#ip route 10.0.0.0 255.0.0.0 10.1.2.4
failed
router#end
router#reload cancel


***
*** --- SHUTDOWN ABORTED ---
***
router#
router#
=END=

############################################################
=TITLE=Info message and warning in command output
=SCENARIO=
[[std_scenario]]
# ip route 10.20.0.0 255.255.0.0 10.1.2.3
INFO: ignored text
WARNING: Route already exists
=NETSPOC=
ip route 10.20.0.0 255.255.0.0 10.1.2.3
=WARNING=
WARNING>>> Got unexpected output from 'ip route 10.20.0.0 255.255.0.0 10.1.2.3':
WARNING>>> WARNING: Route already exists
=END=

############################################################
=TITLE=write mem: overwrite previous NVRAM
=SCENARIO=
[[std_scenario]]
# sh run
ip route 10.0.0.0 255.0.0.0 10.1.2.3
# write memory
Warning: Attempting to overwrite an NVRAM configuration previously written by a different version of the system image.
Overwrite the previous NVRAM configuration?[confirm]<!>
Building configuration...
  Compressed configuration from 10194 bytes to 5372 bytes[OK]
=NETSPOC=
ip route 10.0.0.0 255.0.0.0 10.11.22.33
=OUTPUT=
------ router.login
Enter Password:secret

banner motd  managed by NetSPoC
router>enable
router#
router#term len 0
router#term width 512
router#sh ver
Cisco IOS Software, C2900 Software (C2900-UNIVERSALK9-M), Version 15.1(4)M4,
router#
router#
------ router.change
configure terminal
Enter configuration commands, one per line.  End with CNTL/Z.
router#no logging console
router#line vty 0 15
router#logging synchronous level all
router#ip subnet-zero
router#ip classless
router#end
router#reload in 2

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
=END=

############################################################
=TITLE=write mem: abort on too large config
=SCENARIO=
[[std_scenario]]
# sh run
ip route 10.0.0.0 255.0.0.0 10.1.2.3
# write memory
Building configuration...
Compressed configuration is too large for nvram
Truncate config?? [no]:
=NETSPOC=
ip route 10.0.0.0 255.0.0.0 10.11.22.33
=ERROR=
ERROR>>> write mem: unexpected result: write memory
ERROR>>> Building configuration...
ERROR>>> Compressed configuration is too large for nvram
ERROR>>> Truncate config?? [no]:
ERROR>>> router#
=END=

############################################################
=TITLE=write mem: retry if startup-config open failed
=SCENARIO=
[[std_scenario]]
# sh run
ip route 10.0.0.0 255.0.0.0 10.1.2.3
# write memory
startup-config file open failed (Device or resource busy)
=NETSPOC=
ip route 10.0.0.0 255.0.0.0 10.11.22.33
=ERROR=
ERROR>>> write mem: startup-config open failed - giving up
=END=

############################################################
=TITLE=Referencing unknown crypto map on device
=SCENARIO=
[[std_scenario]]
# sh run
interface eth0
 ip address 10.1.1.1
 crypto map x
=NETSPOC=NONE
=ERROR=
ERROR>>> While reading device: 'crypto map x' references unknown 'crypto map x'
=END=

############################################################
=TITLE=SSH timeout
=SCENARIO=
Warning: Permanently added '10.1.2.3' (RSA) to the list of known hosts.
=NETSPOC=NONE
=ERROR=
ERROR>>> while waiting for login prompt '(?i)password:|\(yes/no.*\)\?': expect: timer expired after 3 seconds
=OUTPUT=
--router.login
Warning: Permanently added '10.1.2.3' (RSA) to the list of known hosts.
=END=

############################################################
=TITLE=Missing IP address in IPv6
=SCENARIO=[[std_scenario]]
=NETSPOC=
--router
ipv6 route 10::3:0/120 10::2:2
ipv6 route 10::2:0/1 10::2:5
--ipv6/router.info
{ "model": "IOS" }
=ERROR=
ERROR>>> Missing IP address in [code/ipv6/router.info]
=END=

############################################################
=TITLE=No credentials found
=SCENARIO=[[std_scenario]]
=NETSPOC=
ip route 10.0.0.0 255.0.0.0 10.11.22.33
=SETUP=
echo pattern user pass >credentials
=ERROR=
ERROR>>> No matching entry found in credentials
=END=

############################################################
=TITLE=Bad credentials file
=SCENARIO=[[std_scenario]]
=NETSPOC=
ip route 10.0.0.0 255.0.0.0 10.11.22.33
=SETUP=
echo abc 123 >credentials
=ERROR=
ERROR>>> Expected 3 fields in lines of credentials
=END=

############################################################
=TITLE=Missing credentials file
=SCENARIO=[[std_scenario]]
=NETSPOC=
ip route 10.0.0.0 255.0.0.0 10.11.22.33
=SETUP=
rm credentials
=ERROR=
ERROR>>> Can't open credentials: no such file or directory
=END=
