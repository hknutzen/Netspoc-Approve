#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Approve;

my($scenario, $scenario2, $in, $out, $title);

############################################################
$title = "SSH login + enable password";
############################################################
$scenario = <<'END';
Enter Password:<!>
banner motd managed by NetSPoC
router>
# enable
Password:<!>
# sh ver
Cisco IOS XE Software, Version 16.06.05
 Cisco IOS Software [Everest], ISR Software (X86_64_LINUX_IOSD-UNIVERSALK9-M), Version 16.6.5, RELEASE SOFTWARE (fc3)
END

$in = '';

$out = <<'END';
--router.login
Enter Password:secret

banner motd managed by NetSPoC
router>enable
Password:secret

router#
router#term len 0
router#term width 512
router#sh ver
Cisco IOS XE Software, Version 16.06.05
 Cisco IOS Software [Everest], ISR Software (X86_64_LINUX_IOSD-UNIVERSALK9-M), Version 16.6.5, RELEASE SOFTWARE (fc3)
router#
router#
END

simul_run($title, 'IOS', $scenario, $in, $out);

############################################################
$title = "No credentials found ";
############################################################
# Reuse previous test data.

my $dir = $ENV{HOME};

my $credentials_file = "$dir/credentials";
write_file($credentials_file, <<"END");
pattern user pass
END

my $err = <<'END';
ERROR>>> No matching entry found in credentials
END

my ($status, $stdout, $stderr) = run("bin/drc3.pl -q -L $dir $dir/code/router");
$stderr ||= '';
$stderr =~ s/\Q$dir\E\///;
eq_or_diff($stderr, $err, $title);

############################################################
$title = "Bad credentials file";
############################################################
# Reuse previous test data.

write_file($credentials_file, <<"END");
abc 123
END

$err = <<'END';
ERROR>>> Expected 3 fields in lines of credentials
END

($status, $stdout, $stderr) = run("bin/drc3.pl -q -L $dir $dir/code/router");
$stderr ||= '';
$stderr =~ s/\Q$dir\E\///;
eq_or_diff($stderr, $err, $title);

############################################################
$title = "Missing credentials file";
############################################################
# Reuse previous test data.

unlink $credentials_file;

$err = <<'END';
ERROR>>> Can't open credentials: no such file or directory
END

($status, $stdout, $stderr) =
    run("bin/drc3.pl -q -L $ENV{HOME} $ENV{HOME}/code/router");
$stderr ||= '';
$stderr =~ s/\Q$dir\E\///;
eq_or_diff($stderr, $err, $title);

############################################################
$title = "SSH login with prompt to TTY, password from user";
############################################################
# Reuse previous test data.

# Create config file without system user.
my $config_file = "$dir/.netspoc-approve";
write_file($config_file, <<"END");
netspocdir = $dir
lockfiledir = $dir
checkbanner = NetSPoC
timeout = 1
END

use Expect;
my $expect = Expect->new();
$expect->log_stdout(0);
my $id = getpwuid($<);
$expect->spawn(
    "$^X -I lib bin/drc3.pl -q -u $id -L $dir $dir/code/router")
    or die "Cannot spawn";

ok($expect->expect(2, "password for"), "$title: prompt");
$expect->send("secret\n");
$expect->expect(2, 'eof');
$expect->soft_close();

check_output($title, $dir, $out, '');

############################################################
$title = "write mem: unexpected output";
############################################################
# Used for multiple tests below
$scenario = <<'END';
Enter Password:<!>
banner motd  managed by NetSPoC
router>
# sh ver
Cisco IOS Software, C2900 Software (C2900-UNIVERSALK9-M), Version 15.1(4)M4,
# sh run
ip route 10.0.0.0 255.0.0.0 10.1.2.3
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
foo
END

$in = <<'END';
ip route 10.0.0.0 255.0.0.0 10.11.22.33
END

$out = <<'END';
ERROR>>> write mem: unexpected result: write memory
ERROR>>> foo
ERROR>>> router#
END

simul_err($title, 'IOS', $scenario, $in, $out);

############################################################
$title = "Log STDERR + STDOUT to file";
############################################################
# Reuse previous test data.

$dir = $ENV{HOME};
$out = <<"END";
--file
ERROR>>> write mem: unexpected result: write memory
ERROR>>> foo
ERROR>>> router#
END

($status, $stdout, $stderr) =
    run("bin/drc3.pl -q -L $dir --LOGFILE $dir/file $dir/code/router");
$stderr ||= '';
check_output($title, $dir, $out, $stderr);

############################################################
$title = "Log STDERR + STDOUT to file in new dir";
############################################################
# Reuse previous test data.

$dir = $ENV{HOME};
$out = <<"END";
--d/file
ERROR>>> write mem: unexpected result: write memory
ERROR>>> foo
ERROR>>> router#
END

($status, $stdout, $stderr) =
    run("bin/drc3.pl -q -L $dir --LOGFILE $dir/d/file $dir/code/router");
$stderr ||= '';
check_output($title, $dir, $out, $stderr);

############################################################
$title = "Can't create log directory";
############################################################
# Reuse previous test data.

$dir = $ENV{HOME};
$out = <<"END";
ERROR>>> Can\'t create file: File exists
END

($status, $stdout, $stderr) =
    run("bin/drc3.pl -q -L $dir --LOGFILE $dir/file/f $dir/code/router");
$stderr ||= '';

# Normalize path: remove temp. directory in output.
$stderr =~ s/\Q$dir\E\///g;
check_output($title, $dir, $out, $stderr);

############################################################
done_testing;
