#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Approve;

# Input from Netspoc, from raw, output from approve.
my($spoc, $out, $title);

############################################################
$title = "Missing device type";
############################################################

$spoc = {
spoc4 => <<END
route inside 10.20.0.0 255.255.255.0 10.1.2.3
route inside 10.22.0.0 255.255.0.0 10.1.2.4
END
,
info4 => <<END
{"ip_list": "1.2.3.4" }
END
};

$out = <<END;
ERROR>>> Can't get device type from file(s): router.info
END

drc3_err($title, 'ASA', $spoc, $out);

############################################################
$title = "No IP address in IPv6";
############################################################

$spoc = {
spoc6 => <<END
ipv6 route 10::3:0/120 10::2:2
ipv6 route 10::2:0/1 10::2:5
END
,
info6 => <<END
{ "model": "IOS" }
END
};

$out = <<END;
ERROR>>> Can't get IP from file(s): ipv6/router.info
END

drc3_err($title, 'IOS', $spoc, $out);

############################################################
$title = "Invalid option";
############################################################

$out = <<'END';
Unknown option: h
usage: 'drc3.pl [options] <file>'
   or: 'drc3.pl <file1> <file2>'
Compare / approve file with device or compare two files.
 -C                   compare only
 -u <username>        use username for login to remote device
 -q                   suppress info messages to STDERR
 -L <logdir>          path for saving session logs
 --LOGFILE <fullpath> path to redirect STDOUT and STDERR
 -v                   print program version

END

my ($status, $stdout, $stderr) = run("bin/drc3.pl -h");

eq_or_diff($stderr, $out, $title);

############################################################
$title = "Show version";
############################################################

$out = <<'END';
drc3.pl, version TESTING
END

($status, $stdout, $stderr) = run("bin/drc3.pl -v");
$stderr =~ s/(?<=^drc3.pl, version ).*/TESTING/;

eq_or_diff($stderr, $out, $title);

############################################################
done_testing;
