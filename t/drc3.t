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
$title = "No IP address in both IPv4 and IPv6";
############################################################

$spoc = {
spoc4 => <<END
route inside 10.20.0.0 255.255.255.0 10.1.2.3
route inside 10.22.0.0 255.255.0.0 10.1.2.4
END
,
spoc6 => <<END
ipv6 route inside 10::3:0/120 10::2:2
ipv6 route inside 10::2:0/1 10::2:5
END
,
hdr4 => <<END
! [ BEGIN router:r1 ]
! [ Model = ASA ]

END
,
hdr6 => <<END
! [ BEGIN router:r1 ]
! [ Model = ASA ]

END
};

$out = <<END;
ERROR>>> Can not get IP from file(s): router, ipv6/router.
END

drc3_err($title, 'ASA', $spoc, $out);

############################################################
$title = "No IP address in IPv4";
############################################################

$spoc = {
spoc4 => <<END
route inside 10.20.0.0 255.255.255.0 10.1.2.3
route inside 10.22.0.0 255.255.0.0 10.1.2.4
END
,
hdr4 => <<END
! [ BEGIN router:r1 ]
! [ Model = ASA ]

END
};

$out = <<END;
ERROR>>> Can not get IP from file(s): router.
END

drc3_err($title, 'ASA', $spoc, $out);

############################################################
$title = "No IP address in IPv6";
############################################################

$spoc = {
spoc6 => <<END
ipv6 route inside 10::3:0/120 10::2:2
ipv6 route inside 10::2:0/1 10::2:5
END
,
hdr6 => <<END
! [ BEGIN router:r1 ]
! [ Model = ASA ]

END
};

$out = <<END;
ERROR>>> Can not get IP from file(s): ipv6/router.
END

drc3_err($title, 'ASA', $spoc, $out);

############################################################
$title = "Different device types for same device";
############################################################

$spoc = {
spoc4 => <<END
route inside 10.20.0.0 255.255.255.0 10.1.2.3
route inside 10.22.0.0 255.255.0.0 10.1.2.4
END
,
spoc6 => <<END
ipv6 route inside 10::3:0/120 10::2:2
ipv6 route inside 10::2:0/1 10::2:5
END
,
hdr4 => <<END
! [ BEGIN router:r1 ]
! [ Model = ASA ]
! [ IP = 10.12.13.14 ]

END
,
hdr6 => <<END
! [ BEGIN router:r1 ]
! [ Model = IOS ]
! [ IP = 10::13 ]

END
};

$out = <<END;
ERROR>>> Ambiguous model specification for device router: ASA, IOS.
END

drc3_err($title, 'ASA', $spoc, $out);

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
