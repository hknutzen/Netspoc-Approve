#!/usr/bin/perl -w
# Author: Arne Spetzler, Heinz Knutzen, Daniel Brunkhorst
#
# Description:
# Approving device with netspoc configuration.
#

use strict;
use warnings;
use Fcntl qw/:flock/;    # import LOCK_* constants
use Fcntl;
use Getopt::Long;
use Netspoc::Approve::Load_Config;
use Netspoc::Approve::Device;
use Netspoc::Approve::Linux;
use Netspoc::Approve::Cisco;
use Netspoc::Approve::IOS;
use Netspoc::Approve::ASA;
use Netspoc::Approve::PIX;
use Netspoc::Approve::NX_OS;
use Netspoc::Approve::Helper;

our $VERSION = '1.073'; # VERSION: inserted by DZP::OurPkgVersion
my $version = __PACKAGE__->VERSION || 'devel';
$| = 1;    # output char by char

my %type2class = (
    Linux   => 'Netspoc::Approve::Linux',
    IOS     => 'Netspoc::Approve::IOS',
    ASA     => 'Netspoc::Approve::ASA',
    PIX     => 'Netspoc::Approve::PIX',
    'NX-OS' => 'Netspoc::Approve::NX_OS',
);

####################################################################
# main
####################################################################
#
# read command line switches:

sub usage {
    print STDERR <<END;
usage: 'drc3.pl [options] <file>'
   or: 'drc3.pl <file1> <file2>'
Compare / approve file with device or compare two files.
 -C                   compare device with netspoc
 -L <logdir>          path for saving telnet-logs
 -t <seconds>         timeout for telnet
 -q                   Suppress info messages to STDERR
 --LOGFILE <fullpath> Path to redirect STDOUT and STDERR
 --NOREACH            do not check if device is reachable
 -v                   show version info

END
    exit -1;
}

sub banner_msg {
    my ($msg) = @_;
    my $time = localtime;
    info('*' x 68);
    info(" $msg: at > $time <");
    info('*' x 68);
}

Getopt::Long::Configure("no_ignore_case");

my %opts;

&GetOptions(
    \%opts,
    'C',
    'L=s',
    't=i',
    'q',
    'LOGFILE=s',
    'NOREACH',
    'v',
);

if ($opts{v}) {
    info $version;
    exit;
}
delete($opts{q}) and quiet();

my $file1 = shift or usage();
my $file2 = shift;
@ARGV and usage();

# Take basename of file as device name.
(my $name = $file1) =~ s|^.*/||;

# Get type and IP addresses from spoc file.
my $spoc_file = $file2 || $file1;
my ($type, @ip) = Netspoc::Approve::Device->get_spoc_data($spoc_file);

$type or abort("Can't get device type from $spoc_file");

# Get class from type.
my $class = $type2class{$type}
  or abort("Can't find class for [ Model = $type ] from $spoc_file");

my $job = $class->new(
    NAME   => $name,
    OPTS   => \%opts,
    IP     => shift(@ip),
);


# Handle file compare first, which can be run
# - without device's IP and password
# - without calling Load_Config (so we can use compare_files for testing).
if ($file2) {
    keys %opts and usage;
    exit($job->compare_files($file1, $file2) ? 1 : 0)
}

$opts{t} ||= 300;
$job->{IP} or abort("Can't get IP from $spoc_file");
$job->{CONFIG} = Netspoc::Approve::Load_Config::load();

# Enable logging if configured.
$job->logging();

$job->check_reachability();
$job->lock($name);

# Start compare / approve.
banner_msg('START');
if ($opts{C}) {
    $job->compare($file1);
}
else {
    $job->approve($file1);
}
banner_msg('STOP');

$job->unlock($name);


