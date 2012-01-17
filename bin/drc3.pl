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
use Netspoc::Approve::Device;
use Netspoc::Approve::Linux;
use Netspoc::Approve::Cisco;
use Netspoc::Approve::IOS;
use Netspoc::Approve::IOS_FW;
use Netspoc::Approve::ASA;
use Netspoc::Approve::PIX;
use Netspoc::Approve::Helper;

# VERSION: inserted by DZP::OurPkgVersion
my $version = __PACKAGE__->VERSION || 'devel';
$| = 1;    # output char by char

my %type2class = (
    Linux  => 'Netspoc::Approve::Linux',
    IOS    => 'Netspoc::Approve::IOS',
    IOS_FW => 'Netspoc::Approve::IOS_FW',
    ASA    => 'Netspoc::Approve::ASA',
    PIX    => 'Netspoc::Approve::PIX',
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
 --LOGFILE <fullpath> path for print output (default is STDOUT)
 --LOGAPPEND          if logfile already exists, append logs
 --LOGVERSIONS        do not overwrite existing logfiles
 --NOLOGMESSAGE       supress output about logfile Names
 --NOREACH            do not check if device is reachable
 -v                   show version info

END
    exit -1;
}

my $global_config = Netspoc::Approve::Device->get_global_config();
Getopt::Long::Configure("no_ignore_case");

my %opts;

&GetOptions(
    \%opts,
    'C',
    'L=s',
    't=i',
    'LOGFILE=s',
    'LOGAPPEND',
    'LOGVERSIONS',
    'NOLOGMESSAGE',
    'NOREACH',
    'v',
);

if ($opts{v}) {
    print STDERR "$version\n";
    exit;
}

my $file1 = shift or usage();
my $file2 = shift;
@ARGV and usage();

# Take basename of file as device name.
(my $name = $file1) =~ s|^.*/||;


# Get type and IP addresses from spoc file.
# If no type is found, we get an empty type and no IP.
my ($type, @ip) = Netspoc::Approve::Device->get_spoc_data($file2 || $file1);

$type or die "Can't get type from $file1\n";

# Get class from type.
my $class = $type2class{$type}
or die "Can't find class for spoc type '$type'\n";

my $job = $class->new(
    NAME          => $name,
    OPTS          => \%opts,
    GLOBAL_CONFIG => $global_config,
    IP            => shift(@ip),
);


# Handle file compare first, which doesn't need device's IP and password.
if ($file2) {
    keys %opts and usage;

    # tell the Helper that we only compare
    errpr_mode("COMPARE");
    exit($job->compare_files($file1, $file2) ? 1 : 0)
}

$job->{IP} or die "Can't get IP from spoc file\n";

# Enable logging if configured.
$job->logging();

if (!$job->{OPTS}->{NOREACH}) {
    if (!$job->check_device()) {
        errpr "$job->{NAME}: reachability test failed\n";
    }
}

# Get password from device DB.
if(my $device_info = 
   Netspoc::Approve::Device->get_obj_info($name, 
                                          $global_config->{DEVICEDBPATH}))
{
    $job->{PASS} = $device_info->{PASS};
    $job->{LOCAL_USER} = $device_info->{LOCAL_USER};
}

# Compare or approve device.

mypr "\n";
mypr "********************************************************************\n";
mypr " START: at > ", scalar localtime, " <\n";
mypr "********************************************************************\n";
mypr "\n";

$job->lock($name) or die "Approve in progress for $name\n";

# Start compare / approve.
if ($opts{C}) {
    $job->compare($file1);
}
else {
    $job->approve($file1);
}

$job->unlock($name);

mypr "\n";
mypr "********************************************************************\n";
mypr " STOP: at > ", scalar localtime, " <\n";
mypr "********************************************************************\n";
mypr "\n";


