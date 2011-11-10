#!/usr/bin/perl -w
# Author: Arne Spetzler, Heinz Knutzen, Daniel Brunkhorst
#
# Description:
# Approving device with netspoc configuration.
#
# $Id$

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

our $VERSION = sprintf "%d.%03d", q$Revision$ =~ /(\d+)/g;

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
usage: 'drc3.pl <file1> <file2>'
usage: 'drc3.pl -v'

 -C                   compare device with netspoc
 --NOREACH            do not check if device is reachable
 -L <logdir>          path for saving telnet-logs
 -N <file>            if set, NetSPoC mode and file
 --LOGFILE <fullpath> path for print output (default is STDOUT)
 --LOGAPPEND          if logfile already exists, append logs
 --LOGVERSIONS        do not overwrite existing logfiles
 --NOLOGMESSAGE       supress output about logfile Names
 -I <username>        Username of invokator (usually submitted by approve.pl)
 -P <policy>          policy
 -S                   update Status
 -t <seconds>         timeout for telnet
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
    'NOREACH',
    'L=s',
    'N=s',
    'LOGFILE=s',
    'LOGAPPEND',
    'LOGVERSIONS',
    'NOLOGMESSAGE',
    'I=s',
    'P=s',
    'S',
    't=i',
    'v',
);

if ($opts{v}) {
    print STDERR "$VERSION\n";
    exit;
}

my $file1 = shift or usage();
my $file2 = shift;
@ARGV and usage();

# Take basename of file as device name.
(my $name = $file1) =~ s|^[^/]*/||;


# Get type and IP address from spoc file.
# Prefer local spoc file; take file from policy DB otherwise.
# This may fail if there is no spoc file or if name is an IP address.
# In this case we get an empty type and no IP.
my ($type, @ip) = Netspoc::Approve::Device->get_spoc_data($file1);

$type or die "Can't get type from $file1\n";

# Get class from type.
my $class = $type2class{$type}
or die "Can't find class for spoc type '$type'\n";

my $job = $class->new(
    NAME          => $name,
    OPTS          => \%opts,
    GLOBAL_CONFIG => $global_config,
);

# Handle file compare first, which doesn't need device's IP and password.
if ($file2) {
    keys %opts and usage;

    # tell the Helper that we only compare
    errpr_mode("COMPARE");
    exit($job->compare_files($file1, $file2) ? 1 : 0)
}

@ip > 0 or die "Can't get IP from spoc file\n";
$job->{IP} = shift(@ip);

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

# Compare or approve network device.
$opts{S} and $opts{P} or die "Must set option 'P' if option 'S' is set.\n";
my $policy = $opts{P} || 'Policy (unknown)';

mypr "\n";
mypr "********************************************************************\n";
mypr " START: $policy at > ", scalar localtime, " <\n";
mypr "********************************************************************\n";
mypr "\n";

$job->lock($job->{NAME}) or die "Approve in process for $job->{NAME}\n";

$opts{S} and open_status($job);

# Compare mode.
if ($opts{C}) {
    errpr_mode("COMPARE");
    my $found_changes = $job->compare($file1);

    # Update compare status fields.
    if ($opts{S}) {
        if ($found_changes) {

            # Only update compare status, 
            # - if status changed to diff for first time,
            # - or device was approved since last compare.
            if (getstatus('COMP_RESULT') ne 'DIFF' ||
                   getstatus('COMP_TIME') < getstatus('COMP_DTIME')) {
                updatestatus('COMP_RESULT', 'DIFF');
                updatestatus('COMP_POLICY', $policy);
                updatestatus('COMP_TIME',   time());
                updatestatus('COMP_CTIME',  localtime(time()));
            }
        }

        # No changes.
        else {
            updatestatus('COMP_RESULT', 'UPTODATE');
            updatestatus('COMP_POLICY', $policy);
            updatestatus('COMP_TIME',   time());
            updatestatus('COMP_CTIME',  localtime(time()));
        }
    }
}

# Approve mode.
else {
    my $user = $opts{I} || getpwuid($>);

    if ($opts{S}) {
        
        # Set preliminary approve status.
        updatestatus('DEVICENAME', $name);
        updatestatus('APP_TIME',   scalar localtime());
        updatestatus('APP_STATUS', '***UNFINISHED APPROVE***');
        updatestatus('APP_USER',   $user);
        updatestatus('APP_POLICY', $policy);
    }
    $job->approve($file1);
    if ($opts{S}) {
        
        # Set real approve status.
        my $status = (check_erro() eq "YES")
                   ? '***ERRORS***'
                   : (check_warn() eq "YES")
                   ? '***WARNINGS***'
                   : 'OK';
        my $sec_time = time();
        my $time     = localtime($sec_time);
        updatestatus('APP_TIME',   $time);
        updatestatus('DEV_TIME',   $time);
        updatestatus('COMP_DTIME', $sec_time);
        updatestatus('DEV_USER',   $user);
        updatestatus('DEV_POLICY', $policy);
        updatestatus('APP_STATUS', $status);
        updatestatus('DEV_STATUS', $status);
    }
}
$job->unlock($job->{NAME});

mypr "\n";
mypr "********************************************************************\n";
mypr " STOP: $policy at > ", scalar localtime, " <\n";
mypr "********************************************************************\n";
mypr "\n";


