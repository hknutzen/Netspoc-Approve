#!/usr/bin/perl -w
# Author: Arne Spetzler, Heinz Knutzen, Daniel Brunkhorst
#
# Description:
# Do the Remote Configuration of network objects

'$Id$ ' =~ / (.+),v (.+?) /;

my $id = "$1 $2";

sub version_drc3() {
    return $id;
}

$| = 1;    # output char by char

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
use Netspoc::Approve::FWSM;
use Netspoc::Approve::Helper;

my %type2class = (
    Linux  => 'Netspoc::Approve::Linux',
    IOS    => 'Netspoc::Approve::IOS',
    IOS_FW => 'Netspoc::Approve::IOS_FW',
    ASA    => 'Netspoc::Approve::ASA',
    PIX    => 'Netspoc::Approve::PIX',
    FWSM   => 'Netspoc::Approve::FWSM',
);

sub parse_ver( $ ) {
    my $package = shift;
    for my $symname (keys %{$package}) {
        my $sym = ${$package}{$symname};
        if ($sym =~ /::version_drc3/) {

            #print "$sym\n";
            print &$sym() . "\n";

            #print ${$package}{$symname}."\n";
            #main->version();
        }
        if ($sym =~ /(\S*)::\z/) {

            # print "HIT:$1\n";
            next if ($sym =~ /::main/);
            &parse_ver(\%{$sym});
        }
    }
}

####################################################################
# main
####################################################################
#
# read command line switches:

sub usage {
    print STDERR <<END;
usage: 'drc3 -v'
usage: 'drc3 [-C <level>] -P1 <conf1> -P2 <conf2> <device>'
usage: 'drc3 [-C <level>] -F1 <file1> -F2 <file2> <device>'
usage: 'drc3 <option> -N <file> <device>'

 -p [<num>]           ping with max. #num retries
 --NOREACH            do not check if device is reachable
 --PING_ONLY          only check reachability and exit
 -P <policy>          policy
 -D <dir>             database directory for object lookup
 --DEBUGVPN           debug code generation for VPN              
 -L <logdir>          path for saving telnet-logs
 -N <file>            if set, NetSPoC mode and file
 --LOGFILE <fullpath> path for print output (default is STDOUT)
 --LOGAPPEND          if logfile already exists, append logs
 --LOGVERSIONS        do not overwrite existing logfiles
 --NOLOGMESSAGE       supress output about logfile Names
 -I <username>        Username of invokator (usually submitted by approve.pl)
 -C <level>           compare device with netspoc
                      0 = show only diffs
		      1 = verbose
		      2 = show matches
		      3 = 1 & 2
		      4 = silent
 -S                   update Status
 -t <seconds>         timeout for telnet
 -P1 p<policy#>       Compare netspoc generated Configs p<policy#>
 -P2 p<policy#>
 -F1 <file1>	      Compare netspoc generated Configs given by absolute paths
 -F2 <file2>
 -Z		      ignored
 -G <file>            ignored
 -v                   show version info

END
    exit -1;
}

my $global_config = Netspoc::Approve::Device->get_global_config();
Getopt::Long::Configure("no_ignore_case");

my %opts;

&GetOptions(
    \%opts,
    'p=i',
    'P=s',
    'D=s',
    'DEBUGVPN',
    't=i',
    'L=s',
    'N=s',
    'LOGFILE=s',
    'LOGAPPEND',
    'LOGVERSIONS',
    'NOLOGMESSAGE',
    'I=s',    # invokator username
    'NOREACH',
    'PING_ONLY',
    'C=i',
    'S',
    'G=s',
    'M=i',
    'v',
    'Z',    	# ignored
    'P1=s',
    'P2=s',
    'F1=s',
    'F2=s'
);

my $nopolicy = "Policy (unknown)";

# Set default values from global configuration.
$opts{D} ||= $global_config->{DEVICEDBPATH};
$opts{P} ||= $nopolicy;

if ($opts{v}) {
    parse_ver(\%main::);
    exit unless @ARGV;
}

my $name = shift;
$name and not @_ or &usage;

# Get type and IP address from spoc file.
# Prefer local spoc file; take file from policy DB otherwise.
# This may fail if there is no spoc file or if name is an IP address.
# In this case we get an empty type and no IP.
my ($type, @ip) = 
    Netspoc::Approve::Device->get_spoc_data($global_config, 
					    $name, $opts{N} || $opts{F2});

$type or die "Can't get type from spoc file\n";

# Get class from type.
my $class = $type2class{$type}
or die "Can't find class for spoc type '$type'\n";

my $job = $class->new(
    NAME          => $name,
    OPTS          => \%opts,
    GLOBAL_CONFIG => $global_config,
);

# Enable logging if configured.
$job->logging();

# Handle methods first, which don't need device's password.
if (my $f1 = $opts{F1}) {
    my $f2 = $opts{F2} or &usage;

    # tell the Helper that we only compare
    errpr_mode("COMPARE");

    if ($job->compare_files($f1, $f2)) {

        # diffs
        exit 1;
    }
    else {

        # no diffs
        exit 0;
    }
}
if (my $p1 = $opts{P1}) {
    my $p2 = $opts{P2} or &usage;

    # tell the Helper that we only compare
    errpr_mode("COMPARE");

    $p1 = readlink $global_config->{NETSPOC} . $p1 || $p1;
    $p2 = readlink $global_config->{NETSPOC} . $p2 || $p2;

    mypr "\n";
    mypr
      "********************************************************************\n";
    mypr " START: $p1 vs. $p2 at > ", scalar localtime, " < ($id)\n";
    mypr
      "********************************************************************\n";
    mypr "\n";

    my $f1 =
        $global_config->{NETSPOC} 
      . $p1 . "/"
      . $global_config->{CODEPATH}
      . $name;
    my $f2 =
        $global_config->{NETSPOC} 
      . $p2 . "/"
      . $global_config->{CODEPATH}
      . $name;
    my $exit = 0;
    if ($job->lock($job->{NAME})) {
        if ($job->{OPTS}->{S}) {
            open_status($job);
            my $fc_state = getstatus('FC_STATE');
            if ($exit = $job->compare_files($f1, $f2)) {

                # diffs
                if ($fc_state eq 'OK') {
                    my $sec_time = time();
                    my $time     = scalar localtime($sec_time);
                    updatestatus('FC_STATE', 'DIFF');
                    updatestatus('FC_TIME',  $sec_time);

                    # this is when we first found the diffs
                    updatestatus('FC_CTIME', $time);
                }
            }
            else {

                # no diffs
                my $sec_time = time();
                my $time     = scalar localtime($sec_time);
                updatestatus('FC_LAST_OK', $p2);
                updatestatus('FC_TIME',    $sec_time);
                updatestatus('FC_CTIME',   $time);
                updatestatus('FC_STATE',   'OK');
            }
        }
        else {
            $exit = $job->compare_files($f1, $f2);
        }
        $job->unlock($job->{NAME});
    }
    else {
        errpr "approve in process for $job->{NAME}\n";
    }
    mypr "\n";
    mypr
      "********************************************************************\n";
    mypr " STOP: $p1 vs. $p2 at > ", scalar localtime, " < ($id)\n";
    mypr
      "********************************************************************\n";
    mypr "\n";
    exit $exit;
}

@ip > 0 or die "Can't get IP from spoc file\n";
$job->{IP} = shift(@ip);

# Check reachability
if (defined $job->{OPTS}->{PING_ONLY}) {
    mypr "\n";
    mypr
      "********************************************************************\n";
    mypr " START: $job->{OPTS}->{P} at > ", scalar localtime, " < ($id)\n";
    mypr
      "********************************************************************\n";
    mypr "\n";
    my $ex;
    if ($job->check_device()) {
        mypr "$job->{NAME}: reachable\n";
        $ex = 0;
    }
    else {
        mypr "$job->{NAME}: reachability test failed\n";
        $ex = -1;
    }
    mypr "\n";
    mypr
      "********************************************************************\n";
    mypr " STOP: $job->{OPTS}->{P} at > ", scalar localtime, " < ($id)\n";
    mypr
      "********************************************************************\n";
    mypr "\n";
    exit $ex;
}

if (!$job->{OPTS}->{NOREACH}) {
    if (!$job->check_device()) {
        errpr "$job->{NAME}: reachability test failed\n";
    }
}
else {
    mypr "reachability test skipped\n";
}

# Get password from device DB.
if(my $device_info = Netspoc::Approve::Device->get_obj_info($name, $opts{D}))
{
    $job->{PASS} = $device_info->{PASS};
    $job->{LOCAL_USER} = $device_info->{LOCAL_USER};
}

if (my $spoc_path = $job->{OPTS}->{N}) {

    # compare or approve network devices
    $job->{POLICY} = $job->{OPTS}->{P};
    mypr "\n";
    mypr
      "********************************************************************\n";
    mypr " START: $job->{OPTS}->{P} at > ", scalar localtime, " < ($id)\n";
    mypr
      "********************************************************************\n";
    mypr "\n";
    if ($job->lock($job->{NAME})) {
        $job->{OPTS}->{S} and open_status($job);
        if (defined $job->{OPTS}->{C}) {
            #####################
            # compare Mode!
            #####################
            errpr_mode("COMPARE");   # tell the Helper that we only compare
            my $compare_result = $job->compare($spoc_path);
            unless ($job->{OPTS}->{P} eq $nopolicy) {
                unless ($job->{POLICY} =~ /^p(\d+)$/) {
                    die
                      "wrong policy format in policy spec. expected \'p<num>\'\n";
                }
                my $job_policy = $1;
                if ($job->{OPTS}->{S}) {

                    #
                    #### COMPARE STATUS FIELDS UPDATE ####
                    #
                    unless (getstatus('DEV_POLICY') =~ /^p(\d+)$/) {
                        mypr getstatus('DEV_POLICY') . "\n";
                        die "wrong policy format in device status file\n";
                    }
                    my $dev_policy = $1;
                    unless ($job->{POLICY} =~ /^p(\d+)$/) {
                        die "wrong policy format in policy spec.\n";
                    }
                    if ($compare_result) {

                        # differences found!
                        # only update status if compare is serious
                        unless ($job_policy < $dev_policy) {
                            if (getstatus('COMP_RESULT') ne 'DIFF') {
                                updatestatus('COMP_RESULT', 'DIFF');
                                updatestatus('COMP_POLICY', $job->{POLICY});
                                updatestatus('COMP_TIME',   time);
                                updatestatus('COMP_CTIME',  localtime(time()));
                            }
                            elsif (getstatus('COMP_TIME') <
                                getstatus('COMP_DTIME'))
                            {

                                # old compare result is not valid
                                updatestatus('COMP_RESULT', 'DIFF');
                                updatestatus('COMP_POLICY', $job->{POLICY});
                                updatestatus('COMP_TIME',   time());
                                updatestatus('COMP_CTIME',  localtime(time()));
                            }
                        }
                    }
                    else {

                        # no changes
                        unless (getstatus('COMP_POLICY') =~ /^p(\d+)$/) {
                            print getstatus('COMP_POLICY');
                            print "\n";
                            die "wrong policy format in device status file\n";
                        }
                        my $comp_policy = $1;

                        # only update status if compare is serious
                        unless ($job_policy < $comp_policy) {
                            updatestatus('COMP_RESULT', 'UPTODATE');
                            updatestatus('COMP_POLICY', $job->{POLICY});
                            updatestatus('COMP_TIME',   time);
                            updatestatus('COMP_CTIME',  localtime(time()));
                        }
                    }
                }
            }
        }
        else {
            ##########################
            # approve Mode!
            ##########################
            my $user;
            if ($job->{OPTS}->{I}) {
                $user = $job->{OPTS}->{I};    # user from approve.pl
            }
            else {
                $user = getpwuid($>);
            }
            if ($job->{OPTS}->{S}) {

                # set approve Status to 'ERROR' - later reset to 'WARNINGS' or 'OK'
                updatestatus('DEVICENAME', $job->{NAME});
                updatestatus('APP_TIME',   scalar localtime);
                updatestatus('APP_STATUS', '***UNFINISHED APPROVE***');
                updatestatus('APP_USER',   $user);
                updatestatus('APP_POLICY', $job->{OPTS}->{P});
            }
            $job->approve($spoc_path);
            if ($job->{OPTS}->{S}) {

                # set approve/device status to 'WARNINGS' or 'OK'
                my $sec_time = time();
                my $time     = scalar localtime($sec_time);
                updatestatus('APP_TIME',   $time);
                updatestatus('DEV_TIME',   $time);
                updatestatus('COMP_DTIME', $sec_time);
                updatestatus('DEV_USER',   $user);
                updatestatus('DEV_POLICY', $job->{OPTS}->{P});
                if (check_erro() eq "YES") {
                    updatestatus('APP_STATUS', '***ERRORS***');
                    updatestatus('DEV_STATUS', '***ERRORS***');
                }
                elsif (check_warn() eq "YES") {
                    updatestatus('APP_STATUS', '***WARNINGS***');
                    updatestatus('DEV_STATUS', '***WARNINGS***');
                }
                else {
                    updatestatus('APP_STATUS', 'OK');
                    updatestatus('DEV_STATUS', 'OK');
                }
            }
        }
        $job->unlock($job->{NAME});
    }
    else {
        errpr "approve in process for $job->{NAME}\n";
    }
    mypr "\n";
    mypr
      "********************************************************************\n";
    mypr " STOP: $job->{OPTS}->{P} at > ", scalar localtime, " < ($id)\n";
    mypr
      "********************************************************************\n";
    mypr "\n";
}
else {
    errpr_info "Invalid option\n";
    usage();
}
exit;

