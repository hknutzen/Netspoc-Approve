#!/usr/bin/perl -w
# Author: Arne Spetzler, Heinz Knutzen, Daniel Brunkhorst
#
# Description:
# Do the Remote Configuration of network objects

'$Id$ ' =~ / (.+),v (.+?) /;

my $id = "$1 $2";

sub version_drc2() {
    return $id;
}

$| = 1;    # output char by char

use FindBin;
use lib $FindBin::Bin;
use strict;
use warnings;

use Fcntl qw/:flock/;    # import LOCK_* constants
use Fcntl;
use Getopt::Long;

use Netspoc::Approve::Device;
use Netspoc::Approve::Device::Cisco::IOS;
use Netspoc::Approve::Device::Cisco::IOS::FW;
use Netspoc::Approve::Device::Cisco::Firewall::ASA;
use Netspoc::Approve::Device::Cisco::Firewall::PIX;
use Netspoc::Approve::Device::Cisco::Firewall::PIX::Fwsm;
use Netspoc::Approve::Helper;

my %type2class = (
    IOS    => 'Netspoc::Approve::Device::Cisco::IOS',
    IOS_FW => 'Netspoc::Approve::Device::Cisco::IOS:FW',
    ASA    => 'Netspoc::Approve::Device::Cisco::Firewall::ASA',
    PIX    => 'Netspoc::Approve::Device::Cisco::Firewall::PIX',
    FWSM   => 'Netspoc::Approve::Device::Cisco::Firewall::PIX::Fwsm',
);

sub parse_ver( $ ) {
    my $package = shift;
    for my $symname (keys %{$package}) {
        my $sym = ${$package}{$symname};
        if ($sym =~ /::version_drc2/) {

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
    errpr_mode("COMPARE");
    errpr "usage: 'drc2 -v'\n";
    errpr "usage: 'drc2 [-C <level>] -P1 <conf1> -P2 <conf2> <device>'\n";
    errpr "usage: 'drc2 [-C <level>] -F1 <file1> -F2 <file2> <device>'\n";
    errpr "usage: 'drc2 <option> -N <file> <device>'\n\n";

    mypr <<END;
 -p [<num>]           ping with max. #num retries
 --NOREACH            do not check if device is reachable
 --PING_ONLY          only check reachability and exit
 -P <policy>          policy
 -D <dir>             database directory for object lookup
 --DEBUGVPN           debug code generation for VPN              
 -L <logdir>          path for saving telnet-logs
 -E <command>         if set, execute command on remote obj and show output
 -N <file>            if set, NetSPoC mode and file
 -G <file>            if set, file with epiloG data
 --LOGFILE <fullpath> path for print output (default is STDOUT)
 --LOGAPPEND          if logfile already exists, append logs
 --LOGVERSIONS        do not overwrite existing logfiles
 --NOLOGMESSAGE       supress output about logfile Names
 -I <username>        Username of Invokator (usually submitted by approve.pl)
 -C <level>           compare device with netspoc
                      0 = show only diffs
		      1 = verbose
		      2 = show matches
		      3 = 1 & 2
		      4 = silent
 -R                   cRypto map checking
 -S                   update Status
 -t <seconds>         timeout for telnet
 -T <telnet port>     port for telnet access. default is 23
 -F                   Force transfer of ACLs with fake ACE
 -h no                hostname checking in spocfile off
 -P1 p<policy#>       Compare netspoc generated Configs p<policy#>
 -P2 p<policy#>
 -F1 <file1>	      Compare netspoc generated Configs given by absolute paths
 -F2 <file2>
 -v                   show version info

END
    exit;
}

my $global_config = Netspoc::Approve::Device->get_global_config();
Getopt::Long::Configure("no_ignore_case");

my %opts = ();

&GetOptions(
    \%opts,
    'p=i',
    'P=s',
    'D=s',
    'DEBUGVPN',
    't=i',
    'L=s',
    'E=s',
    'N=s',
    'LOGFILE=s',
    'LOGAPPEND',
    'LOGVERSIONS',
    'NOLOGMESSAGE',
    'I:s',    # optional invokator username
    'NOREACH',
    'PING_ONLY',
    'C=i',
    'A=s',
    'R',
    'S',
    'G=s',
    'T=i',
    'F',
    'h=s',
    'M=i',
    'v',
    'Z:s',    #device type is optional
    'P1=s',
    'P2=s',
    'FC=s',
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

my $netobj = shift;
$netobj and not @_ or &usage;

my $device_info =
  Netspoc::Approve::Device->get_obj_info($netobj, $opts{D}, $global_config);
my $name  = $device_info->{NAME};
my $type  = Netspoc::Approve::Device->get_spoc_type($name, $global_config);
my $class = $type2class{$type}
  or die "Cant't handle type '$type' of $netobj\n";

my $job = $class->new(
    NAME          => $name,
    IP            => $device_info->{IP},
    PASS          => $device_info->{PASS},
    LOCAL_USER    => $device_info->{LOCAL_USER},
    OPTS          => \%opts,
    GLOBAL_CONFIG => $global_config,
);

# enable logging if configured
$job->logging();

if (my $f1 = $opts{F1}) {
    my $f2 = $opts{F2} or &usage;

    # tell the drc2_helper that we only compare
    errpr_mode("COMPARE");

    if ($job->compare_files($f1, $f2)) {

        # diffs
        mypr "Diffs:\n";
        exit 1;
    }
    else {

        # no diffs
        exit 0;
    }
}
if (my $p1 = $opts{P1}) {
    my $p2 = $opts{P2} or &usage;

    # tell the drc2_helper that we only compare
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
      . $netobj;
    my $f2 =
        $global_config->{NETSPOC} 
      . $p2 . "/"
      . $global_config->{CODEPATH}
      . $netobj;

    if ($job->lock($job->{NAME})) {
        if ($job->{OPTS}->{S}) {
            open_status($job);
            my $fc_state = getstatus('FC_STATE');
            if ($job->compare_files($f1, $f2)) {

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
            $job->compare_files($f1, $f2);
        }
        $job->unlock($job->{NAME});
    }
    else {
        errpr "approve in process for $job->{NAME}\n";
        exit -1;
    }
    mypr "\n";
    mypr
      "********************************************************************\n";
    mypr " STOP: $p1 vs. $p2 at > ", scalar localtime, " < ($id)\n";
    mypr
      "********************************************************************\n";
    mypr "\n";
    exit;
}

# check reachability
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

elsif (!$job->{OPTS}->{NOREACH}) {
    if (!$job->check_device()) {
        errpr "$job->{NAME}: reachability test failed\n";
        exit -1;
    }
}
else {
    mypr "reachability test skipped\n";
}

if ($job->{OPTS}->{R}) {

    # check Crypto Config
    $job->check_crypto();
}
elsif ($job->{OPTS}->{E}) {

    # execute user command
    errpr_mode("COMPARE")
      ;    # tell the drc2_helper not to print message approve aborted
    $job->remote_execute();
}
elsif (my $spoc_path = $job->{OPTS}->{N}) {

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
            errpr_mode("COMPARE");   # tell the drc2_helper that we only compare
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
    errpr "unknown option\n";
    usage();
    exit -1;
}
exit;

