#! /usr/bin/perl -w
# Author: Arne Spetzler
# Address: spoc@spetzler.de, arne.spetzler@dzsh.de
# Description:
# Do the Remote Configuration of network objects 

'$Id$ '=~ / (.+),v (.+?) /; 
 
my $id = "$1 $2";

sub version_drc2(){
    return $id;
}

$| = 1;				# output char by char 

use FindBin;
use lib $FindBin::Bin;
use strict;
use warnings;

use drc2_job;
use drc2_helper;
use drc2_pix;
use drc2_ios;
use drc2_linux;
use drc2_vpn;
use drc2_fwsm;

#---------------------------------------------------------
#require Ping; import Ping;
#require Acltools; import Acltools;

use Fcntl qw/:flock/; # import LOCK_* constants
use Fcntl;

use Getopt::Long;


sub parse_ver( $ ){
    my $package = shift;
    for my $symname (keys %{$package}){
	my $sym = ${$package}{$symname};
	if($sym =~ /::version_drc2/){
	    #print "$sym\n";
	    print &$sym()."\n";
	    #print ${$package}{$symname}."\n";
	    #main->version();
	}
	if($sym =~ /(\S*)::\z/){
	   # print "HIT:$1\n";
	    next if($sym =~ /::main/);
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
    errpr "usage: 'drc2 -v' or\n";
    errpr "usage: 'drc2 [-C <level>] -Z [<devicetype>] -P1 <conf1> -P2 <conf2> <device>'\n";
    errpr "usage: 'drc2 [-C <level>] -FC <devicetype> -F1 <file1> -F2 <file2>'\n";
    errpr "usage: 'drc2 <option> <object specifier>'\n\n";

mypr  <<END;
 -p [<trys>]          ping with max. #trys retrys
 --NOREACH            do not check if device is reachable
 --PING_ONLY          only check reachability and exit
 -P <policy>          policy
 -D <dir>             database directory for object lookup
 --DEBUGVPN           debug code generation for VPN              
 -t <seconds>         timeout for telnet
 -L <logdir>          path for saving telnet-logs
 -E <command>         if set, execute command on remote obj and show output
 -N <file>            if set, NetSPoC mode and file
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
 -A <packet>          ACL-Check if packet is permitted by device
 -R                   cRypto map checking
 -S                   update Status
 -G <file>            if set, file with epiloG data
 -T <telnet port>     port for telnet access. default is 23
 -F                   Force transfer of ACLs with fake ACE
 -h no                hostname checking in spocfile off
 -M <hits>            Migrate Report. Show top 'hits' ace matches
 -Z <devicetype>      Compare netspoc generated Configs (<conf1> and <conf2>) if devicetype is
                      omitted, take from device database
 -P1                  p<policy#>
 -P2                  p<policy#>
 -FC <devicetype>     Compare netspoc generated Configs given by absolute paths <file1> <file2>
                      <devicetype> could be ios or pix
 -F1 <file1>
 -F2 <file2>
 -v                   show version info

END
 exit;
}

Getopt::Long::Configure("no_ignore_case");

my %opts = ();

&GetOptions(\%opts, 
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
	    'I:s', # optional invokator username
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
	    'Z:s', #device type is optional
	    'P1=s',
	    'P2=s',
	    'FC=s',
            'F1=s',
            'F2=s');
    
if($opts{v}){
    #print "$id\n";
    #for my $symname (keys %main::){
#	print $main::{$symname}."\n";
#    }
    parse_ver(\%main::);
    #print Acltools->version()."\n";
    #print Dprs->version()."\n";
    exit unless @ARGV;
}

my $job = drc2_job->new(\%opts);
# enable logging if configured
$job->logging();
# save global config from global config file
$job->get_global_config();

if(exists $opts{FC}){
    ($opts{FC}) or  &usage;
    $job->{OPTS}->{Z} = $opts{FC}; # devicetype must be in Z!
    errpr_mode("COMPARE");	# tell the drc2_helper that we only compare
    # initialize base job data
    my $netobj = "__file__";
    $netobj or &usage;
    ($job->{JOBNAME},$job->{JOBTYPE}) = $job->build_obj($netobj);
    # bless to job specific module !
    bless($job,"drc2_$job->{JOBTYPE}");
    my $job2 = drc2_job->new(\%opts);
    $job2->{OPTS}->{Z} = $opts{FC}; # devicetype must be in Z!
    $job2->get_global_config();
    ($job2->{JOBNAME},$job2->{JOBTYPE}) = $job2->build_obj($netobj);
    # bless to job specific module !
    bless($job2,"drc2_$job->{JOBTYPE}");
    $job->{OPTS}->{h} = "no"; # do not check devicename
    $job->{OPTS}->{N} = $job->{OPTS}->{F1};
    $job->{OPTS}->{G} = '.';
    $job->load_spocfile();
    $job->load_epilog();
    $job2->{OPTS}->{N} = $job->{OPTS}->{F2};
    $job2->{OPTS}->{G} = '.';
    $job2->load_spocfile();
    $job2->load_epilog();
    
    if($job->compare_files($job2)){
	# diffs
	mypr "Diffs:\n";
	exit 1;
    }
    else{
	# no diffs
	exit 0;
    }
} 
if(exists $opts{Z}){
    errpr_mode("COMPARE"); # tell the drc2_helper that we only compare
    # initialize base job data
    my $netobj = shift;
    $netobj or &usage;
    ($opts{Z}) or $job->build_db();   # build internal db for device lookup if no devtype specified
    ($job->{JOBNAME},$job->{JOBTYPE}) = $job->build_obj($netobj);
    # bless to job specific module !
    bless($job,"drc2_$job->{JOBTYPE}");
    my $job2 = drc2_job->new(\%opts);
    $job2->get_global_config();
    ($opts{Z}) or $job2->build_db();   # build internal db for device lookup if no devtype specified
    ($job2->{JOBNAME},$job2->{JOBTYPE}) = $job2->build_obj($netobj);
    # bless to job specific module !
    bless($job2,"drc2_$job->{JOBTYPE}");

    my$GC = $job->{GLOBAL_CONFIG};

    my $p1 = readlink $GC->{NETSPOC}.$opts{P1}?readlink $GC->{NETSPOC}.$opts{P1}:$opts{P1};
    my $p2 = readlink $GC->{NETSPOC}.$opts{P2}?readlink $GC->{NETSPOC}.$opts{P2}:$opts{P2};
    
    mypr "\n";
    mypr "********************************************************************\n";
    mypr " START: $p1 vs. $p2 at > ",scalar localtime," < ($id)\n";
    mypr "********************************************************************\n";
    mypr "\n";

    # check if policys ok
    my  $p1n = $p1;
    $p1n =~ s/p//;
    my $p2n = $p2;
    $p2n =~ s/p//;
    
    if($p1n > $p2n){
	# p2 must be greater or equal than p1! 
	errpr " second policy $p2 less than first $p1!\n";
	exit -1;
    }

    $job->{OPTS}->{N} = $GC->{NETSPOC}.$p1."/".$GC->{CODEPATH}.$netobj;
    $job->{OPTS}->{G} = $GC->{NETSPOC}.$p1."/".$GC->{EPILOGPATH}.$netobj;
    $job->load_spocfile();
    $job->load_epilog();
    $job2->{OPTS}->{N} = $GC->{NETSPOC}.$p2."/".$GC->{CODEPATH}.$netobj;
    $job2->{OPTS}->{G} = $GC->{NETSPOC}.$p2."/".$GC->{EPILOGPATH}.$netobj;
    $job2->load_spocfile();
    $job2->load_epilog();

    if($job->lock($job->{JOBNAME})){
	my $fc_state;
	if($job->{OPTS}->{S}){
	    open_status($job);
	    $fc_state = getstatus('FC_STATE');
	    if($job->compare_files($job2)){
		# diffs
		if($fc_state eq 'OK'){
		    my $sec_time = time();
		    my $time = scalar localtime($sec_time);
		    updatestatus('FC_STATE','DIFF');
		    updatestatus('FC_TIME',$sec_time);
		    updatestatus('FC_CTIME',$time); # this is when we first found the diffs
		}
	    }
	    else{
		# no diffs 
		my $sec_time = time();
		my $time = scalar localtime($sec_time);
		updatestatus('FC_LAST_OK',$p2);
		updatestatus('FC_TIME',$sec_time);
		updatestatus('FC_CTIME',$time);
		updatestatus('FC_STATE','OK');
	    }
	}
	else{
	    $job->compare_files($job2); 
	}
	$job->unlock($job->{JOBNAME});
    }
    else{
	errpr "approve in process for $job->{JOBNAME}\n";
	exit -1;
    }
    mypr "\n";
    mypr "********************************************************************\n";
    mypr " STOP: $p1 vs. $p2 at > ",scalar localtime," < ($id)\n";
    mypr "********************************************************************\n";
    mypr "\n";
exit;
}
# build internal db for device lookup
$job->build_db();
# initialize base job data
my $netobj = shift;
$netobj or &usage;
($job->{JOBNAME},$job->{JOBTYPE}) = $job->build_obj($netobj);
# bless to job specific module !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
bless($job,"drc2_$job->{JOBTYPE}");

# check reachability
if (defined $job->{OPTS}->{PING_ONLY}){
    my $nopolicy = "Policy (unknown)";
    $job->{OPTS}->{P} = $job->{OPTS}->{P}?$job->{OPTS}->{P}: $nopolicy;
    mypr "\n";
    mypr "********************************************************************\n";
    mypr " START: $job->{OPTS}->{P} at > ",scalar localtime," < ($id)\n";
    mypr "********************************************************************\n";
    mypr "\n";
    my $ex;
    if ($job->check_device()){  
	mypr"$job->{JOBNAME}: reachable\n";
	$ex =  0;
    }
    else{
	mypr "$job->{JOBNAME}: reachability test failed\n";
	$ex = -1;
    }
    mypr "\n";
    mypr "********************************************************************\n";
    mypr " STOP: $job->{OPTS}->{P} at > ",scalar localtime," < ($id)\n";
    mypr "********************************************************************\n";
    mypr "\n";
    exit $ex;
}
elsif(!$job->{OPTS}->{NOREACH}){
    if(!$job->check_device()){  
	errpr "$job->{JOBNAME}: reachability test failed\n";
	exit -1;
    }
}
else{
    mypr "reachability test skipped\n";
}

# call device methods
if (defined $job->{OPTS}->{M}){
    # generate Report about Migrate Status
    # WARNING: We do *not* check if approve is necessary!
    unless($job->load_epilog()){
	mypr "nothing to do...\n";
	exit;
    }
    $job->load_spocfile();
    $job->{MIGREP}->{HITS} = $job->{OPTS}->{M}?$job->{OPTS}->{M}:0;
    $job->{MIGREP}->{HITS} =~ /\d+/ or &usage();
    $job->migrate_report();
}
elsif($job->{OPTS}->{R}){
    # check Crypto Config
    $job->check_crypto();   
}
elsif($job->{OPTS}->{E}){
    # execute user command
    errpr_mode("COMPARE"); # tell the drc2_helper not to print message approve aborted
    $job->remote_execute();
}
elsif($job->{OPTS}->{A}){
# Check if packet is permitted by device
    errpr_mode("COMPARE"); # tell the drc2_helper not to print message approve aborted
    $job->check_acl();
}
elsif($job->{OPTS}->{N}){
    # compare or approve network devices
    my $nopolicy = "Policy (unknown)";
    $job->{OPTS}->{P} = $job->{OPTS}->{P}?$job->{OPTS}->{P}: $nopolicy;
    $job->{POLICY} = $job->{OPTS}->{P};
    mypr "\n";
    mypr "********************************************************************\n";
    mypr " START: $job->{OPTS}->{P} at > ",scalar localtime," < ($id)\n";
    mypr "********************************************************************\n";
    mypr "\n";
    # load netspoc files
    $job->load_spocfile();
    $job->load_epilog();
    if($job->lock($job->{JOBNAME})){
	$job->{OPTS}->{S} and open_status($job);
	if(defined $job->{OPTS}->{C}){
	    #####################
	    # compare Mode!
	    #####################
	    errpr_mode("COMPARE"); # tell the drc2_helper that we only compare
	    my $compare_result = $job->compare();
	    unless($job->{OPTS}->{P} eq $nopolicy){
		unless($job->{POLICY} =~ /^p(\d+)$/){
		    die "wrong policy format in policy spec. expected \'p<num>\'\n";
		}
		my $job_policy = $1;
#		my $compare_result = $job->compare();
		if($job->{OPTS}->{S}){
		    #
		    #### COMPARE STATUS FIELDS UPDATE ####
		    #
		    unless(getstatus('DEV_POLICY') =~ /^p(\d+)$/){
			mypr getstatus('DEV_POLICY')."\n";
			die "wrong policy format in device status file\n";
		    }
		    my $dev_policy = $1;
		    unless($job->{POLICY} =~ /^p(\d+)$/){
			die "wrong policy format in policy spec.\n";
		    }
		    if($compare_result){
			# differences found!
			# only update status if compare is serious
			unless($job_policy < $dev_policy){
			    if(getstatus('COMP_RESULT') ne 'DIFF'){ 
				updatestatus('COMP_RESULT','DIFF');
				updatestatus('COMP_POLICY',$job->{POLICY});
				updatestatus('COMP_TIME',time);
				updatestatus('COMP_CTIME',localtime(time()));
			    }
			    elsif(getstatus('COMP_TIME') < getstatus('COMP_DTIME')){
				# old compare result is not valid
				updatestatus('COMP_RESULT','DIFF');
				updatestatus('COMP_POLICY',$job->{POLICY});
				updatestatus('COMP_TIME',time()); 
				updatestatus('COMP_CTIME',localtime(time()));
			    }
			}
		    }
		    else{
			# no changes
			unless(getstatus('COMP_POLICY') =~ /^p(\d+)$/){
			    print getstatus('COMP_POLICY');print "\n";
			    die "wrong policy format in device status file\n"};
			my $comp_policy = $1;
			# only update status if compare is serious
			unless($job_policy < $comp_policy){ 
			    updatestatus('COMP_RESULT','UPTODATE');
			    updatestatus('COMP_POLICY',$job->{POLICY});
			    updatestatus('COMP_TIME',time);
			    updatestatus('COMP_CTIME',localtime(time()));
			}
		    }
		}
	    }
	}
	else{
	    ##########################
	    # approve Mode!
	    ##########################
	    my $user;
	    if($job->{OPTS}->{I}){
		$user = $job->{OPTS}->{I}; # user from approve.pl
	    }
	    else{
		$user = getpwuid($>);
	    }
	    if($job->{OPTS}->{S}){
		# set approve Status to 'ERROR' - later reset to 'WARNINGS' or 'OK'
		updatestatus('DEVICENAME',$job->{JOBNAME});
		updatestatus('APP_TIME',scalar localtime);
		updatestatus('APP_STATUS','***UNFINISHED APPROVE***');
		updatestatus('APP_USER',$user);
		updatestatus('APP_POLICY',$job->{OPTS}->{P});
	    }
	    $job->approve();
	    if($job->{OPTS}->{S}){
		# set approve/device status to 'WARNINGS' or 'OK'
		my $sec_time = time();
		my $time = scalar localtime($sec_time);
		updatestatus('APP_TIME',$time);
		updatestatus('DEV_TIME',$time);
		updatestatus('COMP_DTIME',$sec_time);
		updatestatus('DEV_USER',$user);
		updatestatus('DEV_POLICY',$job->{OPTS}->{P});
		if(check_erro() eq "YES"){
		    updatestatus('APP_STATUS','***ERRORS***');
		    updatestatus('DEV_STATUS','***ERRORS***');
		}
		elsif(check_warn() eq "YES"){
		    updatestatus('APP_STATUS','***WARNINGS***');
		    updatestatus('DEV_STATUS','***WARNINGS***');
		}
		else{
		    updatestatus('APP_STATUS','OK');
		    updatestatus('DEV_STATUS','OK');
		}
	    }
	}
	$job->unlock($job->{JOBNAME});
    }
    else{
	errpr "approve in process for $job->{JOBNAME}\n";
    }
    mypr "\n";
    mypr "********************************************************************\n";
    mypr " STOP: $job->{OPTS}->{P} at > ",scalar localtime," < ($id)\n";
    mypr "********************************************************************\n";
    mypr "\n";
}
else{
    errpr "unknown option\n";
    usage();
    exit -1;
}
exit;



