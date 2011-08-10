#! /usr/bin/perl
# approve.pl
#
# Author: Heinz Knutzen, Arne Spetzler
# Description:
# Wrapper to approve and compare current policy.
# Does history logging.

'$Id$ '=~ / (.+),v (.+?) /;
my $id = "$1 $2";

# check command line argument   

use strict;
use warnings;
use Fcntl qw/:flock/;		# import LOCK_* constants
use POSIX qw(strftime);

my $prog = "diamonds";

# Use old drc2.pl for devices matching this pattern
my $old_device_pattern = qr/^vpn3k_/;


# Read settings from config file
my $netspocdir;
my $codepath;
my $logpath;
my $historypath;
my $systemuser;

my %conf2var = 
    ( NETSPOC     => \$netspocdir,
      CODEPATH    => \$codepath,
      LOGPATH     => \$logpath,
      HISTORYPATH => \$historypath,
      SYSTEMUSER  => \$systemuser,
      );

sub read_global_config {
    my $rcmad = '/home/diamonds/.rcmadnes';
    open(RCMAD,$rcmad) or die "Can't open $rcmad: $!\n";
    while (<RCMAD>){
	if (/^ \s* (\w+) \s* = \s* (\S+) \s* $/x) {
	    if (my $var = $conf2var{$1}) {
		$$var = $2;
	    }
	}
    }
    for my $key (keys %conf2var) {
	my $var = $conf2var{$key};
	defined $$var or die "Error: Missing $key setting in $rcmad\n";
    }
}

# Open history file for logging.
sub init_history_logging {
    my ($devicename, $arguments, $user) = @_;
    my $historyfile = $historypath.$devicename; 
    open(HISTORY, ">>", $historyfile) or 
	die "Error: Can't open $historyfile: $!\n";
    defined(chmod(0644, "$historyfile")) or 
	die "Error: Can't chmod $historyfile: $!\n";
    unless(flock(HISTORY, LOCK_EX | LOCK_NB)){
	die "Error: file '$historyfile' is locked: $!\n";
    }  
    my $date = strftime "%Y %m %e %H:%M:%S", localtime();
    print HISTORY "$date ($id) USER $user called '$arguments'\n";
}

sub log_history {
    my ($message) = @_;
    my $date = strftime "%Y %m %e %H:%M:%S", localtime();
    print HISTORY "$date ($id) $message\n";
 }

sub usage {
    print "Usage:\n";
    print "$prog approve <device-name>\n";
    print "$prog compare <device-name>\n";
    exit -1;
}

sub get_and_cd_current_policy {
    my $currentdir = readlink "${netspocdir}current" or 
	die "Error: could not get 'current' policy directory\n";
    chdir "$netspocdir$currentdir" or
	die "Error: can't cd to $netspocdir$currentdir: $!\n";
    return $currentdir;
}

sub get_drc_cmd {
    my($dev) = @_;
    return $dev =~ $old_device_pattern ? 'drc2.pl' : 'drc3.pl';
}

#############################################################################
##
##  main
##
#############################################################################

read_global_config();

#
# User management
#
my $uname = getpwuid($>);	# $> == effective UID
$uname eq $systemuser or die "Error: $0 should be run as UID $systemuser\n";

my $arguments = join ' ',$0,@ARGV[1..$#ARGV];
my $ruid = shift;
defined $ruid or die "Error: missing calling UID as first arg to $0\n";
my $running_for_user = getpwuid($ruid) or die "ERROR: no user for uid $ruid\n";

#
# Command evaluation
#
my $command = shift(@ARGV) or usage();
my $device = shift(@ARGV) or usage();
@ARGV and usage();

my $policy = get_and_cd_current_policy();
my $drc_cmd = get_drc_cmd($device);

my $logfile = "$logpath$device";
my $compare_option;
if ($command eq "compare") {
    $logfile .= ".compare";
    $compare_option = '-C 0';
}
elsif ($command eq "approve") {
    $logfile .= ".drc";
    $compare_option = '';
}
else{
    usage();
}

my $cmd = 
    "$drc_cmd $compare_option -P $policy -N $codepath$device" .
    " -S -I $running_for_user" .
    " --LOGVERSIONS --NOLOGMESSAGE --LOGFILE $logfile -L $logpath" .
    " $device";

init_history_logging($device, $arguments, $running_for_user);
log_history("START: $cmd");

my $failed = system($cmd);
my $details;
if (open(my $log, '<', $logfile)) {
    while (<$log>) {
	if (/WARNING>>>|ERROR>>>/ || /^comp:.*\*\*\*/) {
	    print $_;
	    chomp;
	    log_history("RES: $_");
	    $details = 1;
	}
    }
}
elsif (not $failed) {
    die "Error: can't open $logfile: $!\n";
}

my $status = $failed ? 'FAILED' : 'OK';
log_history("END: $status");
if ($failed || $details) {
    print STDERR "$status; details in $netspocdir$policy/$logfile\n";
}
exit $failed;
