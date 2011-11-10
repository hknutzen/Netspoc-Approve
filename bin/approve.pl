#!/usr/bin/perl
# approve.pl
#
# Author: Heinz Knutzen, Arne Spetzler
# Description:
# Wrapper to approve and compare current policy.
# Does history logging.
#
# $Id$

use strict;
use warnings;
use Fcntl qw/:flock/;		# import LOCK_* constants
use POSIX qw(strftime);

# Clean PATH if run in taint mode.
$ENV{PATH} = '/usr/local/bin:/usr/bin:/bin';

my $prog = "diamonds";

# Use old drc2.pl for devices matching this pattern
my $old_device_pattern = qr/^vpn3k_/;

sub usage {
    print "Usage:\n";
    print "$prog approve <device-name>\n";
    print "$prog compare <device-name>\n";
    exit -1;
}

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

# File is trusted; values are untainted by pattern match.
sub read_global_config {
    my $rcmad = '/home/knutzehe/.rcmadnes';
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
    print HISTORY "$date USER $user called '$arguments'\n";
}

sub log_history {
    my ($message) = @_;
    my $date = strftime "%Y %m %e %H:%M:%S", localtime();
    print HISTORY "$date $message\n";
}

sub untaint {
    my ($string) = @_;
    $string =~ /^(.*)$/;
    return $1;
}

sub get_and_cd_current_policy {

    # Link is created by trusted program.
    my $currentdir = untaint(readlink "${netspocdir}current") or 
	die "Error: could not get 'current' policy directory\n";
    chdir "$netspocdir$currentdir" or
	die "Error: can't cd to $netspocdir$currentdir: $!\n";
    return $currentdir;
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

# Untaint, because it is only logged.
my $running_for_user = untaint(getpwuid($ruid)) or 
    die "ERROR: no user for uid $ruid\n";

#
# Command evaluation
#
my $command = shift(@ARGV) or usage();
my $device = shift(@ARGV) or usage();
@ARGV and usage();

my $policy = get_and_cd_current_policy();
my $codefile = "$codepath$device";
-f $codefile or die "Error: unknown device $device\n";

# $device is now known to be valid.
$device = untaint($device);

my $logfile = "$logpath$device";
my $is_compare;
if ($command eq "compare") {
    $logfile .= ".compare";
    $is_compare = 1;
}
elsif ($command eq "approve") {
    $logfile .= ".drc";
}
else{
    usage();
}

my $cmd;
if ($device =~ $old_device_pattern) {
    my $compare_option = $is_compare ? '-C 0' : '';
    $cmd = 
        "drc2.pl $compare_option -P $policy -S -I $running_for_user" .
        " --LOGVERSIONS --NOLOGMESSAGE --LOGFILE $logfile -L $logpath" .
        " -N $codepath$device $device";
}
else {
    my $compare_option = $is_compare ? '-C' : '';
    $cmd = 
        "perl -I /home/knutzehe/Netspoc-Approve/lib /home/knutzehe/Netspoc-Approve/bin/" .
        "drc3.pl $compare_option -P $policy -S -I $running_for_user" .
        " --LOGVERSIONS --NOLOGMESSAGE --LOGFILE $logfile -L $logpath" .
        " $codepath$device";
}

init_history_logging($device, $arguments, $running_for_user);
log_history("START: $cmd");

# Prevent taint mode for called program.
$< = $>;
$( = $);
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
