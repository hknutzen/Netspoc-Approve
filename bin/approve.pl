#!/usr/bin/perl
# approve.pl
#
# Author: Heinz Knutzen, Arne Spetzler
# Description:
# Wrapper to approve and compare current policy.
# Does history logging and writes status files.
#

use strict;
use warnings;
use Fcntl qw/:flock/;		# import LOCK_* constants
use POSIX qw(strftime);
use Netspoc::Approve::Status;
use Netspoc::Approve::Load_Config;

our $VERSION = '1.087'; # VERSION: inserted by DZP::OurPkgVersion

# Clean %ENV for taint mode.
$ENV{PATH} = '/usr/local/bin:/usr/bin:/bin';
delete @ENV{'IFS', 'CDPATH', 'ENV', 'BASH_ENV'};

sub usage {
    print "Usage:\n";
    print "$0 approve [--brief] <device-name>\n";
    print "$0 compare [--brief] <device-name>\n";
    exit -1;
}

# Settings from config file
my $config = Netspoc::Approve::Load_Config::load();

# Open history file for logging.
my $history_fh;
sub init_history_logging {
    my ($devicename, $arguments, $user) = @_;
    my $historypath = $config->{historydir} or return;
    my $historyfile = "$historypath/$devicename"; 
    open($history_fh, ">>", $historyfile) or 
	die "Error: Can't open $historyfile: $!\n";
    defined(chmod(0644, "$historyfile")) or 
	die "Error: Can't chmod $historyfile: $!\n";
    unless(flock($history_fh, LOCK_EX | LOCK_NB)){
	die "Error: file '$historyfile' is locked: $!\n";
    }  
    my $date = strftime "%Y %m %e %H:%M:%S", localtime();
    print $history_fh "$date USER $user called '$arguments'\n";
}

sub log_history {
    my ($message) = @_;
    $config->{historydir} or return;
    my $date = strftime "%Y %m %e %H:%M:%S", localtime();
    print $history_fh "$date $message\n";
}

sub untaint {
    my ($string) = @_;
    $string =~ /^(.*)$/;
    return $1;
}

#############################################################################
##  main
#############################################################################

# Get real UID, we may be running with some other effective UID.
my $running_for_user = getpwuid($<) or die "Error: real UID is unknown\n";

# Argument processing.
my $arguments = join ' ', $0, @ARGV;
my $command = shift(@ARGV) or usage();
my $brief = $ARGV[0] eq '--brief' && shift(@ARGV);
my $device = shift(@ARGV) or usage();
@ARGV and usage();

my $netspocdir = $config->{netspocdir};

# Read current policy
# Link is created by trusted program.
my $policy = untaint(readlink "$netspocdir/current") or 
    die "Error: Can't get 'current' policy directory\n";

# Change to current policy directory. 
# We can use relative pathnames now.
chdir "$netspocdir/$policy" or
    die "Error: Can't cd to $netspocdir/$policy: $!\n";

my $codefile = "code/$device";
-f $codefile or die "Error: unknown device $device\n";

# $device is now known to be valid.
$device = untaint($device);
$codefile = "code/$device";

my $logpath = 'log';
my $logfile = "$logpath/$device";
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

my $compare_option = $is_compare ? '-C' : '';
my $cmd = "drc3.pl $compare_option --LOGFILE $logfile -L $logpath $codefile";

init_history_logging($device, $arguments, $running_for_user);
log_history("START: $cmd");
log_history("POLICY: $policy");

my $status;
if (my $statuspath = $config->{statusdir}) {
    $status = Netspoc::Approve::Status->new(device => $device, 
                                            path => $statuspath);
}

# Set preliminary approve status.
if (not $is_compare) {
    $status and $status->start_approve($policy, $running_for_user);
}

# Prevent taint mode for called program.
# Set real to effective UID
$< = $>;
$( = $);

# Run command.
my $failed = system($cmd);

my ($warnings, $errors, $changes);
$errors++ if $failed;
if (open(my $log, '<', $logfile)) { ## no critic (ProhibitUnusedVariables)
    while (<$log>) {
	if (/WARNING>>>/) {
            $warnings++;
        }
        elsif (/ERROR>>>/) {
            if ($brief && /TIMEOUT/) {
                next;
            }
            else {
                $errors++;
            }
        }
        elsif (/^comp:.*\*\*\*/) {
            $changes++;
        }
        else {
            next; 
        }
        print $brief ? "$device:$_" : $_;
        chomp;
        log_history("RES: $_");
    }
}
elsif (not $failed) {
    die "Error: can't open $logfile: $!\n";
}

# Set approve status.
if ($is_compare) {
    $errors or $status and $status->finish_compare($changes, $policy);
}
else {
    my $result = $errors ? '***ERRORS***' : $warnings ? '***WARNINGS***' : 'OK';
    $status and $status->finish_approve($result, $policy, $running_for_user);
}

# Print error messages to STDERR.
my $fail_ok = $failed ? 'FAILED' : 'OK';
log_history("END: $fail_ok");
if (!$brief && ($failed || $warnings || $errors || $changes)) {
    print STDERR "$fail_ok; details in $netspocdir/$policy/$logfile\n";
}
exit $failed;
