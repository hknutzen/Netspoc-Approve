
package Netspoc::Approve::Console;

# Authors: Arne Spetzler, Heinz Knutzen, Daniel Brunkhorst
#
# Description:
# Manage connection to device.
#

use strict;
use warnings;
use Netspoc::Approve::Helper;
use Expect;
require Exporter;

our $VERSION = '1.080'; # VERSION: inserted by DZP::OurPkgVersion

our @ISA = qw(Exporter);
our @EXPORT = qw( open_con close_con  );

############################################################
# Constructor.
############################################################

sub new_console {
    my ($class, $job, $logfile, $startup_message) = @_;
    $job->{CONSOLE} and abort("Console already created");

    my $con = $job->{CONSOLE} = {};
    bless( $con, $class );
    $con->{PARENT} = $job;
    my $console = $con->{EXPECT} = Expect->new();

    if ( $logfile ) {
        my $fh;
        unless ( -f "$logfile" ) {
            open($fh, '>>', $logfile) or abort("Could not open $logfile: $!");

            # Because we create the file here, we have to chmod to
            # allow access by group members!
            defined chmod(0644, $logfile)
              or abort("Couldn't chmod $logfile: $!");
        }
        else {
            open($fh, '>>', $logfile) or abort("Could not open $logfile: $!");
        }
        print $fh "\n";
        print $fh "********************************************************\n";
        print $fh "  $startup_message\n";
        print $fh "********************************************************\n";
        print $fh "\n";
        $console->log_file( $logfile );
        $con->{LOG} = $fh;
    }
    $console->debug( 0 );
    $console->exp_internal( 0 );

    #$Expect::Debug = 1;
    $console->raw_pty( 1 );
    $console->log_stdout( 0 );
    return $con;
}

sub shutdown_console {
    my ($con, $shutdown_message) = @_;
    if ( exists $con->{LOG} ) {
        my $fh = $con->{LOG};
        print $fh "\n";
        print $fh "********************************************************\n";
        print $fh "  $shutdown_message\n";
        print $fh "********************************************************\n";
        print $fh "\n";
    }
    $con->{EXPECT}->soft_close();
    delete $con->{PARENT}->{CONSOLE};
}

#    If called in an array context expect() will return
#    ($matched_pattern_position, $error, $success-
#    fully_matching_string, $before_match, and
#    $after_match).

#    Possible values of $error are undef, indi-
#    cating no error, '1:TIMEOUT' indicating that $timeout
#    seconds had elapsed without a match, '2:EOF' indicat-
#    ing an eof was read from $object, '3: spawn
#    id($fileno) died' indicating that the process exited
#    before matching and '4:$!' indicating whatever error
#    was set in $ERRNO during the last read on $object's
#    handle.

sub con_wait {
    my ($con, $prompt) = @_;
    my $timeout = $con->{TIMEOUT};
    my $exp = $con->{EXPECT};
    my @result = $exp->expect( $timeout, '-re', $prompt );

    $con->{RESULT} = (my $result = {});
    $result->{ERROR}   = $result[1];
    $result->{MPPOS}   = $result[0];
    $result->{MATCH}   = $result[2];
    $result->{BEFORE}  = $result[3];
    $result->{AFTER}   = $result[4];
    $con->con_error() if $result->{ERROR};
}

# We might accidently have read multiple prompt strings.
# This occurs, if reload banner is sent or multiple commands are sent in 
# one packet.
# Check for this case and put extra data after first prompt back into
# accumulator of expect.
sub con_wait_prompt1 {
    my ($con, $prompt) = @_;

    $con->con_wait($prompt);

    # Prompt was found.
    # Check for multiple prompts, find first one.
    my $result = $con->{RESULT};
    my $exp = $con->{EXPECT};
    if ($result->{BEFORE} =~ /^(.*?)($prompt)(.*)$/) {
	debug("Found multiple prompts");
#	debug("Before: $1");
	$result->{BEFORE} = $1;
	my $accum = $3 . $result->{MATCH} . $exp->clear_accum();
	$exp->set_accum($accum);
	debug("Put back: $accum");
	$result->{MATCH} = $2;
    }
}

sub con_send_cmd {
    my ($con, $cmd) = @_;
    $con->{EXPECT}->send( $cmd );
}

sub con_issue_cmd {
    my ($con, $cmd, $prompt, $check_prompt1) = @_;
    $con->con_send_cmd("$cmd\n");
    $check_prompt1 
	? $con->con_wait_prompt1($prompt) 
	: $con->con_wait( $prompt );
}

sub con_error {
    my ($con) = @_;
    my $result = $con->{RESULT};
    my @lines = ($result->{ERROR});
    for my $key (qw(BEFORE AFTER)) {
        my $value = $result->{$key};
        next if not $value;
        push @lines, split /\n/, $value;
    }
    abort(@lines);
}

# Modules must return a true value.
1;
