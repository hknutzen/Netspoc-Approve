
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

# VERSION: inserted by DZP::OurPkgVersion

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
    my ($con, $job, $shutdown_message) = @_;
    if ( exists $con->{LOG} ) {
        my $fh = $con->{LOG};
        print $fh "\n";
        print $fh "********************************************************\n";
        print $fh "  $shutdown_message\n";
        print $fh "********************************************************\n";
        print $fh "\n";
    }
    delete $job->{CONSOLE};
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

sub con_wait0 {
    my ($con, $prompt, $timeout) = @_;
    my $exp = $con->{EXPECT};
    my ($pos, $err, $match, $before, $after)
        = $exp->expect( $timeout, '-re', $prompt );

    my $result = $con->{RESULT} = {
        MPPOS => $pos,
        ERROR => $err,
        MATCH => $match,
        BEFORE => $before,
        AFTER => $after,
    };
    return $result;
}

sub con_wait {
    my ($con, $prompt) = @_;
    my $timeout = $con->{TIMEOUT};
    my $result = $con->con_wait0($prompt, $timeout);
    $con->con_error() if $result->{ERROR};
    return $result;
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

sub con_short_wait {
    my ($self, $prompt) = @_;
    my $timeout = 3;
    return $self->con_wait0($prompt, $timeout);
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
    my $err = $result->{ERROR};
    if ($err =~ /^1:/) {
        $err = 'TIMEOUT';
    }
    elsif ($err =~ /^2:/) {
        $err = 'Got EOF';
    }
    elsif ($err =~ /^3:/) {
        $err = 'Process died';
    }
    elsif ($err =~ /^4:(.*)/) {
        $err = $1;
    }
    my @lines = ($err);
    for my $key (qw(BEFORE AFTER)) {
        my $value = $result->{$key} or next;
        push @lines, split /\n/, $value;
    }
    abort(@lines);
}

# Modules must return a true value.
1;
