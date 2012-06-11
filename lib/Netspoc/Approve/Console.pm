
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
#
# Constructor.
#
############################################################
sub new {
    my $class = shift;
    my $self  = {};

    bless( $self, $class );
    return $self;
}


sub new_console ($$$$) {
    my ($class, $nob, $name, $logfile, $startup_message) = @_;
    if ( exists $nob->{CONSOLE}->{$name} ) {
        die "console \'$name\' already created\n";
    }
    $nob->{CONSOLE}->{$name}->{NAME} = $name;
    my $con = $nob->{CONSOLE}->{$name};
    $con->{NAME}   = $name;
    $con->{PARENT} = $nob->{CONSOLE};
    my $console = Expect->new();
    $con->{EXPECT} = $console;

    if ( $logfile ) {
        my $fh;
        unless ( -f "$logfile" ) {
            ( open( $fh, ">>$logfile" ) )
              or die "could not open $logfile\n$!\n";

            # because we create the file here, we have to chmod to
            # allow access by group members!
            defined chmod 0644, "$logfile"
              or die " couldn't chmod $logfile\n$!\n";
        }
        else {
            ( open( $fh, ">>$logfile" ) )
              or die "could not open $logfile\n$!\n";
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
    bless( $con, $class );
    return $con;
}

sub shutdown_console ($$) {
    my ($con, $shutdown_message) = @_;
    if ( exists $con->{LOG} ) {
        my $fh = $con->{LOG};
        print $fh "\n";
        print $fh "********************************************************\n";
        print $fh "  $shutdown_message\n";
        print $fh "********************************************************\n";
        print $fh "\n";
    }

    # do the right thing... (maybe we have to close something else...)
    #print $ssh->fileno()."\n";
    $con->{EXPECT}->soft_close();    # or die $ssh->error();
    delete $con->{PARENT}->{ $con->{NAME} };
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
    return not defined $con->{RESULT}->{ERROR};
}

# We might accidently have read multiple prompt strings.
# This occurs, if relaod banner is sent or multiple commands are sent in 
# one packet.
# Check for this case and put extra data after first prompt back into
# accumulator of expect.
sub con_wait_prompt1 {
    my ($con, $prompt) = @_;

    $con->con_wait($prompt) or return 0;

    # Prompt was found.
    # Check for multiple prompts, find first one.
    my $result = $con->{RESULT};
    my $exp = $con->{EXPECT};
    if ($result->{BEFORE} =~ /^(.*?)($prompt)(.*)$/) {
	mypr "Found prompt1\n";
	mypr "Before: $1\n";
	$result->{BEFORE} = $1;
	my $accum = $3 . $result->{MATCH} . $exp->clear_accum();
	$exp->set_accum($accum);
	mypr "Accum: $accum\n";
	$result->{MATCH} = $2;
    }
    return 1;	    
}

sub con_send_cmd {
    my ($con, $cmd) = @_;
    $con->{EXPECT}->send( $cmd );
}

sub con_issue_cmd {
    my ($con, $cmd, $prompt, $check_prompt1) = @_;
    $con->con_send_cmd($cmd);
    return $check_prompt1 
	? $con->con_wait_prompt1($prompt) 
	: $con->con_wait( $prompt );
}

sub con_error {
    my $con  = shift;
    my $result = $con->{RESULT};
    for my $key (keys %$result) {
        my $value = $result->{$key};
        errpr_info "$key $value\n" if $value;
    }
    exit -1;
}

# Modules must return a true value.
1;
