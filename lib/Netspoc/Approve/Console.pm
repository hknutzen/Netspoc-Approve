
package Netspoc::Approve::Console;

# Authors: Arne Spetzler, Heinz Knutzen, Daniel Brunkhorst
#
# Description:
# Manage connection to device.
#

'$Id$ ' =~ / (.+),v (.+?) /;

my $id = "$1 $2";


use strict;
use warnings;
use Netspoc::Approve::Helper;
require Exporter;

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
    my $CON = $nob->{CONSOLE}->{$name};
    $CON->{NAME}   = $name;
    $CON->{PARENT} = $nob->{CONSOLE};
    my $console = Expect->new();
    $CON->{EXPECT} = $console;

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
        $CON->{LOG} = $fh;
    }
    $console->debug( 0 );
    $console->exp_internal( 0 );

    #$Expect::Debug = 1;
    $console->raw_pty( 1 );
    $console->log_stdout( 0 );
    bless( $CON, $class );
    return $CON;
}

sub shutdown_console ($$) {
    my ($CON, $shutdown_message) = @_;
    if ( exists $CON->{LOG} ) {
        my $fh = $CON->{LOG};
        print $fh "\n";
        print $fh "********************************************************\n";
        print $fh "  $shutdown_message\n";
        print $fh "********************************************************\n";
        print $fh "\n";
    }

    # do the right thing... (maybe we have to close something else...)
    #print $ssh->fileno()."\n";
    $CON->{EXPECT}->soft_close();    # or die $ssh->error();
    delete $CON->{PARENT}->{ $CON->{NAME} };
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
    my ($CON, $prompt) = @_;
    my $timeout = $CON->{TIMEOUT};
    delete $CON->{RESULT};
    my @result = $CON->{EXPECT}->expect( $timeout, '-re', $prompt );

    $CON->{RESULT}->{ERROR}   = $result[1];
    $CON->{RESULT}->{MPPOS}   = $result[0];
    $CON->{RESULT}->{MATCH}   = $result[2];
    $CON->{RESULT}->{BEFORE}  = $result[3];
    $CON->{RESULT}->{AFTER}   = $result[4];
    return not defined $CON->{RESULT}->{ERROR};
}

sub con_issue_cmd {
    my ($CON, $cmd, $prompt) = @_;
    $CON->con_send_cmd($cmd);
    return $CON->con_wait( $prompt );
}

sub con_cmd {
    my ($CON, $cmd) = @_;
    my $prompt = $CON->{PROMPT};
    return $CON->con_issue_cmd( $cmd, $prompt );
}

sub con_send_cmd {
    my ($CON, $cmd) = @_;
    $CON->{RESULT}->{CMD} = $cmd;
    $CON->{EXPECT}->send( $cmd );
}

sub con_error {
    my $CON  = shift;
    my $subs = "";
    for ( my $i = 1 ; $i <= 3 ; $i++ ) {
        my ( $package, $file, $ln, $sub ) = caller $i;
        $sub and $subs = "$sub($ln) $subs";
    }
    mypr "\n";
    errpr_info "$subs\n";
    for my $key ( keys %{ $CON->{RESULT} } ) {
        my $value =
          defined $CON->{RESULT}->{$key} ? $CON->{RESULT}->{$key} : "";
        errpr_info "$key $value\n";
    }
    exit -1;
}

sub con_dump( $ ) {
    my $CON = shift;
    mypr "$CON->{RESULT}->{BEFORE}$CON->{RESULT}->{MATCH}";
}

# Modules must return a true value.
1;
