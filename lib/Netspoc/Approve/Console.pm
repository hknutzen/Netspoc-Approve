
=head1 DESCRIPTION

Manage connection to device.

=head1 COPYRIGHT AND DISCLAIMER

https://github.com/hknutzen/Netspoc-Approve
(c) 2018 by Heinz Knutzen <heinz.knutzen@gmail.com>
(c) 2008 by Daniel Brunkhorst <daniel.brunkhorst@web.de>
(c) 2007 by Arne Spetzler

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

=cut

package Netspoc::Approve::Console;

use strict;
use warnings;
use Netspoc::Approve::Helper;
use Expect;
require Exporter;

our $VERSION = '2.020'; # VERSION: inserted by DZP::OurPkgVersion

############################################################
# Constructor.
############################################################

sub new_console {
    my ($class) = @_;

    my $con = {};
    bless( $con, $class );
    my $console = $con->{EXPECT} = Expect->new();

    $console->debug( 0 );
    $console->exp_internal( 0 );

    #$Expect::Debug = 1;
    $console->raw_pty( 1 );
    $console->log_stdout( 0 );
    return $con;
}

# Set or change logfile for Expect.
sub set_logfile {
    my ($con, $logfile) = @_;
    my $console = $con->{EXPECT};
    $console->log_file($logfile);

    # Chmod, to allow read access by others.
    defined chmod(0644, $logfile)
        or abort("Couldn't chmod $logfile: $!");
}

# If called in an array context, expect() will return 5 values:
# matched_pattern_position, error,
# success-fully_matching_string,
# before_match, after_match.
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
    $con->con_abort($result) if $err;

    return $result;
}

sub con_wait {
    my ($con, $prompt) = @_;
    my $timeout = $con->{TIMEOUT};
    return $con->con_wait0($prompt, $timeout);
}

sub con_short_wait {
    my ($con, $prompt) = @_;
    my $timeout = $con->{LOGIN_TIMEOUT};
    return $con->con_wait0($prompt, $timeout);
}

sub con_try {
    my ($con, $prompt) = @_;

    # If $timeout is 0 Expect will check one time to see if $con's
    # handle contains any of the match_patterns.
    my $found = $con->{EXPECT}->expect(0, '-re', $prompt);
    return $found;
}

sub con_send_cmd {
    my ($con, $cmd) = @_;
    $con->{EXPECT}->send( $cmd );
}

sub con_issue_cmd {
    my ($con, $cmd, $prompt) = @_;
    $con->con_send_cmd("$cmd\n");
    return $con->con_wait($prompt);
}

# Possible values of $error are
# - undef, indicating no error,
# - '1:TIMEOUT' indicating that $timeout seconds had elapsed without a
#   match,
# - '2:EOF' indicating an eof was read from $object,
# - '3: spawn id($fileno) died' indicating that the process exited before
#   matching and
# - '4:$!' indicating whatever error was set in $ERRNO during the last
#   read on $object's handle or during select().
sub con_abort {
    my ($con, $result) = @_;
    my $error = $result->{ERROR};

    # Remove leading error code from error message.
    $error =~ s/^[1234]://;

    my @lines = ($error);
    for my $key (qw(BEFORE AFTER)) {
        my $value = $result->{$key} or next;
        push @lines, split /\n/, $value;
    }
    abort(@lines);
}

# Modules must return a true value.
1;
