
=head1 DESCRIPTION

Helper functions

=head1 COPYRIGHT AND DISCLAIMER

https://github.com/hknutzen/Netspoc-Approve
(c) 2019 by Heinz Knutzen <heinz.knutzen@gmail.com>
(c) 2010 by Daniel Brunkhorst <daniel.brunkhorst@web.de>
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

package Netspoc::Approve::Helper;

require Exporter;
use strict;
use warnings;
use NetAddr::IP::Util;

our $VERSION = '2.020'; # VERSION: inserted by DZP::OurPkgVersion

our @ISA    = qw(Exporter);
our @EXPORT = qw(info abort warn_info internal_err debug
                 quiet quad2bitstr is_ip is_ipv6 max unique
);

my $verbose = 1;

sub quiet { $verbose = 0; }

sub info {
    say_stderr(@_) if $verbose;
}

sub say_stderr {
    print STDERR @_, "\n";
}

sub abort {
    say_stderr("ERROR>>> ", $_) for @_;
    exit -1;
}

sub warn_info {
    say_stderr("WARNING>>> ", @_);
}

sub internal_err {
    # uncoverable subroutine
    my $sub = (caller 1)[3];                    # uncoverable statement
    abort("Internal error in $sub: ", @_);      # uncoverable statement
}

sub debug {
    # uncoverable subroutine
    info(@_);     # uncoverable statement
}

sub quad2bitstr {
    ($_[0] =~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/) or return;
    ($1 < 256 && $2 < 256 && $3 < 256 && $4 < 256) or return;
    return pack 'C4', $1, $2, $3, $4;
}

sub is_ipv6 {
    my ($bitstr) = @_;
    my $bits = split(//, unpack('b*', $bitstr));
    return $bits == 128;
}

sub max {
    my $max = shift(@_);
    for my $el (@_) {
        $max = $el if $max < $el;
    }
    return $max;
}

# Unique union of all elements.
# Preserves original order.
sub unique {
    my %seen;
    return grep { !$seen{$_}++ } @_;
}

1;
