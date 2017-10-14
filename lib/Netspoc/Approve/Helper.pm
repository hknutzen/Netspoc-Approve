
=head1 DESCRIPTION

Helper functions

=head1 COPYRIGHT AND DISCLAIMER

https://github.com/hknutzen/Netspoc-Approve
(c) 2013 by Heinz Knutzen <heinz.knutzen@gmail.com>
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

# VERSION: inserted by DZP::OurPkgVersion

our @ISA    = qw(Exporter);
our @EXPORT = qw(info abort err_info warn_info internal_err debug
                 quiet quad2int int2quad is_ip max
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

sub err_info {
    say_stderr("ERROR>>> ", @_);
}

sub warn_info {
    say_stderr("WARNING>>> ", @_);
}

sub internal_err {
    my ($package, $file, $line, $sub) = caller 1;
    abort("Internal error in $sub: ", @_);
}

sub debug {
    info(@_);
}

sub quad2int {
    ($_[0] =~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/) or return;
    ($1 < 256 && $2 < 256 && $3 < 256 && $4 < 256) or return;
    return $1 << 24 | $2 << 16 | $3 << 8 | $4;
}

sub max {
    my $max = shift(@_);
    for my $el (@_) {
        $max = $el if $max < $el;
    }
    return $max;
}


1;
