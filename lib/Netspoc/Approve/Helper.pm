
package Netspoc::Approve::Helper;

#
# Author: Arne Spetzler
#
# Description:
# module with misc helpers
#

require Exporter;
use strict;
use warnings;

our $VERSION = '1.079'; # VERSION: inserted by DZP::OurPkgVersion

our @ISA    = qw(Exporter);
our @EXPORT = qw(info abort err_info warn_info internal_err debug
                 quiet quad2int int2quad is_ip
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

sub int2quad {
    return join('.', unpack('C4', pack("N", $_[0])));
}

sub is_ip {
    my ( $obj ) = @_;
    return $obj =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
}


1;
