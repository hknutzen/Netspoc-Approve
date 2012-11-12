
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

our $VERSION = '1.060'; # VERSION: inserted by DZP::OurPkgVersion

our @ISA    = qw(Exporter);
our @EXPORT = qw( mypr errpr check_erro errpr_mode errpr_info
  warnpr check_warn internal_err debug quad2int int2quad is_ip
);

my $warn     = "NO";      # sorry its global...
my $erro     = "NO";      # same applies to this :(
my $err_mode = "";

sub mypr {
    print STDOUT @_;
}

sub errpr {
    $erro = "YES";
    print STDERR "ERROR>>> ", @_;
#    unless ($err_mode eq "COMPARE") {
#        print STDERR "ERROR>>> --- approve aborted ---\n";
        exit -1;
#    }
}

sub errpr_mode( $ ) {
    $err_mode = shift;
    $err_mode eq "COMPARE" or die "COMPARE expected\n";
}

sub check_erro() {
    return $erro;
}

sub errpr_info {
    print STDERR "ERROR>>> ", @_;
}

sub warnpr {
    $warn = "YES";
    print STDOUT "WARNING>>> ", @_;
}

sub check_warn() {
    return $warn;
}

sub internal_err( @ ) {
    my ($package, $file, $line, $sub) = caller 1;
    errpr "Internal error in $sub: ", @_, "\n";
}

sub debug ( @ ) {
    print STDERR @_, "\n";
}

sub quad2int ($) {
    ($_[0] =~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/) or return undef;
    ($1 < 256 && $2 < 256 && $3 < 256 && $4 < 256) or return undef;
    return $1 << 24 | $2 << 16 | $3 << 8 | $4;
}

sub int2quad ($) {
    return join('.', unpack('C4', pack("N", $_[0])));
}

sub is_ip {
    my ( $obj ) = @_;
    return $obj =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
}


1;
