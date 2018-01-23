
=head1 DESCRIPTION

Functions to parse Cisco command lines.

=head1 COPYRIGHT AND DISCLAIMER

https://github.com/hknutzen/Netspoc-Approve
(c) 2015 by Heinz Knutzen <heinz.knutzen@gmail.com>
(c) 2009 by Daniel Brunkhorst <daniel.brunkhorst@web.de>

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

package Netspoc::Approve::Parse_Cisco;

use strict;
use warnings;
use Netspoc::Approve::Helper;

require Exporter;

# VERSION: inserted by DZP::OurPkgVersion

our @ISA = qw(Exporter);
our @EXPORT =
    qw(err_at_line
       get_token get_regex get_int get_ip get_eol unread
       get_ip_pair get_ip_prefix
       check_token check_regex check_int check_loglevel check_ip
       get_sorted_encr_list get_token_list
       skip get_to_eol
 );

sub err_at_line {
    my($arg, @msg) = @_;
    my $line = $arg->{line};

    # $pos starts from 0 and points to next arg.
    # But humans start counting from 1, hence $pos points to current arg.
    # Fix value of $pos for multi word first arg like "ip address",
    # but ignore suffix of multi word arg like "ip address +secondary"
    # using negative lookahead.
    my @arg0 = split(/[ ](?![+])/, $arg->{args}->[0]);
    my $pos = $arg->{pos} + @arg0 - 1;
    abort( @msg, " at line $line, pos $pos:", ">>$arg->{orig}<<");
}

sub check_token {
    my($arg) = @_;
    my $args = $arg->{args};
    $arg->{pos}+1 > @$args and return;
    return $args->[$arg->{pos}++];
}

sub get_token {
    my($arg) = @_;
    my $result = check_token($arg);
    defined($result) or err_at_line($arg, 'Missing token');
    return $result;
}

sub get_eol {
    my($arg) = @_;
    my $result = check_token($arg);
    defined($result) and err_at_line($arg, "Unexpected token '$result'");
    return 1;
}

sub unread {
    my($arg) = @_;
    $arg->{pos}--;
}

sub get_regex {
    my($regex, $arg) = @_;
    my $token = get_token($arg);
    $token =~ /^(:?$regex)$/ or err_at_line($arg, "Missing '$regex'");
    return $token;
}

sub check_regex {
    my($regex, $arg) = @_;
    defined(my $token = check_token($arg)) or return;
    return $token if $token =~ /^(:?$regex)$/;
    unread($arg);
    return;
}

sub get_int {
    my($arg) = @_;
    return get_regex(qr/\d+/, $arg);
}

sub check_int {
    my($arg) = @_;
    return check_regex(qr/\d+/, $arg);
}

my %log2level = (
    emergencies => 0,
    alerts  => 1,
    critical => 2,
    errors => 3,
    warnings => 4,
    notifications => 5,
    informational => 6,
    debugging => 7,
);

sub check_loglevel {
    my($arg) = @_;
    defined(my $token = check_token($arg)) or return;
    if ($token =~ /^\d+$/) {
        return $token;
    }
    elsif (defined(my $level = $log2level{$token})) {
        return $level;
    }
    else {
        unread($arg);
        return;
    }
}

sub get_ip {
    my($arg) = @_;
    my $ip = quad2int(get_token($arg));
    defined $ip or err_at_line($arg, "Missing IP");
    return $ip;
}

sub check_ip {
    my($arg) = @_;
    my $token = check_token($arg) or return;
    my $ip = quad2int($token);
    return $ip if defined $ip;
    unread($arg);
    return;
}

# <ip>[-<ip>]
sub get_ip_pair {
    my($arg) = @_;
    my $pair = get_token($arg);
    my($from, $to) = split(/-/, $pair, 2);
    my $ip1 = quad2int($from);
    defined $ip1 or err_at_line($arg, "Expected IP: $from");
    my $ip2 = $ip1;
    if($to) {
        $ip2 = quad2int($to);
        defined $ip2 or err_at_line($arg, "Expected IP: $to");
    }
    return($ip1, $ip2);
}

# <ip>[/<prefix>] | default
sub get_ip_prefix {
    my($arg) = @_;
    my $pair = get_token($arg);
    my($base, $mask);
    if($pair eq 'default') {
        $base = $mask = 0;
    }
    else {
        my($addr, $prefix) = split(m'/', $pair, 2);
        $base = quad2int($addr);
        defined $base or err_at_line($arg, "Expected IP: $addr");
        if(defined $prefix) {
            ($prefix =~ /^\d+$/ && $prefix <= 32) or
                err_at_line($arg, "Expected IP prefix: $prefix");
            $mask = 2**32 - 2**(32 - $prefix);
        }
        else {
            $mask = 0xffffffff;
        }
    }
    return($base, $mask);
}

# Read list of auth. and encr. methods.
# Read up to 3 values, sort and return as space separated string.
# Sorting is needed to make different definitions comparable.
sub get_sorted_encr_list {
    my($arg) = @_;
    my @result;
    my $v1 = get_token($arg);
    push @result, $v1;
    if (my $v2 = check_token($arg)) {
        push @result, $v2;
        if (my $v3 = check_token($arg)) {
            push @result, $v3;
        }
    }
    return join ' ', sort @result;

}

# Read list of one or more tokens.
# Return as array reference.
sub get_token_list {
    my($arg) = @_;
    my @result = (get_token($arg));
    while (defined(my $v = check_token($arg))) {
        push @result, $v;
    }
    return \@result;
}

# Ignore remaining arguments.
sub skip {
    my($arg) = @_;
    while ( defined( check_token($arg) ) ) {}
    return;
}

# Collect remaining arguments.
sub get_to_eol {
    my($arg) = @_;
    my $string = '';
    while ( defined( my $token = check_token($arg) ) ) {
        $string .= $token . ' ';
    }
    $string =~ s/\s*$//;
    return $string;
}
