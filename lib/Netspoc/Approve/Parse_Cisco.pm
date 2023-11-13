
=head1 DESCRIPTION

Functions to parse Cisco command lines.

=head1 COPYRIGHT AND DISCLAIMER

https://github.com/hknutzen/Netspoc-Approve
(c) 2019 by Heinz Knutzen <heinz.knutzen@gmail.com>
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
use NetAddr::IP::Util;
use Regexp::IPv6 qw($IPv6_re);

require Exporter;

# VERSION: inserted by DZP::OurPkgVersion

our @ISA = qw(Exporter);
our @EXPORT =
    qw(err_at_line
       get_token get_regex get_int get_ip get_eol unread
       get_ip_prefix get_ipv6_prefix
       check_token check_regex check_int check_ip
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

#########################################################################
# Purpose    : Check whether there is another entry in $args-array. If so,
#              return it and increment $arg->{pos} by one, so that next position
#              will be read by next call.
# Parameters : $arg - hash entry of a command within config-hash generated
#              by sub analyze_conf_lines.
# Returns    : Next entry of $arg->{$args} (contains an array: [ $cmd, @args ]).
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

sub get_ip {
    my($arg) = @_;
    my $ip_string = get_token($arg);
    my $ip;
    if ($ip_string =~ m/(:?$IPv6_re|::)/) {
        $ip = NetAddr::IP::Util::ipv6_aton($ip_string);
    }
    else {
        $ip = quad2bitstr($ip_string);
    }
    defined $ip or err_at_line($arg, "Missing IP");
    return $ip;
}

sub check_ip {
    my($arg) = @_;
    my $token = check_token($arg) or return;
    my $ip = quad2bitstr($token);
    return $ip if defined $ip;
    unread($arg);
    return;
}

# <ip>[/<prefix>] | default
sub get_ip_prefix {
    my($arg) = @_;
    my $pair = get_token($arg);
    my($base, $mask);
    if($pair eq 'default') {
	$base = $mask = pack('N', 0);
    }
    else {
        # Is IP/prefix pair.
	my($addr, $prefix) = split(m'/', $pair, 2);
        $addr =~ /(:?$IPv6_re|::)/ and my $is_v6 = 1;

        # Turn address into ipv4/ipv6 bitstring.
        $base = $is_v6
            ? NetAddr::IP::Util::ipv6_aton($addr)
            : quad2bitstr($addr);
        defined $base or err_at_line($arg, "Expected IP: $addr");

        # Turn prefix into ipv4/ipv6 mask.
        if(defined $prefix) {
            ($prefix =~ /^\d+$/ && $prefix <= ($is_v6? 128 : 32)) or
                err_at_line($arg, "Expected IP prefix: $prefix");

            # Generate zero mask of appropriate length.
            $mask = $is_v6
                ? NetAddr::IP::Util::ipv6_aton('0:0:0:0:0:0:0:0')
                : pack('N', 0x00000000);

            # Bitwise turn 0 bits to 1 bits, until prefix length is reached.
            # As vec() has mixed-endian behaviour, @big_to_little_endian is
            # used to transform vec()s big-endianness within bytes to
            # little-endianness.
            my @big_to_little_endian = (7,5,3,1,-1,-3,-5,-7);
            for (my $pos = 0; $pos < $prefix; $pos++) {
                my $bitpos = $pos + $big_to_little_endian[$pos % 8];
                vec($mask, $bitpos, 1) = 1;
            }
        }
        else {
            $mask = $is_v6? NetAddr::IP::Util::ipv6_aton(
                        'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')
                : pack('N', 0xffffffff);
        }
    }
    return($base, $mask);
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
