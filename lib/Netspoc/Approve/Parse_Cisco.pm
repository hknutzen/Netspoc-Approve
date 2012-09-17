package Netspoc::Approve::Parse_Cisco;

# Authors: Arne Spetzler, Heinz Knutzen, Daniel Brunkhorst
#
# Description:
# Functions to parse Cisco command lines.
#

use strict;
use warnings;
use Netspoc::Approve::Helper;

require Exporter;

our $VERSION = '1.057'; # VERSION: inserted by DZP::OurPkgVersion

our @ISA = qw(Exporter);
our @EXPORT = 
    qw(err_at_line
       get_token get_regex get_int get_ip get_eol get_ip_pair get_ip_prefix
       check_token check_regex check_int check_ip
       get_name_in_out get_paren_token test_ne skip get_to_eol
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
    die @msg, " at line $line, pos $pos:\n>>$arg->{orig}<<\n";
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
    $arg->{pos}--;
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
    my $ip = quad2int(get_token($arg));
    defined $ip or err_at_line($arg, "Missing IP");
    return $ip;
}

sub check_ip {
    my($arg) = @_;
    my $token = check_token($arg) or return;
    my $ip = quad2int($token);
    return $ip if defined $ip;
    $arg->{pos}--;
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

# <ip>[/<prefix>] | <ip>/<mask> | default
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
	    if($prefix =~ /^\d+$/) {
		$prefix <= 32 or
		    err_at_line($arg, "Expected IP prefix: $prefix");
		$mask = 2**32 - 2**(32 - $prefix);
	    }
	    else {
		$mask = quad2int($prefix);
		defined $mask or err_at_line($arg, "Expected IP mask: $mask");
	    }
	}
	else {
	    $mask = 0xffffffff;
	}
    }
    return($base, $mask);
}

# parse arguments like 'ip access-group <name> in'
sub get_name_in_out {
    my($arg) = @_;
    my $name = get_token($arg);
    my $direction = get_regex('in|out', $arg);
    return { $direction => $name };
}

sub get_paren_token {
    my($arg) = @_;
    my $token = get_token($arg);
    my($inside) = ($token =~ /^\((.*)\)$/) or 
	err_at_line($arg, 'Expected parenthesized value(s)');
    if(wantarray) {
	split(/,/, $inside);
    }
    else {
	my($result, @rest) = split(/,/, $inside);
	@rest and err_at_line($arg, 'Expected exactly one parenthesized value');
	$result;
    }
}

# Like bulitin function 'ne', but has additional argument $arg and 
# returns undef as false.
sub test_ne {
    my($arg, $a, $b) = @_;
    my $bool = $a ne $b;
    return($bool ? $bool : undef);
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
