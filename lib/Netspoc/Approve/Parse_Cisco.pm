package Netspoc::Approve::Parse_Cisco;

# Authors: Arne Spetzler, Heinz Knutzen, Daniel Brunkhorst
#
# Description:
# Functions to parse Cisco command lines.
#
# $Id$

use strict;
use warnings;
use Netspoc::Approve::Helper;

require Exporter;

our @ISA = qw(Exporter);
our @EXPORT = 
    qw(analyze_conf_lines err_at_line
       get_token get_regex get_int get_ip get_eol get_ip_pair get_ip_prefix
       check_token check_regex check_int check_ip
       get_name_in_out get_paren_token test_ne skip
 );

# A Cisco command line consists of two parts: command and argument.
# A command is either a single word or a multi word command.
# A multi word command is put together from some prefix words 
# and optionally from a suffix word of the command line.
# This function identifies 
# - all words, which are prefix of some command.
# - if the prefix part of a command has a suffix.
# Known commands are read from the hash keys of $parse_info.
# The last word is a suffix if it is marked by a leading '+'.
sub add_prefix_suffix_info {
    my ($parse_info) = @_;
    my $result = {};

    for my $key (keys %$parse_info) {
	my @split = split(' ', $key);
	if($split[-1] =~ /^\+(.*)/) {
	    my $suffix = $1;
	    pop @split;
	    $parse_info->{_suffix}->{join(' ', @split)} = $suffix;
	}
	my $hash = $result;
	while(@split > 1) {
	    my $word = shift(@split);
	    $hash->{$word} ||= {};
	    $hash = $hash->{$word};
	}
	if(my $subcmd = $parse_info->{$key}->{subcmd}) {
	    add_prefix_suffix_info($subcmd);
	}
    }
    $parse_info->{_prefix} = $result if keys %$result;
}
	    
# Read indented lines of commands from Cisco device.
# Build an array where each command line is described by a hash
# - arg: an array of tokens split by whitespace
#      first element, the command name, consists of multiple tokens,
#      if prefix tokens are used.
# - subcmd: sub-commands related to current command
# 
# $config->[{args => [$cmd, @args], subcmd => [{args => [$cmd @args]}, ...]},
#           {args => [$cmd, @args], subcmd => [...]}
#        ..]
#           
sub analyze_conf_lines {
    my ($lines, $parse_info) = @_;
    add_prefix_suffix_info($parse_info);
    my @stack;
    my $level = 0;
    my $config = [];
    my $counter = 0;
    my $in_banner = 0;

    for my $line (@$lines) {
	$counter++;	

	if(my $cmd = $in_banner) {
	    if($line =~ /^\^/) {
		$in_banner = 0;
	    }
	    else {
		push(@{ $cmd->{lines} }, $line);
	    }
	    next;
	}

	# Ignore comment lines.
	next if $line =~ /^ *!/;

	# Ignore empty lines.
	next if $line =~ /^ *$/;

	# Get number of leading spaces.
	my ($indent, $rest) = $line =~ /^( *)(.*)$/;
	my $sub_level = length($indent);

	if($sub_level == $level) {

	    # Got expected command or sub-command.
	}
	elsif($sub_level > $level) {
	    die "Too much indented ($sub_level > $level) at line $counter:\n",
	    ">>$line<<\n";
	}
	else {
	    while($sub_level < $level) {
		($config, $parse_info) = @{ pop @stack };
		$level--;
	    }
	}
	my @args;
	(my $cmd, @args) = split(' ', $rest);
	if(my $prefix_info = $parse_info->{_prefix}) {
	    my $prefix = $cmd;
	    while($prefix_info = $prefix_info->{$prefix}) {
		$prefix = shift(@args);
		$cmd .= ' ' . $prefix;
	    }
	}
	if(my $suffix = $parse_info->{_suffix}->{$cmd}) {
	    if($args[-1] eq $suffix) {
		pop(@args);
		$cmd .= ' +' . $suffix;
	    }
	}

	# Ignore unknown command.
	# Prepare to ignore subcommands as well.
	if(not $parse_info->{$cmd}) {
	    push @stack, [ $config, $parse_info ];
	    $config = undef;
	    $parse_info = undef;
	    $level++;
	}
	else {

	    # Remember current line number, set parse position.
	    # Remember a version of the unparsed line without duplicate 
	    # whitespace.
	    my $new_cmd = { line => $counter, 
			    pos => 0, 
			    orig => join(' ', $cmd, @args),
			    args => [ $cmd, @args ], };
	    push(@$config, $new_cmd);
	    if(my $subcmd = $parse_info->{$cmd}->{subcmd}) {
		push @stack, [ $config, $parse_info ];
		$config = [];
		$new_cmd->{subcmd} = $config;
		$parse_info = $subcmd;
		$level++;
	    }
	    if($parse_info->{$cmd}->{banner}) {
		$new_cmd->{lines} = [];
		$in_banner = $new_cmd;
	    }
		
	}
    }
    while($level--) {
	($config, $parse_info) = @{ pop @stack };
    }
    return $config;
}  

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
	$mask = 0xffffffff;
	if(defined $prefix) {
	    $prefix =~ /^\d+$/ and $prefix <= 32 or
		err_at_line($arg, "Expected IP prefix: $prefix");
	    $mask = 2**32 - 2**(32 - $prefix);
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
    return(split(/,/, $inside));
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
    while(check_token($arg)) {}
    return;
}
