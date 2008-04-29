package Netspoc::Approve::Device::Cisco::Parse;

############################################################
#
# Authors: Arne Spetzler, Heinz Knutzen, Daniel Brunkhorst
#
# Description:
# Module to parse cisco command lines.
#
############################################################

use strict;
use warnings;
use Netspoc::Approve::Helper;

require Exporter;

our @ISA = qw(Exporter);
our @EXPORT = qw(analyze_conf_lines err_at_line
                 get_token get_regex get_int get_ip get_eol
                 check_token check_regex check_int check_ip );


my %cmd_one_arg = ( 'remark' => 1,
		    'description' => 1,
    );
my %cmd_is_prefix = ( 'ip' => 1,
		      'crypto' => 1,
		      'switchport' => 1,
		      'router' => 1,
    );
my %has_subcmd = ( 'interface' => 1,
		   'ip access-list' => 'ordered',
		   'access-list' => 'ordered',
		   'object-group' => 1,
    );

# Read indented lines of commands from Cisco device.
# Build a hash where
# - sub-commands are attached to its master command,
# - command lines are either
#   - grouped by its first keyword 
#   - or pushed to an array.
# 
# $config->{$cmd1 => [{args => [args1, ...], sub => {$cmd => [..]}},
#                     {args => [args2, ...], sub => {$cmd => [..]}},..]
#           $cmd2 => [{args => [args3, ...], ordered => [[$cmd @args], ...]}]
#        ..}
#           
sub analyze_conf_lines {
    my ($lines) = @_;
    my @config_stack;
    my $level = 0;
    my $config = {};
    my $counter = 0;

    for my $line (@$lines) {
	$counter++;	

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
	    die "Got unexpected sub-command at line $counter\n";
	}
	else {
	    while($sub_level < $level) {
		$config = pop @config_stack;
		$level--;
	    }
	}
	my @args;
	(my $cmd, $rest) = split(' ', $rest, 2);
	if($cmd_one_arg{$cmd}) {
	    @args = ($rest);
	}
	else {
	    @args = split(' ', $rest);
	    if($cmd_is_prefix{$cmd}) {
		$cmd .= ' ' . shift(@args);
	    }
	}

	# Remember current line number, set parse position.
	# Remember a version of the unparsed line without duplicate whitespace.
	my $new_cmd = { line => $counter, 
			pos => 0, 
			orig => join(' ', $cmd, @args) };
	if(ref $config eq 'ARRAY') {
	    $new_cmd->{args} = [ $cmd, @args ];
	    push @$config, $new_cmd;
	}
	elsif(ref $config eq 'HASH') {
	    @{$new_cmd}{'cmd', 'args'} = ($cmd, \@args);
	    push @{ $config->{$cmd} }, $new_cmd;
	}
	else {
	    die "Got unexpected sub-command at line $counter\n";
	}
	if(my $type = $has_subcmd{$cmd}) {
	    push @config_stack, $config;
	    $config = ($type eq 'ordered') ? [] : {};
	    $new_cmd->{sub} = $config;
	    $level++;
	}
    }
    while($level--) {
	$config = pop @config_stack;
    }
    return $config;
}  

sub err_at_line {
    my($desc, @args) = @_;
    my $line = $desc->{line};
    my $pos = $desc->{pos};
    die @args, " at line $line, pos $pos\n";
}

sub check_token {
    my($desc) = @_;
    my $args = $desc->{args};
    my $len = length $args;
    $desc->{pos}+1 > $len and return;
    return $args->[$desc->{pos}++];
}
    
sub get_token {
    my($desc) = @_;
    my $result = check_token($desc);
    defined($result) or err_at_line($desc, 'Missing token');
    return $result;
}

sub get_eol {
    my($desc) = @_;
    my $result = check_token($desc);
    defined($result) and err_at_line($desc, "Unexpected token '$result'");
    return 1;
}

sub get_regex {
    my($regex, $desc) = @_;
    my $token = get_token($desc);
    $token =~ /^(:?$regex)$/ or err_at_line($desc, "Missing '$regex'");
    return $token;
}

sub check_regex {
    my($regex, $desc) = @_;
    defined(my $token = check_token($desc)) or return;
    return $token if $token =~ /^(:?$regex)$/;
    $desc->{pos}--;
    return;
}

sub get_int {
    my($desc) = @_;
    return get_regex(qr/\d+/, $desc);
}

sub check_int {
    my($desc) = @_;
    return check_regex(qr/\d+/, $desc);
}

sub get_ip {
    my($desc) = @_;
    my $ip = quad2int(get_token($desc));
    defined $ip or err_at_line($desc, "Missing IP");
    return $ip;
}

sub check_ip {
    my($desc) = @_;
    my $token = check_token($desc) or return;
    my $ip = quad2int($token);
    return $ip if defined $ip;
    $desc->{pos}--;
    return;
}

