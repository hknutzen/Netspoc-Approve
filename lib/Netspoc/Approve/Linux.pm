
=head1 DESCRIPTION

Remote configure Linux iptables and routing

=head1 COPYRIGHT AND DISCLAIMER

https://github.com/hknutzen/Netspoc-Approve
(c) 2014 by Heinz Knutzen <heinz.knutzen@gmail.com>

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

package Netspoc::Approve::Linux;

use strict;
use warnings;
use File::Basename;
use File::Temp qw/ tempfile /;
use base "Netspoc::Approve::Device";
use Netspoc::Approve::Helper;
use Netspoc::Approve::Parse_Cisco;

our $VERSION = '1.113'; # VERSION: inserted by DZP::OurPkgVersion

my $config = {
    user => 'root',
    device_routing_file => '/etc/network/routing',
    device_iptables_file => '/etc/network/packet-filter',
    # Avoid /tmp/, because it may have attribute 'noexec'.
    tmp_routing => '/etc/network/routing.new',
    tmp_iptables => '/etc/network/packet-filter.new',
    store_flash_cmd => '/usr/sbin/backup',
};

sub get_parse_info {
    my ($self) = @_;
    my $result =
    {

# The output of netspoc contains lines like this:
# ip route add 10.2.9.0/24 via 10.1.13.39
# Function 'parse_config' uses the data below to parse the output of netspoc.
#
# The routing information of a device is retrieved with "ip route show".
# The output looks like this:
# 10.2.9.0/24 via 10.1.13.39 dev eth0
# The prefix "ip route add" is added before the string is parsed.
	'ip route add' => {
	    store => 'ROUTING',
	    multi => 1,
	    parse => ['seq',
		      { parse => qr/unicast|local|broadcast|multicast|throw|unreachable|prohibit|blackhole|nat/,
			store => 'TYPE', default => 'unicast' },
		      { parse => \&get_ip_prefix, 
			store_multi => ['BASE', 'MASK'] },
		      ['cond1',
		       { parse => qr/via/ },
		       { parse => \&get_ip, store => 'NEXTHOP' } ],
		      ['cond1',
		       { parse => qr/dev/ },
		       { parse => \&get_token, store => 'NIF' } ],
		      ['cond1',
		       { parse => qr/tos/ },
		       { parse => \&get_token, store => 'TOS' } ],
		      ['cond1',
		       { parse => qr/table/ },
		       { parse => \&get_token, store => 'TABLE' } ],
		      ['cond1',
		       { parse => qr/proto/ },
		       { parse => \&get_token, store => 'PROTO' } ],
		      ['cond1',
		       { parse => qr/scope/ },
		       { parse => \&get_token, store => 'SCOPE' } ],
		      ['cond1',
		       { parse => qr/metric/ },
		       { parse => \&get_token, store => 'METRIC' } ],
		      ['cond1',
		       { parse => qr/mpath/ },
		       { parse => \&get_token, store => 'MPATH' } ],
		      ['cond1',
		       { parse => qr/weight/ },
		       { parse => \&get_ip, store => 'WEIGHT' } ],
		      {parse => qr/onlink|pervasive/, store => 'NHFLAGS' },
		      {parse => qr/equalize/, store => 'FLAGS' },
		      ['cond1',
		       { parse => qr/mtu/ },
		       { parse => \&get_ip, store => 'MTU' } ],
		      ['cond1',
		       { parse => qr/src/ },
		       { parse => \&get_ip, store => 'SRC' } ]]},

	# # Comment
	# *filter
	# :INPUT ACCEPT [68024:74200042]
	# :FORWARD ACCEPT [0:0]
	# :OUTPUT ACCEPT [54724:5982979]
	# -A INPUT -s 10.1.2.3 -j ACCEPT 
	# COMMIT
	# # Comment
	'*' => {
	    store => 'IPTABLES',
	    named => 1,
	    subcmd => {
		':' => {
		    store => 'POLICY',
		    named => 1,
		    parse => 'parse_policy',
		},
		'-A' => { 
		    multi => 1,
		    store => 'RULES',
		    named => 1,
		    parse => 'parse_rule',
		},
		'COMMIT' => {},

		# Only used in code from netspoc.
		'EOF' => {},
	    },
	},
    };
    $result;
};

# Read lines from linux device.
# Build an array where each command line is described by a hash
# - arg: an array of tokens
#      first element, the command name, consists of multiple tokens,
#      if prefix tokens are used.
# - subcmd: sub-commands related to current command
# 
# $config->[{args => [$cmd, @args], subcmd => [{args => [$cmd @args]}, ...]},
#           {args => [$cmd, @args], subcmd => [...]}
#        ..]
sub analyze_conf_lines {
    my ($self, $lines, $parse_info, $strict) = @_;
    $self->add_prefix_info($parse_info);
    my @stack;
    my $config = [];
    my $counter = 0;

    for my $line (@$lines) {
	$counter++;

	# Ignore comment lines.
	next if $line =~ /^\s*#/;

	# Ignore empty lines.
	next if $line =~ /^\s*$/;

	my @args = split(' ', $line);

	# Remember a version of unparsed line without duplicate whitespace.
	my $orig = join(' ', @args);

	# Substitute "*name" by "*" "name" and ":name" by ":" "name".
	if($args[0] =~ /^([*:])(.*)$/) {
	    splice(@args, 0, 1, $1, $2);
	}
	my $cmd = shift(@args);
	if(my $prefix_info = $parse_info->{_prefix}) {
	    my $prefix = $cmd;
	    while($prefix_info = $prefix_info->{$prefix} and 
		  keys %$prefix_info)
	    {
		$prefix = shift(@args);
		$cmd .= ' ' . $prefix;
	    }
	}

	# Remember current line number, set parse position.
	# Remember the original line.
	my $new_cmd = { line => $counter, 
			pos  => 0, 
			orig => $orig,
			args => [ $cmd, @args ], };

	# Unknown command terminates current subcommand level.
	while(not $parse_info->{$cmd} and @stack) {
	    ($config, $parse_info) = @{ pop @stack };
	}

	# Store only known commands.
	if(my $cmd_info = $parse_info->{$cmd}) {
	    $new_cmd->{cmd_info} = $cmd_info;
	    push(@$config, $new_cmd);
	    if(my $subcmd = $parse_info->{$cmd}->{subcmd}) {
		push @stack, [ $config, $parse_info ];
		$config = [];
		$new_cmd->{subcmd} = $config;
		$parse_info = $subcmd;
	    }
	}

	# Terminate on unknown command.
	else {
	    err_at_line($new_cmd, "Unknown command");
	}
    }
    while(@stack) {
	($config, $parse_info) = @{ pop @stack };
    }
    return($config);
}

# Called by parse_config

# :INPUT ACCEPT [68024:74200042]
# :e0_in - [0:0]
sub parse_policy {
    my($self, $arg) = @_;
    my $policy = get_token($arg);

    # Ignore optional counters.
    check_token($arg);

    # Ignore value of user defined chain.
    return($policy eq '-') ? undef : $policy;
}

# -A INPUT -s 10.1.2.3 -p tcp ! --syn -j ACCEPT 
sub parse_rule {
    my($self, $arg) = @_;

    # Store rule as hash.
    # Allow zero, one or more arguments after key.
    # '!' can occur before or after the key,
    # but only after key, if at least one argument.
    my $rule = {};
    my $negate_next_cmd = '';
    while(my $key = check_token($arg)) {
	my $negate = $negate_next_cmd;
	$negate_next_cmd = '';
	if($key eq '!') {
	    $negate ||= $key;
	    $key = get_token($arg);
	}
	my @args;
	my $negate_arg = check_regex(qr/!/, $arg) || '';
	while(defined (my $value = check_regex(qr/[^!-].*/, $arg))) {
	    push @args, $value;
	}
	if(not @args) {
	    $negate_next_cmd = $negate_arg;
	}
	else {
	    $negate ||= $negate_arg;
	}
	my $v = $negate . join(' ', @args);

	# Hard code special case:
	# ! --tcp-flags FIN,SYN,RST,ACK SYN ==> ! --syn
	if($key eq '--tcp-flags' and $v = '!FIN,SYN,RST,ACK SYN') {
	    $key = '--syn';
	    $v = '!';
	}
	$rule->{$key} = $v;
    }
    $negate_next_cmd and err_at_line "Unexpected trailing '!'";
    return $rule;
}

# Convert string to internal representation and vice versa.
sub mode2intern {
    my($token) = @_;
    if($token eq 'ACCEPT') {
	return 'permit';
    }
    elsif($token eq 'DROP') {
	return 'deny';
    }
    else {

	# Leave chain target unchanged.
	return $token;
    }
}

sub prefix2intern {
    my($token) = @_;
    my($addr, $prefix) = split(m'/', $token, 2);
    my $base = quad2int($addr);
    my $mask;
    defined $base or abort("Expected IP: $addr");
    if(defined $prefix) {
	if($prefix =~ /^\d+$/) {
	    $prefix <= 32 or
		abort("Expected IP prefix: $prefix");
	    $mask = 2**32 - 2**(32 - $prefix);
	}
	else {
	    $mask = quad2int($prefix);
	    defined $mask or abort("Expected IP mask: $mask");
	}
    }
    else {
	$mask = 0xffffffff;
    }
    return({ BASE => $base, MASK => $mask });
}

sub range2intern {
    my($token) = @_;
    my($low, $high) = split(':', $token);
    if(defined $high) {
	$low eq '' and $low = 0;
	$high eq '' and $high = 65535;
    }
    else{
	$high = $low;
    }
    return({ LOW => $low, HIGH => $high });
}

sub icmp2intern {
    my($token) = @_;
    my($type, $code) = split('/', $token);
    return({ TYPE => $type, CODE => $code });
}

sub mask2prefix {
    my($mask) = @_;
    my $prefix = 0;
    while($mask) {
	($mask & 0x80000000) or abort("Invalid mask: ", int2quad($mask));
	$mask &= 0x7fffffff;
	$mask <<= 1;
	$prefix++;
    }
    $prefix;
}

sub mode_code {
    my($mode) = @_;
    if($mode eq 'permit') {
	return 'ACCEPT';
    }
    elsif($mode eq 'deny') {
	return 'DROP';
    }
    else {
	return $mode;
    }
}

# Given an IP and mask, return its address
# as "x.x.x.x/x" or "x.x.x.x" if prefix == 32.
sub prefix_code {
    my ($spec) = @_;
    my ($ip, $mask) =  @{$spec}{qw(BASE MASK)};
    my $ip_code     = int2quad($ip);
    my $prefix_code = mask2prefix($mask);
    return $prefix_code == 32 ? $ip_code : "$ip_code/$prefix_code";
}

sub range_code {
    my ($spec) = @_;
    my($v1, $v2) = @{$spec}{qw(LOW HIGH)};
    if ($v1 == $v2) {
	return "$v1";
    }
    elsif ($v1 == 0 and $v2 == 65535) {
	return;
    }
    elsif ($v2 == 65535) {
	return "$v1:";
    }
    elsif ($v1 == 0) {
	return ":$v2";
    }
    else {
	return "$v1:$v2";
    }
};

sub icmp_code {
    my($spec) = @_;
    my($type, $code) = @{$spec}{qw(TYPE CODE)};
    if (defined($type)) {
	if (defined($code)) {
	    return "$type/$code";
	}
	else {
	    return $type;
	}
    }
    else {
	return;
    }
}

sub rule_code {
    my($rule) = @_;
    my ($mode, $type, $src, $dst, $log) = @{$rule}{qw(MODE TYPE SRC DST)};

    my @result;
    push @result, "-s " . prefix_code($src) if $src->{BASE} != 0;
    push @result, "-d " . prefix_code($dst) if $dst->{BASE} != 0;
    if($type eq 'ip') {
	;
    }
    elsif($type eq 'tcp' || $type eq 'udp') {
	push @result, "-p $type";
	my $v = range_code($rule->{SRC_PORT});
	push @result, "--sport $v" if defined $v;
	$v = range_code($rule->{DST_PORT});
	push @result, "--dport $v" if defined $v;
	push @result, "! --syn" if $rule->{ESTA};	
    }
    elsif($type eq 'icmp') {
	push @result, "-p $type";
	my $v = icmp_code($rule->{SPEC});
	push @result, "--icmp-type $v" if defined $v;
    }
    else {
	push @result, "-p $type";
    }
    push @result, "-j " . mode_code($mode) if $mode;
    return(join(' ', @result));
}
	

my $normalize = {
    '-j' => {
	intern => \&mode2intern,
	extern => \&mode_code,
    },
    '-g' => {
	intern => \&mode2intern,
	extern => \&mode_code,
    },
    '-s' => {
	intern => \&prefix2intern,
	extern => \&prefix_code,
    },
    '-d' => {
	intern => \&prefix2intern,
	extern => \&prefix_code,
    },
    '--syn' => {
	must_negate => 1,
	intern => sub { '!' },
	extern => sub { '!' },
    },
    '--sport' => {
	intern => \&range2intern,
	extern => \&range_code,
    },
    '--dport' => {
	intern => \&range2intern,
	extern => \&range_code,
    },
    '--icmp-type' => {
	intern => \&icmp2intern,
	extern => \&icmp_code,
    },
    '-p' => {
	intern => sub { my($v) = @_; 
                        $v = lc $v; 
                        $v =~ s/^vrrp$/112/; 
                        $v =~ s/^ipv6-icmp$/58/; 
                        $v;
        },
	extern => sub { $_[0] },
    },
    '--state' => {
	non_comparable => 1,

	# RELATED,ESTABLISHED -> ESTABLISHED,RELATED
	intern => sub { join(',', sort(split(/,/, $_[0]))) },
	extern => sub { $_[0] },
    },
    '--set-mark' => {
	non_comparable => 1,
	intern => sub { my($v) = @_;

			# Ignore default mask.
			$v =~ s(\/0xffffffff$)()i;

			# Convert from hex to decimal.
			$v =~ s/^0x[0-9a-f]+/hex($v)/ie;

                        return $v;
			},
	extern => sub { $_[0] },
    },
};	

# Normalize values of iptables rules.
# For builtin chains, the value is converted to a normalized string.
# For user defined chains, values are stored in internal representation.
# For user defined chains, only simple key / value pairs and "! --syn" are allowed.
sub normalize {
    my($chain, $chains) = @_;
    for my $rule (@{ $chain->{RULES} }) {

	# Ignore match option for standard protocols.
	if(my $v = $rule->{'-m'}) {
	    my $proto = $rule->{'-p'} || '';
	    if(lc($v) eq lc($proto)) {
		delete $rule->{'-m'};
	    }
	}

	# Check, if no target is called.
	if(not ($rule->{'-j'} or $rule->{'-g'})) {
	    $chain->{NON_COMPARABLE} = 1;
	}

	# Check, if a builtin target other than ACCEPT or DROP is called.
	# Rule with LOG isn't checked, because it is ignored later.
	elsif(my $v = $rule->{'-j'}) {
	    if(not $chains->{$v}) {
		next if $v eq 'LOG';
		if(not ($v eq 'DROP' or $v eq 'ACCEPT')) {
		    $chain->{NON_COMPARABLE} = 1;
		}
	    }
	}

	# --set-xmark is equivalent to --set-mark for default mask /0xffffffff
	if(my $v = $rule->{'--set-xmark'}) {
	    if($v !~ m'/' || $v =~ m'/0xffffffff$'i) {
		delete $rule->{'--set-xmark'};
		$rule->{'--set-mark'} = $v;
	    }
	}

	for my $key (keys %$rule) {
	    next if $key !~ /^-/;
	    my $spec = $normalize->{$key};
	    if(not $spec) {
		$chain->{NON_COMPARABLE} = 1;
		next;
	    }
	    $chain->{NON_COMPARABLE} = 1 if $spec->{non_comparable};
	}
	for my $key (keys %$rule) {
	    next if $key !~ /^-/;
	    my $v = $rule->{$key};
	    my $spec = $normalize->{$key};
	    if(not $spec) {
		next;
	    }
	    my $size = $spec->{size};
	    defined $size or $size = 1;
	    @{[ split(' ', $v) ]} == $size or 
		abort("$key needs $size arguments but got '$v'");
	    my $negate = '';
	    if($v =~/^!/) {

		# Extract '!' and replace it by ''.
		$negate = substr($v, 0, 1, '');
	    }
	    if($spec->{must_negate} xor $negate) {
		$chain->{NON_COMPARABLE} = 1;
	    }
	    $v = $spec->{intern}->($v);
	    $rule->{intern}->{$key} = $v;
	    $v = $negate . $spec->{extern}->($v);
	    $rule->{$key} = $v;
	}
    }
}

# Helper function for flattening chains.
sub intersect_rule {
    my($rule1, $rule2) = @_;
    my $result;
    for my $k1 (keys %$rule1) {
	my $v1 = $rule1->{$k1};
	if(exists $rule2->{$k1}) {
	    my $v2 = $rule2->{$k1};
	    if($k1 eq '-s' || $k1 eq '-d') {
		my($b1, $m1) = @{$v1}{qw(BASE MASK)};
		my($b2, $m2) = @{$v2}{qw(BASE MASK)};

		# Switch values, such that b1/m1 is the larger network 
		# (with smaller mask).
		($b1, $m1, $b2, $m2) = ($b2, $m2, $b1, $m1) if ($m1 > $m2);

		# The smaller network must fit into the larger one.
		($b2 & $m1) == $b1 or internal_err "Empty intersection with '$k1'";
		$result->{$k1} = { BASE => $b2, MASK => $m2 };
	    }
	    elsif($k1 eq '--sport' || $k1 eq '--dport') {
		my($l1, $h1) = @{$v1}{qw(LOW HIGH)};
		my($l2, $h2) = @{$v2}{qw(LOW HIGH)};
		my $max = ($l1 > $l2) ? $l1 : $l2;
		my $min = ($h1 < $h2) ? $h1 : $h2;
		$max <= $min or internal_err "Empty intersection in '$k1'";
		$result->{$k1} = { LOW => $max, HIGH => $min };
	    }
	    elsif($k1 eq '--icmp-type') {
		my($t1, $c1) = @{$v1}{qw(TYPE CODE)};
		my($t2, $c2) = @{$v2}{qw(TYPE CODE)};
		$t1 == $t2 
		    or internal_err "Empty intersection with '$k1' (type)";
		my $c = (not defined $c1) 
		      ? $c2 
		      : (not defined $c2) 
		      ? $c1 
		      : ($c1 == $c2) 
		      ? $c1 
		      : internal_err "Empty intersection with '$k1' (code)";
		$result->{$k1} = { TYPE => $t1, CODE => $c};
	    }

	    # For protocol 'ip', no key 'p' is present.
	    elsif($k1 eq '-p') {
		$v1 eq $v2 or internal_err "Empty intersection in '$k1'";
		$result->{$k1} = $v1;
	    }
	    elsif($k1 eq '-j' or $k1 eq '-g') {
		
		# Ignore $v1, because it is a chain name by calling convention.
		$result->{$k1} = $v2;
	    }
	    elsif($k1 eq 'name' or $k1 eq 'line' or $k1 eq 'orig') {
		;
	    }
	    else {
		internal_err "Unexpected '$k1' during intersection";
	    }
	}
	else {
	    $result->{$k1} = $v1;
	}
    }
    for my $k2 (keys %$rule2) {

	# Has already been processed above.
	next if exists $rule1->{$k2};

	$result->{$k2} = $rule2->{$k2};
    }
    $result;
}

# Helper function while checking validity of '-g'
sub disjoint {
    my($rule1, $rule2) = @_;
    my $result;
    for my $k1 (keys %$rule1) {
	my $v1 = $rule1->{$k1};
	if(exists $rule2->{$k1}) {
	    my $v2 = $rule2->{$k1};
	    if($k1 eq '-s' || $k1 eq '-d') {
		my($b1, $m1) = @{$v1}{qw(BASE MASK)};
		my($b2, $m2) = @{$v2}{qw(BASE MASK)};

		# Switch values, such that b1/m1 is the larger network 
		# (with smaller mask).
		($b1, $m1, $b2, $m2) = ($b2, $m2, $b1, $m1) if ($m1 > $m2);

		# The smaller network must fit into the larger one.
		($b2 & $m1) == $b1 or return 1
	    }
	    elsif($k1 eq '--sport' || $k1 eq '--dport') {
		my($l1, $h1) = @{$v1}{qw(LOW HIGH)};
		my($l2, $h2) = @{$v2}{qw(LOW HIGH)};
		my $max = ($l1 > $l2) ? $l1 : $l2;
		my $min = ($h1 < $h2) ? $h1 : $h2;
		$max <= $min or return 1;
	    }
	    elsif($k1 eq '--icmp-type') {
		my($t1, $c1) = @{$v1}{qw(TYPE CODE)};
		my($t2, $c2) = @{$v2}{qw(TYPE CODE)};
		$t1 == $t2 or return 1;
		my $c = (not defined $c1) 
		      ? $c2 
		      : (not defined $c2) 
		      ? $c1 
		      : ($c1 == $c2) 
		      ? $c1 
		      : return 1;
	    }

	    # For protocol 'ip', no key '-p' is present.
	    elsif($k1 eq '-p') {
		$v1 eq $v2 or return 1;
	    }
	    elsif($k1 eq '-j' or $k1 eq '-g') {
		;
	    }
	    else {
		internal_err "Unexpected '$k1' during disjoint test";
	    }
	}
    }
    return 0;
}

# Process all rules of current chain and flatten calls to sub-chains.
# Mark chains which can't be flattend because of unknown attributes.
sub expand_chain {
    my($chain, $chains) = @_;
    return $chain->{EXPANDED} if $chain->{EXPANDED};
    my $rules = $chain->{RULES};
    my @result;
    for(my $i = 0; $i < @$rules; $i++) {
	my $rule = $rules->[$i];

	# We only accept the goto flag '-g' as equivalent to '-j' if
	# all following rules of the same chain are disjoint to current rule.
	if($rule->{'-g'}) {
	    for (my $j = $i+1; $j < @$rules; $j++) {
		my $next = $rules->[$j];
		disjoint($rule->{intern}, $next->{intern}) or
		    abort("Unsupported '-g' for rules",
                          "'$rule->{orig}', '$next->{orig}'");
	    }
	}

	my $target = $rule->{'-j'} || $rule->{'-g'} or 
	    abort("Missing target in rule");

	# Ignore LOG target; it can't be compared currently.
	next if $target eq 'LOG';

	# Terminal target.
	if(not $chains->{$target}) {
	    push @result, $rule->{intern};
	    next;
	}
	my $called_chain = $chains->{$target};
	$called_chain->{NON_COMPARABLE} and
	    abort("Expand: Must not call '$target' from '$chain->{name}'");
	my $expanded = expand_chain($called_chain, $chains);
	for my $erule (@$expanded) {
	    push @result, intersect_rule($rule->{intern}, $erule);
	}
    }
    $chain->{EXPANDED} = \@result;
    \@result;
}

my %iptables2intern = (
    '-p' => [ 'TYPE', 'ip' ],
    '-s' => [ 'SRC', { BASE => 0, MASK => 0 } ],
    '-d' => [ 'DST', { BASE => 0, MASK => 0 } ],
    '--sport' => [ 'SRC_PORT', { LOW => 0, HIGH => 65535 } ],
    '--dport' => [ 'DST_PORT', { LOW => 0, HIGH => 65535 } ],
    '--icmp-type' => [ 'SPEC', {} ],
    '--syn' => [ 'ESTA' ],
    '-j' => [ 'MODE' ],
    '-g' => [ 'MODE' ],
);

# Convert expanded rules to internal format used in acl_array_compare_a_in_b.
sub convert_rules {
    my($chain) = @_;
    my $rules = $chain->{EXPANDED};
    my @converted_result;
    my $line = 1;
    for my $rule (@$rules) {
	my $converted;
	for my $key (sort keys %$rule) {

	    # Ignore internal keys not starting with '-'.
	    next if $key !~ /^-/;

	    my $value = $rule->{$key};

	    if(my $spec = $iptables2intern{$key}) {
		my $conv_key = $spec->[0];
		$converted->{$conv_key} = $value;
	    }
	    else {
		abort("Key $key not supported in" .
                      " chain '$chain->{name}' of iptables");
	    }
	}
	for my $spec (values %iptables2intern) {
	    my($key, $default) = @$spec;
	    next if not defined $default;
	    if(not exists $converted->{$key}) {
		$converted->{$key} = $default;
	    }
	}
	$converted->{orig} = rule_code($converted);
	$converted->{line} = $line++;
	push @converted_result, $converted;
    }
    $chain->{EXPANDED} = \@converted_result;
    return \@converted_result;
}

# First convert parse tree into a simpler format.
# Pre:
# IPTABLES->{$table}->{RULES|POLICY}->{$chain}
# Post:
# IPTABLES->{$table}->{$chain}->{RULES|POLICY}
#
# Convert parsed iptables data to that format which is parsed from cisco
# devices. Then we can reuse the code to compare ACLs.
sub postprocess_iptables {
    my ($self, $p) = @_;

    my $tables = $p->{IPTABLES};

    # Convert to simpler format.
    for my $table (values %$tables) {
	my $new;
	my $policies = $table->{POLICY};
	my $chains = $table->{RULES};
	for my $name (keys %$chains) {
	    my $entry = { name => $name, RULES => $chains->{$name}};
	    $entry->{POLICY} = $policies->{$name} if $policies->{$name};
	    $new->{$name} = $entry;
	};
	for my $name (keys %$policies) {
	    next if $new->{$name};
	    $new->{$name} = { name => $name, 
			      RULES => [], 
			      POLICY => $policies->{$name} };
	}
	$table = $new;
    }

    for my $chains (values %$tables) {
	for my $chain (values %$chains) {
	    normalize($chain, $chains);
	}
	for my $chain (values %$chains) {
	    next if $chain->{NON_COMPARABLE};
	    expand_chain($chain, $chains);
	}
	for my $chain (values %$chains) {
	    next if $chain->{NON_COMPARABLE};
	    convert_rules($chain);
	}
    }
}

sub merge_acls {
    my ($self, $spoc_conf, $raw_conf, $append) = @_;
    my $spoc_tables = $spoc_conf->{IPTABLES};
    my $raw_tables = $raw_conf->{IPTABLES};
    for my $table_name (keys %$raw_tables) {

        # Delete entry from raw because it must not be processed again
        # in generic merge_rawdata.
	my $raw_chains = delete($raw_tables->{$table_name});
	my $spoc_chains = $spoc_tables->{$table_name};
	if(not $spoc_chains) {
	    info("Adding all chains of table '$table_name'");
	    $spoc_tables->{$table_name} = $raw_chains;
	    next;
	}
	for my $raw_chain (values %$raw_chains) {
	    my $chain_name = $raw_chain->{name};
	    my $spoc_chain = $spoc_chains->{$chain_name};
	    if(not $spoc_chain) {
		info("Adding chain '$chain_name' of table '$table_name'");
		$spoc_chains->{$chain_name} = $raw_chain;
		next;
	    }
	    if(not $spoc_chain->{POLICY}) {
		abort("Must not redefine chain '$spoc_chain' from rawdata");
	    }

            # Prepend/append raw acl.
            my $msg;
            my $spoc_entries = $spoc_chain->{RULES} ||= [];
            my $raw_entries = $raw_chain->{RULES};
            if ($append) {
                $msg = 'Appending';

                # Find last non deny line.
                my $index = @$spoc_entries;
                while ($index > 0) {
                    if ($spoc_entries->[$index-1]->{-j} =~ /^drop/i) {
                        $index--;
                    }
                    else {
                        last;
                    }
                }
                splice(@$spoc_entries, $index, 0, @$raw_entries);
            }
            else {
                $msg = 'Prepending';
                unshift(@$spoc_entries, @$raw_entries);
            }
	    info("$msg to chain '$chain_name' of table '$table_name'");
	}
    }
}	    
    
sub postprocess_routes {
    my ($self, $config) = @_;
    return if ! $config->{ROUTING};

    # Ignore entries with 'scope link'.
    # Ignore entries with 'proto xxx' except 'proto static'.
    # Ignore attribute 'dev', if 'via' is provided.
    my @routes;
    for my $entry (@{ delete $config->{ROUTING} }) {
	next if $entry->{SCOPE} && $entry->{SCOPE} eq 'link';
	next if $entry->{PROTO} && $entry->{PROTO} ne 'static';
	if($entry->{NEXTHOP}) {
	    delete $entry->{NIF};
	}
	push(@routes, $entry);
    }
    $config->{ROUTING_VRF}->{''} = \@routes;
}    

sub postprocess_config {
    my ($self, $config) = @_;
    $self->postprocess_routes($config);
    $self->postprocess_iptables($config);
} 

sub compare_chains_semantically {
    my($self, $conf_chain, $spoc_chain, $context) = @_;
    my($conf_acl, $conf_name) = @{$conf_chain}{qw(EXPANDED name)};
    my($spoc_acl, $spoc_name) = @{$spoc_chain}{qw(EXPANDED name)};
}

# Compare two rules.
# Return undef if rules are different.
# Return targets called by these rules, if rules are equal.
sub compare_rules {
    my($r1, $r2) = @_;
    keys %$r1 == keys %$r2 or return;
    my $jump;
    for my $k (keys %$r1) {

	# Ignore internal keys like 'name', 'line', 'orig'.
	next if $k !~ /^-/;
	if($k eq '-j' or $k eq '-g') {
	    $jump = $k;
	    next;
	}
	my $v1 = $r1->{$k};
	my $v2 = $r2->{$k};
	return if not $v2;
	return if not $v1 eq $v2;
    }
    if(my $k = $jump) {
	my $v1 = $r1->{$k};
	my $v2 = $r2->{$k};
	return if not defined $v2;
	return($v1, $v2);
    }
    else {

	# Rules call no chain, only used as counter.
	return('', '');
    }
}	

# Compare two chains.
sub chains_equal {
    my($self, $c_chains, $s_chains, $conf_chain, $spoc_chain, $context) = @_;
    my $c_name = $conf_chain->{name};
    my $s_name = $spoc_chain->{name};

    # Compare semantically
    if(not($conf_chain->{NON_COMPARABLE} or $spoc_chain->{NON_COMPARABLE})) {
	return $self->acl_equal($conf_chain->{EXPANDED},
				$spoc_chain->{EXPANDED}, 
				$c_name, $s_name, $context);
    }

    # Compare textually
    my $conf_rules = $conf_chain->{RULES} || [];
    my $spoc_rules = $spoc_chain->{RULES} || [];
    my $conf_count = @$conf_rules;
    my $spoc_count = @$spoc_rules;
    my $msg = ($c_name eq $s_name) 
	    ? "Chains '$c_name'" 
	    : "Chains '$c_name' and '$s_name";
    info("Comparing $msg textually");
    if($conf_count != $spoc_count) {
	info("$msg of $context have different",
             " length: $conf_count at device, $spoc_count at netspoc");
	return 0;
    }
    my $equal = 1;
    for (my $i = 0; $i < $conf_count; $i++) {
	if(my($c_target, $s_target) = compare_rules($conf_rules->[$i],
						    $spoc_rules->[$i]))
	{
	    my $c_chain = $c_chains->{$c_target};
	    my $s_chain = $s_chains->{$s_target};
	    if($c_chain and $s_chain) {
		my $context = $conf_chain->{name};
		$self->chains_equal($c_chains, $s_chains, 
				    $c_chain, $s_chain, $context)
		    or $equal = 0;
	    }
	    elsif($c_target ne $s_target) {
		my $which = $i+1;
		info("Rules $which of $msg of $context",
                     " have different target '$c_target' vs. '$s_target'");
		$equal = 0;
	    }
	}
	else {
	    my $which = $i+1;
	    info("Rules $which of $msg of $context are different");
	    $equal = 0;
	}
    }
    return $equal;
}

# - Iterate over all available tables.
# - Compare rule sets of builtin chains pairwise:
#   - both rules are identical: ok
#   - rules differ only for called chain: compare chains semantically
#   - else: report builtin chains as different 
sub process_iptables {
    my ($self, $conf, $spoc) = @_;
    my $conf_tables = $conf->{IPTABLES};
    my $spoc_tables = $spoc->{IPTABLES};
    my $changed = 0;
    for my $tname (keys %$conf_tables) {
	info("Comparing table '$tname'");
	my $conf_chains = $conf_tables->{$tname};
	my $spoc_chains = $spoc_tables->{$tname};
	if(not $spoc_chains) {
	  $changed = 1;
	  info("Extra table on device: $tname");
	  next;
	}
	for my $cname (keys %$conf_chains) {
	    my $conf_chain = $conf_chains->{$cname};

	    # Only check builtin chains.
	    next if not $conf_chain->{POLICY};
	    my $spoc_chain = $spoc_chains->{$cname};
	    if(not $spoc_chain) {
		$changed = 1;
		info("Extra chain on device: $cname");
		next;
	    }
	    $self->chains_equal($conf_chains, $spoc_chains,
				$conf_chain, $spoc_chain, $tname)
		or $changed = 1;
	}   
    }
    for my $tname (keys %$spoc_tables) {
        if (!$conf_tables->{$tname}) {
          $changed = 1;
	  info("Extra table from Netspoc: $tname");
        }
    }
    $self->{CHANGE}->{ACL} = $changed;
}

sub status_ok {
    my($self) = @_;
    my $status = $self->get_cmd_output('echo $?');
    return(@$status == 1 and $status->[0] eq '0');
}

sub cmd_ok {
    my ($self, $cmd) = @_;

    # Ignore Output; only check exit status.
    my $lines = $self->get_cmd_output($cmd);
    return($self->status_ok);
}

my %valid_cmd_output = (
    $config->{store_flash_cmd} => q#tar: Removing leading `/' from member names#,
);

sub cmd_check_error {
    my ($self, $cmd, $lines) = @_;
    if(@$lines) {
	my $valid = $valid_cmd_output{$cmd};
	if(not(@$lines == 1 and $valid and $lines->[0] eq $valid)) {
	    abort("Unexpected output of '$cmd'", @$lines);
	}
    }
    elsif(not $self->status_ok) {
	abort("$cmd failed (exit status)");
    }
}

# NoOp.
sub enter_conf_mode {
    my($self) = @_;
}

# NoOp.
sub leave_conf_mode {
    my($self) = @_;
}

# Entry from netspoc is complete  command.
sub route_add {
    my($self, $entry) = @_;
    return($entry->{orig});
}

sub route_del {
    my($self, $entry) = @_;
    my $orig = $entry->{orig};
    $orig =~ s/^ip route add//;
    return("ip route del$orig");
}

sub do_scp {
    my ($self, $mode, $src, $dst) = @_;
    my $ip = $self->{IP};
    my $user = $config->{user};
    my @args =
	       ($mode eq 'put') 
	     ? ($src, "$user\@$ip:$dst")
	     : ($mode eq 'get')
	     ? ("$user\@$ip:$src", $dst)
	     :  abort("undefined mode $mode for secure copy");
    unshift @args, 'scp', '-q';
    info(join(' ', 'Executing:', @args));
    system(@args) == 0
	or abort("system(". join(' ', @args) .") failed: $?");
}

sub write_startup_routing {
    my ($self, $spoc, $file) = @_;
    local $\ = "\n";

    # Create and open temporary file. 
    # File is automatically removed when the program exits.
    my ($fh, $tmpname) = tempfile(UNLINK => 1) or abort("Can't create tempfile: $!");
    print $fh '#!/bin/sh';
    print $fh '# Generated by NetSPoC';
    for my $entry (@{ $spoc->{ROUTING_VRF}->{''} }) {
	my $cmd = $self->route_add($entry);
	chomp $cmd;
	print $fh $cmd;
    }
    close $fh or abort("Can't close $tmpname: $!");
    $self->do_scp('put', $tmpname, $file);
}

sub find_iptables_restore_cmd {
    my ($self) = @_;
    my $path = ($self->get_cmd_output('which iptables-restore'))->[0] or
        abort("Can't find path of 'iptables-restore'");
    return $path;
}

sub write_startup_iptables {
    my ($self, $spoc, $file) = @_;
    my $path = $self->find_iptables_restore_cmd();
    local $\ = "\n";
    my ($fh, $tmpname) = tempfile(UNLINK => 1) or 
        abort("Can't create tempfile: $!");
    print $fh "#!$path";
    print $fh '# Generated by NetSPoC';
    my $iptables = $spoc->{IPTABLES};
    for my $tname (keys %$iptables) {
	my $chains = $iptables->{$tname};
	print $fh "*$tname";
	for my $cname (sort keys %$chains) {
	    my $chain = $chains->{$cname};
	    my $policy = $chain->{POLICY} || '-';
	    print $fh ":$cname $policy";
	}
	for my $cname (sort keys %$chains) {
	    my $chain = $chains->{$cname};
	    for my $rule (@{$chain->{RULES}}) {
		my $line = $rule->{orig};
		chomp $line;
		print $fh $line;
	    }
	}
	print $fh 'COMMIT';
    }
    close $fh or abort("Can't close $tmpname: $!");
    $self->do_scp('put', $tmpname, $file);
}

sub transfer {
    my ($self, $conf, $spoc_conf) = @_;

    # Change running configuration of device.
    $self->process_routing($conf, $spoc_conf);

    # This only compares.
    $self->process_iptables($conf, $spoc_conf);

    return if $self->{COMPARE};

    # Copy startup routing config to temporary file on device. 
    if ($self->{CHANGE}->{ROUTING}) {
        my $tmp_routing = $config->{tmp_routing}; 
        $self->write_startup_routing($spoc_conf, $tmp_routing);
    }
    
    # Copy startup iptables config to temporary file on device.
    # Change iptables configuration of device.
    if ($self->{CHANGE}->{ACL}) {
        my $tmp_iptables = $config->{tmp_iptables};
        $self->write_startup_iptables($spoc_conf, $tmp_iptables); 
        $self->cmd("chmod a+x $tmp_iptables");
        info("Changing iptables running config");
        $self->cmd($tmp_iptables);
    }
}

sub write_mem {
    my ($self) = @_;

    # Change routing startup configuration of device.
    my $tmp_routing = $config->{tmp_routing};
    my $startup_routing = $config->{device_routing_file};   
    if ($self->{CHANGE}->{ROUTING}) {
        
        # Running config has already been changed differentially.
        info("Writing routing startup config");  
        $self->cmd("mv -f $tmp_routing $startup_routing");
    }
    
    # Change iptables startup configuration of device.
    my $tmp_iptables = $config->{tmp_iptables};
    my $startup_iptables = $config->{device_iptables_file};
    if ($self->{CHANGE}->{ACL}) {
        info("Writing iptables startup config");  
        $self->cmd("mv -f $tmp_iptables $startup_iptables");
    }
    
    # Write configuration to flash if platform has this cmd.
    if((my $cmd = $config->{store_flash_cmd}) &&
       $self->cmd_ok('ls /etc/router-version')) 
    {
        info("Saving config to flash");  
        $self->cmd($cmd);
    }
}

sub get_config_from_device {
    my ($self) = @_;

    my $route_lines = $self->get_cmd_output('ip route show');
    my $iptables_lines = $self->get_cmd_output('iptables-save');
    return [ map({ "ip route add $_" } @$route_lines), @$iptables_lines ];
}

sub get_identity {
    my ($self) = @_;
    return ($self->get_cmd_output('hostname -s'))->[0];
}

sub parse_version {
    my ($self) = @_;
    $self->{VERSION} = ($self->get_cmd_output('uname -r'))->[0];
    $self->{HARDWARE} = ($self->get_cmd_output('uname -m'))->[0];
}

sub set_terminal {
    my ($self) = @_;
}

sub search_banner {
    my ($self, $string) = @_;
    return $self->cmd_ok("grep '$string' /etc/issue");
}

sub login_enable {
    my ($self) = @_;
    my $std_prompt = qr/\r\n\S*\s?[\%\>\$\#]\s?(?:\e\S*)?$/;
    my($con, $ip) = @{$self}{qw(CONSOLE IP)};
    $con->{EXPECT}->spawn('ssh', '-l', $config->{user}, $ip)
	or abort("Cannot spawn ssh: $!");
    my $prompt = qr/$std_prompt|password:|\(yes\/no\)\?/i;
    my $result = $con->con_short_wait($prompt);
    if ($result->{ERROR}) {
        $con->con_error();
    }
    if ($con->{RESULT}->{MATCH} =~ qr/\(yes\/no\)\?/i) {
	$prompt = qr/$std_prompt|password:/i;
	$con->con_issue_cmd('yes', $prompt);
	info("SSH key for $ip permanently added to known hosts");
    }

    # Password prompt comes only if no ssh keys are in use.
    if($con->{RESULT}->{MATCH} =~ qr/password:/i) {
	my $pass = $self->get_user_password('device');
	$prompt = qr/$std_prompt|password:/i;
	$con->con_issue_cmd($pass, $prompt);
	if ($con->{RESULT}->{MATCH} !~ $std_prompt) {
	    abort("Authentication failed");
	}
    }
    $self->{ENAPROMPT} = $std_prompt;

    # Force prompt to simple, known value.
    # Don't use '#', because it is used as comment character
    # in output of iptables-save.
    # This is a workaround for bug #100342 in Expect.pm.
    my $new_prompt = 'netspoc#';
    $self->device_cmd("PS1=$new_prompt");
    $self->{ENAPROMPT} = qr/\r\n \Q$new_prompt\E $/x;
}

# Packages must return a true value;
1;

