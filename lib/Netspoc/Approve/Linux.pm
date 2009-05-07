
package Netspoc::Approve::Linux;

# Author: Heinz Knutzen
#
# Description:
# Module to remote configure Linux devices.


'$Id$' =~ / (.+),v (.+?) /;

my $id = "$1 $2";

use strict;
use warnings;
use base "Netspoc::Approve::Device";
use Netspoc::Approve::Helper;
use Netspoc::Approve::Parse_Cisco;

my $config = {
    device_routing_file => '/etc/network/routing',
    iptables_restore_cmd => '/usr/sbin/iptables-restore',
    device_iptables_file => '/etc/network/packet-filter',
    tmp_file => '/tmp/netspoc',
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
		      ['seq',
		       { parse => qr/via/ },
		       { parse => \&get_ip, store => 'NEXTHOP' } ],
		      ['seq',
		       { parse => qr/dev/ },
		       { parse => \&get_token, store => 'NIF' } ],
		      ['seq',
		       { parse => qr/tos/ },
		       { parse => \&get_token, store => 'TOS' } ],
		      ['seq',
		       { parse => qr/table/ },
		       { parse => \&get_token, store => 'TABLE' } ],
		      ['seq',
		       { parse => qr/proto/ },
		       { parse => \&get_token, store => 'PROTO' } ],
		      ['seq',
		       { parse => qr/scope/ },
		       { parse => \&get_token, store => 'SCOPE' } ],
		      ['seq',
		       { parse => qr/metric/ },
		       { parse => \&get_token, store => 'METRIC' } ],
		      ['seq',
		       { parse => qr/mpath/ },
		       { parse => \&get_token, store => 'MPATH' } ],
		      ['seq',
		       { parse => qr/weight/ },
		       { parse => \&get_ip, store => 'WEIGHT' } ],
		      {parse => qr/onlink|pervasive/, store => 'NHFLAGS' },
		      {parse => qr/equalize/, store => 'FLAGS' },
		      ['seq',
		       { parse => qr/mtu/ },
		       { parse => \&get_ip, store => 'MTU' } ],
		      ['seq',
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
    my ($self, $lines, $parse_info) = @_;
    $self->add_prefix_suffix_info($parse_info);
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

	# Substitute "*name" by "*" "name" and ":name" by ":" "name".
	if($args[0] =~ /^([*:])(.*)$/) {
	    splice(@args, 0, 1, $1, $2);
	}
	my $cmd = shift(@args);
	if(my $prefix_info = $parse_info->{_prefix}) {
	    my $prefix = $cmd;
	    while($prefix_info = $prefix_info->{$prefix}) {
		$prefix = shift(@args);
		$cmd .= ' ' . $prefix;
	    }
	}

	# Remember current line number, set parse position.
	# Remember the original line.
	my $new_cmd = { line => $counter, 
			pos  => 0, 
			orig => $line,
			args => [ $cmd, @args ], };

	# Unknown command terminates current subcommand level.
	while(not $parse_info->{$cmd} and @stack) {
	    ($config, $parse_info) = @{ pop @stack };
	}

	# Store only known commands.
	if($parse_info->{$cmd}) {
	    push(@$config, $new_cmd);
	    if(my $subcmd = $parse_info->{$cmd}->{subcmd}) {
		push @stack, [ $config, $parse_info ];
		$config = [];
		$new_cmd->{subcmd} = $config;
		$parse_info = $subcmd;
	    }
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

# Helper functions.
# Convert string to internal representation and vice versa.

sub internal_err( @ ) {
    my ($package, $file, $line, $sub) = caller 1;
    die "Internal error in $sub: ", @_, "\n";
}

sub debug {
    print(STDERR "@_\n");
}

sub err_msg {
    errpr("@_\n");
}

sub info_msg {
    print("@_\n");
}

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
    defined $base or err_msg("Expected IP: $addr");
    if(defined $prefix) {
	if($prefix =~ /^\d+$/) {
	    $prefix <= 32 or
		err_msg("Expected IP prefix: $prefix");
	    $mask = 2**32 - 2**(32 - $prefix);
	}
	else {
	    $mask = quad2int($prefix);
	    defined $mask or err_msg("Expected IP mask: $mask");
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
	($mask & 0x80000000) or err_msg("Invalid mask: ", int2quad($mask));
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
sub prefix_code( $ ) {
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
    my ($mode, $type, $src, $dst) = @{$rule}{qw(MODE TYPE SRC DST)};
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
    return join(' ', @result);
}
	

my $normalize = {
    '-j' => {
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
};	

# Normalize values of iptables rules.
# For builtin rules, the value is converted to a normalized string.
# For user defined rules, values are stored in internal representation.
# For user defined chains, only simple key / value pairs and "! --syn" are allowed.
sub normalize {
    my($chain) = @_;
    my $is_user_chain = not $chain->{POLICY};
    for my $rule (@{ $chain->{RULES} }) {
	for my $key (keys %$rule) {
	    my $v = $rule->{$key};
	    my $spec = $normalize->{$key};
	    if(not $spec) {
		next;
	    }
	    my $size = $spec->{size};
	    defined $size or $size = 1;
	    @{[ split(' ', $v) ]} == $size or 
		err_msg("$key needs $size arguments but got '$v'");
	    my $negate = '';
	    if($v =~/^!/) {

		# Extract '!' and replace it by ''.
		$negate = substr($v, 0, 1, '');
	    }
	    $v = $spec->{intern}->($v);
	    if($is_user_chain) {
		if($spec->{must_negate}) {
		    $negate or 
			err_msg("$key must be negated in user chain");
		}
		else {
		    $negate and
			err_msg("$key must not be negated in user chain");
		}
	    }
	    else {
		$v = $negate . $spec->{extern}->($v);
	    }
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
	    elsif($k1 eq 'name' or $k1 eq 'line' or $k1 eq 'orig') {
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
sub expand_chain {
    my($chain, $chains) = @_;
    return $chain->{EXPANDED} if $chain->{EXPANDED};
    my $rules = $chain->{RULES};
    my @result;
    for(my $i = 0; $i < @$rules; $i++) {
	my $rule = $rules->[$i];

	# We only accept the goto flag '-g' as equivalent to '-j'
	# if all following rules of the same chain are disjoint to current rule.
	if($rule->{-g}) {
	    for (my $j = $i+1; $j < @$rules; $j++) {
		my $next = $rules->[$j];
		disjoint($rule, $next) or
		    err_msg "Unsuported '-g' for rules",
		    "\n $rule->{orig} $next->{orig}";
	    }
	}

	my $target = $rule->{-j} || $rule->{-g} or err_msg "Missing target in rule";

	# Terminal target.
	if(not $chains->{$target}) {
	    push @result, $rule;
	    next;
	}
	my $expanded = expand_chain($chains->{$target}, $chains);
	for my $erule (@$expanded) {
	    push @result, intersect_rule($rule, $erule);
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
	my $printed;
	for my $key (sort keys %$rule) {

	    # Ignore internal keys not starting with '-'.
	    next if $key !~ /^-/;

	    my $value = $rule->{$key};

	    # Ignore match option for standard protocols.
	    if($key eq '-m') {
		my $proto = $rule->{-p} || '';
		$value eq $proto or
		    err_msg "Unsupported key/value '-m $value'",
		    " in chain '$chain->{name}' of iptables";
		next;
	    }

	    if(my $spec = $iptables2intern{$key}) {
		my $conv_key = $spec->[0];
		$converted->{$conv_key} = $value;
	    }
	    else {
		err_msg "Key $key not supported in chain '$chain->{name}' of iptables";
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
	$table = $new;
    }

    for my $chains (values %$tables) {
	for my $chain (values %$chains) {
	    normalize($chain);
	}
	for my $chain (values %$chains) {

	    # Ignore toplevel chains
	    next if $chain->{POLICY};
	    expand_chain($chain, $chains);
	}
	for my $chain (values %$chains) {
	    convert_rules($chain);
	}
    }
}

sub merge_iptables {
    my ($self, $spoc_conf, $raw_conf) = @_;
    my $spoc_tables = $spoc_conf->{IPTABLES};
    my $raw_tables = $raw_conf->{IPTABLES};
    for my $table_name (keys %$raw_tables) {
	info_msg "rawdata: table: $table_name";
	my $raw_chains = $raw_tables->{$table_name};
	my $spoc_chains = $spoc_tables->{$table_name};
	if(not $spoc_chains) {
	    info_msg "Adding all chains of table '$table_name'";
	    $spoc_tables->{$table_name} = $raw_chains;
	    next;
	}
	for my $raw_chain (values %$raw_chains) {
	    my $chain_name = $raw_chain->{name};
	    my $spoc_chain = $spoc_chains->{$chain_name};
	    if(not $spoc_chain) {
		info_msg "Adding chain '$chain_name' of table '$table_name'";
		$spoc_chains->{$chain_name} = $raw_chain;
		next;
	    }
	    if(not $spoc_chain->{POLICY}) {
		err_msg "rawdata: Must not redefine chain '$spoc_chain' from rawdata";
	    }
	    info_msg "Prepending chain '$chain_name' of table '$table_name'";
	    unshift @{ $spoc_chain->{RULES} }, @{$raw_chain->{RULES} };
	}
    }
}	    
    
sub postprocess_routes {
    my ($self, $config) = @_;

    # Ignore entries with 'scope link'.
    # Ignore entries with 'proto xxx' except 'proto static'.
    # Ignore attribute 'dev', if 'via' is provided.
    my @routes;
    for my $entry (@{ $config->{ROUTING} }) {
	next if $entry->{SCOPE} && $entry->{SCOPE} eq 'link';
	next if $entry->{PROTO} && $entry->{PROTO} ne 'static';
	if($entry->{NEXTHOP}) {
	    delete $entry->{NIF};
	}
	push(@routes, $entry);
    }
    $config->{ROUTING} = \@routes;
    return($config);
}    

sub postprocess_config {
    my ($self, $config) = @_;
    $self->postprocess_routes($config);
    $self->postprocess_iptables($config);
} 

sub compare_chains {
    my($self, $conf_chain, $spoc_chain, $context) = @_;
    my($conf_acl, $conf_name) = @{$conf_chain}{qw(EXPANDED name)};
    my($spoc_acl, $spoc_name) = @{$spoc_chain}{qw(EXPANDED name)};
    $self->acl_equal($conf_acl, $spoc_acl, $conf_name, $spoc_name, $context);
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
	info_msg "Comparing table '$tname'";
	if(not $spoc_tables->{$tname}) {
	  $changed = 1;
	  info_msg "#### Extra table on device: $tname";
	  next;
	}
	my $conf_chains = $conf_tables->{$tname};
	my $spoc_chains = $spoc_tables->{$tname};
	for my $cname (keys %$conf_chains) {
	    my $conf_chain = $conf_chains->{$cname};

	    # Only check builtin chains.
	    next if not $conf_chain->{POLICY};
	    my $spoc_chain = $spoc_chains->{$cname};
	    my $conf_rules = $conf_chain->{RULES};
	    my $spoc_rules = $spoc_chain->{RULES};
	    my $conf_count = @$conf_rules;
	    my $spoc_count = @$spoc_rules;
	    if($conf_count != $spoc_count) {
		$changed = 1;
		info_msg "#### Chain '$cname' of table '$tname' has different",
		"length: $conf_count at device, $spoc_count at netspoc";
		next;
	    }
	    for (my $i = 0; $i < $conf_count; $i++) {
		if(my($c_target, $s_target) = compare_rules($conf_rules->[$i],
							    $spoc_rules->[$i]))
		{
		    if(my $c_chain = $conf_chains->{$c_target}) {
			my $s_chain = $spoc_chains->{$s_target};
			my $context = "targets called by chain '$cname'";
			$self->compare_chains($c_chain, $s_chain, $context) or
			    $changed = 1;
		    }
		    elsif($c_target ne $s_target) {
			$changed = 1;
			info_msg "#### Rule $i of chain '$cname' of table '$tname'",
			" has changed target '$c_target' vs. '$s_target'";
		    }
		}
		else {
		    $changed = 1;
		    info_msg "#### Rule $i of chain '$cname' of table '$tname'",
		    " has changed";
		}
	    }
	}   
    }
    $self->{CHANGE}->{ACL} = $changed;
    return 1;
}

sub merge_rawdata {
    my ($self, $spoc_conf, $raw_conf) = @_;

    $self->merge_routing($spoc_conf, $raw_conf);
    $self->merge_iptables($spoc_conf, $raw_conf);
}

# NoOp.
sub checkinterfaces {
    my($self) = @_;
}

# NoOp.
sub check_firewall {
    my($self) = @_;
}

sub cmd {
    my ($self, $cmd) = @_;
    if ( $self->{CMD2STDOUT} ) {
	mypr "$cmd\n";
    }
    else {
	my $lines = $self->get_cmd_output($cmd);

	# Check for unexpected command output.
	$self->cmd_check_error($cmd, $lines);
    }
}

sub status_ok {
    my($self) = @_;
    my $status = $self->get_cmd_output('echo $?');
    return(@$status == 1 and $status->[0] eq '0');
}

sub cmd_ok {
    my ($self, $cmd) = @_;
    if ( $self->{CMD2STDOUT} ) {
	mypr "$cmd\n";
	return 1;
    }
    else {

	# Ignore Output; only check exit status.
	my $lines = $self->get_cmd_output($cmd);
	return($self->status_ok);
    }
}

my %valid_cmd_output = (
    $config->{store_flash_cmd} => q#tar: Removing leading `/' from member names#,
);

sub cmd_check_error($$) {
    my ($self, $cmd, $lines) = @_;
    if(@$lines) {
	if(not(@$lines == 1 and $lines->[0] eq $valid_cmd_output{$cmd})) {
	    errpr_info "$cmd failed\n";
	    for my $line (@$lines) {
		errpr_info "+++ $line\n";
	    }
	    errpr "+++\n";
	}
    }
    elsif(not $self->status_ok) {
	errpr "$cmd failed (exit status)\n";
    }
}

# NoOp.
sub schedule_reload {
    my($self, $time) = @_;
}

# NoOp.
sub cancel_reload {
    my($self) = @_;
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

sub write_startup_routing {
    my ($self, $conf, $file) = @_;
    $self->cmd("rm -f $file");
    $self->cmd("echo '#!/bin/sh' >> $file");
    $self->cmd("echo '# Generated by NetSPoC' >> $file");
    for my $entry (@{ $conf->{ROUTING} }) {
	my $cmd = $self->route_add($entry);
	chomp $cmd;
	$self->cmd("echo $cmd >> $file");
    }
}

sub write_startup_iptables {
    my ($self, $conf, $file) = @_;
    my $out = sub { my($line) = @_; $self->cmd("echo '$line' >> $file"); };
    $self->cmd("rm -f $file");
    $out->("#!$config->{iptables_restore_cmd}");
    $out->("# Generated by NetSPoC");
    my $iptables = $conf->{IPTABLES};
    for my $tname (keys %$iptables) {
	my $chains = $iptables->{$tname};
	$out->("*$tname");
	for my $cname (sort keys %$chains) {
	    my $chain = $chains->{$cname};
	    my $policy = $chain->{POLICY} || '-';
	    $out->(":$cname $policy");
	}
	for my $cname (sort keys %$chains) {
	    my $chain = $chains->{$cname};
	    for my $rule (@{$chain->{RULES}}) {
		my $line = $rule->{orig};
		chomp $line;
		$out->($line);
	    }
	}
	$out->('COMMIT');
    }
}

sub transfer {
    my ($self, $conf, $spoc_conf) = @_;

    # Change running configuration of device.
    $self->process_routing($conf, $spoc_conf) or return 0;

    # Only compare, no changes.
    $self->process_iptables($conf, $spoc_conf) or return 0;

    if (not $self->{COMPARE}) {
	my $tmp_file = $config->{tmp_file};
	my $startup_file;

	# Change iptables running + startup configuration of device.
	$startup_file = $config->{device_iptables_file};    
	$self->write_startup_iptables($spoc_conf, $tmp_file);
        if ($self->{CHANGE}->{ACL}) {
	    mypr "Changing iptables running config\n";
	    $self->cmd($tmp_file);
            mypr "Writing iptables startup config\n";  
	    $self->cmd("mv -f $tmp_file $startup_file");
            mypr "...done\n";
        }
        else {
            mypr "No changes to save - check if iptables startup is uptodate\n";
	    if($self->cmd_ok("cmp $tmp_file $startup_file")) {
                mypr "Startup is uptodate\n";
            }
            else {
                warnpr "Iptables startup is *NOT* uptodate - trying to fix:\n";
		$self->cmd("mv -f $tmp_file $startup_file");
		mypr "...done\n";
	    }
        }
	
	# Change routing startup configuration of device.
	$startup_file = $config->{device_routing_file};    
	$self->write_startup_routing($spoc_conf, $tmp_file);
        if ($self->{CHANGE}->{ROUTING}) {

	    # Running config has already been changed differentially.
            mypr "Writing routing startup config\n";  
	    $self->cmd("mv -f $tmp_file $startup_file");
            mypr "...done\n";
        }
        else {
            mypr "No changes to save - check if routing startup is uptodate\n";
	    if($self->cmd_ok("cmp $tmp_file $startup_file")) {
                mypr "Startup is uptodate\n";
            }
            else {
                warnpr "Routing startup is *NOT* uptodate - trying to fix:\n";
		$self->cmd("mv -f $tmp_file $startup_file");
		mypr "...done\n";
	    }
        }

	# Always write configuration to flash.
	# Someone may have changed it.
	if(my $cmd = $config->{store_flash_cmd}) {
            mypr "Saving config to flash\n";  
	    $self->cmd($cmd);
            mypr "...done\n";
	}
    }
    else {
        mypr "compare finish\n";
    }
    return 1;
}

sub get_config_from_device {
    my ($self) = @_;

    my $route_lines = $self->get_cmd_output('ip route show');
    my $iptables_lines = $self->get_cmd_output('iptables-save');
    return [ map({ "ip route add $_" } @$route_lines), @$iptables_lines ];
}

sub prepare {
    my ($self) = @_;
    $self->{PROMPT}    = qr/\r\n.*[\%\>\$\#]\s?$/;
    $self->{ENAPROMPT} = qr/\r\n.*#\s?$/;
    $self->{ENA_MODE}  = 0;
    $self->login_enable() or exit -1;
    mypr "logged in\n";
    $self->{ENA_MODE} = 1;
    my $result = $self->issue_cmd('');
    $result->{MATCH} =~ m/^\r\n\s?(\S+):.*\#\s?$/;
    my $name = $1;
    $self->checkidentity($name);

    # Set prompt again because of performance impact of standard prompt.
    $self->{ENAPROMPT} = qr/\r\n\s?$name:.*\#\s?$/;

    # Parameter --noediting prevents \r to be inserted in echoed commands.
    $self->issue_cmd('exec /bin/bash --noediting');
}

sub login_enable {
    my ($self) = @_;
    my($con, $ip) = @{$self}{qw(CONSOLE IP)};
    $con->{EXPECT}->spawn('ssh', '-l', 'root', $ip)
	or errpr "Cannot spawn ssh: $!\n";
    my $prompt = qr/$self->{PROMPT}|password:|\(yes\/no\)\?/i;
    $con->con_wait($prompt) or $con->con_error();
    if ($con->{RESULT}->{MATCH} =~ qr/\(yes\/no\)\?/i) {
	$con->con_dump();
	$con->{PROMPT}  = qr/$self->{PROMPT}|password:/i;
	$con->con_cmd("yes\n") or $con->con_error();
	$con->{PROMPT}  = $self->{PROMPT};
	mypr "\n";
	$con->con_dump();
    }
    if($con->{RESULT}->{MATCH} =~ qr/password:/i) {
	my $pass = $self->get_password();
	$con->con_cmd("$pass\n") or $con->con_error();
	$con->con_dump();
    }
    $self->{PRE_LOGIN_LINES} = $con->{RESULT}->{BEFORE};
    return 1;
}

# Packages must return a true value;
1;

