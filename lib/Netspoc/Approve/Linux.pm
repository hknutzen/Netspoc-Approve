
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
# A separate function 'parse_routes' uses part of the data below to parse this.
	'ip route' => {
	    store => 'ROUTING',
	    multi => 1,
	    parse => ['seq',
		      ['or',
		       { parse => qr/add/ },
		       { error => 'expected keyword "add"' } ],
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
    };
    $result;
};

sub analyze_args {
    my ($lines) = @_;
    my $config = [];
    my $counter = 0;

    for my $line (@$lines) {
	$counter++;
	next if $line =~ /^#/;
	next if $line =~ /^\s*$/;
	my @args = split(' ', $line);

	# Remember current line number, set parse position.
	# Remember a version of the unparsed line without duplicate 
	# whitespace.
	my $new_cmd = { line => $counter, 
			pos  => 0, 
			orig => join(' ', @args),
			args => \@args, };
	push(@$config, $new_cmd);
    }
    return($config);
}
   
# Parse output of "ip route show".
# Output is like single "ip route add ..." commands 
# without the prefix "ip route add".
sub parse_routes {
    my ($self, $lines, $result) = @_;

    my $parse_route = $self->get_parse_info->{'ip route'};
    my $parser = $parse_route->{parse};

    # Remove 2. element 'add' from array.
    $parser = [ @$parser ];
    splice(@$parser, 1, 1);
    my $store = $parse_route->{store};
    $parse_route->{multi} or errpr  "internal: expected attribute 'multi'\n";
    my $args = analyze_args($lines);
    my @routes;
    for my $arg (@$args) {
	my $entry = $self->parse_line($arg, $parser);
	get_eol($arg);
	$entry->{orig} = $arg->{orig};
	push(@routes, $entry); 
    }
    $result->{$store} = \@routes;
}

my $normalize;

# # Comment
# *filter
# :INPUT ACCEPT [68024:74200042]
# :FORWARD ACCEPT [0:0]
# :OUTPUT ACCEPT [54724:5982979]
# -A INPUT -s 10.1.2.3 -j ACCEPT 
# COMMIT
# # Comment
sub parse_iptables {
    my($self, $lines, $result) = @_;
    my %tables;
    my $table;
    my $args = analyze_args($lines);
    for my $arg (@$args) {
	my $cmd = get_token($arg);
	if($cmd eq 'COMMIT') {
	    ;
	}
	elsif($cmd =~ /^\*(.+)$/) {
	    my $name = $1;
	    $tables{$name} and 
		err_at_line($arg, 'Multiple occurences of $line');
	    $table = {};
	    $tables{$name} = $table;
	}
	elsif($cmd =~ /^:(.+)$/) {
	    my $name = $1;
	    my $chain = { name => $name };
	    $table->{$name} = $chain;
	    my $policy = get_token($arg);
	    if(not $policy eq '-') {
		$chain->{default_policy} = $policy;
	    }
	}
	elsif($cmd eq '-A') {
	    my $name = get_token($arg);

	    # Store rule as hash.
	    # For non builtin chains,
	    # only simple key / value pairs and "! --syn" are allowed.
	    my $is_user_chain = not $table->{$name}->{default_policy};
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
		while(my $arg = check_regex(qr/[^!-].*/, $arg)) {
		    push @args, $arg;
		}
		if(not @args) {
		    $negate_next_cmd = $negate_arg;
		}
		else {
		    $negate ||= $negate_arg;
		}
		my $v = normalize(\@args, $negate, $is_user_chain, $arg);

		# Hard code special case:
		# ! --tcp-flags FIN,SYN,RST,ACK SYN ==> ! --syn
		if($key == '--tcp-flags' and $v = '!FIN,SYN,RST,ACK SYN') {
		    $key = '--syn';
		    $v = '!';
		}
		$rule->{$key} = $v;
	    } 	
	    push @{ $table->{$name}->{rules} }, $rule;

	}
	else {
	    err_at_line($arg, 'Syntax error');
	}
    }
    $result->{IPTABLES} = \%tables;
}

sub prefix2intern {
    my($token, $state) = @_;
    my($addr, $prefix) = split(m'/', $token, 2);
    my $base = quad2int($addr);
    my $mask;
    defined $base or err_at_line($state, "Expected IP: $addr");
    if(defined $prefix) {
	if($prefix =~ /^\d+$/) {
	    $prefix <= 32 or
		err_at_line($state, "Expected IP prefix: $prefix");
	    $mask = 2**32 - 2**(32 - $prefix);
	}
	else {
	    $mask = quad2int($prefix);
	    defined $mask or err_at_line($state, "Expected IP mask: $mask");
	}
    }
    else {
	$mask = 0xffffffff;
    }
    return({ base => $base, mask => $mask });
}

sub range2intern {
    my($token, $state) = @_;
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

sub type_code2intern {
    my($token, $state) = @_;
    my($type, $code) = split('/', $token);
    return({ TYPE => $type, CODE => $code });
}

$normalize = {
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
	extern => \&print_range,
    },
    '--dport' => {
	intern => \&range2intern,
	extern => \&print_range,
    },
    '--icmp-type' => {
	intern => \&type_code2intern,
	extern => \&print_icmp,
    },
};	

sub normalize {
    my($key, $args, $negate, $is_user_chain, $state) = @_;
    my $spec = $normalize->{$key};
    if(not $spec) {
	return $negate . join(' ', @$args);
    }
    my $size = $spec->{size};
    defined $size or $size = 1;
    @$args == $size or err_at_line($state, "$key needs $size arguments");
    my $v = $spec->{intern}->($args);
    if($is_user_chain) {
	if($spec->{must_negate}) {
	    $negate or 
		err_at_line($state, "$key must be negated in user chain");
	}
	else {
	    $negate and
		err_at_line($state, "$key must not be negated in user chain");
	}
    }
    else {
	$v = $negate . $spec->{extern}->($v);
    }
    return $v;
}

sub internal_err {
    my($msg) = @_;
    errpr("internal: $msg\n");
}

sub err_msg {
    my(@msg) = @_;
    my $msg = join('', @msg);
    errpr("$msg\n");
}

sub cmp_info {
    my(@msg) = @_;
    my $msg = join('', @msg);
    print("$msg\n");
}
    
sub intersect_rule {
    my($rule1, $rule2) = @_;
    my $result;
    for my $k1 (keys %$rule1) {
	my $v1 = $rule1->{$k1};
	if(exists $rule2->{$k1}) {
	    my $v2 = $rule2->{$k1};
	    if($k1 eq 's' || $k1 eq 'd') {
		my $b1 = $v1->{BASE};
		my $m1 = $v1->{MASK};
		my $b2 = $v2->{BASE};
		my $m2 = $v2->{MASK};
		my $max = ($m1 > $m2) ? $m1 : $m2;
		$b1 &= $max;
		$b2 &= $max;
		$b1 == $b2 or internal_err "Empty intersection with '$k1'";
		$result->{$k1} = { BASE => $b1, MASK => $max };
	    }
	    elsif($k1 eq '-sport' || $k1 eq '-dport') {
		my $l1 = $v1->{LOW};
		my $h1 = $v1->{HIGH};
		my $l2 = $v2->{LOW};
		my $h2 = $v2->{HIGH};
		my $max = ($l1 > $l2) ? $l1 : $l2;
		my $min = ($h1 < $h2) ? $h1 : $h2;
		$max <= $min or internal_err "Empty intersection in '$k1'";
		$result->{$k1} = { LOW => $max, HIGH => $min };
	    }

	    # Note, first '-' has been removed.
	    elsif($k1 eq '-icmp-type') {
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
	    elsif($k1 eq 'p') {
		$v1 eq $v2 or internal_err "Empty intersection in '$k1'";
		$result->{$k1} = $v1;
	    }
	    elsif($k1 eq 'j') {
		
		# Ignore $v1, because it is a chain name by calling convention.
		if($v2 eq 'ACCEPT') {
		    $result->{MODE} = 'permit';
		}
		elsif($v2 eq 'DROP') {
		    $result->{MODE} = 'deny';
		}
		elsif($v2 eq 'LOG') {
		    $result->{MODE} = $v2;
		}
		else {
		    internal_err;
		}
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
	my $v2 = $rule2->{$k2};

	# Has already been processed above.
	next if exists $rule1->{$k2};
	$result->{$k2} = $v2;
    }
    $result;
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

sub print_range {
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

sub print_icmp {
    my($spec) = @_;
    my($type, $code) = @{$spec}{qw(type code)};
    if (defined(my $type = $spec->{type})) {
	if (defined(my $code = $spec->{code})) {
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

sub print_acl_line {
    my($rule) = @_;
    my ($mode, $type, $src, $dst) = @{$rule}{qw( mode type src dst)};
    my @result;
    push @result, "-s " . prefix_code($src) if $src->{BASE} != 0;
    push @result, "-d " . prefix_code($dst) if $dst->{BASE} != 0;
    if($type eq 'ip') {
	;
    }
    elsif($type eq 'tcp' || $type eq 'udp') {
	push @result, "-p $type";
	my $v = print_range($rule->{SRC_PORT});
	push @result, "--sport $v" if defined $v;
	$v = print_range($rule->{DST_PORT});
	push @result, "--dport $v" if defined $v;
	push @result, "! --syn" if $rule->{ESTA};	
    }
    elsif($type eq 'icmp') {
	push @result, "-p $type";
	my $v = print_icmp($rule->{SPEC});
	push @result, "--icmp-type $v" if defined $v;
    }
    push @result, "-j $mode";
    return join(' ', @result);
}
	
    

# Process all rules of current chain and expand calls to sub-chains.
sub expand_chain {
    my($chain, $chains) = @_;
    return $chain->{expanded} if $chain->{expanded};
    my $rules = $chain->{rules};
    my @result;
    $chain->{expanded} = \@result;
    for my $rule (@$rules) {
	my $target = $rule->{j} or internal_err;

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
    $chain->{expanded} = \@result;
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
);

# Convert expanded rules to internal format used in acl_array_compare_a_in_b.
sub convert_rules {
    my($chain) = @_;
    my $rules = $chain->{expanded};
    my @converted_result;
    my $line = 1;
    for my $rule (@$rules) {
	my $converted;
	my $printed;
	for my $key (sort keys %$rule) {
	    my $value = $rule->{$key};
	    if(my $spec = $iptables2intern{$key}) {
		my $conv_key = $spec->[0];
		$converted->{$conv_key} = $value;
	    }
	    else {
		err_msg "Key -$key not supported in chain of iptables";
	    }
	}
	$converted->{orig} = print_iptables($converted);
	$converted->{line} = $line++;
	for my $spec (values %iptables2intern) {
	    my($key, $default) = @$spec;
	    next if not defined $default;
	    if(not exists $converted->{$key}) {
		$converted->{$key} = $default;
	    }
	}
    }
    $chain->{expanded} = \@converted_result;
    return \@converted_result;
}
	
# Convert parsed iptables data to that format which is parsed from cisco
# devices. Then we can reuse the code to compare ACLs.
sub postprocess_iptables {
    my ($self, $p) = @_;
    my $tables = $p->{iptables};
    for my $chains (values %$tables) {
	for my $chain (values %$chains) {
	    
	    # Ignore toplevel chains
	    next if $chain->{default_policy};
	    expand_chain($chain, $chains);
	    convert_rules($chain);
	}
    }
}

sub compare_rules {
    my($r1, $r2) = @_;
    keys %$r1 == keys %$r2 or return;
    my $jump;
    for my $k (keys %$r1) {
	if($k eq '-j' or $k eq '-g') {
	    $jump = $k;
	    next;
	}
	my $v1 = $r1->{$k};
	my $v2 = $r2->{$k};
	return if not $v1 eq $v2;
    }
    if(my $k = $jump) {
	my $v1 = $r1->{$k};
	my $v2 = $r2->{$k};
	return if not defined $v2;
	return($v1, $v2);
    }
    else {
	return (undef, undef);
    }
}	
	
# - Iterate over all available tables.
# - Compare rule sets of builtin chains pairwise:
#   - both rules are identical: ok
#   - rules differ only for called chain: compare chains semantically
#   - else: report builtin chains as different 
sub process_iptables {
    my ($self, $conf, $spoc) = @_;
    my $conf_tables = $conf->{iptables};
    my $spoc_tables = $spoc->{iptables};
    my $changed = 0;
    for my $tname (keys %$conf_tables) {
	cmp_info "Comparing $tname";
	if(not $spoc_tables->{$tname}) {
	  $changed = 1;
	  cmp_info "Extra table on device: $tname";
	  next;
	}
	my $conf_chains = $conf_tables->{$tname};
	my $spoc_chains = $spoc_tables->{$tname};
	for my $cname (keys %$conf_chains) {
	    my $conf_chain = $conf_chains->{$cname};

	    # Only check builtin chains.
	    next if not $conf_chain->{default_policy};
	    my $spoc_chain = $spoc_chains->{$cname};
	    my $conf_rules = $conf_chain->{rules};
	    my $spoc_rules = $spoc_chain->{rules};
	    my $conf_count = @$conf_rules;
	    my $spoc_count = @$spoc_rules;
	    if($conf_count != $spoc_count) {
		$changed = 1;
		cmp_info "Chain $cname of $tname has different length",
		" $conf_count at devive, $spoc_count at netspoc";
		next;
	    }
	    for (my $i = 0; $i < $conf_count; $i++) {
		if(my($c_target, $s_target) = compare_rules($conf_rules->[$i],
							    $spoc_rules->[$i]))
		{
		    if(my $c_chain = $conf_chains->{$c_target}) {
			my $s_chain = $spoc_chains->{$s_target};
			compare_chains($c_chain, $s_chain) or $changed = 1;
		    }
		    elsif($c_target ne $s_target) {
			$changed = 1;
			cmp_info "Rules $i of chain $cname of $tname",
			" call different target '$c_target' vs. '$s_target'";
		    }
		}
		else {
		    $changed = 1;
		    cmp_info "Rules $i of chain $cname of $tname",
		    " are different";
		}
	    }
	}   
    }
    $self->{CHANGE}->{ACL} = $changed;
    return 1;
}

sub get_parsed_config_from_device {
    my ($self) = @_;
    my $config = {};    

    my $route_lines = $self->get_cmd_output('ip route show');
    $self->parse_routes($route_lines, $config);

    my $iptables_lines = $self->get_cmd_output('iptables-save');
    $self->parse_iptables($iptables_lines, $config);
    
    $self->postprocess_device_config($config);
    return $config;
}

sub postprocess_device_config {
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
    $self->postprocess_iptables($config);
} 
  
sub merge_rawdata {
    my ($self, $spoc_conf, $raw_conf) = @_;

    $self->merge_routing($spoc_conf, $raw_conf);
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
    my $lines = $self->get_cmd_output($cmd);
    
    # Check for unexpected command output.
    $self->cmd_check_error($cmd, $lines);
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

# Entry from device is output of 'ip route show',
# but is full command in case of filecompare.
sub route_del {
    my($self, $entry) = @_;
    my $orig = $entry->{orig};
    $orig =~ s/^ip route add//;
    return("ip route del $orig");
}

sub write_startup_routing {
    my ($self, $conf, $file) = @_;
    $self->cmd("rm -f $file");
    $self->cmd("echo '#!/bin/sh' >> $file");
    $self->cmd("echo '# Generated by NetSPoC' >> $file");
    for my $entry (@{ $conf->{ROUTING} }) {
	my $cmd = $self->route_add($entry);
	$self->cmd("echo $cmd >> $file");
    }
}

sub transfer() {
    my ($self, $conf, $spoc_conf) = @_;

    # Change running configuration of device.
    $self->process_routing($conf, $spoc_conf) or return 0;
    $self->process_iptables($conf, $spoc_conf) or return 0;

    # Change startup configuration of device.
    my $tmp_file = $config->{tmp_file};
    my $startup_file = $config->{device_routing_file};    
    if (not $self->{COMPARE}) {
        if (grep { $_ } values %{ $self->{CHANGE} }) {
            mypr "Writing startup config\n";  
	    $self->write_startup_routing($spoc_conf, $tmp_file);
	    $self->cmd("mv -f $tmp_file $startup_file");
            mypr "...done\n";
        }
        else {
            mypr "No changes to save - check if startup is uptodate\n";
	    $self->write_startup_routing($spoc_conf, $tmp_file);
	    if($self->cmd_ok("cmp $tmp_file $startup_file")) {
                mypr "Startup is uptodate\n";
            }
            else {
                warnpr "Startup is *NOT* uptodate - trying to fix:\n";
		$self->cmd("mv -f $tmp_file $startup_file");
		mypr "...done\n";
	    }
        }
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

