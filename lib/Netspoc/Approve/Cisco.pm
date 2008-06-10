
package Netspoc::Approve::Cisco;

# Authors: Arne Spetzler, Heinz Knutzen, Daniel Brunkhorst
#
# Description:
# Module to remote configure cisco devices.


'$Id$' =~ / (.+),v (.+?) /;

my $id = "$1 $2";

sub version_drc2_cisco() {
    return $id;
}

use base "Netspoc::Approve::Device";
use strict;
use warnings;
use IO::Socket ();
use Netspoc::Approve::Helper;
use Netspoc::Approve::Parse_Cisco;

sub parse_device {
    my ($self, $lines) = @_;

    my $parse_info = $self->get_parse_info();
    my $config = analyze_conf_lines($lines, $parse_info);
    my $result = $self->parse_config($config, $parse_info);
    $self->postprocess_config($result);
    return $result;
}

sub parse_seq {
    my($self, $arg, $info, $result) = @_;
    my $type = $info->[0];
    my $success;
    for my $part (@{$info}[1..(@$info-1)]) {
	my $ref = ref $part;
	my $part_success;
	if(not $ref) {

	    # A method call which fills $result.
	    # Return value: true if success.
	    $part_success = $self->$part($arg, $result);
	}
	elsif($ref eq 'HASH') {
	    if(my $msg = $part->{error}) {
		err_at_line($arg, $msg);
	    }
	    my $parser = $part->{parse};
	    my $params = $part->{params};
	    my @evaled = map( { /^\$(.*)/ ? $result->{$1} : $_ } 
			      $params ? @$params : ());
	    if(my $keys = $part->{store_multi}) {
		my @values = parse_line($self, $arg, $parser, @evaled) 
		    if $parser;
		for(my $i = 0; $i < @values; $i++) {
		    $result->{$keys->[$i]} = $values[$i];
		}
		$part_success = @values;
	    }
	    else {
		my $value = parse_line($self, $arg, $parser, @evaled) 
		    if $parser;
		if(not defined $value) {
		    $value = $part->{default};
		}
		if(defined $value) {
		    if(my $key = $part->{store}) {
			$result->{$key} = $value;
		    }
		    $part_success = 1;
		}
	    }
	}
	elsif($ref eq 'CODE') {
	    $part_success = $part->($arg, $result);
	}
	elsif($ref eq 'ARRAY') {
	    $part_success = parse_seq($self, $arg, $part, $result);
	}
	$success ||= $part_success;
	if($type eq 'or') {
	    last if $success;
	}
	elsif($type eq 'seq') {

	    # Stop if first arg doesn't match.
	    last if not $success;
	}
	else {
	    errpr "internal: unexpected 'seq' type $type\n";
	}
    }
    return $success;
}
	    
sub parse_line {
    my($self, $arg, $info, @params) = @_;
    my $ref = ref $info;
    if(not $ref) {

	# A method name.
	return($self->$info($arg, @params));
    }
    elsif($ref eq 'Regexp') {
	return(check_regex($info, $arg));
    }
    elsif($ref eq 'CODE') {
	return($info->($arg, @params));
    }   
    elsif($ref eq 'ARRAY') {
	my $result = {};
	parse_seq($self, $arg, $info, $result);
	not keys %$result and $result = undef;
	return($result);
    }
    else {
	errpr "internal: unexpected parse attribute: $info\n";
    }
}

# $config are prepared config lines.
# $parse_info describes grammar.
sub parse_config {
    my($self, $config, $parse_info) = @_;
    my $result = {};
    for my $arg (@$config) {
	my $cmd = get_token($arg);
        my $cmd_info = $parse_info->{$cmd} or 
	    errpr "internal: parsed unexpected cmd: $cmd\n";
	if(my $msg = $cmd_info->{error}) {
	    err_at_line($arg, $msg);
	}
	my $named = $cmd_info->{named};
	my $name;
	if($named and $named ne 'from_parser') {
	    $name = get_token($arg);
	}
	my $parser = $cmd_info->{parse};
	my $value = parse_line($self, $arg, $parser) if $parser;
	if($named and $named eq 'from_parser') {
	    $name = $value->{name} or err_at_line($arg, 'Missing name');
	}
	get_eol($arg);
	if(my $subcmds = $arg->{subcmd}) {
	    my $parse_info = $cmd_info->{subcmd} or 
		err_at_line($arg, 'Unexpected subcommand');
	    my $value2 = parse_config($self, $subcmds, $parse_info);
	    if(keys %$value2) {
		if(defined $value) {
		    $value = { %$value, %$value2 };
		}
		else {
		    $value = $value2;
		}
	    }
	}
	if(not defined $value) {
	    $value = $cmd_info->{default};
	}
	if(not defined $value) {
	    next;
	}
	if(ref($value) eq 'HASH') {
	    $named and $value->{name} = $name;
	    $value->{orig} = $arg->{orig};
	}
	my $store = $cmd_info->{store};
	my @extra_keys = ref $store ? @$store : $store;
	my $key;
	if($named) {
	    $key = $name;
	}
	else {
	    $key = pop @extra_keys;
	}
	my $dest = $result;
	for my $x (@extra_keys) {
	    $dest->{$x} ||= {};
	    $dest = $dest->{$x};
	}
	if($cmd_info->{multi}) {
	    push(@{ $dest->{$key} }, $value);
	}
	else {
	    defined $dest->{$key} and
		err_at_line($arg, 'Multiple occurences of command not allowed');
	    $dest->{$key} = $value;
	}
    }
    return($result);
}

# ip mask
# host ip
# any
sub parse_address {
    my ($self, $arg) = @_;
    my ($ip, $mask);
    my $token = get_token($arg);
    if ($token eq 'any') {
        $ip = $mask = 0;
    }
    elsif ($token eq 'host') {
        $ip   = get_ip($arg);
        $mask = 0xffffffff;
    }
    else {
        $ip   = quad2int($token);
        $mask = get_ip($arg);
    }
    return ({ BASE => $ip, MASK => $self->dev_cor($mask) });
}

sub parse_port {
    my ($self, $arg, $proto) = @_;
    my $port = get_token($arg);
    if ($proto eq 'tcp') {
        $port = $PORT_Trans_TCP{$port} || $port;
    }
    else {
        $port = $PORT_Trans_UDP{$port} || $port;
    }
    $port =~ /^\d+$/ or err_at_line($arg, 'Expected port number');
    return $port;
}

# ( 'lt' | 'gt' | 'eq' | 'neq' ) port
# 'range' port port
sub parse_port_spec {
    my ($self, $arg, $proto) = @_;
    my ($low, $high);
    my $spec = check_regex('eq|gt|lt|neq|range', $arg)
      or return {};
    my $port = $self->parse_port($arg, $proto);
    if ($spec eq 'eq') {
        $low = $high = $port;
        $spec = 'range';
    }
    elsif ($spec eq 'gt') {
        $low  = $port + 1;
        $high = 0xffff;
        $spec = 'range';
    }
    elsif ($spec eq 'lt') {
        $low  = 0;
        $high = $port - 1;
        $spec = 'range';
    }
    elsif ($spec eq 'neq') {
        errpr "port specifier 'neq' not implemented yet\n";
    }
    elsif ($spec eq 'range') {
        $low = $port;
        $high = $self->parse_port($arg, $proto);
    }
    else {
        internal_err();
    }
    return ({ SPEC => $spec, PORT_L => $low, PORT_H => $high });
}

my $icmp_regex = join('|', '\d+', keys %ICMP_Trans);

# <message-name> | (/d+/ [/d+])
# ->{TYPE} / ->{CODE} (if defined)
sub parse_icmp_spec {
    my ($self, $arg) = @_;
    my ($type, $code);
    my $token = check_regex($icmp_regex, $arg);
    return({}) if not defined $token;
    if (my $spec = $ICMP_Trans{$token}) {
        ($type, $code) = @{$spec}{ 'type', 'code' };
    }
    else {
        $type = $token;
        $code = check_regex('\d+', $arg) || -1;
    }
    return ({ TYPE => $type, CODE => $code });
}

sub normalize_proto {
    my ($self, $arg, $proto) = @_;
    $proto = $IP_Trans{$proto} || $proto;
    $proto =~ /^\d+$/ 
	or $self->err_at_line($arg, "Expected numeric proto '$proto'");
    $proto =~ /^(1|6|17)$/
	and $self->err_at_line($arg, "Don't use numeric proto for", 
			       " icmp|tcp|udp: '$proto'");
    return($proto);
}
    
#################################################
# --- comparing ---
#################################################

#
# return value: 0: no
#               1: yes
#               2: intersection
#
sub ports_a_in_b ($$) {
    my ($a, $b) = @_;
    unless ($b->{SPEC}) {

        # no ports spec matches all ports
        return 1;
    }
    unless ($a->{SPEC}) {
        if ($b->{PORT_L} == 0 && $b->{PORT_H} == 0xffff) {
            return 1;
        }
        else {
            return 2;
        }
    }
    if ($a->{PORT_H} < $b->{PORT_L} || $b->{PORT_H} < $a->{PORT_L}) {
        return 0;
    }
    if ($b->{PORT_L} <= $a->{PORT_L} && $a->{PORT_H} <= $b->{PORT_H}) {
        return 1;
    }
    else {
        return 2;
    }
}

#
# a in b iff (a_mask | b_mask) = a_mask
#            AND
#            (a_mask & b_mask) & a_base) = (a_mask & b_mask & b_base)
#
#  WARNING: DO NOT CHANGE THE RETURN VALUES!
# THEY ARE USED IN  static_global_local_match_a_b()
#
sub ip_netz_a_in_b {
    my ($self, $a, $b) = @_;
    my $am = $a->{MASK};
    my $bm = $b->{MASK};
    my $mm = $am & $bm;
    ($mm & $a->{BASE} ^ $mm & $b->{BASE}) and return 0;    # no
    (($am | $bm) ^ $am) or return 1;                       # yes
    return 2;                                              # intersection
}

#
# return value: 0: no
#               1: yes
#               2: intersection
#
sub services_a_in_b {
    my ($a, $b) = @_;
    my $aproto = $a->{TYPE};
    my $bproto = $b->{TYPE};
    if ($bproto eq 'ip') {
        return 1;
    }
    if ($bproto eq $aproto) {
        if ($bproto eq 'icmp') {
            unless (exists $b->{SPEC}->{TYPE}) {
                return 1;
            }
            unless (exists $a->{SPEC}->{TYPE}) {
                return 2;
            }

            # ok. TYPE has to be set for both a and b
            if ($a->{SPEC}->{TYPE} ne $b->{SPEC}->{TYPE}) {
                return 0;
            }

            # types are equal, check CODE
            unless (exists $b->{SPEC}->{CODE}) {
                return 1;
            }
            unless (exists $a->{SPEC}->{CODE}) {
                return 2;
            }

            # both SPEC are 'code'
            if ($a->{SPEC}->{CODE} eq $b->{SPEC}->{CODE}) {
                return 1;
            }
            else {
                return 0;
            }
        }
        if ($bproto eq 'tcp' or $bproto eq 'udp') {
            my $src = ports_a_in_b($a->{SRC_PORT}, $b->{SRC_PORT})
		or return 0;
            my $dst = ports_a_in_b($a->{DST_PORT}, $b->{DST_PORT})
		or return 0;
            if ($src == 1 and $dst == 1) {
                ($b->{ESTA}) or return 1;
                ($a->{ESTA}) and return 1;
            }
            return 2;    # intersection
        }
        return 1;
    }
    elsif ($aproto eq 'ip') {

        # intersection
        return 2;
    }
    return 0;
}

#
# check if SRC SRV DST SRV  from a
# is subset of or intersection with
#          SRC SRV DST SRV from b
#
# do not check permit/deny !
#
#
# return value: 0: no
#               1: yes
#               2: intersection
#
sub acl_line_a_in_b {
    my ($self, $a, $b) = @_;
    exists $a->{REMARK} and return 1;
    exists $b->{REMARK} and return 0;
    my $src;
    my $dst;
    my $srv;
    $src = $self->ip_netz_a_in_b($a->{SRC}, $b->{SRC});
    ($src) or return 0;
    $dst = $self->ip_netz_a_in_b($a->{DST}, $b->{DST});
    ($dst) or return 0;
    $srv = services_a_in_b($a, $b);
    ($srv) or return 0;
    ($src == $dst and $dst == $srv and $srv == 1) and return 1;
    return 2;
}

sub acl_line_a_eq_b ($$$) {

    # fast :)
    my ($self, $a, $b) = @_;
    if (exists $a->{REMARK}) {
        exists $b->{REMARK} or return 0;
        if ($a->{REMARK} eq $b->{REMARK}) {
            return 1;
        }
        else {
            return 0;
        }
    }
    exists $b->{REMARK} and return 0;

    my $asrc = $a->{SRC};
    my $adst = $a->{DST};
    my $bsrc = $b->{SRC};
    my $bdst = $b->{DST};
    unless ($a->{MODE} eq $b->{MODE}
        && $a->{TYPE} eq $b->{TYPE}
        && $asrc->{BASE} == $bsrc->{BASE}
        && $asrc->{MASK} == $bsrc->{MASK}
        && $adst->{BASE} == $bdst->{BASE}
        && $adst->{MASK} == $bdst->{MASK})
    {
        return 0;
    }

    # source and destination equal
    if ($a->{TYPE} eq 'icmp') {
        my $as = $a->{SPEC};
        my $bs = $b->{SPEC};
        (exists $as->{TYPE} xor exists $bs->{TYPE}) and return 0;
        if (exists $as->{TYPE}) {
            ($as->{TYPE} == $bs->{TYPE}) or return 0;
            (exists $as->{CODE} xor exists $bs->{CODE}) and return 0;
            if (exists $as->{CODE}) {
                ($as->{CODE} == $bs->{CODE}) or return 0;
            }
        }

        # icmp messages equal
    }
    elsif ($a->{TYPE} eq 'tcp' or $a->{TYPE} eq 'udp') {
        my $ass = $a->{SRC_PORT};
        my $ads = $a->{DST_PORT};
        my $bss = $b->{SRC_PORT};
        my $bds = $b->{DST_PORT};
        ($ass->{SPEC} xor $bss->{SPEC}) and return 0;
        ($ads->{SPEC} xor $bds->{SPEC}) and return 0;
        if ($ass->{SPEC}) {
            ($ass->{SPEC} eq $bss->{SPEC}) or return 0;
            (         $ass->{PORT_L} == $bss->{PORT_L}
                  and $ass->{PORT_H} == $bss->{PORT_H})
              or return 0;
        }
        if ($ads->{SPEC}) {
            ($ads->{SPEC} eq $bds->{SPEC}) or return 0;
            (         $ads->{PORT_L} == $bds->{PORT_L}
                  and $ads->{PORT_H} == $bds->{PORT_H})
              or return 0;
        }

        # Ports are equal
        if ($a->{TYPE} eq 'tcp') {
            ($a->{ESTA} xor $b->{ESTA}) and return 0;
            if ($a->{ESTA}) {
                ($a->{ESTA} eq $b->{ESTA}) or return 0;
            }

            # Established entry equal
        }
    }
    ($a->{LOG} xor $b->{LOG}) and return 0;
    if ($a->{LOG}) {
        ($a->{LOG} eq $b->{LOG}) or return 0;
    }
    return 1;
}

sub route_line_a_eq_b {
    my ($self, $a, $b) = @_;
    ($a->{BASE} eq $b->{BASE} && $a->{MASK} eq $b->{MASK})
      or return 0;
    for my $key (qw(IF NIF NEXTHOP METRIC MISC MISC_ARG)) {
        if (defined($a->{$key}) || defined($b->{$key})) {
            (        defined($a->{$key})
                  && defined($b->{$key})
                  && $a->{$key} eq $b->{$key})
              or return 0;
        }
    }
    return 1;
}

sub route_line_destination_a_eq_b {
    my ($self, $a, $b) = @_;
    return($a->{BASE} eq $b->{BASE} && $a->{MASK} eq $b->{MASK});
}

################################################################
# Compare two arrays with acl objects.
################################################################

# Find unique src and dst in all rules.
# If parameter $do_acl_hash is set,
#  build a mapping from triple ($prot, $src, $dst) to list of rules
#  using $acl_hash
# else
#  build a mapping from $rule to triple ($prot, $src, $dst)
#  by adding attribute {MATCHES} with [ $prot, $src, $dst ] to each rule,
#  fill
# Return 3 values, array references to unique proto, src and dst addresses
# return 4. value $acl_hash if $do_acl_hash is set.
#
# Add attribute {line} to each rule.
sub acl_prepare ( $;$ ) {
    my ($rules, $do_acl_hash) = @_;
    my $i = 0;
    my %prot;
    my %sb2sm2src;
    my %db2dm2dst;
    my @all_src;
    my @all_dst;
    my %acl_hash;
    my @acl_list;

    for my $r (@$rules) {
        $r->{line} = $i++;
        next if $r->{REMARK};
        my $prot = $r->{TYPE};
        my $src  = $r->{SRC};
        my $dst  = $r->{DST};
        my $sb   = $src->{BASE};
        my $sm   = $src->{MASK};
        my $db   = $dst->{BASE};
        my $dm   = $dst->{MASK};
        $prot{$prot} = $prot;

        if (my $unique = $sb2sm2src{$sb}->{$sm}) {
            $src = $unique;
        }
        else {
            $src = $sb2sm2src{$sb}->{$sm} = [ $sb, $sm ];
            push @all_src, $src;
        }
        if (my $unique = $db2dm2dst{$db}->{$dm}) {
            $dst = $unique;
        }
        else {
            $dst = $db2dm2dst{$db}->{$dm} = [ $db, $dm ];
            push @all_dst, $dst;
        }
        if ($do_acl_hash) {
            push @{ $acl_hash{$prot}->{$src}->{$dst} }, $r;
        }
        else {
            $r->{MATCHES} = [ $prot, $src, $dst ];
        }

    }
    return [ values %prot ], \@all_src, \@all_dst, \%acl_hash;
}

# Parameter: 2 lists with protocols A and B
# Result: A hash having entries a->b->1 for protocols where intersection is not empty.
sub prot_relation ( $$ ) {
    my ($aprot, $bprot) = @_;
    my %hash;
    for my $a (@$aprot) {
        for my $b (@$bprot) {
            if ($a eq $b or $a eq 'ip' or $b eq 'ip') {
                $hash{$a}->{$b} = 1;
            }
        }
    }
    return \%hash;
}

# Parameter: 2 lists with objects A and B
# Result: A hash having entries a->b->1 for elements where intersection is not empty.
sub obj_relation ( $$ ) {
    my ($aobj, $bobj) = @_;
    my %hash;
    for my $a (@$aobj) {
        my ($ab, $am) = @$a;
        for my $b (@$bobj) {
            my ($bb, $bm) = @$b;
            my $m = $am & $bm;
            if (($ab & $m) == ($bb & $m)) {
                $hash{$a}->{$b} = 1;
            }
        }
    }
    return \%hash;
}

# Parameter:
# - Description of a rule R: [ $proto, $src_obj, $dst_obj ]
# - Relation between protocols, source-objects, destination-objects
# - Hash of other rules
# Result:
# A list of rules matching R.
sub get_hash_matches ( $$$$$ ) {
    my ($matches, $p_rel, $s_rel, $d_rel, $bhash) = @_;
    my ($prot, $src, $dst) = @$matches;
    my @found;
    for my $p (keys %{ $p_rel->{$prot} }) {
        if (my $bhash = $bhash->{$p}) {
            for my $s (keys %{ $s_rel->{$src} }) {
                if (my $bhash = $bhash->{$s}) {
                    for my $d (keys %{ $d_rel->{$dst} }) {
                        if (my $r2_aref = $bhash->{$d}) {
                            push @found, @$r2_aref;
                        }
                    }
                }
            }
        }
    }
    return @found;
}

sub acl_array_compare_a_in_b {
    my ($self, $ac, $bc) = @_;

    # setting verbosity
    my $opt = $self->{CMPVAL};
    my $verbose = 0;
    if ($opt & 1) {
        $verbose = 1;
    }
    my $showmatches = 0;
    if ($opt & 2) {
        $showmatches = 1;
    }
    my $silent = 0;
    if ($opt eq 4) {
        $silent = 1;
    }

    my ($aprot, $asrc, $adst) = acl_prepare($ac);
    my ($bprot, $bsrc, $bdst, $bhash) = acl_prepare($bc, 1);
    my $p_rel = prot_relation($aprot, $bprot);
    my $s_rel = obj_relation($asrc,   $bsrc);
    my $d_rel = obj_relation($adst,   $bdst);

    my @ad;    # denys lines from "a"

    my $clean = 1;    # be optimistic ;)

    my $log_mismatch = 0;

    my $lines = 0;
  OUTER: for my $s (@$ac) {
        $lines++;
        exists $s->{REMARK} and next;

        my $inner           = 0;
        my @currentdenylist = ();
        if ($s->{MODE} eq 'deny') {

            # push deny for later inspection
            push @ad, [ $lines, $s ];
            next;
        }
        else {

            # check if current permit is subject of deny
            for my $deny (@ad) {
                my $result = $self->acl_line_a_in_b($s, $deny->[1]);
                if ($result == 1) {
                    unless ($silent) {
                        print "**** USELESS **** ", $lines, " : ";
                        print $s->{orig}, "\n";
                        print " denied by ", $deny->[0], " : ";
                        print $deny->[1]->{orig}, "\n";
                    }
                    next OUTER;
                }
                if ($result == 2) {

                    # list of curent denys
                    push @currentdenylist, $deny;
                    ($verbose) and do {
                        print "**** VERBOSE (fill currentdenylist) **** ",
                          $lines, " : ";
                        print $s->{orig};
                        print " partial ", $deny->[0], " : ";
                        print $deny->[1]->{orig}, "\n";
                      }
                }

                # else nothing to do - no intersection
            }
        }
        my @perm_int   = ();
        my @deny_int   = ();
        my $deny_match = "NO";
        my $matches    = delete $s->{MATCHES};
        my @found =
          sort { $a->{line} <=> $b->{line} }
          get_hash_matches($matches, $p_rel, $s_rel, $d_rel, $bhash);
        my $p;
      INNER: for my $ace (@found) {
	    $p = $ace;
            $inner = $p->{line} + 1;
            exists $p->{REMARK} and next;
            ($self->acl_line_a_in_b($s, $p)) or next;
            if ($self->acl_line_a_in_b($s, $p) == 1) {
                if ($p->{MODE} eq 'deny') {

                    # this is denied, but maybe some permits before...
                    # this is ok because @perm_int is checked at last.
                    $deny_match = 'YES';
                    last;
                }
                else {

                    # full permit
                    #check if found denys subset of @cdlist
                  CHECK: for my $deny (@deny_int) {
                        for my $cd (@currentdenylist) {
                            if ($self->acl_line_a_in_b($deny->[1], $cd->[1]) ==
                                1)
                            {
                                ($verbose) and do {
                                    print "**** VERBOSE (right side) **** (";
                                    print $inner, "): ",
                                      $p->{orig};
                                    print " partial ";
                                    print $deny->[0], " : ",
                                      $deny->[1]->{orig};
                                    print " has full match at left side: (";
                                    print $cd->[0], "): ",
                                      $cd->[1]->{orig};
                                    print "\n";
                                };
                                next CHECK;
                            }
                        }

                        # deny mismatch!
                        ($silent) or do {
                            print "+++ DENY MISMATCH +++ (";
                            print $inner, "): ", $p->{orig};
                            print " at right side has predecessor (";
                            print $deny->[0], "): ",
                              $deny->[1]->{orig};
                            print " which has no full match at left side\n";
                            print "+++ While searching for match: (";
                            print $lines, "): ", $s->{orig},
                              "\n";
                        };
                        $deny_match = 'DMIS';

                        #last INNER;
                    }
                    if ($deny_match eq 'DMIS') {
                        last INNER;
                    }

                    # ok
                    if (@perm_int && $verbose) {
                        print "**** VERBOSE **** $lines match  $inner ";
                        print "with ", scalar(@perm_int), " intersections\n";
                    }

                    #unless(1 || $self->acl_line_a_eq_b($s,$p)){
                    #    print "($lines): ". $s->{orig};
                    #    print " in ($inner): ", $p->{orig};
                    #    print "\n";
                    #}
                }
                my $lm;
                if ($p->{LOG} xor $s->{LOG}) {
                    $lm = $log_mismatch = 1;
                }
                elsif ($p->{LOG}) {
                    if ($p->{LOG} ne $s->{LOG}) {
                        $lm = $log_mismatch = 1;
                    }
                }
                if ($lm and !$silent) {
                    print "**** LOG MISMATCH **** ($lines): ",
                      $s->{orig};
                    print " in ($inner): ", $p->{orig}, "\n";
                }
                elsif ($showmatches) {
                    print "**** SHOW MATCHES **** ($lines): ",
                      $s->{orig};
                    print " in ($inner): ", $p->{orig}, "\n";
                }
                next OUTER;
            }
            else {
                if ($p->{MODE} eq 'deny') {

                    # partial deny
                    #$deny_match = 'YES';
                    push @deny_int, [ $inner, $p ];
                    ($verbose) and do {
                        print "**** VERBOSE (fill deny_intersec) **** ", $lines,
                          " : ";
                        print $s->{orig};
                        print " partial ", $inner, " : ";
                        print $p->{orig}, "\n";
                      }
                }
                else {

                    # permit intersection!
                    push @perm_int, [ $inner, $p ];
                    if ($verbose) {
                        print "($lines): ", $s->{orig};
                        print " INTERSECTION ($inner): ", $p->{orig};
                        print "\n";
                    }
                }
            }
        }
        $clean = 0;
        ($silent) or do {
            unless ($deny_match eq 'DMIS') {
                my $deny_line;
                if ($deny_match eq 'YES') {
                    $deny_line = $p->{orig};
                }
                else {
                    $inner     = "";
                    $deny_line = 'implicit deny at end of acl';
                }
                if (@perm_int) {
                    print " **** DENY **** (", $lines, "): ";
                    print $s->{orig};
                    print " by ($inner): $deny_line\n";
                    my @intersec = 
			sort { $a->[0] <=> $b->[0] } (@deny_int, @perm_int);
                    for my $p (@intersec) {
                        print " **** INTERSEC **** ", $p->[0], " : ";
                        print $p->[1]->{orig}, "\n";
                    }
                }
                else {
                    print " **** DENY **** (", $lines, "): ";
                    print $s->{orig};
                    print " by ($inner): $deny_line\n";
                }
            }
          }
    }
    ($clean and !$log_mismatch) and return 1;    # a in b
    return 0;
}

# calling rule: a should be spoc (new) acl
#               b should be conf (old) acl
sub acl_equal {
    my ($self, $a_acl, $b_acl, $a_name, $b_name, $context) = @_;
    my $diff = 0;
    mypr "compare ACLs $a_name $b_name for $context\n";

    ### textual compare
    if (@{$a_acl} == @{$b_acl}) {
        mypr "length equal: ", scalar @{$a_acl}, "\n";
        mypr "compare line by line: ";
        for (my $i = 0 ; $i < scalar @{$a_acl} ; $i++) {
            if ($self->acl_line_a_eq_b($$a_acl[$i], $$b_acl[$i])) {
                next;
            }
            else {

                # acls differ
                mypr " diff at ", $i + 1;
                $diff = 1;
                last;
            }
        }
        mypr "\n";
    }
    else {
        $diff = 1;
        mypr "lenght differ:" .
	    " OLD: " . scalar @{$b_acl} . 
	    " NEW: " . scalar @{$a_acl} . "\n";
    }
    ### textual compare finished
    if (!$diff) {
        mypr "acl's textual identical!\n";
	return 1;
    }

    my $newinold;
    my $oldinnew;
    mypr "acl's differ textualy!\n";
    mypr "begin semantic compare:\n";
    if ($self->{CMPVAL} eq 4) {
	$newinold = $self->acl_array_compare_a_in_b($a_acl, $b_acl);
	$oldinnew = $self->acl_array_compare_a_in_b($b_acl, $a_acl);
    }
    else {
	mypr "#### BEGIN NEW in OLD - $context\n";
	mypr "#### $a_name in $b_name\n";
	$newinold = $self->acl_array_compare_a_in_b($a_acl, $b_acl);
	mypr "#### END   NEW in OLD - $context\n";
	mypr "#### BEGIN OLD in NEW - $context\n";
	mypr "#### $b_name in $a_name\n";
	$oldinnew = $self->acl_array_compare_a_in_b($b_acl, $a_acl);
	mypr "#### END   OLD in NEW - $context\n";
    }
    if ($newinold and $oldinnew) {
	$diff = 0;
	mypr "#### ACLs equal ####\n";
	return 1;
    }
    else {
	mypr "acl's differ semanticaly!\n";
	return 0;
    }
}

###########################################
# Rawdata processing
###########################################

sub merge_acls {
    my ($self, $spoc_conf, $raw_conf, $extra) = @_;
    for my $intf (keys %{ $raw_conf->{IF} }) {
	mypr " interface: $intf\n";
	my $ep_name;
	my $sp_name;
        unless ($ep_name = $raw_conf->{IF}->{$intf}->{ACCESS}) {
            mypr " - no acl in raw data -\n";
            next;
        }

        # There is a raw acl for this interface.
        $spoc_conf->{IF}->{$intf} or 
	    errpr "rawdata: $intf not found in spocfile\n";
        unless ($sp_name = $spoc_conf->{IF}->{$intf}->{ACCESS}) {
            warnpr "rawdata: no spocacl for interface: $intf\n";
            next;
        }

        # There is a corresponding acl in spocfile.
        unless ($raw_conf->{ACCESS}->{$ep_name}) {
            errpr "rawdata: no matching raw acl found for name $ep_name" .
		" in interface definition\n";
            exit -1;
        }
        my $rawacl  = $raw_conf->{ACCESS}->{$ep_name};
        my $spocacl = $spoc_conf->{ACCESS}->{$sp_name};

	# Prepend raw acl._
	unshift(@{$spoc_conf->{ACCESS}->{$sp_name}}, @$rawacl);

	# Additionally prepend to original acl having object_groups.
	if($extra) {
	    unshift(@{$spoc_conf->{$extra}->{$sp_name}}, @$rawacl);
	}
	mypr "   entries prepended: " . scalar @{$rawacl} . "\n";
    }
}

sub merge_rawdata {
    my ($self, $spoc_conf, $raw_conf) = @_;
    mypr "--- raw processing\n";
    
    # Route processing.
    if ($spoc_conf->{ROUTING}) {
	my $newroutes = ();
      SPOC: for (my $i = 0 ; $i < scalar @{ $spoc_conf->{ROUTING} } ; $i++) {
	  my $se = $spoc_conf->{ROUTING}->[$i];
	  for my $re (@{ $raw_conf->{ROUTING} }) {
	      if ($self->route_line_a_eq_b($se, $re)) {
		  warnpr "RAW: double RE '$re->{orig}'" .
		      " scheduled for remove from spocconf.\n";
		  next SPOC;
	      }
	      elsif ( $re->{BASE} eq $se->{BASE}
		      and $re->{MASK} eq $se->{MASK})
	      {
		  warnpr "RAW: inconsistent NEXT HOP in routing entries:\n";
		  warnpr "     spoc: $se->{orig} (scheduled for remove)\n";
		  warnpr "     raw:  $re->{orig} \n";
		  next SPOC;
	      }
	  }
	  push @{$newroutes}, $se;
      }
	$spoc_conf->{ROUTING} = $newroutes;
    }
    for my $re (@{ $raw_conf->{ROUTING} }) {
	push @{ $spoc_conf->{ROUTING} }, $re;
    }
    mypr " attached routing entries: "
	. scalar @{ $raw_conf->{ROUTING} } . "\n";

    mypr "--- raw processing: done\n";
    return 1;
}
###########################################
#
# END RAW processing
#
###########################################

sub process_routing {
    my ($self, $conf, $spoc_conf) = @_;
    my $spoc_routing = $spoc_conf->{ROUTING};
    my $conf_routing = $conf->{ROUTING};
    if ($spoc_routing) {
        if (not $conf_routing) {
            if (not $conf->{OSPF}) {
                errpr "ERROR: no routing entries found on device\n";
                return 0;
            }
            else {
                mypr "no routing entries found on device - but OSPF found...\n";

                # generate empty routing config for device:
                $conf_routing = $conf->{ROUTING} = [];
            }
        }
	$self->{CHANGE}->{ROUTE} = 0;
        my $counter;
        mypr "==== compare routing information ====\n";
        mypr " routing entries on device:    ", scalar @$conf_routing, "\n";
        mypr " routing entries from netspoc: ", scalar @$spoc_routing, "\n";
        for my $c (@$conf_routing) {
            for my $s (@$spoc_routing) {
                if ($self->route_line_a_eq_b($c, $s)) {
                    $c->{DELETE} = $s->{DELETE} = 1;
                    last;
                }
            }
        }
        unless ($self->{COMPARE}) {

            #
            # *** SCHEDULE RELOAD ***
            #
            # TODO: check if 10 minutes are OK
            #
            $self->schedule_reload(10);

            # Transfer to device.
            $self->cmd('configure terminal') or exit -1;
            mypr "transfer routing entries to device:\n";
            $counter = 0;
	    
	    # Add routes with long mask first.
	    # If we switch the default route, this ensures, that we have the
	    # new routes available before deleting the old default route.
            for my $r ( sort {$b->{MASK} <=> $a->{MASK}} 
			@{ $spoc_conf->{ROUTING} }) {
                ($r->{DELETE}) and next;
                $counter++;
		
		# PIX and ASA don't allow two routes to identical destination.
		# Remove old route immediatly before adding the new one.
		for my $c (@$conf_routing) {
		    next if $c->{DELETE};
		    if($self->route_line_destination_a_eq_b($r, $c)){
			$self->cmd("no $c->{orig}") or exit -1;
			$c->{DELETE} = 1; # Must not delete again.
		    }
		}
                $self->cmd($r->{orig}) or exit -1;
            }
            mypr " $counter\n";
            ($counter) and $self->{CHANGE}->{ROUTE} = 1;
            mypr "deleting non matching routing entries from device\n";
            $counter = 0;
            for my $r (@$conf_routing) {
                ($r->{DELETE}) and next;
                $counter++;
                my $tr = join ' ', "no", $r->{orig};
                $self->cmd($tr) or exit -1;
            }
            mypr " $counter\n";
            $self->cmd('end') or exit -1;
            $counter and $self->{CHANGE}->{ROUTE} = 1;
            $self->cancel_reload();
        }
        else {

            # show compare results
            mypr "additional routing entries from spoc:\n";
            $counter = 0;
            for my $r (@$spoc_routing) {
                ($r->{DELETE}) and next;
                $counter++;
                mypr $r->{orig}, "\n";
            }
            mypr "total: ", $counter, "\n";
            ($counter) and $self->{CHANGE}->{ROUTE} = 1;
            mypr "non matching routing entries on device:\n";
            $counter = 0;
            for my $r (@$conf_routing) {
                $r->{DELETE} and next;
                $counter++;
                mypr $r->{orig}, "\n";
            }
            mypr "total: ", $counter, "\n";
            ($counter) and $self->{CHANGE}->{ROUTE} = 1;
        }
        mypr "==== done ====\n";
    }
    else {
        mypr "no routing entries specified - leaving routes untouched\n";
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
    $result->{MATCH} =~ m/^\r\n\s?(\S+)\#\s?$/;
    my $name = $1;

    unless ($self->{CHECKHOST} eq 'no') {
        $self->checkidentity($name) or exit -1;
    }
    else {
        mypr "hostname checking disabled!\n";
    }

    # Set prompt again because of performance impact of standard prompt.
    $self->{ENAPROMPT} = qr/\r\n\s?$name\S*#\s?$/;
}

sub login_enable {
    my ($self) = @_;
    my $ip = $self->{IP};
    my $user;
    my $pass;
    my $con = $self->{CONSOLE};

    if ($self->{PASS} =~ /:/ or $self->{LOCAL_USER}) {
        if ($user = $self->{LOCAL_USER}) {
            $pass = $self->{PASS};
        }
        else {
            ($user, $pass) = split(/:/, $self->{PASS});
        }
        mypr "Username found\n";
        mypr "checking for SSH access at port 22\n";
        my $server = IO::Socket::INET->new(
            'PeerAddr' => $ip,
            'PeerPort' => 22
        );
        if ($server) {
            $server->close();
            mypr "port 22 open - trying SSH for login\n";
            $con->{EXPECT}->spawn("ssh", ("-l", "$user", "$ip"))
              or errpr "Cannot spawn ssh: $!\n";
            my $prm = qr/password:|\(yes\/no\)\?/i;
            my $tmt = $self->{telnet_timeout};
            $con->con_wait("$prm", $tmt) or $con->con_error();
            if ($con->{RESULT}->{MATCH} =~ qr/\(yes\/no\)\?/i) {
                $con->con_dump();
                $con->{PROMPT}  = qr/password:/i;
                $con->{TIMEOUT} = $self->{telnet_timeout};
                $con->con_cmd("yes\n") or $con->con_error();
                mypr "\n";
                warnpr
                  "RSA key for $self->{IP} permanently added to the list of known hosts\n";
                $con->con_dump();
            }
            $con->{PROMPT}  = $self->{PROMPT};
            $con->{TIMEOUT} = $self->{telnet_timeout};
            $con->con_cmd("$pass\n") or $con->con_error();
            $con->con_dump();
            $self->{PRE_LOGIN_LINES} = $con->{RESULT}->{BEFORE};
        }
        else {
            mypr "port 22 closed -  trying telnet for login\n";
            $con->{EXPECT}->spawn("telnet", ($ip))
              or errpr "Cannot spawn telnet: $!\n";
            my $tmt = $self->{telnet_timeout};
            my $prm = "Username:";
            $con->con_wait("$prm", $tmt) or $con->con_error();
            $con->con_dump();
            $self->{PRE_LOGIN_LINES} = $con->{RESULT}->{BEFORE};
            $con->con_issue_cmd("$user\n", "[Pp]assword:", $tmt)
              or $con->con_error();
            $con->con_dump();
            $con->{PROMPT}  = $self->{PROMPT};
            $con->{TIMEOUT} = $tmt;
            $con->con_cmd("$pass\n") or $con->con_error();
            $con->con_dump();
        }
    }
    else {
        mypr "using simple TELNET for login\n";
        $pass = $self->{PASS};
        $con->{EXPECT}->spawn("telnet", ($ip))
          or errpr "Cannot spawn telnet: $!\n";
        my $prm = "PIX passwd:|Password:";
        my $tmt = $self->{telnet_timeout};
        $con->con_wait("$prm", $tmt) or $con->con_error();
        $con->con_dump();
        $self->{PRE_LOGIN_LINES} = $con->{RESULT}->{BEFORE};
        $con->{PROMPT}           = $self->{PROMPT};
        $con->{TIMEOUT}          = $self->{telnet_timeout};
        $con->con_cmd("$pass\n") or $con->con_error();
        $con->con_dump();
    }
    my $psave = $self->{PROMPT};
    $self->{PROMPT} = qr/Password:|#/;
    $self->cmd('enable') or return 0;
    unless ($con->{RESULT}->{MATCH} eq "#") {

        # Enable password required.
        $self->{PROMPT} = $psave;
        $self->cmd($self->{ENABLE_PASS} || $pass) or return 0;
    }
    return 1;
}

sub checkbanner($) {
    my ($self) = @_;
    if ( $self->{CHECKBANNER}
     and $self->{PRE_LOGIN_LINES} !~ /$self->{CHECKBANNER}/)
    {
        if ($self->{COMPARE}) {
            warnpr "Missing banner at NetSPoC managed device.\n";
        }
        else {
            errpr "Missing banner at NetSPoC managed device.\n";
        }
    }
}

# Packages must return a true value;
1;

