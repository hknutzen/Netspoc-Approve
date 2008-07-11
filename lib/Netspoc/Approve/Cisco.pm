
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

sub get_parsed_config_from_device {
    my ($self) = @_;
    my $device_lines = $self->get_config_from_device();
    mypr "Parse device config\n";
    my $conf  = $self->parse_config($device_lines);
    mypr "... done parsing config\n";
    return($conf);
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
        $mask = $self->dev_cor(get_ip($arg));
    }
    return ({ BASE => $ip, MASK => $mask });
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
      or return { LOW => 0, HIGH => 0xffff };
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
        errpr "port specifier 'neq' not implemented\n";
    }
    elsif ($spec eq 'range') {
        $low = $port;
        $high = $self->parse_port($arg, $proto);
    }
    else {
        internal_err();
    }
    return ({ LOW => $low, HIGH => $high });
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
# comparing 
#################################################

# return value: 0: no
#               1: yes
#               2: intersection
sub ports_a_in_b ($$) {
    my ($a, $b) = @_;
    return 0 if $a->{HIGH} < $b->{LOW} || $b->{HIGH} < $a->{LOW};
    return 1 if $b->{LOW} <= $a->{LOW} && $a->{HIGH} <= $b->{HIGH};
    return 2;
}

# a in b iff (a_mask | b_mask) == a_mask
#            AND
#            (a_mask & b_mask & a_base) == (a_mask & b_mask & b_base)
#
# return value: 0: no
#               1: yes
#               2: intersection
sub ip_netz_a_in_b {
    my ($self, $a, $b) = @_;
    my $am = $a->{MASK};
    my $bm = $b->{MASK};
    my $m  = $am & $bm;
    return 0 if ($m & $a->{BASE}) != ($m & $b->{BASE});
    return 1 if ($am | $bm) == $am;
    return 2;
}

# return value: 0: no
#               1: yes
#               2: intersection
sub services_a_in_b {
    my ($self, $a, $b) = @_;
    my $aproto = $a->{TYPE};
    my $bproto = $b->{TYPE};
    if ($bproto eq 'ip') {
        return 1;
    }
    if ($bproto eq $aproto) {
        if ($bproto eq 'icmp') {
	    my $a_spec = $a->{SPEC};
	    my $b_spec = $b->{SPEC};
	    for my $what (qw(TYPE CODE)) {
                return 1 if not defined $b_spec->{$what};
                return 2 if not defined $a_spec->{$what};
                return 0 if not $a_spec->{$what} eq $b_spec->{$what};
	    }
	    return 1;
        }
        if ($bproto eq 'tcp' or $bproto eq 'udp') {
            my $src = ports_a_in_b($a->{SRC_PORT}, $b->{SRC_PORT}) or return 0;
            my $dst = ports_a_in_b($a->{DST_PORT}, $b->{DST_PORT}) or return 0;
            if ($src == 1 and $dst == 1) {
                $b->{ESTA} or return 1;
                $a->{ESTA} and return 1;
            }
            return 2;
        }
        return 1;
    }
    elsif ($aproto eq 'ip') {
        return 2;
    }
    return 0;
}

# check if SRC SRV DST SRV  from a
# is subset of or intersection with
#          SRC SRV DST SRV from b
#
# do not check permit/deny !
#
# return value: 0: no
#               1: yes
#               2: intersection
sub acl_line_a_in_b {
    my ($self, $a, $b) = @_;
    my $src = $self->ip_netz_a_in_b($a->{SRC}, $b->{SRC}) or return 0;
    my $dst = $self->ip_netz_a_in_b($a->{DST}, $b->{DST}) or return 0;
    my $srv = $self->services_a_in_b($a, $b) or return 0;
    $src == 1 and $dst == 1 and $srv == 1 and return 1;
    return 2;
}

sub acl_line_a_eq_b {
    my ($self, $a, $b) = @_;
    return 0 if $a->{MODE} ne $b->{MODE};
    return 0 if $a->{TYPE} ne $b->{TYPE};
    for my $where (qw(SRC DST)) {
	my $aobj = $a->{$where};
	my $bobj = $b->{$where};
        return 0 if $aobj->{BASE} != $bobj->{BASE};
        return 0 if $aobj->{MASK} != $bobj->{MASK};
    }
    if ($a->{TYPE} eq 'icmp') {
        my $as = $a->{SPEC};
        my $bs = $b->{SPEC};
	for my $where (qw(TYPE CODE)) {
	    return 0 if defined $as->{$where} xor defined $bs->{$where};
	    return 1 if not defined $as->{$where};
	    return 0 if $as->{$where} != $bs->{$where};
	}
    }
    elsif ($a->{TYPE} eq 'tcp' or $a->{TYPE} eq 'udp') {
	for my $where (qw(SRC_PORT DST_PORT)) {
	    my $aport = $a->{$where};
	    my $bport = $b->{$where};
	    return 0 if $aport->{LOW} != $bport->{LOW} or 
		        $aport->{HIGH} != $bport->{HIGH};
        }
	return 0 if $a->{ESTA} xor $b->{ESTA};
    }
    return 0 if $a->{LOG} xor $b->{LOG};
    return 0 if $a->{LOG} and $a->{LOG} ne $b->{LOG};
    return 1;
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
sub acl_prepare ( $;$ ) {
    my ($rules, $do_acl_hash) = @_;
    my $line = 1;
    my %prot;
    my %sb2sm2src;
    my %db2dm2dst;
    my @all_src;
    my @all_dst;
    my %acl_hash;
    my @acl_list;

    for my $r (@$rules) {
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
# Result: 
# A hash having entries a->b->1 for protocols where intersection is not empty.
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
# Result: 
# A hash having entries a->b->1 for elements where intersection is not empty.
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

    # Set verbosity.
    my $opt = $self->{CMPVAL};
    my $verbose = ($opt & 1);
    my $showmatches = ($opt & 2);
    my $silent = ($opt eq 4);

    my ($aprot, $asrc, $adst) = acl_prepare($ac);
    my ($bprot, $bsrc, $bdst, $bhash) = acl_prepare($bc, 1);
    my $p_rel = prot_relation($aprot, $bprot);
    my $s_rel = obj_relation($asrc,   $bsrc);
    my $d_rel = obj_relation($adst,   $bdst);

    my @ad;    # denys lines from "a"

    my $clean = 1;    # be optimistic ;)

    my $log_mismatch = 0;

  OUTER: 
    for my $s (@$ac) {
	my @currentdenylist;
	if ($s->{MODE} eq 'deny') {

	    # Push deny for later inspection.
	    push @ad, $s;
	    next;
	}

	# Check if current permit is subject of deny.
	for my $deny (@ad) {
	    my $result = $self->acl_line_a_in_b($s, $deny);
	    if ($result == 1) {
		if (not $silent) {
		    print "**** USELESS **** ($s->{line}) : $s->{orig}";
		    print " denied by ($deny->{line}) : $deny->{orig}\n";
		}
		next OUTER;
	    }
	    elsif ($result == 2) {
		push @currentdenylist, $deny;
		if ($verbose) {
		    print "**** VERBOSE (fill currentdenylist) ****";
		    print " $s->{line} : $s->{orig}";
		    print " partial $deny->{line} : $deny->{orig}\n";
		}
	    }

	    # else nothing to do - no intersection
	}
	my @perm_int;
	my @deny_int;
	my $deny_match   = 'NO';
	my $deny_line    = 'implicit deny at end of acl';
	my $deny_line_nr = '';
	my $matches      = delete $s->{MATCHES};
	my @found =
	    sort { $a->{line} <=> $b->{line} }
	get_hash_matches($matches, $p_rel, $s_rel, $d_rel, $bhash);
      INNER: 
	for my $p (@found) {
	    my $result = $self->acl_line_a_in_b($s, $p);
	    if ($result == 1) {
		if ($p->{MODE} eq 'deny') {

		    # this is denied, but maybe some permits before...
		    # this is ok because @perm_int is checked at last.
		    $deny_match = 'YES';
		    $deny_line = $p->{orig};
		    $deny_line_nr = $p->{line};
		    last;
		}
		else {

		    # full permit
		    # check if found deny is subset of @currentdenylist
		  CHECK: 
		    for my $deny (@deny_int) {
			for my $cd (@currentdenylist) {
			    if ($self->acl_line_a_in_b($deny, $cd) == 1) {
				if ($verbose) {
				    print "**** VERBOSE (right side) ****";
				    print " ($p->{line}): $p->{orig}";
				    print " partial";
				    print " $deny->{line} : $deny->{orig}";
				    print " has full match at left side:";
				    print " ($cd->{line}): $cd->{orig}\n";
				};
				next CHECK;
			    }
			}

			if (not $silent) {
			    print "+++ DENY MISMATCH +++";
			    print " ($p->{line}): $p->{orig}";
			    print " at right side has predecessor";
			    print " ($deny->{line}): $deny->{orig}";
			    print " which has no full match at left side\n";
			    print "+++ While searching for match:";
			    print " ($s->{line}): $s->{orig}\n";
			};
			$deny_match = 'DMIS';
		    }
		    if ($deny_match eq 'DMIS') {
			last INNER;
		    }

		    # ok
		    if (@perm_int && $verbose) {
			print "**** VERBOSE **** $s->{line} match  $p->{line} ";
			print "with ", scalar(@perm_int), " intersections\n";
		    }
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
		    print "**** LOG MISMATCH **** ($s->{line}): $s->{orig}";
		    print " in ($p->{line}): $p->{orig}\n";
		}
		elsif ($showmatches) {
		    print "**** SHOW MATCHES **** ($s->{line}): $s->{orig}";
		    print " in ($p->{line}): $p->{orig}\n";
		}
		next OUTER;
	    }
	    elsif($result == 2) {
		if ($p->{MODE} eq 'deny') {
		    push @deny_int, $p;
		    if ($verbose) {
			print "**** VERBOSE (fill deny_intersec) **** ";
			print "$s->{line} : $s->{orig}";
			print " partial $p->{line} : $p->{orig}\n";
		    }
		}
		else {

		    # permit intersection
		    push @perm_int, $p;
		    if ($verbose) {
			print "($s->{line}): $s->{orig}";
			print " INTERSECTION ($p->{line}): $p->{orig}\n";
		    }
		}
	    }

	    # else nothing to do - no intersection
	}
	$clean = 0;
	if(not $silent) {
	    unless ($deny_match eq 'DMIS') {
		if (@perm_int) {
		    print " **** DENY **** ($s->{line}): $s->{orig}";
		    print " by ($deny_line_nr): $deny_line\n";
		    my @intersec = sort { $a->{line} <=> $b->{line } }
		    (@deny_int, @perm_int);
		    for my $p (@intersec) {
			print " **** INTERSEC **** $p->{line} : $p->{orig}\n";
		    }
		}
		else {
		    print "**** DENY **** ($s->{line}): $s->{orig}";
		    print " by ($deny_line_nr): $deny_line\n";
		}
	    }
	}
    }
    return ($clean and !$log_mismatch);    # a in b
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

# Rawdata processing
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

	# Prepend raw acl.
	unshift(@{$spoc_conf->{ACCESS}->{$sp_name}}, @$rawacl);

	# Additionally prepend to original acl having object_groups.
	if($extra) {
	    unshift(@{$spoc_conf->{$extra}->{$sp_name}}, @$rawacl);
	}
	mypr "   entries prepended: " . scalar @{$rawacl} . "\n";
    }
}

sub enter_conf_mode {
    my($self) = @_;
    $self->cmd('configure terminal');
}

sub leave_conf_mode {
    my($self) = @_;
    $self->cmd('end');
}

sub route_add {
    my($self, $entry) = @_;
    return($entry->{orig});
}

sub route_del {
    my($self, $entry) = @_;
    return("no $entry->{orig}");
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
    $self->checkidentity($name);

    # Set prompt again because of performance impact of standard prompt.
    $self->{ENAPROMPT} = qr/\r\n\s?$name\S*#\s?$/;
}

sub login_enable {
    my ($self) = @_;
    my($con, $ip, $user, $pass) = @{$self}{qw(CONSOLE IP LOCAL_USER PASS)};

    if(not $pass) {
	($user, $pass) = $self->get_aaa_password();
    }
    if ($user) {
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
            my $prompt = qr/password:|\(yes\/no\)\?/i;
            $con->con_wait($prompt) or $con->con_error();
            if ($con->{RESULT}->{MATCH} =~ qr/\(yes\/no\)\?/i) {
                $con->con_dump();
                $con->{PROMPT}  = qr/password:/i;
                $con->con_cmd("yes\n") or $con->con_error();
                mypr "\n";
                warnpr
                  "RSA key for $self->{IP} permanently added to the list of known hosts\n";
                $con->con_dump();
            }
            $con->{PROMPT}  = $self->{PROMPT};
            $con->con_cmd("$pass\n") or $con->con_error();
            $con->con_dump();
            $self->{PRE_LOGIN_LINES} = $con->{RESULT}->{BEFORE};
        }
        else {
            mypr "port 22 closed -  trying telnet for login\n";
            $con->{EXPECT}->spawn("telnet", ($ip))
              or errpr "Cannot spawn telnet: $!\n";
            my $prompt = "Username:";
            $con->con_wait($prompt) or $con->con_error();
            $con->con_dump();
            $self->{PRE_LOGIN_LINES} = $con->{RESULT}->{BEFORE};
            $con->con_issue_cmd("$user\n", "[Pp]assword:")
              or $con->con_error();
            $con->con_dump();
            $con->{PROMPT}  = $self->{PROMPT};
            $con->con_cmd("$pass\n") or $con->con_error();
            $con->con_dump();
        }
    }
    else {
        mypr "using simple TELNET for login\n";
        $pass = $self->{PASS};
        $con->{EXPECT}->spawn("telnet", ($ip))
          or errpr "Cannot spawn telnet: $!\n";
        my $prompt = "PIX passwd:|Password:";
        $con->con_wait($prompt) or $con->con_error();
        $con->con_dump();
        $self->{PRE_LOGIN_LINES} = $con->{RESULT}->{BEFORE};
        $con->{PROMPT}           = $self->{PROMPT};
        $con->con_cmd("$pass\n") or $con->con_error();
        $con->con_dump();
    }
    my $psave = $self->{PROMPT};
    $self->{PROMPT} = qr/Password:|#/;
    $self->issue_cmd('enable');
    unless ($con->{RESULT}->{MATCH} eq "#") {

        # Enable password required.
        $self->{PROMPT} = $psave;
        $self->issue_cmd($self->{ENABLE_PASS} || $pass);
    }
    return 1;
}

# Packages must return a true value;
1;

