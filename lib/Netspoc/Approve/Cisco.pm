
package Netspoc::Approve::Device::Cisco;

# Authors: Arne Spetzler, Heinz Knutzen, Daniel Brunkhorst
#
# Description:
# Remote configure cisco devices
# 

'$Id$' =~ / (.+),v (.+?) /;  

my $id = "$1 $2";

sub version_drc2_cisco(){
    return $id;
}

use strict;
use warnings;
use base "Netspoc::Approve::Device";
use IO::Socket ();
use Netspoc::Approve::Helper;
use Netspoc::Approve::Device::Cisco::Parse;

sub parse_device {
    my($self, $lines) = @_;

    mypr "parse device config\n";
    my $config = analyze_conf_lines($lines);
    
    my $result;
    my $parse_info = $self->get_parse_info();
    for my $cmd (keys %$config) {

	# Parse known commands, ignore unknown commands.
	my $cmd_info = $parse_info->{$cmd} or next;
	my($method, $key) = @$cmd_info;
	for my $arg (@{ $config->{$cmd} }) {
	    my($value, $name, $push) = $self->$method($arg);
	    get_eol($arg);
	    next if not $value;

	    # Attach unparsed command line.
	    # This isn't possible if the command is parsed into an
	    # array from its subcommands.
	    $value->{orig} = $arg->{orig} if ref($value) eq 'HASH';
	    if($name) {
		if($push) {

		    # Named commands of same type, parsed separately.
		    push @{ $result->{$key}->{$name} }, $value;
		}
		else {

		    # One named command with arguments or with multiple 
		    # subcommands; parsed together.
		    $result->{$key}->{$name} and
			err_at_line($arg, "Redefining '$cmd $name'");
		    $result->{$key}->{$name} = $value;
		}
	    }
	    else {

		# Unnamed commands of same type, parsed separately.
		push @{ $result->{$key} }, $value;
	    }
        }
    }
    mypr "... done parsing config\n";
    $self->postprocess_config($result);
    return $result;
}

# ip mask
# host ip
# any
# ->{SPEC} ->{PORT_L} / {PORT_H}
sub parse_address {
    my($self, $desc) = @_;
    my($ip, $mask);
    my $token = get_token($desc);
    if($token eq 'any') {
	$ip = $mask = 0;
    }
    elsif($token eq 'host') {
	$ip = get_ip($desc);
	$mask = 0xffffffff;
    }
    else {
	$ip = quad2int($token);
	$mask = get_ip($desc);
    }
    return( { BASE => $ip, MASK => $self->dev_cor($mask) } );
}

sub parse_port {
    my($self, $proto, $desc) = @_;
    my $port = get_token($desc);
    if($proto eq 'tcp') {
	$port = $PORT_Trans_TCP{$port} || $port;
    }
    else {
	$port = $PORT_Trans_UDP{$port} || $port;
    }
    $port =~ /^\d+$/ or err_at_line('Syntax');
    return $port;
}	
    
# ( 'lt' | 'gt' | 'eq' | 'neq' ) port
# 'range' port port
sub parse_port_spec {
    my($self, $proto, $desc) = @_;
    my($low, $high);
    my $spec = check_regex('eq|gt|lt|neq|range', $desc) or
	return {};    
    my $port = $self->parse_port($proto, $desc);
    if($spec eq 'eq') {
	$low = $high = $port;
	$spec = 'range';
    }
    elsif($spec eq 'gt') {
	$low = $port + 1;
	$high = 0xffff;
	$spec = 'range';
    }
    elsif($spec eq 'lt') {
	$low = 0;
	$high = $port - 1;
	$spec = 'range';
    }
    elsif($spec eq 'neq') {
	die "port specifier 'neq' not implemented yet\n";
    }
    elsif($spec eq 'range') {
	$low = $port;
	$high = $self->parse_port($proto, $desc);
    }
    else {
	internal_err();
    }
    return( { SPEC => $spec, PORT_L => $low, PORT_H => $high } );
}

my $icmp_regex = join('|', '\d+', keys %ICMP_Trans);

# <message-name> | (/d+/ [/d+])
# ->{TYPE} / ->{CODE} (if defined)
sub parse_icmp_spec {
    my($self, $desc) = @_;
    my($type, $code);
    my $token = check_regex($icmp_regex, $desc) or
	return {};
    if(my $spec = $ICMP_Trans{$token}){
	($type, $code)  = @{$spec}{'type', 'code'};
    }
    else {
	$type = $token;
	$code = check_regex('\d+', $desc) || -1;
    }
    return( { TYPE => $type, CODE => $code } );
}

############################################################
# --- helper ---
############################################################
sub num_compare { $a->[0] <=> $b->[0] }

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
    my ($a, $b) = @_;
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
    my $bproto = $b->{TYPE};
    if ($bproto eq 'ip') {
        return 1;
    }
    if ($bproto eq $a->{TYPE}) {
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
        if ($bproto eq 'tcp') {
            my $src = ports_a_in_b($a->{SRC}->{SRV}, $b->{SRC}->{SRV});
            ($src) or return 0;
            my $dst = ports_a_in_b($a->{DST}->{SRV}, $b->{DST}->{SRV});
            ($dst) or return 0;
            if ($src == 1 and $dst == 1) {
                ($b->{ESTA}) or return 1;
                ($a->{ESTA}) and return 1;
            }
            return 2;    # intersection
        }
        if ($bproto eq 'udp') {
            my $src = ports_a_in_b($a->{SRC}->{SRV}, $b->{SRC}->{SRV});
            ($src) or return 0;
            my $dst = ports_a_in_b($a->{DST}->{SRV}, $b->{DST}->{SRV});
            ($dst) or return 0;
            ($src == $dst) and return $src;    # this is ok!
            return 2;                          # intersection
        }
        return 1;
    }
    elsif ($a->{TYPE} eq 'ip') {

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
    $src = ip_netz_a_in_b($a->{SRC}, $b->{SRC});
    ($src) or return 0;
    $dst = ip_netz_a_in_b($a->{DST}, $b->{DST});
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
    if ($a->{TYPE} eq 'icmp' or $a->{TYPE} eq 1) {
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
        my $ass = $asrc->{SRV};
        my $ads = $adst->{SRV};
        my $bss = $bsrc->{SRV};
        my $bds = $bdst->{SRV};
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
	    (defined($a->{$key}) && defined($b->{$key})
	     && $a->{$key} eq $b->{$key})
		or return 0;
	}
    }
    return 1;
}


#
# May only be used for pix routes.
#
sub route_line_destination_a_eq_b {
    my ($self, $a, $b) = @_;
    unless (defined($a->{IF}) && defined($b->{IF})) {
        die "route_line_destination_a_eq_b only defined for pix\n";
    }

    # we do not consider the pix interfaces - otherwise - if pix os
    # version changes -> weired behavior
    ($a->{BASE} eq $b->{BASE} && $a->{MASK} eq $b->{MASK})
      or return 0;
    return 1;
}

sub route_line_a_supersedes_b {
    my ($self, $a, $b) = @_;
    if ($a->{BASE} eq $b->{BASE} && $a->{MASK} eq $b->{MASK}) {
	for my $key (qw(NIF NEXTHOP)) {
	    if (defined($a->{$key}) || defined($b->{$key})) {
		(defined($a->{$key}) && defined($b->{$key})
		 && $a->{$key} eq $b->{$key})
		    or return 0;
	    }
	}
        return 1;
    }
    return $self->ip_netz_a_in_b($a, $b);
}

################################################################
# compare two arrays with acl objects
################################################################

### helper ###

sub hash_masks( $ ) {
    my %msk;
    for my $acl (@{ $_[0] }) {
        next if exists $acl->{REMARK};
        $msk{ $acl->{SRC}->{MASK} }->{ $acl->{DST}->{MASK} } =
          {};
    }
    return \%msk;
}

sub hash_acl( $$ ) {
    my ($msk, $acl) = @_;
    my $H = {};    # source hash
    for (my $i = 0 ; $i < scalar @$acl ; $i++) {
        my $ace = $acl->[$i];
        next if exists $ace->{REMARK};
        my $prot = $ace->{TYPE};
        my $bsrc = $ace->{SRC};
        my $bsm  = $bsrc->{MASK};
        my $bsb  = $bsrc->{BASE};
        my $bdst = $ace->{DST};
        my $bdm  = $bdst->{MASK};
        my $bdb  = $bdst->{BASE};
        for my $asm (keys %$msk) {

            for my $adm (keys %{ $msk->{$asm} }) {

                #push @{$H->{$prot}->{$asm}->{$bsm}->{$bsm&$bsb&$asm}->{$adm}->{$bdm}->{$bdm&$bdb&$adm}},[$ace,$i];
                push @{ $H->{$prot}->{$bsm}->{$bdm}->{$asm}->{$adm}
                      ->{ $bsm & $bsb & $asm }->{ $bdm & $bdb & $adm } },
                  [ $ace, $i ];
            }
        }
    }
    return $H;
}

sub get_hash_matches( $$$ ) {
    my ($ace, $msk, $H) = @_;
    my $asrc   = $ace->{SRC};
    my $asm    = $asrc->{MASK};
    my $asb    = $asrc->{BASE};
    my $adst   = $ace->{DST};
    my $adm    = $adst->{MASK};
    my $adb    = $adst->{BASE};
    my $proto  = $ace->{TYPE};
    my %found  = ();
    my @result = ();
    for my $bsm (keys %$msk) {

        for my $bdm (keys %{ $msk->{$bsm} }) {
            if ($proto eq 'ip') {
                for my $p (keys %$H) {
                    if (
                        defined $H->{$p}->{$bsm}->{$bdm}->{$asm}->{$adm}
                        ->{ $asm & $asb & $bsm }->{ $adm & $adb & $bdm })
                    {
                        $found{ $H->{$p}->{$bsm}->{$bdm}->{$asm}->{$adm}
                              ->{ $asm & $asb & $bsm }->{ $adm & $adb & $bdm } }
                          = $H->{$p}->{$bsm}->{$bdm}->{$asm}->{$adm}
                          ->{ $asm & $asb & $bsm }->{ $adm & $adb & $bdm };
                    }
                }
            }
            else {
                if (
                    defined $H->{$proto}->{$bsm}->{$bdm}->{$asm}->{$adm}
                    ->{ $asm & $asb & $bsm }->{ $adm & $adb & $bdm })
                {
                    $found{ $H->{$proto}->{$bsm}->{$bdm}->{$asm}->{$adm}
                          ->{ $asm & $asb & $bsm }->{ $adm & $adb & $bdm } } =
                      $H->{$proto}->{$bsm}->{$bdm}->{$asm}->{$adm}
                      ->{ $asm & $asb & $bsm }->{ $adm & $adb & $bdm };
                }
                if (
                    defined $H->{'ip'}->{$bsm}->{$bdm}->{$asm}->{$adm}
                    ->{ $asm & $asb & $bsm }->{ $adm & $adb & $bdm })
                {
                    $found{ $H->{'ip'}->{$bsm}->{$bdm}->{$asm}->{$adm}
                          ->{ $asm & $asb & $bsm }->{ $adm & $adb & $bdm } } =
                      $H->{'ip'}->{$bsm}->{$bdm}->{$asm}->{$adm}
                      ->{ $asm & $asb & $bsm }->{ $adm & $adb & $bdm };
                }
            }
        }
    }
    map { @result = (@result, @$_) } values %found;
    return \@result;
}

sub show( $$$ ) {

    #
    # this is only for debugging
    #
    my ($self, $ac, $bc) = @_;

    my $amsk = hash_masks($ac);
    my $bmsk = hash_masks($bc);
    my $bhsh = hash_acl($amsk, $bc);

    my $c = 0;
    for my $ace (@{$ac}) {
        my $found = get_hash_matches($ace, $bmsk, $bhsh);
        print $self->acl_line_to_string($ace), "\n";
        for my $a (@$found) {
            print "  ($c) ", $self->acl_line_to_string($a->[0]),
              " -> $a->[1]\n";
            ++$c;
        }
        print "\n";
    }
}

### main func ###

sub acl_array_compare_a_in_b ( $$$$ ) {
    my ($self, $ac, $bc, $opt) = @_;

    # setting options

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

    my $amsk = hash_masks($ac);
    my $bmsk = hash_masks($bc);
    my $bhsh = hash_acl($amsk, $bc);

    my @ad;    # denys lines from "a"

    my $clean = 1;    # be optimistic ;)

    my $log_mismatch = 0;

    my $lines = 0;
  OUTER: for my $s (@$ac) {
        $lines++;
        exists $s->{REMARK} and next;

        #if($lines == 100){ exit;}
        my $inner           = 0;
        my @currentdenylist = ();
        if ($s->{MODE} eq 'deny') {

            # push deny for later inspection
            push @ad, [ $lines, $s ];

            #for my $l (@ad){
            #    print $l->[0],acl_line_to_string($l->[1]),"\n";
            #};
            next;
        }
        else {

            # check if current permit is subject of deny
            for my $deny (@ad) {
                my $result = $self->acl_line_a_in_b($s, $deny->[1]);
                if ($result == 1) {
                    unless ($silent) {
                        print "**** USELESS **** ", $lines, " : ";
                        print $self->acl_line_to_string($s), "\n";
                        print " denied by ", $deny->[0], " : ";
                        print $self->acl_line_to_string($deny->[1]), "\n";
                    }
                    next OUTER;
                }
                if ($result == 2) {

                    # list of curent denys
                    push @currentdenylist, $deny;
                    ($verbose) and do {
                        print "**** VERBOSE (fill currentdenylist) **** ",
                          $lines, " : ";
                        print $self->acl_line_to_string($s);
                        print " partial ", $deny->[0], " : ";
                        print $self->acl_line_to_string($deny->[1]), "\n";
                      }
                }

                # else nothing to do - no intersection
            }
        }
        my @perm_int   = ();
        my @deny_int   = ();
        my $deny_match = "NO";
        my @found =
          sort { $a->[1] <=> $b->[1] } @{ get_hash_matches($s, $bmsk, $bhsh) };
        my $p;
      INNER: for my $ace (@found) {
            $p     = $ace->[0];
            $inner = $ace->[1] + 1;
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
                            if ($self->acl_line_a_in_b($deny->[1], $cd->[1]) == 1)
                            {
                                ($verbose) and do {
                                    print "**** VERBOSE (right side) **** (";
                                    print $inner, "): ",
                                      $self->acl_line_to_string($p);
                                    print " partial ";
                                    print $deny->[0], " : ",
                                      $self->acl_line_to_string($deny->[1]);
                                    print " has full match at left side: (";
                                    print $cd->[0], "): ",
                                      $self->acl_line_to_string($cd->[1]);
                                    print "\n";
                                };
                                next CHECK;
                            }
                        }

                        # deny mismatch!
                        ($silent) or do {
                            print "+++ DENY MISMATCH +++ (";
                            print $inner, "): ", $self->acl_line_to_string($p);
                            print " at right side has predecessor (";
                            print $deny->[0], "): ",
                              $self->acl_line_to_string($deny->[1]);
                            print " which has no full match at left side\n";
                            print "+++ While searching for match: (";
                            print $lines, "): ", $self->acl_line_to_string($s),
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
                    #    print "($lines): ".$self->acl_line_to_string($s);
                    #    print " in ($inner): ",$self->acl_line_to_string($p);
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
                      $self->acl_line_to_string($s);
                    print " in ($inner): ", $self->acl_line_to_string($p), "\n";
                }
                elsif ($showmatches) {
                    print "**** SHOW MATCHES **** ($lines): ",
                      $self->acl_line_to_string($s);
                    print " in ($inner): ", $self->acl_line_to_string($p), "\n";
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
                        print $self->acl_line_to_string($s);
                        print " partial ", $inner, " : ";
                        print $self->acl_line_to_string($p), "\n";
                      }
                }
                else {

                    # permit intersection!
                    push @perm_int, [ $inner, $p ];
                    if ($verbose) {
                        print "($lines): ", $self->acl_line_to_string($s);
                        print " INTERSECTION ($inner): ",
                          $self->acl_line_to_string($p);
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
                    $deny_line = $self->acl_line_to_string($p);
                }
                else {
                    $inner     = "";
                    $deny_line = 'implicit deny at end of acl';
                }
                if (@perm_int) {
                    print " **** DENY **** (", $lines, "): ";
                    print $self->acl_line_to_string($s);
                    print " by ($inner): $deny_line\n";
                    my @intersec = sort num_compare (@deny_int, @perm_int);
                    for my $p (@intersec) {
                        print " **** INTERSEC **** ", $p->[0], " : ";
                        print $self->acl_line_to_string($p->[1]), "\n";
                    }
                }
                else {
                    print " **** DENY **** (", $lines, "): ";
                    print $self->acl_line_to_string($s);
                    print " by ($inner): $deny_line\n";
                }
            }
          }
    }
    ($clean and !$log_mismatch) and return 1;    # a in b
    return 0;
}

sub login_enable( $ ) {
    my ($self) = @_;
    my $ip = $self->{IP};
    my $user;
    my $pass;
    my $con = $self->{CONSOLE};

    if ($self->{PASS} =~ /:/ or $self->{LOCAL_USER}) {
        if ($self->{LOCAL_USER}) {
            $pass = $self->{PASS};
            $user = $self->{LOCAL_USER} or die "no user found\n";
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
              or die "Cannot spawn ssh: $!\n";
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
              or die "Cannot spawn telnet: $!\n";
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
          or die "Cannot spawn telnet: $!\n";
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
    unless($con->{RESULT}->{MATCH} eq "#"){

	# Enable password required.
	$self->{PROMPT} = $psave;
	$self->cmd($self->{ENABLE_PASS} || $pass) or return 0;
    }
    return 1;
}

# Packages must return a true value;
1;

