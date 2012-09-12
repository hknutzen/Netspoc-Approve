
package Netspoc::Approve::Device;

#
# Authors: Arne Spetzler, Heinz Knutzen, Daniel Brunkhorst
#
# Description:
# Base class for the different varieties of devices (IOS, PIX, etc.).
#

use strict;
use warnings;
use Fcntl qw/:flock/;    # import LOCK_* constants
use File::Basename;
use Netspoc::Approve::Helper;
use Netspoc::Approve::Console;
use Netspoc::Approve::Parse_Cisco;

# VERSION: inserted by DZP::OurPkgVersion

############################################################
# --- constructor ---
############################################################
sub new {
    my $class = shift;
    my $self  = {@_};
    return bless($self, $class);
}

###########################################################################
#   methods
###########################################################################

# Get password from file.
# Format:
# - Comma separated values:
#   0: <name>
#   has at least 9 fields (Cisco Works format)
#   8: <Telnet password>
#   else
#   1: <password>
# - ignore 
#   - empty lines.
#   - comment lines starting with ';' or #
sub get_cw_password ($$) {
    my ($self, $name) = @_;
    my $path = "$self->{CONFIG}->{PASSWDPATH}" or return;

    open(my $csv, '<', $path) or die "Can't open $path: $!\n";
    for my $line (<$csv>) {
        chomp $line;
        $line =~ /^[;#]/ and next;
        $line =~ s/[\"]//g;
        $line or next;
        my @fields = split(/,/, $line);
        if ($name eq $fields[0]) {
            return $fields[@fields >= 9 ? 8 : 1];
        }
    }
    return;
}

sub get_aaa_password {
    my ($self) = @_;
    my $pass;
    my $user = getpwuid($>);
    my $system_user = $self->{CONFIG}->{SYSTEMUSER};
    if ($system_user && $user eq $system_user) {

	# Use AAA credentials.
	my $aaa_credential = $self->{CONFIG}->{AAA_CREDENTIALS}
            or die "Must configure AAA_CREDENTIALS together with SYSTEMUSER\n";
	open(my $file, '<', $aaa_credential)
	    or die "Could not open $aaa_credential: $!\n";
	my $credentials = <$file>;
	close($file);
	($user, $pass) = $credentials =~ (/^\s*(\S+)\s*(\S+)\s*$/)
	    or die "No AAA credential found\n";
	mypr "User $user extracted from aaa credentials\n";
    }
    return ($user, $pass);
}

sub get_user_password {
    my ($self, $user) = @_;
    my $pass;

    # Write directly to tty, because STDOUT may be redirected.
    open(my $tty, '>:unix', '/dev/tty') or die "Can't open /dev/tty: $!\n";
    print $tty "Running in non privileged mode and no "
	. "password found in database.\n";
    print $tty "Password for $user?";
    system('stty', '-echo');
    $pass = <STDIN>;
    system('stty', 'echo');
    print $tty "  ...thank you :)\n";
    close $tty;
    chomp $pass;
    return ($pass);
}

# Read type and IP addresses from header of spoc file.
# ! [ Model = IOS ]
# ! [ IP = 10.1.13.80,10.1.14.77 ]
sub get_spoc_data {
    my ($self, $spocfile) = @_;
    my $type;
    my @ip;
    open(my $file, '<', $spocfile) or die "Can't open $spocfile: $!\n";
    while (my $line = <$file>) {
        if ($line =~ /\[ Model = (\S+) ]/) {
            $type = $1;
        }
        if ($line =~ /\[ IP = (\S+) ]/) {
            @ip = split(/,/, $1);
	    last;
        }
    }
    close $file;
    return($type, @ip);
}

sub load_spocfile {
    my ($self, $path) = @_;
    my @result;

    open(my $file, '<', $path) or die "Could not open spocfile $path: $!\n";
    @result = <$file>;
    close($file);

    my $count = @result;
    mypr "### Read config file $path with $count lines\n";
    return \@result;
}

sub load_raw {
    my ($self, $path) = @_;
    my $raw = "$path.raw";
    my @result;
    if (-f $raw) {
        open(my $file, '<', $raw) or die "Could not open $raw: $!\n";
        @result = <$file>;
        close $file;
    }
    my $count = @result;
    mypr "### Read rawdata file $raw with $count lines\n" if $count;
    return \@result;
}

sub load_spoc {
    my ($self, $path) = @_;
    my $lines     = $self->load_spocfile($path);
    my $conf      = $self->parse_config($lines);
    my $raw_lines = $self->load_raw($path);
    my $raw_conf  = $self->parse_config($raw_lines);
    $self->merge_rawdata($conf, $raw_conf);
    return($conf);
}

sub load_device {
    my ($self) = @_;
    my $device_lines = $self->get_config_from_device();
    mypr "### Parsing device config\n";
    my $conf  = $self->parse_config($device_lines);
    return($conf);
}

# A command line consists of two parts: command and argument.
# A command is either a single word or a multi word command.
# A multi word command is put together from some words at fixed positions 
# of the word list.
# Examples:
# - ip access-group NAME in
#   coded as "ip access-group _skip in", takes first two words and 4th word.
# - tunnel-group NAME type TYPE
#   coded as "tunnel-group _skip type"
# - isakmp ikev1-user-authentication|keepalive
#   coded as "isakmp _any", takes two words, but second is unspecified.
#   such a wildcard command may be referenced by "_cmd".
# This function identifies 
# - all words, which are prefix of some command.
# Known commands are read from the hash keys of $parse_info.
sub add_prefix_info {
    my ($self, $parse_info) = @_;
    my $result = {};
    for my $key (keys %$parse_info) {
	my @split = split(' ', $key);
	if (@split > 1) {
	    my $hash = $result;
	    while(@split) {
		my $word = shift(@split);
		$hash->{$word} ||= {};
		$hash = $hash->{$word};
	    }
	}
	elsif ($key eq '_any') {
	    $result->{_any} = 1;
	}
	if(my $subcmd = $parse_info->{$key}->{subcmd}) {
	    $self->add_prefix_info($subcmd);
	}
    }
    $parse_info->{_prefix} = $result if keys %$result;
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
		my $value;
		$value = parse_line($self, $arg, $parser, @evaled) 
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
	if($type eq 'seq') {

	    # All args must match
	}
	elsif($type eq 'or') {
	    last if $success;
	}
	elsif($type eq 'cond1') {

	    # Stop if first arg doesn't match.
	    last if not $success;
	}
	else {
	    internal_err "Expected 'seq|cond1|or' but got $type";
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
	internal_err "Unexpected parse attribute: $info";
    }
}

# $config are prepared config lines.
# $parse_info describes grammar.
sub parse_config1 {
    my($self, $config, $parse_info) = @_;
    my $result = {};
    for my $arg (@$config) {
	my $cmd = get_token($arg);
        my $cmd_info = $arg->{cmd_info};
	if(my $msg = $cmd_info->{error}) {
	    err_at_line($arg, $msg);
	}
	my $named = $cmd_info->{named};
	my $name;
	if($named and $named ne 'from_parser') {
	    $name = get_token($arg);
	}
	my $parser = $cmd_info->{parse};
        my @params = $cmd_info->{params} ? @{ $cmd_info->{params} } : ();
	my $value;
	$value = parse_line($self, $arg, $parser, @params) if $parser;
	get_eol($arg);
	if(my $subcmds = $arg->{subcmd}) {
	    my $parse_info = $cmd_info->{subcmd} or 
		err_at_line($arg, 'Unexpected subcommand');
	    my $value2 = parse_config1($self, $subcmds, $parse_info);
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
	if($named and $named eq 'from_parser') {
	    $name = $value->{name} or err_at_line($arg, 'Missing name');
	}
	if(ref($value) eq 'HASH') {
	    $named and $value->{name} = $name;
	    $value->{orig} = $arg->{orig};
	    $value->{line} = $arg->{line};
	}
	my $store = $cmd_info->{store};
	my @extra_keys = ref $store ? @$store : $store;
	my $key;
	if($named) {
	    $key = $name;
	}
	else {
	    $key = pop @extra_keys;
	    $key = $cmd if $key eq '_cmd';
	}
	my $dest = $result;
	for my $x (@extra_keys) {
	    $x = $cmd if $x eq '_cmd';
	    $dest->{$x} ||= {};
	    $dest = $dest->{$x};
	}
	if($cmd_info->{multi}) {
	    push(@{ $dest->{$key} }, $value);
	}
	else {
	    if(my $old = $dest->{$key}) {
		if($cmd_info->{merge}) {
		    for my $key (keys %$value) {
			next if $key =~ /(?:name|line|orig)/;
			if(defined $old->{$key}) {
			    err_at_line($arg, "Duplicate '$key' while merging");
			}
			$old->{$key} = $value->{$key};
		    }
		}
		else {
		    err_at_line($arg, 
				'Multiple occurences of command not allowed');
		}
	    }
	    else {
		$dest->{$key} = $value;
	    }
	}
    }
    return($result);
}

sub parse_config {
    my ($self, $lines) = @_;

    my $parse_info = $self->get_parse_info();
    my $config = $self->analyze_conf_lines($lines, $parse_info);
    my $result = $self->parse_config1($config, $parse_info);
    $self->postprocess_config($result);
    return $result;
}

# Rawdata processing
sub merge_routing {
    my ($self, $spoc_conf, $raw_conf) = @_;
    
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
    mypr "RAW: attached routing entries: "
	. scalar @{ $raw_conf->{ROUTING} } . "\n";
}

sub route_line_a_eq_b {
    my ($self, $a, $b) = @_;
    ($a->{BASE} == $b->{BASE} && $a->{MASK} == $b->{MASK})
      or return 0;
    for my $key (qw(VRF IF NIF NEXTHOP METRIC TRACK TAG PERMANENT)) {
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
    return($a->{BASE} == $b->{BASE} && $a->{MASK} == $b->{MASK});
}

sub process_routing {
    my ($self, $conf, $spoc_conf) = @_;
    my $spoc_routing = $spoc_conf->{ROUTING};
    my $conf_routing = $conf->{ROUTING} ||= [];
    if (not $spoc_routing) {
        mypr "no routing entries specified - leaving routes untouched\n";
	return;
    }

    $self->{CHANGE}->{ROUTE} = 0;
    for my $c (@$conf_routing) {
	for my $s (@$spoc_routing) {
	    if ($self->route_line_a_eq_b($c, $s)) {
		$c->{DELETE} = $s->{DELETE} = 1;
		last;
	    }
	}
    }

    my @cmds;

    # Add routes with long mask first.
    # If we switch the default route, this ensures, that we have the
    # new routes available before deleting the old default route.
    for my $r ( sort {$b->{MASK} <=> $a->{MASK}} @{ $spoc_conf->{ROUTING} }) {
	next if $r->{DELETE};
	$self->{CHANGE}->{ROUTE} = 1;

	# PIX and ASA don't allow two routes to identical destination.
	# Remove old route immediatly before adding the new one.
	for my $c (@$conf_routing) {
	    next if $c->{DELETE};
	    if($self->route_line_destination_a_eq_b($r, $c)){
		push(@cmds, $self->route_del($c));
		$c->{DELETE} = 1; # Must not delete again.
	    }
	}
	push(@cmds, $self->route_add($r));
    }
    for my $r (@$conf_routing) {
	next if $r->{DELETE};
	$self->{CHANGE}->{ROUTE} = 1;
	push(@cmds, $self->route_del($r));
    }
    if(@cmds) {
	mypr "### Change routing entries on device\n";
	$self->schedule_reload(5);
	$self->enter_conf_mode;
	map { $self->cmd($_); } @cmds;
	$self->leave_conf_mode;
	$self->cancel_reload();
    }
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
                print "**** USELESS **** ($s->{line}) : $s->{orig}";
                print " denied by ($deny->{line}) : $deny->{orig}\n";
		next OUTER;
	    }
	    elsif ($result == 2) {
		push @currentdenylist, $deny;
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
				next CHECK;
			    }
			}

                        print "+++ DENY MISMATCH +++";
                        print " ($p->{line}): $p->{orig}";
                        print " at right side has predecessor";
                        print " ($deny->{line}): $deny->{orig}";
                        print " which has no full match at left side\n";
                        print "+++ While searching for match:";
                        print " ($s->{line}): $s->{orig}\n";
			$deny_match = 'DMIS';
		    }
		    if ($deny_match eq 'DMIS') {
			last INNER;
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
		if ($lm) {
		    print "**** LOG MISMATCH **** ($s->{line}): $s->{orig}";
		    print " in ($p->{line}): $p->{orig}\n";
		}
		next OUTER;
	    }
	    elsif($result == 2) {
		if ($p->{MODE} eq 'deny') {
		    push @deny_int, $p;
		}
		else {

		    # permit intersection
		    push @perm_int, $p;
		}
	    }

	    # else nothing to do - no intersection
	}
	$clean = 0;
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
    return ($clean and !$log_mismatch);    # a in b
}

sub acl_equal {
    my ($self, $conf_acl, $spoc_acl, $conf_name, $spoc_name, $context) = @_;
    my $diff = 0;
    mypr "compare ACLs OLD=$conf_name NEW=$spoc_name for $context\n";

    ### textual compare
    if (@{$conf_acl} == @{$spoc_acl}) {
        mypr "length equal: ", scalar @{$conf_acl}, "\n";
        mypr "compare line by line: ";
        for (my $i = 0 ; $i < scalar @{$conf_acl} ; $i++) {
            if ($self->acl_line_a_eq_b($$conf_acl[$i], $$spoc_acl[$i])) {
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
	    " OLD: " . scalar @{$conf_acl} . 
	    " NEW: " . scalar @{$spoc_acl} . "\n";
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
    mypr "#### BEGIN NEW in OLD - $context\n";
    $newinold = $self->acl_array_compare_a_in_b($spoc_acl, $conf_acl);
    mypr "#### END   NEW in OLD - $context\n";
    mypr "#### BEGIN OLD in NEW - $context\n";
    $oldinnew = $self->acl_array_compare_a_in_b($conf_acl, $spoc_acl);
    mypr "#### END   OLD in NEW - $context\n";

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

sub checkidentity {
    my ($self, $name) = @_;
    if($name ne $self->{NAME}) {
	errpr "wrong device name: $name, expected: $self->{NAME}\n";
    }
}

sub checkbanner {
    my ($self) = @_;
    my $check = $self->{CONFIG}->{CHECKBANNER} or return;
    if ( $self->{PRE_LOGIN_LINES} !~ /$check/) {
        if ($self->{COMPARE}) {
            warnpr "Missing banner at NetSPoC managed device.\n";
        }
        else {
            errpr "Missing banner at NetSPoC managed device.\n";
        }
    }
}

sub con_setup {
    my ($self, $startup_message) = @_;
    my $logfile;
    if (my $logdir = $self->{OPTS}->{L}) {
        $logfile = "$self->{telnet_logs}$self->{NAME}.tel";
    }

    my $con = $self->{CONSOLE} =
	Netspoc::Approve::Console->new_console($self, "telnet", $logfile,
					      $startup_message);
    $con->{TIMEOUT} = $self->{OPTS}->{t};
}

sub con_shutdown {
    my ($self, $shutdown_message) = @_;
    my $con = $self->{CONSOLE};
    $con->{TIMEOUT} = 5;
    $con->con_issue_cmd("exit\n", eof);
    $con->shutdown_console("$shutdown_message");
}

sub issue_cmd {
    my ($self, $cmd) = @_;

    my $con = $self->{CONSOLE};
    $con->con_issue_cmd("$cmd\n",
			$self->{ENAPROMPT},
			$self->{RELOAD_SCHEDULED}) or 
	$con->con_error();
    return($con->{RESULT});
}

# Send command to device or
# print to STDOUT if in compare mode.
sub cmd {
    my ($self, $cmd) = @_;

    if ( $self->{COMPARE} ) {
	mypr "> $cmd\n";
    }
    else {
	$self->device_cmd($cmd);
    }
}

# Send command to device, regardless of compare mode.
sub device_cmd {
    my ($self, $cmd) = @_;
    my $lines = $self->get_cmd_output($cmd);
    @$lines and $self->cmd_check_error($cmd, $lines);
}

sub shcmd {
    my ($self, $cmd) = @_;
    my $result = $self->issue_cmd($cmd);
    return($result->{BEFORE});
}

sub cmd_check_echo {
    my ($self, $cmd, $echo, $lines) = @_;
    if ($echo ne $cmd) {
	my $msg = "Got unexpected echo in response to '$cmd':\n'" .
	    join("\n", $echo, @$lines) ."'";
	$self->abort_cmd($msg);
    }
}

sub get_cmd_output {
    my ($self, $cmd) = @_;
    my $out = $self->shcmd($cmd);
    my $need_reload;
    $self->{RELOAD_SCHEDULED} and 
	$self->handle_reload_banner(\$out) and $need_reload = 1;
    my @lines = split(/\r?\n/, $out);
    my $echo = shift(@lines);
    $self->cmd_check_echo($cmd, $echo, \@lines);
    $need_reload and $self->schedule_reload(2);
    return(\@lines);
}

# Send 2 commands in one data packet to device.
sub two_cmd {
    my ($self, $cmd1, $cmd2) = @_;

    if ( $self->{COMPARE} ) {
	mypr "> $cmd1\\N $cmd2\n";
    }
    else {
	my $con = $self->{CONSOLE};
	$con->con_send_cmd("$cmd1\n$cmd2\n");
	my $prompt = $self->{ENAPROMPT};
	my $need_reload;

	# Read first prompt and check output of first command.
	$con->con_wait_prompt1($prompt) or $con->con_error();
	my $out = $con->{RESULT}->{BEFORE};
	$self->{RELOAD_SCHEDULED} and
	    $self->handle_reload_banner(\$out) and $need_reload = 1;
	my @lines1 = split(/\r?\n/, $out);
	my $echo = shift(@lines1);
	$self->cmd_check_echo($cmd1, $echo, \@lines1);

	# Read second prompt and check output of second command.
	$con->con_wait_prompt1($prompt) or $con->con_error();
	$out = $con->{RESULT}->{BEFORE};
	$self->{RELOAD_SCHEDULED} and
	    $self->handle_reload_banner(\$out) and $need_reload = 1;
	my @lines2 = split(/\r?\n/, $out);
	$echo = shift(@lines2);
	$self->cmd_check_echo($cmd2, $echo, \@lines2);

	$self->cmd_check_error("$cmd1\\N $cmd2\n", [ @lines1, @lines2 ]);
	$need_reload and $self->schedule_reload(2);
    }
}

sub abort_cmd {
    my ($self, $msg) = @_;
    $self->cancel_reload('force');
    errpr "$msg\n";
}

# Return 0 if no answer.
sub check_device {
    my ($self) = @_;
    for my $i (1 ..3) {
        my $result = `ping -q -w $i -c 1 $self->{IP}`;
	return $i if $result =~ /1 received/;
    }
    return 0;
}

sub approve {
    my ($self, $spoc_path) = @_;
    $self->{COMPARE} = undef;

    # set up console
    my $time = localtime();
    $self->con_setup("START: at > $time <");

    # prepare device for configuration
    $self->prepare();

    # Check for Netspoc message in device banner.
    $self->checkbanner();

    my $spoc_conf = $self->load_spoc($spoc_path);
    my $device_conf = $self->load_device();

    if ($self->transfer($device_conf, $spoc_conf)) {
        mypr "approve done\n";
    }
    else {
        errpr "approve failed\n";
    }
    $time = localtime();
    $self->con_shutdown("STOP: at > $time <");
}

sub get_change_status {
    my ($self) = @_;
    my $time = localtime();
    mypr "comp: $time\n";
    for my $key (sort keys %{$self->{CHANGE}}) {
	if($self->{CHANGE}->{$key}) { 
	    mypr "comp: $self->{NAME} *** $key changed ***\n";
	}
	else {
	    mypr "comp: $self->{NAME} $key unchanged\n";
	}
    }
    return(grep { $_ } values %{ $self->{CHANGE} });
}

sub compare {
    my ($self, $spoc_path) = @_;
    $self->{COMPARE} = 1;

    # set up console
    my $time = localtime();
    $self->con_setup("START: at > $time <");

    # prepare device for configuration
    $self->prepare();

    # check if Netspoc message in device banner
    $self->checkbanner();

    my $spoc_conf = $self->load_spoc($spoc_path);
    my $device_conf = $self->load_device();

    if ($self->transfer($device_conf, $spoc_conf)) {
        mypr "compare done\n";
    }
    else {
        errpr "compare failed\n";
    }

    $time = localtime();
    $self->con_shutdown("STOP: at > $time <");
    return($self->get_change_status());
}

sub compare_files {
    my ($self, $path1, $path2) = @_;
    $self->{COMPARE} = 1;

    my $conf1 = $self->load_spoc($path1);
    my $conf2 = $self->load_spoc($path2);

    if ($self->transfer($conf1, $conf2)) {
        mypr "compare done\n";
    }
    else {
        errpr "compare failed\n";
    }
    return($self->get_change_status());
}

sub logging {
    my $self = shift;
    my $logfile = $self->{OPTS}->{LOGFILE} or
        return;
    if ($logfile !~ /\A\//) {

        # $logfile given as relative path - extend to absolute path
        my $wd = `pwd`;
        chomp $wd;
        $logfile = "$wd/$logfile";
    }
    my $basename = basename($self->{OPTS}->{LOGFILE});
    $basename or die "No filename for logging specified\n";
    my $dirname = dirname($self->{OPTS}->{LOGFILE});

    # Create logdir
    if (not -d $dirname) {
        if (mkdir($dirname, 0755)) {
	    defined(chmod(0755, $dirname))
		or die "Couldn't chmod logdir $dirname: $!\n";
	}

	# Check -d again, because some other process may have created 
	# the directory in the meantime.
	elsif (not -d $dirname) {
	    die "Couldn't create $dirname: $!\n";
	}
    }
    my $appmode;
    if ($self->{OPTS}->{LOGAPPEND}) {
        $appmode = ">>";    # append
    }
    else {
        $appmode = ">";     # clobber
        if ($self->{OPTS}->{LOGVERSIONS}) {
            if (-f "$logfile") {
                my $date = time();
                system("mv $logfile $logfile.$date") == 0
                  or die "Could not backup $logfile: $!\n";
                $self->{OPTS}->{NOLOGMESSAGE}
                  or mypr "Existing logfile saved as '$logfile.$date'\n";
            }
        }
    }
    $self->{OPTS}->{NOLOGMESSAGE}
      or mypr "--- output redirected to $logfile\n";

    # Print the above message *before* redirecting!
    unless (-f $logfile) {
        (open(STDOUT, $appmode, $logfile))
          or die "Could not open $logfile: $!\n";
        defined chmod 0644, "$logfile"
          or die "Couldn't chmod $logfile: $!\n";
    }
    else {
        (open(STDOUT, $appmode, $logfile))
          or die "Could not open $logfile: $!\n";
    }
    (open(STDERR, ">&STDOUT"))
      or die "STDERR redirect: could not open $logfile: $!\n";
}

{

    # A closure, beause we need the lock in both functions.
    my $lock;

    sub lock( $$ ) {
        my ($self, $name) = @_;

        # set lock for exclusive approval
        my $lockfile = "$self->{CONFIG}->{LOCKFILEDIR}/$name";
        unless (-f "$lockfile") {
            open($lock->{$name}, '>', "$lockfile")
              or die "Could not aquire lock file $lockfile: $!\n";
            defined chmod 0666, "$lockfile"
              or die "Couldn't chmod lockfile $lockfile: $!\n";
        }
        else {
            open($lock->{$name}, '>', "$lockfile")
              or die "Could not aquire lock file $lockfile: $!\n";
        }
        unless (flock($lock->{$name}, LOCK_EX | LOCK_NB)) {
            mypr "$!\n";
            return 0;
        }
    }

    sub unlock( $$ ) {
        my ($self, $name) = @_;
        close($lock->{$name}) or die "could not unlock lockfile\n$!\n";
    }
}

1;
