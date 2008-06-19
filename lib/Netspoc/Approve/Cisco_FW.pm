
package Netspoc::Approve::Cisco_FW;

# Authors: Arne Spetzler, Heinz Knutzen, Daniel Brunkhorst
#
# Description:
# Base class for Cisco firewalls (ASA, PIX, FWSM)


'$Id$ ' =~ / (.+),v (.+?) /;

my $id = "$1 $2";

sub version_drc2_Firewall() {
    return $id;
}

use base "Netspoc::Approve::Cisco";
use strict;
use warnings;
use IO::Socket ();
use Netspoc::Approve::Helper;
use Netspoc::Approve::Parse_Cisco;

sub get_parse_info {
    my ($self) = @_;
    { 

#  global [(<ext_if_name>)] <nat_id>
#         {<global_ip>[-<global_ip>] [netmask <global_mask>]} | interface
#
	global => {
	    store => 'GLOBAL',
	    multi => 1,
	    parse => ['seq',
		      { store => 'EXT_IF_NAME', parse => \&get_paren_token },
		      { store => 'NAT_ID', parse => \&get_token },
		      ['or',
		       { store => 'INTERFACE', parse => qr/interface/ },
		       ['seq',
			{ store_multi => ['BEGIN', 'END'], 
			  parse => \&get_ip_pair },
			['seq',
			 { parse => qr/netmask/ },
			 { store => 'NETMASK', parse => \&get_ip } ]]]] },

# nat [(<real_ifc>)] <nat-id>
#     {<real_ip> [<mask>]} | {access-list <acl_name>}
#     [dns] [norandomseq] [outside] [<max_conn> [<emb_limit>]] 
	nat => {
	    store => 'NAT',
	    multi => 1,
	    parse => ['seq',
		      { store => 'IF_NAME', parse => \&get_paren_token },
		      { store => 'NAT_ID', parse => \&get_token },
		      ['or',
		       ['seq',
			{ parse => qr/access-list/ },
			{ store => 'ACCESS_LIST', parse => \&get_token } ],
		       ['seq',
			{ store => 'BASE', parse => \&get_ip },
			{ store => 'MASK', parse => \&get_ip } ]],
		      { store => 'DNS', parse => qr/dns/ },
		      { store => 'OUTSIDE', parse => qr/outside/ },
		      ['seq',
		       { store => 'MAX_CONS', 
			 parse => \&check_int,
			 default => 0 },
		       { store => 'EMB_LIMIT', 
			 parse => \&check_int,
			 default => 0 } ],
		      { store => 'NORANDOMSEQ', parse => qr/norandomseq/ } ] },
# static [(local_ifc,global_ifc)] {global_ip | interface} 
#        {local_ip [netmask mask] | access-list acl_name} 
#        [dns] [norandomseq] [max_conns [emb_limit]]
# static [(local_ifc,global_ifc)] {tcp | udp} {global_ip | interface} 
#        global_port 
#        {local_ip local_port [netmask mask] | access-list acl_name}
#        [dns] [norandomseq] [max_conns [emb_limit]]
	static => {
	    store => 'STATIC',
	    multi => 1,
	    parse => ['seq',
		      { store_multi => ['LOCAL_IF', 'GLOBAL_IF'], 
			parse => \&get_paren_token },
		      { store => 'TYPE', 
			parse => qr/tcp|udp/, default => 'ip' },
		      ['or',
		       { store => 'INTERFACE', parse => qr/interface/ },
		       { store => 'GLOBAL_IP', parse => \&get_ip } ],
		      ['seq',
		       { parse => \&test_ne, params => ['ip', '$TYPE'] },
		       { store => 'GLOBAL_PORT', 
			 parse => 'parse_port', params => ['$TYPE'] } ],
		      ['or',
		       ['seq',
			{ parse => qr/interface/ },
			{ store => 'ACCESS_LIST', parse => \&get_token },
			{ store => 'DNS', parse => qr/dns/ } ],
		       ['seq',
			{ store => 'LOCAL_IP', parse => \&get_ip },
			['seq',
			 { parse => \&test_ne, params => ['ip', '$TYPE'] },
			 { store => 'LOCAL_PORT', 
			   parse => 'parse_port', params => ['$TYPE'] } ],
			{ store => 'DNS', parse => qr/dns/ },
			['seq',
			 { parse => qr/netmask/ },
			 { store => 'NETMASK', 
			   parse => \&get_ip, 
			   default => 0xffffffff } ]]],
		      ['seq',
		       { store => 'MAX_CONS', 
			 parse => \&check_int,
			 default => 0 },
		       { store => 'EMB_LIMIT', 
			 parse => \&check_int,
			 default => 0 } ],
		      { store => 'NORANDOMSEQ', parse => qr/norandomseq/ } ],
	},

# route if_name ip_address netmask gateway_ip [metric]
	route => {
	    store => 'ROUTING',
	    multi => 1,
	    parse => ['seq',
		      { store => 'IF', parse => \&get_token },
		      { store => 'BASE', parse => \&get_ip },
		      { store => 'MASK', parse => \&get_ip },
		      { store => 'NEXTHOP', parse => \&get_ip },
		      { store => 'METRIC', 
			parse => \&check_int, 
			default => 1 } ],
	},

# access-group <access_list_name> in interface <if_name>
	'access-group' => {
	    store =>'ACCESS_GROUP',
	    named => 1,
	    parse => ['seq',
		      { parse => qr/in/ },
		      { parse => qr/interface/ },
		      { store => 'IF_NAME', parse => \&get_token } ],
	},
	'object-group' => {
	    store => 'OBJECT_GROUP',
	    named => 'from_parser',
	    parse => ['seq',
		      { store => 'TYPE', parse => qr/network/ },
		      { store => 'name', parse => \&get_token } ],
	    subcmd => {
		'network-object' => {
		    store => 'NETWORK_OBJECT', 
		    multi => 1,
		    parse => 'parse_address',
		},
		'group-object' => { 
		    error => 'Nested object group not supported' },
	    }
	},

# access-list deny-flow-max n
# access-list alert-interval secs
# access-list [id] compiled
# access-list id [line line-num] remark text
# access-list id [line line-num] {deny  | permit }
#  {protocol | object-group protocol_obj_grp_id}
#  {source_addr | local_addr} {source_mask | local_mask} 
#  | object-group network_obj_grp_id
#  [operator port [port] | interface if_name | object-group service_obj_grp_id]
#  {destination_addr | remote_addr} {destination_mask | remote_mask} 
#  | object-group network_obj_grp_id 
#  [operator port [port] | object-group service_obj_grp_id]} 
#  [log [[disable | default] | [level] [interval secs]]
# access-list id [line line-num] {deny  | permit } 
#  icmp  {source_addr | local_addr} {source_mask | local_mask} 
#  | interface if_name | object-group network_obj_grp_id 
#  {destination_addr | remote_addr} {destination_mask | remote_mask} 
#  | interface if_name | object-group network_obj_grp_id 
#  [icmp_type | object-group icmp_type_obj_grp_id] 
#  [log [[disable | default] | [level] [interval secs]]
	'access-list' => {
	    store => 'ACCESS_LIST', 
	    multi => 1,
	    named => 'from_parser',
	    parse => 
		['or',
		 { parse => qr/compiled/ },
		 ['seq',
		  { parse => qr/deny-flow-max|alert-interval/ },
		  { parse => \&get_int } ],
		 ['seq',
		  { store => 'name', parse => \&get_token },
		  ['or',

		   # ignore 'access-list <name> compiled'
		   { parse => qr/compiled/ },
		   ['seq',
		    { parse => qr/remark/ },
		    { parse => \&skip } ],
		   ['seq',
		    { parse => qr/extended/, default => 1 },
		    { store => 'MODE', parse => qr/permit|deny/ },
		    ['or',
		     ['seq',
		      { parse => qr/object-group/ },
		      { error => '"object-group" as proto is unsupported' } ],
		     ['seq',
		      { store => 'TYPE', parse => qr/ip/ },
		      { store => 'SRC', parse => 'parse_address' },
		      { store => 'DST', parse => 'parse_address' } ],,
		     ['seq',
		      { store => 'TYPE', parse => qr/udp|tcp/ },
		      { store => 'SRC', parse => 'parse_address' },
		      { store => 'SRC_PORT', 
			parse => 'parse_port_spec', params => ['$TYPE'] },
		      { store => 'DST', parse => 'parse_address' },
		      { store => 'DST_PORT', 
			parse => 'parse_port_spec', params => ['$TYPE'] } ],
		     ['seq',
		      { store => 'TYPE', parse => qr/icmp/ },
		      { store => 'SRC', parse => 'parse_address' },
		      { store => 'DST', parse => 'parse_address' },
		      { store => 'SPEC', parse => 'parse_icmp_spec' }, ],
		     ['seq',
		      { store => 'TYPE', parse => \&get_token },
		      { store => 'TYPE' ,
			parse => 'normalize_proto', params => [ '$TYPE' ] },
		      { store => 'SRC', parse => 'parse_address' },
		      { store => 'DST', parse => 'parse_address' } ]],
		    ['seq',
		     { store => 'LOG', parse => qr/log/ },
		     ['or',
		      { store => 'LOG_MODE', parse => qr/disable|default/ },
		      ['seq',
		       { store => 'LOG_LEVEL', 
			 parse => \&check_int, default => 6 },
		       ['seq',
			{ parse => qr/interval/ },
			{ store => 'LOG_INTERVAL', 
			  parse => \&check_int } ]]]]]]]]
	},

# crypto map map-name seq-num match address acl_name
	'crypto map' => {
	    store => ['CRYPTO', 'MAP'],
	    named => 1,
	    multi => 1,
	    parse => ['seq',
		      { store => 'SEQU', parse => \&get_int, },
		      ['or',
		       ['seq',
			{ parse => qr/match/ },
			{ parse => qr/address/ },
			{ store => 'MATCH_ADDRESS', parse => \&get_token } ],
		       { parse => \&skip } ]] 
	},
    }
}

sub dev_cor ($$) {
    my ($self, $addr) = @_;
    return $addr;
}

sub parse_address {
    my ($self, $arg) = @_;

    if(check_regex('object-group', $arg)) {
	my $result;
	$result->{OBJECT_GROUP} = get_token($arg);
	return $result;
    }
    else {
	return $self->SUPER::parse_address($arg);
    }
}


# This is for raw processing: we want to kick out the netspoc static,
# if the raw entry covers the netspoc entry totally.
#        - used to overwrite netspoc generated statics
#
# possible results:
#        0 - no match
#        1 -  match or inclusion
#        2 -  match with intersection
#        3 -  warning
#
# ToDo: Handle all attributes.
sub static_global_local_match_a_b( $$$ ) {
    my ($self, $a, $b) = @_;
    my $result = 0;
    $a->{LOCAL_IF} eq $b->{LOCAL_IF} and $a->{GLOBAL_IF} eq $b->{GLOBAL_IF}
      or return 0;

    for my $k (qw(INTERFACE ACCESS_LIST)) {
	next if defined $a->{$k} xor defined $b->{$k};
	next if not defined $a->{$k};
	$a->{$k} eq $b->{$k} or return 3;
    }

    # Default value has been set to 0xffffffff by parser.
    my $a_addr = { MASK => $a->{NETMASK} };
    my $b_addr = { MASK => $b->{NETMASK} };

    for my $key (qw(LOCAL_IP GLOBAL_IP)) {
	$a_addr->{BASE} = $a->{$key};
	$b_addr->{BASE} = $b->{$key};
	$result = $self->ip_netz_a_in_b($a_addr, $b_addr) and return $result;
    }
    return $result;
}

sub attr_eq( $$$ ) {
    my ($self, $a, $b) = @_;
    keys %$a == keys %$b or return 0;
    for my $k (keys %$a) {
	next if $k eq 'orig';
	return 0 if defined $a->{$k} xor defined $b->{$k};
	next if not defined $a->{$k};
	$a->{$k} eq $b->{$k} or return 0;
    }
    return 1;
}

##############################################################
# issue command
##############################################################
sub cmd_check_error($$) {
    my ($self, $out) = @_;

    # do ERROR if unexpected line appears
    if (my($msg) = $$out =~ /\n(.+)$/m) {
        #### hack start ###
        ($msg =~ /\[OK\]/m) and return 1;    ### for write memory
        ($msg =~ /will be identity translated for outbound/)
          and return 1;                       # identity nat
        ($msg =~ /nat 0 0.0.0.0 will be non-translated/)
          and return 1;                       # identity nat
        ($msg =~ /Global \d+\.\d+\.\d+\.\d+ will be Port Address Translated/)
          and return 1;                       # PAT
        if ($msg =~ /(
		      # overlapping statics from netspoc
		      overlapped\/redundant |
		      # overlapping statics with global from netspoc
		      static[ ]overlaps |
		      # route warnings
		      Route[ ]already[ ]exists |
		      # ace warnings
		      ACE[ ]not[ ]added[.][ ]Possible[ ]duplicate[ ]entry)/x) {
            my @pre = split(/\n/, $msg);
            for my $line (@pre) {
                warnpr $line, "\n";
            }
            return 1;
        }
        ### hack end ###
        my @pre = split(/\n/, $msg);
        for my $line (@pre) {
            errpr_info "+++ ", $line, "\n";
        }
        errpr "+++\n";
        return 0;
    }
    return 1;
}

#
#    *** some checking ***
#
sub checkinterfaces($$$) {
    my ($self, $devconf, $spocconf) = @_;
    mypr " === check for unknown or missconfigured interfaces at device ===\n";
    for my $intf (sort keys %{ $devconf->{IF} }) {
        next if ($devconf->{IF}->{$intf}->{SHUTDOWN});
        if (not $spocconf->{IF}->{$intf}) {
            warnpr "unknown interface detected: $intf\n";
        }
    }
    mypr " === done ===\n";
}

sub check_firewall {
    my ($self, $conf) = @_; 

    # NoOp
    # ToDo: check for active fixup
}

sub schedule_reload {
    my ($self, $minutes) = @_;

    # No op; not implemented for Cisco firewall products.
}

sub cancel_reload {
    my ($self) = @_;

    # No op; not implemented for Cisco firewall products.
}

#######################################################
# telnet login, check name and set convenient options
#######################################################
sub prepare {
    my ($self) = @_;
    $self->SUPER::prepare();

    # Check pager settings.
    my $output = $self->shcmd('sh pager');
    if ($output !~ /no pager/) {
	$self->set_pager();
    }
    mypr "---\n";
    $output = $self->shcmd('sh ver');
    if($output =~ /Version +(\d+\.\d+)/i) {	
	$self->{VERSION} = $1;
    }
    else {
	errpr "Could not identify version number from 'sh ver'\n";
    }
    if($output =~ /Hardware:\s+(\S+),/i) {	
	$self->{HARDWARE} = $1;
    }
    else {
	warnpr "could not identify hardware type from 'sh ver'\n";
	$self->{HARDWARE} = 'unknown';
    }
    mypr "-----------------------------------------------------------\n";
    mypr " DINFO: $self->{HARDWARE} $self->{VERSION}\n";
    mypr "-----------------------------------------------------------\n";

    # Max. term width is 511 for PIX.
    $output = $self->shcmd('sh term');
    if ($output !~ /511/) {

        if ($self->{VERSION} >= 6.3) {

            # Only warn. Otherwise the generated configure message 
	    # triggers IDS at night.
            warnpr "Terminal width should be 511\n";
        }
        else {
            $self->cmd('term width 511');
        }
    }
}

sub get_config_from_device( $ ) {
    my ($self) = @_;
    my $cmd = 'write term';
    my $output = $self->shcmd($cmd);
    my @conf = split(/\r\n/, $output);
    my $echo = shift(@conf);
    $echo =~ /^\s*$cmd\s*$/ or 
	errpr "Got unexpected echo in response to '$cmd': '$echo'\n";
    return(\@conf);
}

##############################################################
# rawdata processing
##############################################################
sub merge_rawdata {
    my ($self, $spoc_conf, $raw_conf) = @_;

    # Routing
    $self->SUPER::merge_rawdata($spoc_conf, $raw_conf);

    # access-list 
    keys %{$raw_conf->{OBJECT_GROUP}} and 
	errpr "Raw config must not use object-groups\n";
    $self->merge_acls($spoc_conf, $raw_conf, 'ACCESS_LIST');

    #static 
    my @std_static = ();
    if ($raw_conf->{STATIC}) {
	my @remove = ();
	for my $s (@{ $raw_conf->{STATIC} }) {
	    my $covered = 0;
	    for (my $i = 0 ; $i < scalar @{ $spoc_conf->{STATIC} } ; $i++) {
		my $spoc  = $spoc_conf->{STATIC}[$i];
		my $match = 0;
		if ($self->attr_eq($spoc, $s)) {
		    warnpr "RAW: ignoring useless: '$s->{orig}'\n";
		    $covered = 1;
		}
		elsif ($match =
		       $self->static_global_local_match_a_b($spoc, $s))
		{
		    unless ($match == 3) {
			mypr "RAW: spoc static \'",
			$spoc->{orig},
			" replaced by \'",
			$s->{orig}, "\'\n";
			push @remove, $i;
		    }
		    else {
			warnpr "RAW: weired match RAW: \'",
			$s->{orig}, "\'\n";
			warnpr "RAW: weired match SPOC: \'",
			$spoc->{orig}, "\'\n";
			warnpr "RAW: static discarded!\n";
			$covered = 1;
		    }
		}
	    }
	    $covered or push @std_static, $s;
	}
	for my $r (reverse sort @remove) {
	    splice @{ $spoc_conf->{STATIC} }, $r, 1;
	}
	@{ $spoc_conf->{STATIC} } = (@{ $spoc_conf->{STATIC} }, @std_static),
	mypr " attached static entries: " . scalar @std_static . "\n";
    }

    # global + nat 
    for my $x (qw(GLOBAL NAT)) {
	my $raw_x = $raw_conf->{$x} or next;
	my @add = ();
	for my $raw (@$raw_x) {
	    my $covered = 0;
	    for my $spoc (@{ $spoc_conf->{$x} }) {
		if ($self->attr_eq($spoc, $raw)) {
		    warnpr "RAW: ignoring useless: '$raw->{orig}'\n";
		    $covered = 1;
		}
	    }
	    $covered or push @add, $raw;
	}
	push(@{ $spoc_conf->{$x} }, @add);
	mypr " attached $x entries: " . scalar @add . "\n";
    }
}


# Supports only object-group type 'network', no nested groups.
sub expand_acl_entry($$$$) {
    my ($self, $ace, $parsed, $acl_name, $adr) = @_;

    my $groups = $parsed->{OBJECT_GROUP};
    my $replace;
    my @expanded;
    for my $adr ('SRC', 'DST') {
	if (my $obj_id = $ace->{$adr}->{OBJECT_GROUP}) {
	    my $group = $groups->{$obj_id} or
		errpr meself(1), "no group name '$obj_id' found\n";
	    $group->{TYPE} eq 'network' or
		errpr meself(1),
		"unsupported object type '$group->{TYPE}'\n";
	    
	    $replace->{$adr} = 
		[ "object-group $obj_id", $group->{NETWORK_OBJECT} ];

            # Remember that group $obj_id is referenced by ACL $acl 
	    # and vice versa.
            $parsed->{group2acl}->{$obj_id}->{$acl_name} = 1;
            $parsed->{acl2group}->{$acl_name}->{$obj_id} = 1;
        }
        else {
            $replace->{$adr} = [ undef, [$ace->{$adr}] ];
        }
    }
    my($src_find, $src_aref) = @{ $replace->{SRC} };
    my($dst_find, $dst_aref) = @{ $replace->{DST} };
    for my $src (@$src_aref) {
        for my $dst (@$dst_aref) {
            my $copy = { %$ace };
            $copy->{SRC} = $src;
            $copy->{DST} = $dst;

	    # Construct a printable version of expanded ACE.
	    if($src_find) {
		my $src_replace = $src->{orig};
		$src_replace =~ s/network-object//;
		$copy->{orig} =~ s/$src_find(?!\S)/$src_replace/;
	    }
	    if($dst_find) {
		my $dst_replace = $dst->{orig};
		$dst_replace =~ s/network-object//;
		$copy->{orig} =~ s/$dst_find(?!\S)/$dst_replace/;
	    }

	    # Remove 'access-list <name>' because we don't need this info
	    # when printing during ACL compare.
	    $copy->{orig} =~ s/^access-list\s+\S+\s+(extended\s+)?//;
            push @expanded, $copy;
        }
    }
    return \@expanded;
}

sub postprocess_config {
    my ($self, $p) = @_;

    # Expand object-groups in access-lists.
    for my $acl_name (keys %{ $p->{ACCESS_LIST} }) {
        my %seen_acl;
        for my $entry (@{ $p->{ACCESS_LIST}->{$acl_name} }) {
            my $e_acl = $self->expand_acl_entry($entry, $p, $acl_name);
	    push @{$p->{ACCESS}->{$acl_name}},@$e_acl;
        }
    }

    # access-group
    for my $acl_name (keys %{ $p->{ACCESS_GROUP} }) {
        my $if_name = $p->{ACCESS_GROUP}->{$acl_name}->{IF_NAME};
        $p->{IF}->{$if_name}->{ACCESS} = $acl_name;
        if (my $acl = $p->{ACCESS_LIST}->{$acl_name}) {
	    $p->{is_filter_acl}->{$acl_name} = 1;
        }
    }

    for my $if (sort keys %{ $p->{IF} }) {
	my $entry = $p->{IF}->{$if};
        if ($entry->{SHUTDOWN}) {
            mypr meself(1) . "Interface $if: shutdown\n";
        }
        else {
            if (my $base = $entry->{BASE}) {
		mypr meself(1)
		    . "Interface $if: IP: "
		    . int2quad($base) . "/"
		    . int2quad($entry->{MASK}) . "\n";
	    }
	}
    }

    # crypto maps
    for my $aref (values %{ $p->{CRYPTO}->{MAP} }) {
        for my $entry (@$aref) {
            if (my $acl_name = $entry->{MATCH_ADDRESS}) {
                if ($p->{ACCESS_LIST}->{$acl_name}) {
		    $p->{is_crypto_acl}->{$acl_name} = 1;
                }
                else {
                    warnpr "crypto map $entry->{name} references" 
			. " unknown acl $acl_name\n";
                }
            }
        }
    }
    mypr meself(1)
      . ": CRYPTO MAPS found: "
      . scalar(keys %{ $p->{CRYPTO}->{MAP} }) . "\n";

    #
    # ****** TO DO: more consistency checking
    #
    mypr meself(1)
      . ": OBJECT GROUPS found: "
      . scalar(keys %{ $p->{OBJECT_GROUP} }) . "\n";
    mypr meself(1)
      . ": ACCESS LISTS found: "
      . scalar(keys %{ $p->{ACCESS_LIST} }) . "\n";
    my $c_acl_counter = 0;
    for my $acl_name (sort keys %{ $p->{ACCESS_LIST} }) {
        if ($p->{is_crypto_acl}->{$acl_name}) {
            $c_acl_counter++;
        }
        elsif ($p->{is_filter_acl}->{$acl_name}) {
            mypr meself(1)
              . ": $acl_name "
              . scalar @{ $p->{ACCESS_LIST}->{$acl_name} } . "\n";
        }
        else {
            mypr meself(1)
              . ": $acl_name "
              . scalar @{ $p->{ACCESS_LIST}->{$acl_name} }
              . " *** SPARE ***\n";
        }
    }
    ($c_acl_counter)
      and mypr "--> found $c_acl_counter acls referenced by crypto maps\n";
    for my $what (qw(GLOBAL NAT STATIC ROUTING)) {
	next if not $p->{$what};
	mypr meself(1) . ": $what found: " . scalar @{ $p->{$what} } . "\n";
    }
}

sub transfer_lines {
    my ($self, $spoc_lines, $device_lines) = @_;
    my $counter;
    my $change = 0;
    $spoc_lines ||= [];
    $device_lines ||= [];
    mypr "compare device entries with netspoc:\n";
    scalar @{$device_lines} or mypr "-";
    for my $d (@{$device_lines}) {    # from device
        $counter++;
        mypr " $counter";
        for my $s (@{$spoc_lines}) {    # from netspoc
                                        #($s) or next;
            if ($self->attr_eq($d, $s)) {
                $d->{DELETE} = $s->{DELETE} = 1;
                last;
            }
        }
    }
    mypr "\n";
    unless ($self->{COMPARE}) {
        mypr "deleting non matching entries from device:\n";
        $counter = 0;
	$self->cmd('configure terminal');
        for my $d (@{$device_lines}) {
            ($d->{DELETE}) and next;
            $counter++;
            my $tr = join(' ', "no", $d->{orig});
            $self->cmd($tr);
            mypr " $counter";
        }
        $counter and $change = 1;
        mypr " $counter\n";
        mypr "transfer entries to device:\n";
        $counter = 0;
        for my $s (@{$spoc_lines}) {
            ($s->{DELETE}) and next;
            $counter++;
            $self->cmd($s->{orig});
            mypr " $counter";
        }
	$self->cmd('end');
        $counter and $change = 1;
        mypr " $counter\n";
    }
    else {

        # show compare results
        mypr "non matching entries on device:\n";
        $counter = 0;
        for my $d (@{$device_lines}) {
            ($d->{DELETE}) and next;
            $counter++;
            mypr $d->{orig} . "\n";
        }
        mypr "total: " . $counter, "\n";
        ($counter) and $change = 1;
        mypr "additional entries from spoc:\n";
        $counter = 0;
        for my $s (@{$spoc_lines}) {
            ($s->{DELETE}) and next;
            $counter++;
            mypr $s->{orig}, "\n";
        }
        mypr "total: ", $counter, "\n";
        ($counter) and $change = 1;
    }
    return $change;
}

sub acls_identical {
    my ($self, $confacl, $spocacl, $intf) = @_;
    mypr "check for textual identity\n";
    if (@$spocacl != @$confacl) {
        mypr "lenght of acls differ: at device ", scalar @{$confacl},
          " from netspoc ", scalar @{$spocacl}, "\n";
        return 0;
    }
    mypr " acls have equal lenght: ", scalar @$spocacl, "\n";
    mypr " compare line by line: ";
    for (my $i = 0 ; $i < scalar @{$spocacl} ; $i++) {
	if ($self->acl_line_a_eq_b($$spocacl[$i], $$confacl[$i])) {
	    next;
	}
	else {
	    mypr "equal lenght acls (", scalar @{$spocacl}, ") differ at ",
	    ++$i, "!\n";
	    return 0;
	}
    }
    mypr "no diffs\n";

    if ($self->{COMPARE}) {

        # show compare results
        mypr "#### BEGIN NEW in OLD - interface $intf\n";
        my $newinold =
          $self->acl_array_compare_a_in_b($spocacl, $confacl);
        mypr "#### END   NEW in OLD - interface $intf\n";
        mypr "#### BEGIN OLD in NEW - interface $intf\n";
        my $oldinnew =
          $self->acl_array_compare_a_in_b($confacl, $spocacl);
        mypr "#### END   OLD in NEW - interface $intf\n";
        if ($newinold && $oldinnew) {
            mypr "#### ACLs equal for interface $intf\n";
            return 1;
        }
        else {
            mypr "#### ACLs differ - at interface $intf ####\n";
            return 0;
        }
    }
    else {
        mypr "  do semantic compare - at interface $intf:\n";
        if (
            $self->acl_array_compare_a_in_b($spocacl, $confacl)  
            && $self->acl_array_compare_a_in_b($confacl, $spocacl)
          )
        {
            mypr "   -> interface $intf: acls identical\n";
            return 1;
        }
        else {
            mypr "   -> interface $intf: acls differ\n";
            return 0;
        }
    }
}

sub transfer () {
    my ($self, $conf, $spoc_conf) = @_;

    $self->process_routing($conf, $spoc_conf) or return 0;

    #
    # *** access-lists ***
    #
    my $get_acl_names_and_objects = sub {
        my ($intf)  = @_;
        my $sa_name = $spoc_conf->{IF}->{$intf}->{ACCESS};
        my $spocacl = $spoc_conf->{ACCESS}->{$sa_name};
        my $ca_name = $conf->{IF}->{$intf}->{ACCESS} || '';
        my $confacl = $ca_name ? $conf->{ACCESS}->{$ca_name} : '';
        return ($confacl, $spocacl, $ca_name, $sa_name);
    };

    # generate new names for transfer
    #
    # possible names are (per name convention):  <spoc-name>-DRC-<index>
    #
    my $generate_names_for_transfer = sub {
        my ($obj_id, $objects) = @_;
        my $new_id_prefix = "$obj_id-DRC-";
        my $new_id_index  = 0;
        while ($objects->{"$new_id_prefix$new_id_index"}) {
            $new_id_index++;
        }
        return "$new_id_prefix$new_id_index";
    };

    my %acl_need_transfer;
    my %group_need_transfer;

    my $mark_for_transfer;
    $mark_for_transfer = sub {
        my ($acl_name) = @_;
	return if $acl_need_transfer{$acl_name};
	$acl_need_transfer{$acl_name} = 1;
        mypr "marked acl $acl_name for transfer\n";
        for my $gid (keys %{ $spoc_conf->{acl2group}->{$acl_name} }) {
            unless ($group_need_transfer{$gid}) {
                $group_need_transfer{$gid} = 1;
                print "marked group $gid for transfer\n";
            }
            for my $name (keys %{ $spoc_conf->{group2acl}->{$gid} }) {
                &$mark_for_transfer($name);
            }
        }
    };

    my %acl_need_remove;
    my %group_need_remove;

    my $mark_for_remove = sub {
        my ($acl_name) = @_;
	$acl_need_remove{$acl_name} and errpr "unexpected REMOVE mark\n";
        $acl_need_remove{$acl_name} = 1;
        mypr "marked acl $acl_name for remove\n";
        for my $gid (keys %{ $conf->{acl2group}->{$acl_name} }) {
            next if $group_need_remove{$gid};
            my $remove_group = 1;
            for my $name (keys %{ $conf->{group2acl}->{$gid} }) {

                # Only remove group from PIX if all ACLs that reference
                # this group are renewed by netspoc.
                if(not $acl_need_transfer{$name}) {
                    $remove_group = 0;
                    last;
                }
            }
            if ($remove_group) {
                $group_need_remove{$gid} = 1;
                mypr "marked group $gid for remove\n";
            }
        }
    };
    unless ($spoc_conf->{IF}) {
        warnpr " no interfaces specified - leaving access-lists untouched\n";
    }
    else {
        mypr "processing access-lists\n";
	$self->{CHANGE}->{ACL} = 0;
        for my $intf (keys %{ $spoc_conf->{IF} }) {
            $conf->{IF}->{$intf} or
                errpr 
		"netspoc configured interface '$intf' not found on device\n";
	}

        # detect diffs
        if ($self->{COMPARE}) {
            for my $intf (keys %{ $spoc_conf->{IF} }) {
                mypr "interface $intf\n";
                my ($confacl, $spocacl, $confacl_name, $spocacl_name) =
                  &$get_acl_names_and_objects($intf);

                if ($confacl_name && $confacl) {
                    $self->acl_equal($confacl, $spocacl, 
				     $confacl_name, $spocacl_name, 
				     "interface $intf")
                        or $self->{CHANGE}->{ACL} = 1;
                }
                else {

                    $self->{CHANGE}->{ACL} = 1;
                    mypr "#### OOPS:  $spocacl_name at interface $intf:\n";
                    mypr "#### OOPS:  no corresponding acl on device\n";
                }
                mypr "-------------------------------------------------\n";
            }
        }
        else {

            # mark objects to transfer
            for my $intf (keys %{ $spoc_conf->{IF} }) {
                mypr "interface $intf\n";
                my ($confacl, $spocacl, $confacl_name, $spocacl_name) =
                  &$get_acl_names_and_objects($intf);
                if ($acl_need_transfer{$spocacl_name}) {
                    mypr " ...already marked for transfer\n";
                    next;
                }
                if (!$confacl) {
                    warnpr "interface $intf no acl on device - new acl has ",
                      scalar @{ $spoc_conf->{ACCESS}->{$spocacl_name} },
                      " entries\n";
                    $self->{CHANGE}->{ACL} = 1;
                    &$mark_for_transfer($spocacl_name);
                }
                elsif (not $self->acl_equal($confacl, $spocacl, 
					    $confacl_name, $spocacl_name, 
					    "interface $intf"))
                {

                    # Either there is no acl on $intf or the acl differs.
                    # Mark groups and interfaces recursive for transfer 
		    # of spocacls
                    $self->{CHANGE}->{ACL} = 1;
                    &$mark_for_transfer($spocacl_name);
                }
                elsif ($self->{FORCE_TRANSFER}) {
                    warnpr "Interface $intf: transfer of ACL forced!\n";
                    $self->{CHANGE}->{ACL} = 1;
                    &$mark_for_transfer($spocacl_name);
                }
                mypr "-------------------------------------------------\n";
            }

            # Mark objects for removal.
            for my $intf (keys %{ $spoc_conf->{IF} }) {
                my ($confacl, $spocacl, $confacl_name, $spocacl_name) =
                  &$get_acl_names_and_objects($intf);
                next if not $acl_need_transfer{$spocacl_name};
                $confacl and $mark_for_remove->($confacl_name);
            }

            # Generate names for transfer.
	    my %new_group_id;
	    my %new_acl_name;
            for my $obj_id (keys %{ $spoc_conf->{OBJECT_GROUP} }) {
                next if not $group_need_transfer{$obj_id};
                $new_group_id{$obj_id} =
                  $generate_names_for_transfer->($obj_id, $conf->{OBJECT_GROUP});
            }
            for my $obj_id (keys %{ $spoc_conf->{ACCESS_LIST} }) {
                next if not $acl_need_transfer{$obj_id};
		$new_acl_name{$obj_id} =
                  $generate_names_for_transfer->($obj_id, $conf->{ACCESS_LIST});
            }

	    $self->cmd('configure terminal');

            # Transfer groups.
            mypr "transfer object-groups to device\n";
            for my $obj_id (keys %{ $spoc_conf->{OBJECT_GROUP} }) {
		my $group = $spoc_conf->{OBJECT_GROUP}->{$obj_id};
                next if not $group_need_transfer{$obj_id};
		my $new_id = $new_group_id{$obj_id};
		my $cmd = "object-group $group->{TYPE} $new_id";
                mypr " $cmd\n";
		$self->cmd($cmd);
		map({ $self->cmd($_->{orig}) } @{ $group->{NETWORK_OBJECT} });
		$self->cmd('exit');
            }

            # Transfer ACLs.
            mypr "transfer access-lists to device\n";
            for my $obj_id (keys %{ $spoc_conf->{ACCESS_LIST} }) {
                next if not $acl_need_transfer{$obj_id};
                my $new_id = $new_acl_name{$obj_id};
                mypr "access-list $new_id\n";
                for my $ace (@{ $spoc_conf->{ACCESS_LIST}->{$obj_id} }) {
		    my $cmd = $ace->{orig};
		    for my $where (qw(SRC DST)) {
			if (my $gid = $ace->{$where}->{OBJECT_GROUP}) {
			    my $new_gid = $new_group_id{$gid};
			    $cmd =~ 
				s/object-group $gid(?!\S)/object-group $new_gid/;
			}
		    }
		    $cmd =~ s/access-list $obj_id/access-list $new_id/;
                    $self->cmd($cmd);
                }
                mypr "\n";

                # Assign list to interface.
                my $intf = $spoc_conf->{ACCESS_GROUP}->{$obj_id}->{IF_NAME};
                mypr "access-group $new_id in interface $intf\n";
                $self->cmd("access-group $new_id in interface $intf");
            }

            # Remove ACLs.
	    # Do it first, because otherwise group remove would not work.
            mypr "remove spare acls from device\n";
            for my $acl_name (keys %{ $conf->{ACCESS_LIST} }) {
                if (    $acl_need_remove{$acl_name}
		    or (    not $conf->{is_filter_acl}->{$acl_name}
		        and not $conf->{is_crypto_acl}->{$acl_name}))
                {
		    my $cmd = ($self->{VERSION} >= 7.0) 
  			    ? "clear configure access-list $acl_name"
			    : "no access-list $acl_name";
		    mypr " $cmd\n";
                        $self->cmd($cmd);
                }
            }

            # Remove groups.
            mypr "remove spare object-groups from device\n";
            for my $gid (keys %{ $conf->{OBJECT_GROUP} }) {
                my $type = $conf->{OBJECT_GROUP}->{$gid}->{TYPE};
                if (   $group_need_remove{$gid}
		    or not $conf->{group2acl}->{$gid})
                {
		    my $cmd = "no object-group $type $gid";
                    mypr " $cmd\n";
                    $self->cmd($cmd);
                }
            }
	    $self->cmd('end');
        }
    }

    # STATIC, GLOBAL, NAT
    for my $type (qw(STATIC GLOBAL NAT)) {
	mypr " === processing $type ===\n";
	$self->{CHANGE}->{$type} = 0;
	$self->transfer_lines($spoc_conf->{$type}, $conf->{$type}) and 
	    $self->{CHANGE}->{$type} = 1;
    }

    if (not $self->{COMPARE}) {
        if (grep { $_ } values %{ $self->{CHANGE} })
        {
            mypr "saving config to flash\n";
            $self->cmd('write memory');
            mypr "...done\n";
        }
        else {
            mypr "no changes to save\n";
        }
    }
    else {
        mypr "compare finish\n";
    }
    return 1;
}

# Packages must return a true value;
1;

