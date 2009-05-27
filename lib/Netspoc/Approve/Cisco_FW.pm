
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


# Global variables.
my %connected;
my %transfered2orig;
my %acl_transfered_as;
my %acl_needed;
my %acl_need_transfer;
my %acl_need_remove;
my %new_name;
my %attr_with_value = (
		       'banner'                    => 1,
		       'vpn-filter'                => 1,
		       'address-pools'             => 1,
		       'split-tunnel-network-list' => 1,
		       );

my %tunnel_group_ipsec = (
			  'isakmp'           => 1,
			  'peer-id-validate' => 1,
			  'trust-point'      => 1,
			  );

my %define_object = (
		     TUNNEL_GROUP => {
			 prefix  => 'tunnel-group',
			 postfix => 'type remote-access',
		     },
		     GROUP_POLICY => {
			 prefix  => 'group-policy',
			 postfix => 'internal',
		     },
		     USERNAME => {
			 prefix  => 'username',
			 postfix => 'nopassword',
		     },
		     );

my %conf_mode_entry = (
		       TUNNEL_GROUP => {
			   prefix  => 'tunnel-group',
			   postfix => 'general-attributes',
		       },
		       TUNNEL_GROUP_IPSEC => {
			   prefix  => 'tunnel-group',
			   postfix => 'ipsec-attributes',
		       },
		       GROUP_POLICY => {
			   prefix  => 'group-policy',
			   postfix => 'attributes',
		       },
		       OBJECT_GROUP => {
			   prefix  => 'object-group',
			   postfix => '',
		       },
		       CA_CERT_MAP => {
			   prefix  => 'crypto ca certificate map',
			   postfix => '10',
		       },
		       USERNAME => {
			   prefix  => 'username',
			   postfix => 'attributes',
		       },
		       DEFAULT_GROUP => {
			   prefix  => 'tunnel-group-map default-group',
			   postfix => '',
		       },
		       );

my %attr2cmd = (
		# username
		VPN_FRAMED_IP_ADDRESS     => 'vpn-framed-ip-address',
		VPN_FILTER                => 'vpn-filter value',
		VPN_GROUP_POLICY          => 'vpn-group-policy',
		SERVICE_TYPE              => 'service-type',
		# group-policy
		BANNER	                  => 'banner value',
		SPLIT_TUNNEL_POLICY       => 'split-tunnel-policy',
		SPLIT_TUNNEL_NETWORK_LIST => 'split-tunnel-network-list value',
		VPN_IDLE_TIMEOUT          => 'vpn-idle-timeout value',
		ADDRESS_POOL              => 'address-pools value',
		VPN_FILTER                => 'vpn-filter value',
		PFS	                  => 'pfs',
		# tunnel-group
		CERTIFICATE_FROM	  => 'username-from-certificate',
		AUTHZ_SERVER_GROUP        => 'authorization-server-group',
		AUTHEN_SERVER_GROUP       => 'authentication-server-group',
		AUTHZ_REQUIRED            => 'authorization-required',
		DEFAULT_GROUP_POLICY      => 'default-group-policy',
		# tunnel-group-map
		TUNNEL_GROUP_MAP	  => 'tunnel-group-map',
		# tunnel-group ipsec-attributes
		PEER_ID_VALIDATE          => 'peer-id-validate',
		CHAIN                     => 'chain',
		TRUST_POINT               => 'trust-point',
		ISAKMP                    => 'isakmp ikev1-user-authentication',
		# crypto ca certificates
		IDENTIFIER                => 'subject-name attr',
		# ip local pool
		IP_LOCAL_POOL             => 'ip local pool',
		);

my %parse2attr = (
		  USERNAME => {
		      GROUP_POLICY => 'VPN_GROUP_POLICY',
		      ACCESS       => {
			  'vpn_filter'   => 'VPN_FILTER',
		      }
		  },
		  GROUP_POLICY => {
		      POOL   => 'ADDRESS_POOL',
		      ACCESS => {
			  'split_tunnel' => 'SPLIT_TUNNEL_NETWORK_LIST',
			  'vpn_filter'   => 'VPN_FILTER',
		      }
		  },
		  TUNNEL_GROUP => {
		      GROUP_POLICY => 'DEFAULT_GROUP_POLICY',
		  },
		  IF => {
		      ACCESS       => {
			  'in_filter'    => 'ACCESS_GROUP_IN',
			  'out_filter'   => 'ACCESS_GROUP_OUT',
		      },
		  },
		  );
		      
		      

sub type_for_acl {
    my ( $spoc, $acl_name ) = @_;
    
    my $type;
    if ( $spoc->{is_vpn_filter_acl}->{$acl_name} ) {
	$type = 'vpn_filter';
    }
    elsif ( $spoc->{is_split_tunnel_acl}->{$acl_name} ) {
	$type = 'vpn_filter';
    }
    elsif ( $spoc->{is_out_filter_acl}->{$acl_name} ) {
	$type = 'out_filter';
    }
    elsif ( $spoc->{is_filter_acl}->{$acl_name} ) {
	$type = 'in_filter';
    }
    elsif ( $spoc->{is_crypto_acl}->{$acl_name} ) {
	$type = 'crypto';
    }
    else {
	errpr "Unknow ACL-type for $acl_name! \n";
    }
    return $type;
}    

sub get_parse_info {
    my ($self) = @_;
    my $null = {
	'BASE' => 0,
	'MASK' => 0
	};
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
		      # don't store METRIC, values seem to be arbitrary for PIX
		      { parse => \&check_int } ],
	},

# access-group <access_list_name> in interface <if_name>
	'access-group' => {
	    store =>'ACCESS_GROUP',
	    named => 1,
	    parse => ['seq',
		      ['or',
		      { store => 'TYPE', parse => qr/out/ },
		      { store => 'TYPE', parse => qr/in/ },
		       ],
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
		   
		   ['or', # standard or extended access-list
		    ['seq',
		     { store => 'ACL_TYPE', parse => qr/standard/ },
		     { store => 'MODE', parse => qr/permit|deny/ },
		     { store => 'DST',  parse => 'parse_address' },
		     { store => 'SRC',  parse => \&skip, default => $null },
		     { store => 'TYPE', parse => \&skip, default => 'ip'  },
		     ],
		    ['seq',
		     { store => 'ACL_TYPE',
		       parse => qr/extended/, default => 'extended' },
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
			   parse => \&check_int }
			 ]
			]
		       ]
		      ]
		     ]
		    ]
		   ]
		  ]
		 ],
	     },

# crypto map map-name seq-num match address acl_name
# ignore 
# crypto map map-name seq-num *
# crypto map map-name interface *
	'crypto map' => {
	    store => ['CRYPTO', 'MAP'],
	    named => 1,
	    multi => 1,
	    parse => ['or',
		      ['seq',
		       { parse => qr/interface/ },
		       { parse => \&skip } ],
		      ['seq',
		       { store => 'SEQU', parse => \&get_int, },
		       ['or',
			['seq',
			 { parse => qr/match/ },
			 { parse => qr/address/ },
			 { store => 'MATCH_ADDRESS', parse => \&get_token } ],
			{ parse => \&skip } ]]]
	},
    }
}

sub postprocess_config {
    my ($self, $p) = @_;

    # Expand object-groups in access-lists.
    for my $acl_name (keys %{ $p->{ACCESS_LIST} }) {
        my %seen_acl;
        for my $entry (@{ $p->{ACCESS_LIST}->{$acl_name} }) {
            my $e_acl = $self->expand_acl_entry($entry, $p, $acl_name);
	    push @{$p->{ACCESS}->{$acl_name}},@$e_acl;

	    # Remove 'access-list <name>' from original input line.
	    # 1. to get shorter output during ACL compare.
	    # 2. we merge different names from raw files and need to add
	    #    a new name during approve anyway.
	    $entry->{orig} =~ s/^access-list\s+\S+\s+(extended\s+)?//;
        }
    }

    # Link interfaces to access lists via access-groups.
    # (Same way certificate-maps are connected to tunnel-groups
    #  via tunnel-group-maps.)
    for my $access_group ( values %{$p->{ACCESS_GROUP}} ) {
	my $acl_name = $access_group->{name};
	my $is_out_acl = $access_group->{TYPE} eq 'out' ?
	    '1' : '0';
	# Mark as filter-acl or as outgoing-filter-acl.
        if ( $p->{ACCESS_LIST}->{$acl_name} ) {
	    if ( $is_out_acl ) {
		$p->{is_out_filter_acl}->{$acl_name} = 1;
	    }
	    else {
		$p->{is_filter_acl}->{$acl_name} = 1;
	    }
	}

	# Create in- or out-access-group on interface.
	# Create artificial interface if necessary.
	my $if_name  = $access_group->{IF_NAME};
	if ( my $intf = $p->{IF}->{$if_name} ) {
	    if ( $is_out_acl ) {
		$p->{ACCESS_GROUP_OUT}->{$acl_name} = $access_group;
		$intf->{ACCESS_GROUP_OUT} = $acl_name;
	    }
	    else {
		$p->{ACCESS_GROUP_IN}->{$acl_name} = $access_group;
		$intf->{ACCESS_GROUP_IN} = $acl_name;
	    }
	}
	else {
	    # Netspoc does not generate interface definitions
	    # for PIX and ASA, so we can have access-groups
	    # without corresponding interface.
	    # In this case we create an "artificial" interface.
	    $p->{IF}->{$if_name}->{name} = $if_name;
	    if ( $is_out_acl ) {
		$p->{ACCESS_GROUP_OUT}->{$acl_name} = $access_group;
		$p->{IF}->{$if_name}->{ACCESS_GROUP_OUT} =
		    $acl_name;
	    }
	    else {
		$p->{ACCESS_GROUP_IN}->{$acl_name} = $access_group;
		$p->{IF}->{$if_name}->{ACCESS_GROUP_IN} =
		    $acl_name;
	    }
	}
    }
    # We don't need "ACCESS_GROUP" anymore ...
    delete $p->{ACCESS_GROUP};

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
      . ": USERS found: "
      . scalar(keys %{ $p->{USERNAME} }) . "\n";

    mypr meself(1)
      . ": GROUP POLICIES found: "
      . scalar(keys %{ $p->{GROUP_POLICY} }) . "\n";

    mypr meself(1)
      . ": TUNNEL GROUPS found: "
      . scalar(keys %{ $p->{TUNNEL_GROUP} }) . "\n";

    mypr meself(1)
      . ": TUNNEL GROUP MAPS found: "
      . scalar(keys %{ $p->{TUNNEL_GROUP_MAP} }) . "\n";

    if ( $p->{TUNNEL_GROUP_MAP}->{DEFAULT_GROUP} ) {
	mypr meself(1)
	    . ": DEFAULT TUNNEL GROUP: "
	    . $p->{TUNNEL_GROUP_MAP}->{DEFAULT_GROUP} . "\n";
    }

    mypr meself(1)
      . ": CERTIFICATE MAPS found: "
      . scalar(keys %{ $p->{CA_CERT_MAP} }) . "\n";

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
        elsif ($p->{is_out_filter_acl}->{$acl_name}) {
            mypr meself(1)
              . ": $acl_name "
              . scalar @{ $p->{ACCESS_LIST}->{$acl_name} } . "\n";
        }
        elsif ($p->{is_vpn_filter_acl}->{$acl_name}) {
            mypr meself(1)
              . ": $acl_name "
              . scalar @{ $p->{ACCESS_LIST}->{$acl_name} } . "\n";
        }
        elsif ($p->{is_split_tunnel_acl}->{$acl_name}) {
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
	next if $k eq 'line';
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
    if (my($msg) = $$out =~ /\n(.+)$/s) {
        #### hack start ###
        ($msg =~ /\[OK\]/m) and return 1;    ### for write memory
        ($msg =~ /will be identity translated for outbound/)
          and return 1;                       # identity nat
        ($msg =~ /nat 0 0.0.0.0 will be non-translated/)
          and return 1;                       # identity nat
        ($msg =~ /Global \d+\.\d+\.\d+\.\d+ will be Port Address Translated/)
          and return 1;                       # PAT

	# global (xxx) interface
	# PIX: xxx interface address added to PAT pool
	# ASA: INFO: xxx interface address added to PAT pool
	$msg =~ /interface address added to PAT pool/
	    and return 1;

        if ($msg =~ /(
		      # overlapping statics from netspoc
		      overlapped\/redundant |
		      # overlapping statics with global from netspoc
		      static[ ]overlaps |
		      # route warnings
		      Route[ ]already[ ]exists |
		      # object-group warnings
		      Adding[ ]obj[ ]\([^()]+\)[ ]to[ ]grp[ ]\([^()]+\)[ ]failed;[ ]object[ ]already[ ]exists |
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

    $self->merge_routing($spoc_conf, $raw_conf);

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

	    # Remove 'access-list <name>' from original input line.
	    # 1. to get shorter output during ACL compare.
	    # 2. we merge different names from raw files and need to add
	    #    a new name during approve anyway.
	    $copy->{orig} =~ s/^access-list\s+\S+\s+(extended\s+)?//;
            push @expanded, $copy;
        }
    }
    return \@expanded;
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
    if ( $self->{COMPARE} ) {

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
    else {
        mypr "deleting non matching entries from device:  ";
        $counter = 0;
	$self->enter_conf_mode;
        for my $d (@{$device_lines}) {
            ($d->{DELETE}) and next;
            $counter++;
            my $tr = join(' ', "no", $d->{orig});
            $self->cmd($tr);
            mypr " $counter";
        }
        $counter and $change = 1;
        mypr " $counter\n";
        mypr "transfer entries to device:  ";
        $counter = 0;
        for my $s (@{$spoc_lines}) {
            ($s->{DELETE}) and next;
            $counter++;
            $self->cmd($s->{orig});
            mypr " $counter";
        }
	$self->leave_conf_mode;
        $counter and $change = 1;
        mypr " $counter\n";
    }
    return $change;
}

sub generate_names_for_transfer {
    my ( $conf, $spoc, $structure ) = @_;

    # Generate new names for transfer.
    # New names are:  <spoc-name>-DRC-<index>
    my $generate_names_for_transfer = sub {
        my ($obj_id, $objects) = @_;
        my $new_id_prefix = "$obj_id-DRC-";
        my $new_id_index  = 0;
        while ($objects->{"$new_id_prefix$new_id_index"}) {
            $new_id_index++;
        }
        return "$new_id_prefix$new_id_index";
    };

    for my $parse_name ( keys %{$structure} ) {
	next if $parse_name eq 'USERNAME';
	# Generate new names for object $object.
	for my $object ( keys %{ $spoc->{$parse_name} } ) {
	    $new_name{$object} =
		$generate_names_for_transfer->( $object,
						$conf->{$parse_name} );
	}
    }
}

sub equalize_attributes {
    my ( $self, $conf_value, $spoc_value,
	 $parse_name, $structure ) = @_;

    my $modified;
    my $parse = $structure->{$parse_name};
    if ( not ( $structure && $parse_name ) ) {
	errpr "structure or parse_name not defined! \n";
    }

    # Equalize "normal" (normal=non-next) attributes.
    for my $attr ( @{$parse->{attributes}} ) {
	#mypr "Check attribute $attr ... \n";
	my $spoc_attr = $spoc_value->{$attr};
	my $conf_attr = $conf_value->{$attr};
	if ( $spoc_attr  &&  $conf_attr ) { 
	    # Attribute present on both.
	    if ( $spoc_attr ne $conf_attr ) {
#		mypr " < " . $conf_value->{name} . " > " .
#		    " --> ATTR:$attr  DEV:$conf_attr  SPOC:$spoc_attr \n";
		$modified = 1;
		$spoc_value->{change_attr}->{$attr} = $spoc_attr;
	    }		    
	}
	elsif ( $spoc_attr  &&  ! $conf_attr ) {
	    #mypr "Attribute $attr present only in netspoc. \n";
	    $modified = 1;
	    $spoc_value->{change_attr}->{$attr} = $spoc_attr;
	}
	elsif ( ! $spoc_attr  &&  $conf_attr ) {
	    #mypr "Attribute $attr present only on device. \n";
	    $modified = 1;
	    $conf_value->{remove_attr}->{$attr} = $conf_attr;
	}
	else {
	    #warnpr "Attribute '$attr' not on device and not in Netspoc! \n";
	}
    }

    # Equalize next-attributes.
    for my $next_key ( @{$parse->{next}} ) {
	my $next_attr_name  = $next_key->{attr_name};
	my $next_parse_name = $next_key->{parse_name};
	my $conf_next = $conf_value->{$next_attr_name};
	my $spoc_next = $spoc_value->{$next_attr_name};
	if ( $conf_next && !$spoc_next ) {
	    $modified = 1;
	    $conf_value->{remove_attr}->{$next_attr_name} =
		$conf_next;
	}
    }
    return $modified;
}

sub make_equal {
    my ( $self, $conf, $spoc, $parse_name, $conf_name,
	 $spoc_name, $structure ) = @_;

    return undef unless ( $spoc_name  ||  $conf_name );

#    mypr "\nMAKE EQUAL( $parse_name ) => CONF:$conf_name, " .
#	"SPOC:$spoc_name \n";

    my $modified;
    my $conf_value = object_for_name( $conf, $parse_name,
				      $conf_name, 'no_err' );
    my $spoc_value = object_for_name( $spoc, $parse_name,
				      $spoc_name, 'no_err' );

    my $spoc_name_is_acl;
    if ( is_acl( $spoc, $spoc_name )  &&
	 $parse_name eq 'ACCESS' ) {
	$spoc_name_is_acl = 1;
    }	

    # If object already has been tranfered before, just
    # return the name of the transfered object.
    if ( $spoc_name_is_acl ) {
	if ( $acl_need_transfer{$spoc_name} ) {
	    return new_name_for( $spoc_name );
	}
    }
    else {
	if ( $spoc_value ) {
	    if ( $spoc_value->{transfer} ) {
		return new_name_for( $spoc_name );
	    }
	}
    }

    if ( $conf_value  &&  $spoc_value ) {
	# On both, compare attributes.
	if ( $spoc_name_is_acl ) {
	    # Compare acl using acl_equal.
	    if ( $self->acl_equal( $conf_value, $spoc_value,
				   $conf_name, $spoc_name, $parse_name ) )
	    {
		# Acls that do not have attribute "needed"
		# will be removed from device later.
		$acl_needed{$conf_name} = 1;
	    }
	    else {
		$modified = 1;
		$acl_need_transfer{$spoc_name} = 1;
	    }
	}
	else {
	    $conf_value->{needed} = 1;
	    # String-compare and mark changed attributes.
	    $modified = $self->equalize_attributes( $conf_value, $spoc_value,
						    $parse_name, $structure );
	    $spoc_value->{name_on_dev} = $conf_name;
	}
    }
    elsif ( $conf_value  &&  !$spoc_value ) {
	# On dev but not on spoc.
#	mypr "$parse_name => $conf_name on dev but not on spoc. \n";
	$self->mark_as_changed( $parse_name );
	mark_for_remove( $conf, $conf_name, $conf_value );
    }
    elsif ( !$conf_value  &&  $spoc_value ) {
	# On spoc but not on dev.
#	mypr "$parse_name => $spoc_name on spoc but not on dev. \n";
	$self->mark_as_changed( $parse_name );
	mark_for_transfer( $spoc, $spoc_name, $spoc_value );
    }
    else {
	if ( $conf_name ) {
	    warnpr "Referenced $parse_name -> $conf_name " .
		"not found on device! \n";
	}
    }

    if ( my $parse = $structure->{$parse_name} ) {
	# See if we have to continue recursively.
	if ( my $next = $parse->{next} ) {
	    for my $next_key ( @$next ) {
		my $next_attr_name  = $next_key->{attr_name};
		my $next_parse_name = $next_key->{parse_name};
		my $conf_next;
		$conf_next = $conf_value->{$next_attr_name} if $conf_value;
		my $spoc_next;
		$spoc_next = $spoc_value->{$next_attr_name} if $spoc_value;
		
		my $new_conf_next =
		    $self->make_equal( $conf, $spoc, $next_parse_name,
				       $conf_next, $spoc_next,
				       $structure );

		# If an object is transfered, a new name is
		# generated for that object (exception:USERNAME).
		# If there is a superior object,
		# the corresponding attribute in that superior object
		# has to be altered, so that it carries the name of the
		# transfered object.
		my $spoc_next_is_acl;
		if ( $spoc_next ) {
		    if ( is_acl( $spoc, $spoc_next ) &&
			 $next_parse_name eq 'ACCESS' ) {
			$spoc_next_is_acl = 1;
		    }
		    if ( my $next_obj =
			 $spoc->{$next_parse_name}->{$spoc_next} ) {
			if ( $spoc_next_is_acl ) {
			    if ( $acl_need_transfer{$spoc_next} ) {
				$spoc_value->{change_attr}->{$next_attr_name} =
				    new_name_for( $spoc_next );
			    }
			}
			elsif ( $next_obj->{transfer} ) {
			    $spoc_value->{change_attr}->{$next_attr_name} =
				new_name_for( $spoc_next );
			}
		    }
		}

		if ( $new_conf_next ) {
		    if ( ! $conf_next ||
			 ( $conf_next ne $new_conf_next ) ) {

			$transfered2orig{$new_conf_next} = $spoc_next;

			if ( $spoc_value ) {

			    if ( $spoc_next_is_acl ) {
				my $acl_type = type_for_acl( $spoc, $spoc_next );
				my $types2attr =
				    $parse2attr{$parse_name}->{$next_parse_name};
				if ( my $attr = $types2attr->{$acl_type} ) {
				    $spoc_value->{change_attr}->{$attr} =
					$new_conf_next;
				}
				else {
				    errpr "Attr undefined for $acl_type!\n";
				}
			    }
			    else {
				my $attr =
				    $parse2attr{$parse_name}->{$next_parse_name};

				$spoc_value->{change_attr}->{$attr} =
				    $new_conf_next;
			    }
			}
			else {
			    die "spoc-value undefined!";
			}		    
		    }
		}
	    }
	}
    }
    
    if ( $modified ) {
	$self->mark_as_changed( $parse_name );
	if ( $structure->{$parse_name}->{copy_on_modify} ) {
	    if ( $new_name{$spoc_name} ) {
		return $new_name{$spoc_name};
	    }
	    else {
		errpr "New name needed for transfer of $conf_name! \n";
	    }
	}
    }
    else {
	# Create hash entry with false value, so that
	# Device::get_change_status outputs status for
	# unchanged object types, too.
	$self->mark_as_unchanged( $parse_name );
    }
    
    # Standard return value ...
    return $conf_name;
}

sub unify_anchors {
    my ( $self, $conf, $spoc, $structure ) = @_;

    for my $key ( keys %$structure ) {
        my $value = $structure->{$key};
        next if not $value->{anchor};
#	mypr "\n\nProcessing anchor $key ... \n";
        my $conf_anchor = $conf->{$key};
        my $spoc_anchor = $spoc->{$key};
	my %seen;

	# Iterate over anchors on device.
        for my $conf_key ( keys %$conf_anchor ) {
	    $seen{$conf_key} = 1;
	    my $new_conf = 
		$self->make_equal( $conf, $spoc, $key,
				   $conf_key, $conf_key,
				   $structure );
	    if ( not $conf_key eq $new_conf ) {
		errpr "Anchors known so far are made equal by " .
		    "changing their attributes, not by transfer. " .
		    "(Anchor:$conf_key) \n";
	    }
	}
	# Iterate over anchors in netspoc (without those already
	# processed iterating over anchors on device).
        for my $spoc_key ( keys %$spoc_anchor ) {
	    next if $seen{$spoc_key};
	    my $new_spoc = 
		$self->make_equal( $conf, $spoc, $key,
				   $spoc_key, $spoc_key,
				   $structure );
	    if ( not $spoc_key eq $new_spoc ) {
		errpr "Anchors known so far are made equal by " .
		    "changing their attributes, not by transfer. " .
		    "(Anchor:$spoc_key) \n";
	    }
	}
    }
}

sub change_modified_attributes {
    my ( $self, $spoc, $parse_name,
	 $spoc_name, $structure ) = @_;

    my $spoc_value =
	object_for_name( $spoc, $parse_name,
			 $spoc_name );

    if ( my $parse = $structure->{$parse_name} ) {
	# Change or remove attributes marked accordingly.
	# Skip objects that are always transfered (acls, pools).
	if ( ! $parse->{copy_on_modify} ) {
	    my $attr;
	    if ( $attr = $spoc_value->{change_attr} ) {
		$self->change_attributes( $parse_name, $spoc_name,
					  $spoc_value, $attr );
	    }
	}

	# Enter recursion ...
	if ( my $next = $parse->{next} ) {
	    for my $next_key ( @$next ) {
		my $next_attr_name  = $next_key->{attr_name};
		my $next_parse_name = $next_key->{parse_name};
		if ( my $spoc_next = $spoc_value->{$next_attr_name} ) {
		    $self->change_modified_attributes( $spoc, $next_parse_name,
						       $spoc_next, $structure );
		}
	    }
	}
    }
}

#
# Recursively transfer marked objects.
#
sub transfer1 {
    my ( $self, $spoc, $parse_name, $spoc_name, $structure ) = @_;

    #mypr "PROCESS $spoc_name ... \n"; 
    my $spoc_value = object_for_name( $spoc, $parse_name,
				      $spoc_name, 'no_err' );

    if ( not $spoc_value ) {
	if ( my $original = $transfered2orig{$spoc_name} ) {
	    $spoc_name = $original;
	    $spoc_value = object_for_name( $spoc, $parse_name,
					   $original );
	}
    }

    if ( my $parse = $structure->{$parse_name} ) {
	if ( my $next = $parse->{next} ) {
	    for my $next_key ( @$next ) {
		my $next_attr_name  = $next_key->{attr_name};
		my $next_parse_name = $next_key->{parse_name};
		if ( my $spoc_next = $spoc_value->{$next_attr_name} ) {
		    $self->transfer1( $spoc, $next_parse_name,
				      $spoc_next, $structure );
		}
	    }
	}

	# Do actual transfer after recursion so
	# that we start with the leaves.

	my $method = $parse->{transfer};
	if ( is_acl( $spoc, $spoc_name ) ) {
	    if ( $acl_need_transfer{$spoc_name} ) {
		if ( my $transfered_as = $acl_transfered_as{$spoc_name} ) {
		    #mypr "$spoc_name ALREADY TRANSFERED AS $transfered_as! \n";
		}
		else {
		    $self->$method( $spoc, $structure,
				    $parse_name, $spoc_name );
		    $acl_transfered_as{$spoc_name} =
			new_name_for( $spoc_name );
		}
	    }
	}
	elsif ( $spoc_value->{transfer} ) {
	    if ( my $transfered_as = $spoc_value->{transfered_as} ) {
		#mypr "$spoc_name ALREADY TRANSFERED AS $transfered_as! \n";
	    }
	    else {
		$self->$method( $spoc, $structure,
				$parse_name, $spoc_name );
		$spoc_value->{transfered_as} = $new_name{$spoc_name};
	    }
	}
	
    }
}

#
# Entry point for tree traversal (starting with
# the anchors) in order to transfer,
# remove or modify marked objects.
#
sub traverse_netspoc_tree {
    my ( $self, $spoc, $structure ) = @_;

    mypr "\n##### Transfer objects to device ##### \n";

    # Transfer items ...
    for my $key ( keys %$structure ) {
        my $value = $structure->{$key};
        next if not $value->{anchor};

	#mypr "\nITERATING over netspoc-anchor $key ... \n";
        my $spoc_anchor = $spoc->{$key};

	# Iterate over anchors in netspoc.
        for my $spoc_key ( keys %$spoc_anchor ) {
	    $self->transfer1( $spoc, $key,
			      $spoc_key, $structure );
	}
    }

    # Change attributes of items ...
    for my $key ( keys %$structure ) {
        my $value = $structure->{$key};
        next if not $value->{anchor};

        my $spoc_value = $spoc->{$key};

	# Iterate over objects on device.
        for my $spoc_key ( keys %$spoc_value ) {
	    $self->change_modified_attributes( $spoc, $key,
			   $spoc_key, $structure );
	}
    }
}

sub remove_unneeded_on_device {
    my ( $self, $conf, $spoc, $structure ) = @_;
    
    # Caution: the order is significant in this array!
    my @parse_names = qw( USERNAME CA_CERT_MAP TUNNEL_GROUP GROUP_POLICY 
			  ACCESS IP_LOCAL_POOL
			  );

    mypr "\n##### Remove unneeded objects from device ##### \n";
	
    for my $parse_name ( @parse_names ) {
	my $parse = $structure->{$parse_name};
      OBJECT:
	for my $obj_name ( keys %{$conf->{$parse_name}} ) {

	    # Skip special default-group-policy 'DfltGrpPolicy'.
	    next OBJECT if $obj_name eq 'DfltGrpPolicy';

	    my $object = object_for_name( $conf, $parse_name,
					  $obj_name );

	    # Do not remove users that have their own explicit
	    # password (e.g. 'netspoc'-user used to access device).
	    next OBJECT if ( $parse_name eq 'USERNAME'  &&
			     not $object->{NOPASSWORD} );
	    # Remove unneeded objects from device.
	    if ( not object_needed( $conf, $obj_name, $object ) ) {
		my $method = $parse->{remove};
		$self->$method( $conf, $structure,
				$parse_name, $obj_name );
	    }
	    # Remove attributes marked for deletion.
	    if ( ! $parse->{copy_on_modify} ) {
		if ( my $attr = $object->{remove_attr} ) {
		    $self->remove_attributes( $parse_name,
					      $obj_name, $attr );
		}
	    }
	}
    }
}

sub remove_spare_objects_on_device {
    my ( $self, $conf, $structure ) = @_;

    my @parse_names = qw( USERNAME CA_CERT_MAP TUNNEL_GROUP GROUP_POLICY 
			  ACCESS IP_LOCAL_POOL OBJECT_GROUP 
			  );
    
    mypr "\n##### Remove SPARE objects from device ##### \n";

    for my $parse_name ( @parse_names ) {
	my $parse = $structure->{$parse_name};
      OBJECT:
	for my $obj_name ( keys %{$conf->{$parse_name}} ) {
	    
	    my $object = object_for_name( $conf, $parse_name,
					  $obj_name );
	    
	    # Skip special default-group-policy 'DfltGrpPolicy'.
	    next OBJECT if $obj_name eq 'DfltGrpPolicy';

	    # Remove spare objects from device.
	    if ( not $connected{$obj_name} ) {
		# So we do not try to remove the object
		# again later. (This is a hack and should be
		# done in a more consistent way! -->TODO)
		if ( $parse_name eq 'ACCESS' ) {
		    $acl_needed{$obj_name} = 1;
		}
		else {
		    $object->{needed} = 1;
		}
		# Leave crypto-acls on device!
		if ( $parse_name eq 'ACCESS'  &&
		     $conf->{is_crypto_acl}->{$obj_name} ) {
		    #mypr "LEAVE CRYPTO-ACL $obj_name on DEV!\n";
		    next OBJECT;
		}
		# Remove object ...
		my $method = $parse->{remove};
		$self->$method( $conf, $structure,
				$parse_name, $obj_name );
	    }
	}
    }
}    

sub mark_connected {
    my ( $self, $conf, $parse_name, $conf_name, $structure ) = @_;

#    mypr "MARK $conf_name AS CONNECTED ... \n"; 
    my $conf_value = object_for_name( $conf, $parse_name,
				      $conf_name, 'no_err' );
    return unless $conf_value;

    $connected{$conf_name} = 1;

    if ( my $parse = $structure->{$parse_name} ) {
	if ( my $next = $parse->{next} ) {
	    for my $next_key ( @$next ) {
		my $next_attr_name  = $next_key->{attr_name};
		my $next_parse_name = $next_key->{parse_name};
		if ( my $conf_next = $conf_value->{$next_attr_name} ) {
		    $self->mark_connected( $conf, $next_parse_name,
					   $conf_next, $structure );
		}
	    }
	}
    }
}

#
sub mark_connected_objects {
    my ( $self, $conf, $structure ) = @_;

    # Transfer items ...
    for my $key ( keys %$structure ) {
        my $value = $structure->{$key};
        next if not $value->{anchor};

        my $conf_anchor = $conf->{$key};

	# Iterate over anchors in conf.
        for my $conf_key ( keys %$conf_anchor ) {
	    $self->mark_connected( $conf, $key,
				   $conf_key, $structure );
	}
    }
}

sub change_attributes {
    my ( $self, $parse_name,
	 $spoc_name, $spoc_value, $attributes ) = @_;
    my @cmds;

    return if ( $parse_name eq 'CERT_ANCHOR' ||
		$parse_name eq 'IF'    );

    mypr "### CHANGE ATTRIBUTES of  $parse_name -> $spoc_name \n";
    if ( my $name = $spoc_value->{name_on_dev} ) {
	$spoc_name = $name; 
    }
    elsif ( $spoc_value->{transfer} ) {
	if ( my $new_name = $new_name{$spoc_name} ) {
	    $spoc_name = $new_name;
	}
    }

    # In case of ip-local-pools changed attributes means
    # the pool present on device needs to be overwritten
    # with new values in one line, because pools do not have
    # sub-command-attributes.
    if ( $parse_name eq 'IP_LOCAL_POOL' ) {
	my $from = int2quad( $spoc_value->{RANGE_FROM} );
	my $to   = int2quad( $spoc_value->{RANGE_TO}   );
	my $mask = int2quad( $spoc_value->{MASK}    );
	push @cmds, "ip local pool $spoc_name $from-$to mask $mask";
    }
    else {
	if ( not $parse_name eq 'DEFAULT_GROUP' ) {
	    push @cmds, item_conf_mode_cmd( $parse_name, $spoc_name );
	}
	
	my $value_string;
	for my $attr ( keys %{$attributes}  ) {
	    my $value = $attributes->{$attr};
	    $value_string = $attr_with_value{$attr}  ?  'value'  :  '';
	    my $attr_cmd = $attr2cmd{$attr};
	    if ( ! $attr_cmd ) {
		errpr "Command not found for attribute $attr! \n";
	    }
	    if ( $parse_name eq 'CA_CERT_MAP' ) {
		$attr_cmd .= ' ' . $spoc_name . ' 10 ';
	    }
	    elsif ( $parse_name eq 'DEFAULT_GROUP' ) {
		$attr_cmd .= " default-group ";
	    }
	    push @cmds, "$attr_cmd $value_string $value";
	}
    }
    map { mypr " $_\n"; } @cmds;
    map { $self->cmd( $_ ) } @cmds;
}

sub remove_attributes {
    my ( $self, $parse_name,
	 $item_name, $attributes ) = @_;

    mypr " ### remove attributes for $item_name! \n";
    my @cmds;
    push @cmds, item_conf_mode_cmd( $parse_name, $item_name );

    my $value_string;
    for my $attr ( keys %{$attributes} ) {
	my $value = $attributes->{$attr};
	$value_string = $attr_with_value{$attr}  ?  'value'  :  '';
	my $attr_cmd = $attr2cmd{$attr};
	push @cmds, "no $attr_cmd $value_string $value";
    }
    map { mypr " $_\n"; } @cmds;
    map { $self->cmd( $_ ) } @cmds;
}

sub transfer_interface {
    my ( $self, $spoc, $structure,
	 $parse_name, $intf ) = @_;
    errpr "transfer_interface $intf: interfaces MUST be same " .
	"on device and in netspoc!\n";
}

sub remove_interface {
    my ( $self, $conf, $structure,
	 $parse_name, $intf ) = @_;
    errpr "remove_interface $intf: interfaces MUST be same " .
	"on device and in netspoc!\n";
}

sub transfer_ca_cert_map {
    my ( $self, $spoc, $structure,
	 $parse_name, $cert_map ) = @_;

    my $new_cert_map = new_name_for( $cert_map );
    mypr "### transfer ca-cert-map $cert_map to device as " .
	"$new_cert_map \n";
    
    my $object = object_for_name( $spoc, $parse_name, $cert_map );
    my @cmds;
    push @cmds, item_conf_mode_cmd( $parse_name, $new_cert_map );
    for my $attr ( @{$structure->{$parse_name}->{attributes}} ) {
	my $attr_cmd = cmd_for_attribute( $attr );
	push @cmds, $attr_cmd . ' ' . $object->{$attr};
    }

    # Create tunnel-group-map that connects certificate-map
    # to tunnel-group.
    if ( my $tunnel_group = $object->{TUNNEL_GROUP_MAP} ) {
	my $name = $new_name{$tunnel_group}  ?
	    $new_name{$tunnel_group}  :  $tunnel_group;
	push @cmds, "tunnel-group-map $new_cert_map 10 $name";
    }
    else {
	errpr "Missing tunnel-group in tunnel-group-map for " .
	    "certificate $cert_map! \n";
    }
    map { mypr " $_\n"; } @cmds;
    map { $self->cmd( $_ ) } @cmds;
}

sub remove_ca_cert_map {
    my ( $self, $conf, $structure,
	 $parse_name, $cert_map ) = @_;

    mypr "### remove ca-cert-map $cert_map from device \n";
    my $object = object_for_name( $conf, $parse_name, $cert_map );

    my $cmd = "clear configure crypto ca certificate map $cert_map";
    mypr " $cmd \n";
    $self->cmd( $cmd );
}

sub transfer_default_group {
    my ( $self, $spoc, $structure,
	 $parse_name, $default ) = @_;

    my $object = $spoc->{$parse_name}->{$default};
    my $new_default_group = new_name_for( $object->{TUNNEL_GROUP_MAP} );
    mypr "### transfer default-group to device " .
	"as $new_default_group \n";

    my $cmd = "tunnel-group-map default-group $new_default_group";
    mypr " $cmd \n";
    $self->cmd( $cmd );
}

sub remove_default_group {
    my ( $self, $conf, $structure,
	 $parse_name, $default ) = @_;

    mypr "### remove default-group $default from device \n";

    my $object = $conf->{$parse_name}->{$default};
    my @cmds;
    push @cmds, "no " . $object->{orig};
    map { mypr " $_\n"; } @cmds;
    map { $self->cmd( $_ ) } @cmds;
}

sub transfer_user {
    my ( $self, $spoc, $structure,
	 $parse_name, $username ) = @_;

    mypr "### transfer username $username to device \n";

    my $user = $spoc->{$parse_name}->{$username};
    errpr "No user-object found for $username!" unless $user;

    my @cmds;
    push @cmds, define_item_cmd( $parse_name, $username );
    push @cmds, item_conf_mode_cmd( $parse_name, $username );
    push @cmds, add_attribute_cmds( $structure, $parse_name,
				    $user, 'attributes' );

    map { mypr " $_\n"; } @cmds;
    map { $self->cmd( $_ ) } @cmds;
}

sub remove_user {
    my ( $self, $conf, $structure,
	 $parse_name, $username ) = @_;

    mypr "### remove username $username from device \n";

    my @cmds;
    my $cmd = "clear configure username $username";
    mypr " $cmd \n";
    $self->cmd( $cmd );
}

sub transfer_tunnel_group {
    my ( $self, $spoc, $structure,
	 $parse_name, $tg_name ) = @_;

    my $new_tg = new_name_for( $tg_name );
    mypr "### transfer tunnel-group $tg_name to " .
	"device as $new_tg \n";

    my $tunnel_group = $spoc->{$parse_name}->{$tg_name};
    errpr "No tunnel-group-object found for $tg_name!"
	unless $tunnel_group;

    my @cmds;
    push @cmds, define_item_cmd( $parse_name, $new_tg );
    push @cmds, item_conf_mode_cmd( $parse_name, $new_tg );
    push @cmds, add_attribute_cmds( $structure, $parse_name,
				    $tunnel_group, 'attributes' );
    
    if ( my $tunnel_group_ipsec =
	 $spoc->{TUNNEL_GROUP_IPSEC}->{$tg_name} ) {
	push @cmds, item_conf_mode_cmd( 'TUNNEL_GROUP_IPSEC', $new_tg );
	push @cmds, add_attribute_cmds( $structure, $parse_name,
					$tunnel_group_ipsec,
					'ipsec_attributes' );
    }
    
    map { mypr " $_\n"; } @cmds;
    map { $self->cmd( $_ ) } @cmds;
}

sub remove_tunnel_group {
    my ( $self, $conf, $structure,
	 $parse_name, $tg_name ) = @_;

    mypr "### remove tunnel-group $tg_name from device \n";

    my $object = $conf->{$parse_name}->{$tg_name};
    my @cmds;
    push @cmds, "clear configure tunnel-group $tg_name";
    map { mypr " $_\n"; } @cmds;
    map { $self->cmd( $_ ) } @cmds;
}

sub transfer_group_policy {
    my ( $self, $spoc, $structure,
	 $parse_name, $gp_name ) = @_;

    my $new_gp = new_name_for( $gp_name );
    mypr "### transfer group-policy $gp_name to device " .
	"as $new_gp \n";

    my $group_policy = $spoc->{$parse_name}->{$gp_name};
    errpr "No group-policy-object found for $gp_name!"
	unless $group_policy;

    my @cmds;
    push @cmds, define_item_cmd( $parse_name, $new_gp );
    push @cmds, item_conf_mode_cmd( $parse_name, $new_gp );
    push @cmds, add_attribute_cmds( $structure, $parse_name,
				    $group_policy, 'attributes' );
    
    map { mypr " $_\n"; } @cmds;
    map { $self->cmd( $_ ) } @cmds;
}

sub remove_group_policy {
    my ( $self, $spoc, $structure,
	 $parse_name, $gp_name ) = @_;

    mypr "### remove group-policy $gp_name from device \n";
    my $cmd = "clear configure group-policy $gp_name";
    mypr " $cmd \n";
    $self->cmd( $cmd );
}

sub transfer_ip_local_pool {
    my ( $self, $spoc, $structure,
	 $parse_name, $pool_name ) = @_;

    my $new_pool = new_name_for( $pool_name );
    mypr "### transfer ip local pool $pool_name to device " .
	"as $new_pool \n";

    my $pool = $spoc->{$parse_name}->{$pool_name};
    my $cmd = $pool->{orig}; 
    $cmd =~ s/ip local pool $pool_name(?!\S)/ip local pool $new_pool/;
    mypr " $cmd \n";
    $self->cmd( $cmd );
}

sub remove_ip_local_pool {
    my ( $self, $conf, $structure,
	 $parse_name, $pool_name ) = @_;

    mypr "### remove ip local pool $pool_name from device \n";

    my $pool = $conf->{$parse_name}->{$pool_name};
    my $cmd = "no " . $pool->{orig};
    mypr " $cmd \n";
    $self->cmd( $cmd );
}

sub transfer_object_group {
    my ( $self, $spoc, $parse_name,
	 $object_group ) = @_;

    mypr " ### transfer object-group $object_group to device\n";
    my $group = object_for_name( $spoc, $parse_name, $object_group );
    my $new_id = new_name_for( $object_group );
    $group->{transfered_as} = $new_id;
    $group->{needed} = 1;
    my $cmd = "object-group $group->{TYPE} $new_id";
    mypr " $cmd\n";
    map( { mypr " " . $_->{orig} . "\n" } @{ $group->{NETWORK_OBJECT} } );
    $self->cmd($cmd);
    map( { $self->cmd( $_->{orig} ) } @{ $group->{NETWORK_OBJECT} } );
}

sub remove_object_group {
    my ( $self, $conf, $structure,
	 $parse_name, $object_group ) = @_;
    
    if ( not $conf->{group2acl}->{$object_group} ) {
	mypr "### remove object-group $object_group from device \n";
	
	my $og = object_for_name( $conf, $parse_name, $object_group );
	my $cmd = "no " . $og->{orig};
	mypr " $cmd \n";
	$self->cmd( $cmd );
    }
}

sub transfer_acl {
    my ( $self, $spoc, $structure,
	 $parse_name, $acl ) = @_;

    my $new_acl = new_name_for( $acl );
    mypr "### transfer access-list $acl to device as $new_acl \n";

    # $parse_name holds value 'ACCESS' where the expanded
    # acls are stored. We need the unexpanded acls here which
    # are stored under 'ACCESS_LIST'.
    $parse_name = 'ACCESS_LIST';

    my @cmds;
    for my $ace ( @{ $spoc->{$parse_name}->{$acl} } ) {
	my $cmd = $ace->{orig};
	for my $where ( qw( SRC DST ) ) {
	    if ( my $gid = $ace->{$where}->{OBJECT_GROUP} ) {
		my $new_gid;
		if ( my $group =
		     object_for_name( $spoc, 'OBJECT_GROUP', $gid ) ) {
		    if ( $group->{transfered_as} ) {
			$new_gid = $group->{transfered_as};
		    }
		    else {
			$self->transfer_object_group( $spoc, 'OBJECT_GROUP',
						      $gid );
			$new_gid = new_name_for( $gid );
		    }
		}
		$cmd =~ 
		    s/object-group $gid(?!\S)/object-group $new_gid/;
		$ace->{$where}->{OBJECT_GROUP} = $new_gid;  
	    }
	}
	push @cmds, "access-list $new_acl " . $cmd;
    }


    # If this acl is attached to an interface, create
    # access-group connecting acl to interface.
    if ( my $access_groups = $spoc->{ACCESS_GROUP_IN} ) {
	if ( my $access_group = $access_groups->{$acl} ) {
	    push @cmds, "access-group $new_acl in interface " .
		$access_group->{IF_NAME};
	}
    }
    # If this acl is an outgoing-acl and attached to an interface,
    # create access-group connecting acl to interface.
    if ( my $access_groups = $spoc->{ACCESS_GROUP_OUT} ) {
	if ( my $access_group = $access_groups->{$acl} ) {
	    push @cmds, "access-group $new_acl out interface " .
		$access_group->{IF_NAME};
	}
    }
    map { mypr " $_\n"; } @cmds;
    map { $self->cmd( $_ ) } @cmds;
}

sub remove_acl {
    my ( $self, $conf, $structure,
	 $parse_name, $acl ) = @_;

    mypr "### remove access-list $acl from device \n";
    my $cmd = $self->acl_removal_cmd( $acl );
    mypr " $cmd\n";
    $self->cmd( $cmd );

    # Remove object group(s) that might be referenced
    # by this acl, but only if no other ACL references it!
    for my $ace ( @{ $conf->{ACCESS_LIST}->{$acl} } ) {
	my $cmd = $ace->{orig};
	for my $where ( qw( SRC DST ) ) {
	    if ( my $gid = $ace->{$where}->{OBJECT_GROUP} ) {
		if ( my $some_acl =
		     referenced_by_acl( $conf, $acl, $gid ) ) {
		    # Object-groups not marked as "needed" will
		    # be removed later!
		    my $group = object_for_name( $conf, 'OBJECT_GROUP',
						 $gid );
		    $group->{needed} = 1;
		}
	    }
	}
    }
}

sub referenced_by_acl {
    my ( $conf, $current_acl, $obj_group ) = @_;

    my $acls = $conf->{ACCESS_LIST};

  ACL:
    for my $acl ( keys %{$acls} ) {
	next ACL if $acl eq $current_acl;
	for my $ace ( @{ $acls->{$acl} } ) {
	    for my $where ( qw( SRC DST ) ) {
		if ( my $gid = $ace->{$where}->{OBJECT_GROUP} ) {
		    if ( $gid eq $obj_group ) {
			return $acl;
		    }
		}
	    }
	}
    }
    return;
}

sub define_item_cmd {
    my ( $parse_name, $item_name ) = @_;
    
    if ( $define_object{$parse_name} ) {
	my $prefix  = $define_object{$parse_name}->{prefix};
	my $postfix = $define_object{$parse_name}->{postfix};
	if ( ! $prefix ) {
	    errpr "Prefix not defined for object-definition of " .
		"object '$item_name'! \n";
	}
	return "$prefix $item_name $postfix";
    }
    else {
	errpr "Command for object-definition not found of " .
	    " object $item_name! \n";
    }
    return;
}

sub item_conf_mode_cmd {
    my ( $parse_name, $item_name ) = @_;

    my $prefix  = $conf_mode_entry{$parse_name}->{prefix};
    my $postfix = $conf_mode_entry{$parse_name}->{postfix};

    if ( ! $prefix ) {
	errpr "Prefix undefined for configure terminal " .
	    "entry command of item '$item_name'! \n";
    }
    return "$prefix $item_name $postfix";
}

sub add_attribute_cmds {
    my ( $structure, $parse_name,
	 $object, $attributes ) = @_;

    my @cmds;
  ATTRIBUTE:
    for my $attr ( @{$structure->{$parse_name}->{$attributes}} ) {
	# Some attributes are optional.
	next ATTRIBUTE if not $object->{$attr};
	my $attr_cmd = cmd_for_attribute( $attr );
	if ( ! $ attr_cmd ) {
	    errpr "No command found for attribute $attr!\n";
	}
	my $name = $new_name{$object->{$attr}}  ?
	    $new_name{$object->{$attr}}  :  $object->{$attr};
	push @cmds, $attr_cmd . ' ' . $name;
    }
    return @cmds;
}

sub object_for_name {
    my ( $c, $parse_name, $c_name, $no_err ) = @_;

    return if not $c_name;

    if ( $no_err && $no_err ne 'no_err' ) {
	errpr "Illegal parameter $no_err \n";
    }

    my $c_value;
    if ( $c_name ) {
	if ( my $parse = $c->{$parse_name} ) {
	    if ( exists $parse->{$c_name} ) {
		$c_value = $parse->{$c_name};
	    }
	}
    }
    if ( ! $no_err ) {
	if ( ! $c_value ) {
	    errpr "No object found for $c_name \n";
	}
    }
    return $c_value;
}

sub is_acl {
    my ( $c, $object ) = @_;
    return if not $c;
    return if not $object;
    return exists $c->{ACCESS}->{$object};
}

sub mark_for_transfer {
    my ( $spoc, $name, $object ) = @_;

    my $new_name = $new_name{$name};
    if ( is_acl( $spoc, $name ) ) {
	$acl_need_transfer{$name} = 1;
    }
    else {
	$object->{transfer} = 1;
    }
}

sub mark_for_remove {
    my ( $conf, $name, $object ) = @_;

    if ( is_acl( $conf, $name ) ) {
	$acl_need_remove{$name} = 1;
    }
    else {
	$object->{remove} = 1;
    }
}

sub new_name_for {
    my ( $name ) = shift;
    if ( my $new = $new_name{$name} ) {
	return $new;
    }
    else {
	errpr "No new generated name for $name! \n";
    }
}

sub transfer {
    my ( $self, $conf, $spoc, $structure ) = @_;

    $structure ||= $self->define_structure();

    $self->process_routing( $conf, $spoc )
	or return 0;

    # Fill global hash %new_name.
    generate_names_for_transfer( $conf, $spoc, $structure );
	
    $self->unify_anchors( $conf, $spoc, $structure );
	
    if ( !$self->{COMPARE} ) {
	# APPROVE
	$self->mark_connected_objects( $conf, $structure );
	
	$self->enter_conf_mode();
	
	$self->remove_spare_objects_on_device( $conf, $structure );
	
	$self->traverse_netspoc_tree( $spoc, $structure );
	
	$self->remove_unneeded_on_device( $conf, $spoc, $structure );

	$self->leave_conf_mode()
    }

    # STATIC, GLOBAL, NAT
    mypr "\n";
    for my $type ( qw( STATIC GLOBAL NAT ) ) {
	mypr " === processing $type ===\n";
	$self->{CHANGE}->{$type} = 0;
	$self->transfer_lines( $spoc->{$type}, $conf->{$type} )
	    and $self->{CHANGE}->{$type} = 1;
    }

    if ( !$self->{COMPARE} ) {
	# Only write memory on device if there
	# have been changes.
	if ( grep { $_ } values %{ $self->{CHANGE} } ) {
	    mypr "saving config to flash ..... ";
	    $self->cmd('write memory');
	    mypr "done! \n";
	}
	else {
	    mypr "no changes to save \n";
	}
    }	

    return 1;
}

sub define_structure {
    my $self = shift;

    my $structure = {
	ACCESS => {
	    attributes => [ qw( SRC DST TYPE ACL_TYPE MODE ) ],
	    copy_on_modify => 1,
	    transfer => 'transfer_acl',
	    remove   => 'remove_acl',
	},
	OBJECT_GROUP => {
	    attributes => [],
	    transfer => 'transfer_object_group',
	    remove   => 'remove_object_group',
	},
	IF => {
	    anchor => 1,
	    next => [ { attr_name  => 'ACCESS_GROUP_IN',
			parse_name => 'ACCESS', },
		      { attr_name  => 'ACCESS_GROUP_OUT',
			parse_name => 'ACCESS', },
		      ],
	    attributes => [],
	    transfer => 'transfer_interface',
	    remove   => 'remove_interface',
	},
    };

    return $structure;
}



sub cmd_for_attribute {
    my ( $attr ) = @_;
    my $attr_cmd = $attr2cmd{$attr};
    if ( ! $attr_cmd ) {
	errpr "Command not found for attribute $attr! \n";
    }
    return $attr_cmd;
}

sub object_needed {
    my ( $conf, $obj_name, $object ) = @_;
    
    if ( is_acl( $conf, $obj_name ) ) {
	return $acl_needed{$obj_name};
    }
    else {
	return $object->{needed};
    }
}

sub mark_as_changed {
    my ( $self, $parse_name ) = @_;

    return if $parse_name eq 'IF';
    return if $parse_name eq 'CERT_ANCHOR';
    return if $parse_name eq 'DEFAULT_GROUP';

    my $name = $parse_name eq 'ACCESS' ?
	'ACL' : $parse_name;
    $self->{CHANGE}->{$name} = 1;
}

sub mark_as_unchanged {
    my ( $self, $parse_name ) = @_;

    return if $parse_name eq 'IF';
    return if $parse_name eq 'CERT_ANCHOR';
    return if $parse_name eq 'DEFAULT_GROUP';

    my $name = $parse_name eq 'ACCESS' ?
	'ACL' : $parse_name;
    $self->{CHANGE}->{$name} ||= 0;
}

sub acl_removal_cmd {
    my ( $self, $acl_name ) = @_;
    return unless $acl_name;
    return "no access-list $acl_name";
}


# Packages must return a true value;
1;

