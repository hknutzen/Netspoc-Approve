
package Netspoc::Approve::Cisco_FW;

# Authors: Arne Spetzler, Heinz Knutzen, Daniel Brunkhorst
#
# Description:
# Base class for Cisco firewalls (ASA, PIX, FWSM)
#

# VERSION: inserted by DZP::OurPkgVersion

use base "Netspoc::Approve::Cisco";
use strict;
use warnings;
use IO::Socket ();
use Algorithm::Diff;
use Netspoc::Approve::Helper;
use Netspoc::Approve::Parse_Cisco;

# Global variables.

my %define_object = (
		     TUNNEL_GROUP => {
			 prefix  => 'tunnel-group',
			 postfix => 'type remote-access',
		     },
		     TUNNEL_GROUP_IPNAME => {
			 prefix  => 'tunnel-group',
			 postfix => 'type ipsec-l2l',
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
 		       TUNNEL_GROUP_IPNAME_IPSEC => {
			   prefix  => 'tunnel-group',
			   postfix => 'ipsec-attributes',
		       },
		       TUNNEL_GROUP_WEBVPN => {
			   prefix  => 'tunnel-group',
			   postfix => 'webvpn-attributes',
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

my %attr2cmd = 
    (
     USERNAME => {
	 VPN_FILTER                => 'vpn-filter value',
	 VPN_GROUP_POLICY          => 'vpn-group-policy',
     },
     GROUP_POLICY => {
	 SPLIT_TUNNEL_NETWORK_LIST => 'split-tunnel-network-list value',
	 ADDRESS_POOL              => 'address-pools value',
	 VPN_FILTER                => 'vpn-filter value',
     },
     TUNNEL_GROUP => {
	 DEFAULT_GROUP_POLICY      => 'default-group-policy',
     },
     DEFAULT_GROUP => {
	 TUNNEL_GROUP		  => 'tunnel-group-map',
     },
     CA_CERT_MAP => {
	 IDENTIFIER                => 'subject-name attr',
     },
     IP_LOCAL_POOL => {
	 IP_LOCAL_POOL             => 'ip local pool',
     },
     CRYPTO_MAP_SEQ => {
	 DYNAMIC_MAP		  => 'ipsec-isakmp dynamic',
	 MATCH_ADDRESS		  => 'match address',
	 NAT_T_DISABLE		  => 'set nat-t-disable',
	 PEER			  => 'set peer',
	 PFS 			  => 'set pfs',
	 REVERSE_ROUTE		  => 'set reverse-route',
	 SA_LIFETIME_SEC	  => 'set security-association lifetime seconds',
	 SA_LIFETIME_KB		  => 'set security-association lifetime kilobytes',
	 TRANSFORM_SET		  => 'set transform-set',
	 TRANSFORM_SET_IKEV1	  => 'set ikev1 transform-set',
	 TRUSTPOINT		  => 'set trustpoint',
     },
     );

my %attr_no_value = (
		     # crypto map
		     NAT_T_DISABLE => 1,
		     REVERSE_ROUTE => 1,
		     );

my %attr_need_remove = (
			# GROUP_POLICY
			banner                => 1,
			'vpn-tunnel-protocol' => 1,
			# CRYPTO_MAP_SEQ
			PEER          => 1,
			TRANSFORM_SET => 1,
			);
		      

sub get_parse_info {
    my ($self) = @_;
    my $null = {
	'BASE' => 0,
	'MASK' => 0
	};
    { 

	# To enable the association of a name with an IP address.
	# This interferes with parsing of ACL and object-groups.
	names => {
	    error => "'names' command must be disabled with 'no names'",
	},

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
			['cond1',
			 { parse => qr/netmask/ },
			 { store => 'NETMASK', parse => \&get_ip } ]]]] },

# PIX and ASA pre 8.4
####
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
		       ['cond1',
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
#		       { store => 'INTERFACE', parse => qr/interface/ },
		       { store => 'GLOBAL_IP', parse => \&get_ip } ],
		      ['cond1',
		       { parse => \&test_ne, params => ['ip', '$TYPE'] },
		       { store => 'GLOBAL_PORT', 
			 parse => 'parse_port', params => ['$TYPE'] } ],
		      ['or',
#		       ['cond1',
#			{ parse => qr/access-list/ },
#			{ store => 'ACCESS_LIST', parse => \&get_token } ],
		       ['seq',
			{ store => 'LOCAL_IP', parse => \&get_ip },
			['cond1',
			 { parse => \&test_ne, params => ['ip', '$TYPE'] },
			 { store => 'LOCAL_PORT', 
			   parse => 'parse_port', params => ['$TYPE'] } ],
			['cond1',
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
		      { store => 'DNS', parse => qr/dns/ },
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

# access-group <access_list_name> {in|out} interface <if_name>
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
	'object-group network' => {
	    store => 'OBJECT_GROUP',
	    named => 1,
            parse => ['seq', { store => 'TYPE', default => 'network', },],
	    subcmd => {
		'network-object' => {
		    store => 'OBJECT', 
		    multi => 1,
		    parse => 'parse_address',
		},
		'group-object' => { 
		    error => 'Nested object group not supported' 
                },
            }
        },
	'object-group service _skip tcp' => {
	    store => 'OBJECT_GROUP',
	    named => 1,
            parse => ['seq', { store => 'TYPE', default => 'tcp', },],
	    subcmd => {
                'port-object' => {
		    store => 'OBJECT', 
                    multi => 1,
                    parse => 'parse_port_spec', params => ['tcp'],
                },
		'group-object' => { 
		    error => 'Nested object group not supported' 
                },
            }
        },
	'object-group service _skip udp' => {
	    store => 'OBJECT_GROUP',
	    named => 1,
            parse => ['seq', { store => 'TYPE', default => 'udp', },],
	    subcmd => {
                'port-object' => {
		    store => 'OBJECT', 
                    multi => 1,
                    parse => 'parse_port_spec', params => ['udp'],
                },
		'group-object' => { 
		    error => 'Nested object group not supported' 
                },
            }
        },
	'object-group service _skip tcp-udp' => {
	    store => 'OBJECT_GROUP',
	    named => 1,
            parse => ['seq', { store => 'TYPE', default => 'tcp-udp', },],
	    subcmd => {
                'port-object' => {
		    store => 'OBJECT', 
                    multi => 1,
                    parse => 'parse_port_spec', params => ['tcp-udp'],
                },
		'group-object' => { 
		    error => 'Nested object group not supported' 
                },
            }
        },
	'object-group service' => {
	    store => 'OBJECT_GROUP',
	    named => 1,
            parse => ['seq', { store => 'TYPE', default => 'service', },],
	    subcmd => {
                'service-object' => {
                    store => 'OBJECT',
                    multi => 1,
                    parse => 
                        ['or',
                         ['cond1', { store => 'TYPE', parse => qr/ip/ }, ],
                         ['cond1',
                          { store => 'TYPE', parse => qr/udp|tcp|tcp-udp/ },
                          { store => 'PORT', 
                            parse => 'parse_port_spec', params => ['$TYPE'] } ],
                        ['cond1',
                         { store => 'TYPE', parse => qr/icmp/ },
                         { store => 'SPEC', parse => 'parse_icmp_spec' }, ]],
                },
		'group-object' => { 
		    error => 'Nested object group not supported' 
                },
	    }
	},
        'object-group protocol' => {
            store => 'OBJECT_GROUP',
	    named => 1,
            parse => ['seq', { store => 'TYPE', default => 'protocol', },],
	    subcmd => {
                'protocol-object' => {
                    store => 'OBJECT',
                    multi => 1,
                    parse => 
                        ['seq',
                         { store => 'TYPE', parse => \&get_token },
                         { store => 'TYPE' ,
                           parse => 'normalize_proto', params => [ '$TYPE' ] },
                        ],
                }
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
		 ['cond1',
		  { parse => qr/deny-flow-max|alert-interval/ },
		  { parse => \&get_int } ],
		 ['seq',
		  { store => 'name', parse => \&get_token },
		  ['or',

		   # ignore 'access-list <name> compiled'
		   # ignore 'access-list <name> remark ...'
		   { parse => qr/compiled/ },
		   ['cond1',
		    { parse => qr/remark/ },
		    { parse => \&skip } ],
		   
		   ['or', # standard or extended access-list
		    ['cond1',
		     { store => 'ACL_TYPE', parse => qr/standard/ },
		     { store => 'MODE', parse => qr/permit|deny/  },
		     { store => 'DST',  parse => 'parse_address'  },
		     { store => 'SRC',  default => $null          },
		     { store => 'TYPE', default => 'ip'           },
		     ],
		    ['seq',
		     { store => 'ACL_TYPE',
		       parse => qr/extended/, default => 'extended' },
		     { store => 'MODE', parse => qr/permit|deny/ },
		     ['or',
		      ['cond1',
		       { store => 'TYPE', parse => qr/ip/ },
		       { store => 'SRC', parse => 'parse_address' },
		       { store => 'DST', parse => 'parse_address' } ],
		      ['cond1',
                       ['or',
                        { store => 'TYPE', parse => qr/udp|tcp/ },
                        { store => 'TYPE', parse => 'parse_object_group' },
                       ],
		       { store => 'SRC', parse => 'parse_address' },
		       { store => 'SRC_PORT',

                         # We don't support object-group for source port,
                         # because this would eat the value for DST.
			 parse => 'parse_port_spec', params => ['$TYPE'] },
		       { store => 'DST', parse => 'parse_address' },
		       { store => 'DST_PORT', 
			 parse => 'parse_og_port_spec', params => ['$TYPE'] } ],
		      ['cond1',
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
		     ['cond1',
		      { store => 'LOG', parse => qr/log/ },
		      ['or',
		       { store => 'LOG_MODE', parse => qr/disable|default/ },
		       ['seq',
			{ store => 'LOG_LEVEL', 
			  parse => \&check_int, default => 6 },
			['cond1',
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
# crypto map map-name seq-num ipsec-isakmp dynamic WORD
# crypto map map-name seq-num set nat-t-disable
# crypto map map-name seq-num set peer {Hostname|A.B.C.D}+
# crypto map map-name seq-num set pfs [group1|group2|group5|group7]
# crypto map map-name seq-num set reverse-route
# crypto map map-name seq-num set security-association lifetime {kilobytes|seconds} N
# crypto map map-name seq-num set [ikev1] transform-set WORD
# crypto map map-name seq-num set trustpoint WORD
# 
# crypto map map-name interface intf_name
#
# Ignore:
#  crypto map map-name client


	'crypto map' => {
	    store => ['CRYPTO_MAP'],
	    named => 'from_parser',
	    merge => 1,
	    parse => ['seq',
		      { store => 'name', parse => \&get_token },
		      ['or',
		       ['cond1',
			{ parse => qr/client/ },
			{ parse => \&skip } ],
		       ['cond1',
			{ parse => qr/interface/ },
			{ store => 'INTERFACE', parse => \&get_token } ],
		       ['seq',
			{ store => 'name', 
			  parse => sub { my ($arg, $name) = @_;
					 my $seq = get_int($arg);
					 join(':', $name, $seq);
				     },
			  params => [ '$name' ], },
			['or',
			 ['cond1',
			  { parse => qr/match/ },
			  { parse => qr/address/ },
			  { store => 'MATCH_ADDRESS', parse => \&get_token } ],

			 ['cond1',
			  { parse => qr/ipsec-isakmp/ },
			  { parse => qr/dynamic/ },
			  { store => 'DYNAMIC_MAP', parse => \&get_token } ],
			 # Old PIX has other syntax.
#			  { parse => qr/dynamic/ },
#			  { store => 'DYNAMIC_MAP', parse => \&get_token } ],

			 ['seq',
			  { parse => qr/set/ },
			  ['or',
			   { parse => qr/nat-t-disable/,
			     store => 'NAT_T_DISABLE', },
			   ['cond1',
			    { parse => qr/peer/ },
			    { store => 'PEER', parse => \&get_to_eol } ],
			   ['cond1',
			    { parse => qr/pfs/ },
			    { store => 'PFS', parse => \&check_token, 
			      default => 'group2' } ],
			   { parse => qr/reverse-route/, 
			     store => 'REVERSE_ROUTE',  },
			   ['cond1',
			    { parse => qr/security-association/ },
			    { parse => qr/lifetime/ },
			    ['seq',
			     ['cond1',
			       { parse => qr/seconds/ },
			       { parse => \&get_int, 
				 store => 'SA_LIFETIME_SEC', } ],
			     ['cond1',
			      { parse => qr/kilobytes/ },
			      { parse => \&get_int, 
				store => 'SA_LIFETIME_KB', }, ]]],
			   [ 'or',
			   ['cond1',
			    { parse => qr/ikev1/ },
			    { parse => qr/transform-set/ },
			    { parse => \&get_token,
			      store => 'TRANSFORM_SET_IKEV1' } ],
			   ['cond1',
			      { parse => qr/transform-set/ },
			      { parse => \&get_token,
				store => 'TRANSFORM_SET' } ]],
			   ['cond1',
			    { parse => qr/trustpoint/ },
			    { parse => \&get_token,
			      store => 'TRUSTPOINT', } ]]]]]]]
	},
    }
}

sub postprocess_config {
    my ($self, $p) = @_;

    # For each access list, change array of access list entries to
    # hash element with attribute 'LIST'.
    # This simplifies later processing because we can add 
    # auxiliary elements to the hash element.
    my $access_lists = $p->{ACCESS_LIST};
    my $object_groups =  $p->{OBJECT_GROUP};
    for my $acl_name (keys %$access_lists) {
	my $entries = $access_lists->{$acl_name};
	$access_lists->{$acl_name} = { name => $acl_name, LIST => $entries };
        
        # Change object-group NAME to object-group OBJECT in ACL entries.
        for my $entry (@$entries) {
            for my $where (qw(TYPE SRC DST SRC_PORT DST_PORT)) {
                my $what = $entry->{$where};
                my $group_name = ref($what) && $what->{GROUP_NAME} or next;
                my $group = $object_groups->{$group_name} or
                    abort("Can't find OBJECT_GROUP $group_name" .
                          " referenced by $acl_name");
                $what->{GROUP} = $group;
            }
        }
    }

    # Link interfaces to access lists via attribute ACCESS_GROUP_XXX.
    for my $access_group (values %{$p->{ACCESS_GROUP}}) {
	my $acl_name = $access_group->{name};
	my $attr = 'ACCESS_GROUP_' . uc($access_group->{TYPE});

	# Create in- or out-access-group on interface.
	# Create artificial interface if necessary.
	my $if_name  = $access_group->{IF_NAME};
	my $intf = $p->{IF}->{$if_name} ||= { name => $if_name };
	$intf->{$attr} = $acl_name;
    }

    # We don't need "ACCESS_GROUP" anymore ...
    delete $p->{ACCESS_GROUP};

    # Separate "crypto map name seq" vs. "crypto map name interface"
    # "name seq" is stored with key "name:seq".
    my @no_crypto_seq = grep { $_ !~ /:/ } keys %{$p->{CRYPTO_MAP}};
    my $seq = $p->{CRYPTO_MAP_SEQ} = delete $p->{CRYPTO_MAP};
    my $map = $p->{CRYPTO_MAP} = {};
    for my $key (@no_crypto_seq) {
	$map->{$key} = delete $seq->{$key};
    }

    # Add entries of CRYPTO_MAP_SEQ to attribute PEER of artificial
    # anchor CRYPTO_MAP_LIST.
    my $lists = $p->{CRYPTO_MAP_LIST} = {};
    my %peers;
    for my $name (keys %$seq) {
	my ($map_name, $seq_nr) = split(/:/, $name);
	my $map = $p->{CRYPTO_MAP_SEQ}->{$name};
	my $peer = $map->{PEER} || $map->{DYNAMIC_MAP} or 
	    abort("Missing peer or dynamic in crypto map $map_name $seq_nr");
	$map->{SEQ} = $seq_nr;
	$peers{$peer} and 
	    abort("Duplicate peer or dynamic $peer in" .
                  " crypto map $map_name $seq_nr");
	$peers{$peer} = $map;
	push @{ $lists->{$map_name}->{PEERS} }, $name;
    }

    # Some statistics.
    for my $key (%$p) {
	my $v = $p->{$key};
	my $count = (ref $v eq 'ARRAY') ? @$v : keys %$v;
	info("Found $count $key") if $count;
    }
}

sub dev_cor ($$) {
    my ($self, $addr) = @_;
    return $addr;
}

sub parse_object_group  {
    my ($self, $arg) = @_;
    if(check_regex('object-group', $arg)) {
	return { GROUP_NAME => get_token($arg) };
    }
    else {
        return undef;
    }
}

sub parse_address {
    my ($self, $arg) = @_;
    return 
        $self->parse_object_group($arg) || $self->SUPER::parse_address($arg);
}

sub parse_og_port_spec {
    my ($self, $arg, $type) = @_;
    return 
        $self->parse_object_group($arg) || 
        $self->SUPER::parse_port_spec($arg, $type);
}

##############################################################
my @known_status =
    (
     # for write memory
     qr/^Building configuration/,
     qr/^Cryptochecksum:/,
     qr/^\d+ bytes copied in /,
     qr/^\s*$/, # empty line
     qr/^\[OK\]/,
     # identity nat
     qr/will be identity translated for outbound/,
     # identity nat
     qr/nat 0 0.0.0.0 will be non-translated/,
     # PAT
     qr/Global \d+\.\d+\.\d+\.\d+ will be Port Address Translated/,
     # global (xxx) interface
     # PIX: "xxx interface address added to PAT pool"
     # ASA: "INFO: xxx interface address added to PAT pool"
     qr/interface address added to PAT pool/,
     # ASA: general info
     qr/^INFO:/,
      );

my @known_warning = 
    (
     # overlapping statics from netspoc
     qr/overlapped\/redundant/,
     # overlapping statics with global from netspoc
     qr/static overlaps/,
     # route warnings
     qr/Route already exists/,
     # object-group warnings
     qr/Adding obj \([^()]+\) to grp \([^()]+\) failed; object already exists/,
     # ace warnings
     qr/ACE not added[.] Possible duplicate entry/,
     # general warnings
     qr/^WARNING:/,
     );

sub cmd_check_error {
    my ($self, $cmd, $lines) = @_;

    # Check unexpected lines:
    # - known status messages
    # - known warning messages
    # - unknown messages, handled as error messages.
    my @err_lines;
  LINE:
    for my $line (@$lines) {
	for my $regex (@known_status) {
	    if($line =~ $regex) {
		next LINE;
	    }
	}
	for my $regex (@known_warning) {
	    if($line =~ $regex) {
                warn_info($line);
		next LINE;
	    }
	}
	push @err_lines, "$cmd: $line\n";
    }
    abort(@err_lines) if @err_lines;
}

sub get_identity {
    my ($self) = @_;
    my $name = $self->SUPER::get_identity();
    
    # Ignore customized prompt extensions following the first slash "/".
    $name =~ s(/.*)();
    return($name);
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

sub parse_version {
    my ($self) = @_;
    my $output = $self->shcmd('sh ver');
    if($output =~ /Version +(\d+\.\d+)/i) {	
	$self->{VERSION} = $1;
    }
    if($output =~ /Hardware:\s+(\S+),/i) {	
	$self->{HARDWARE} = $1;
    }
}

# Set terminal length and width
sub set_terminal {
    my ($self) = @_;

    # Check pager settings.
    my $output = $self->shcmd('sh pager');
    if ($output !~ /no pager/) {
	$self->set_pager();
    }

    # Max. term width is 511 for PIX.
    $output = $self->shcmd('sh term');
    if ($output !~ /511/) {
        abort("Terminal width should be 511");
    }
}

sub get_config_from_device( $ ) {
    my ($self) = @_;
    my $cmd = 'write term';
    my $output = $self->shcmd($cmd);
    my @conf = split(/\r\n/, $output);
    my $echo = shift(@conf);
    $echo =~ /^\s*$cmd\s*$/ or 
	abort("Got unexpected echo in response to '$cmd': '$echo'");
    return(\@conf);
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

sub transfer_lines {
    my ($self, $conf, $spoc, $type) = @_;
    my %equal;
    my $conf_lines = $conf->{$type} || [];
    my $spoc_lines = $spoc->{$type} || [];
    for my $d (@{$conf_lines}) { 
        for my $s (@{$spoc_lines}) {
            if ($self->attr_eq($d, $s)) {
                $equal{$d} = $equal{$s} = 1;
                last;
            }
        }
    }
    for my $d (@{$conf_lines}) {
        $self->{CHANGE}->{$type} ||= 0;
	$equal{$d} and next;
        $self->{CHANGE}->{$type} = 1;
	$self->cmd("no $d->{orig}");
    }
    for my $s (@{$spoc_lines}) {
	$equal{$s} and next;
        $self->{CHANGE}->{$type} = 1;
	$self->cmd($s->{orig});
    }
}

sub add_object_lines {
    my ($self, $conf, $spoc) = @_;
    my $conf_hash = $conf->{OBJECT} || {};
    my $spoc_hash = $spoc->{OBJECT} || {};
    for my $name (keys %$spoc_hash) { 
        $self->{CHANGE}->{OBJECT} ||= 0;
        next if $conf_hash->{$name};
        $self->{CHANGE}->{OBJECT} = 1;
        my $value = $spoc_hash->{$name};

        # Code from Netspoc contains line number for some commands.
	$self->cmd($value->{orig});
        for my $type (qw(SUBNET RANGE HOST)) {
            if (my $subcmd = $value->{$type}) {
                $self->cmd($subcmd->{orig});
                last;
            }
        }
    }
}

sub delete_object_lines {
    my ($self, $conf, $spoc) = @_;
    my $conf_hash = $conf->{OBJECT} || {};
    my $spoc_hash = $spoc->{OBJECT} || {};
    for my $name (keys %$conf_hash) { 
        $self->{CHANGE}->{OBJECT} ||= 0;
        next if $spoc_hash->{$name};
        $self->{CHANGE}->{OBJECT} = 1;
	$self->cmd("no $conf_hash->{$name}->{orig}");
    }
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
	next if $structure->{$parse_name}->{anchor};
	next if $parse_name eq 'CRYPTO_MAP_SEQ';
	my $hash = $spoc->{$parse_name};
	for my $name ( keys %$hash ) {
	    next if ($parse_name eq 'TUNNEL_GROUP'
		     && $name eq 'DefaultL2LGroup');
	    $hash->{$name}->{new_name} =
		$generate_names_for_transfer->( $name, $conf->{$parse_name} );
	}
    }
}

sub equalize_attributes {
    my ( $self, $conf_value, $spoc_value,
	 $parse_name, $structure ) = @_;

    my $modified;
    my $parse = $structure->{$parse_name};
    if ( not ( $structure && $parse_name ) ) {
	internal_err "Structure or parse_name not defined";
    }

    # Equalize "normal" (normal=non-next) attributes.
    for my $attr ( @{$parse->{attributes}} ) {
	my $spoc_attr = $spoc_value->{$attr};
	my $conf_attr = $conf_value->{$attr};
	if ( $spoc_attr  &&  $conf_attr ) { 

	    # Attribute present on both.
	    # Value is either a scalar which can be compared directly
	    # or a hash, which is compared pairwise.
	    if (ref $spoc_attr) {
		my %seen;
		for my $cmd (keys %$spoc_attr) {
		    my $new = $spoc_attr->{$cmd};
		    if (defined (my $conf_args = $conf_attr->{$cmd})) {
			$seen{$cmd} = 1;
			if ($new ne $conf_args) {
			    $modified = 1;
			    $spoc_value->{change_attr}->{$attr}->{$cmd} = $new;
			}
		    }
		    else {
			$modified = 1;
			$spoc_value->{change_attr}->{$attr}->{$cmd} = $new;
		    }
			
		}
		for my $cmd (keys %$conf_attr) {
		    next if $seen{$cmd};
		    my $args = $spoc_attr->{$cmd};
		    $conf_value->{remove_attr}->{$attr}->{$cmd} = $args;
		}
	    }
	    else {
		if ( $spoc_attr ne $conf_attr ) {
		    $modified = 1;
		    $spoc_value->{change_attr}->{$attr} = $spoc_attr;
		}
	    }
	}
	elsif ( $spoc_attr  &&  ! $conf_attr ) {
	    #info("Attribute $attr present only in netspoc. ");
	    $modified = 1;
	    $spoc_value->{change_attr}->{$attr} = $spoc_attr;
	}
	elsif ( ! $spoc_attr  &&  $conf_attr ) {
	    #info("Attribute $attr present only on device. ");
	    $modified = 1;
	    $conf_value->{remove_attr}->{$attr} = $conf_attr;
	}
	else {
	    #warn_info("Attribute '$attr' not on device and not in Netspoc");
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

my %object2key_sub = (
    network => sub { my ($e) = @_; "$e->{BASE}/$e->{MASK}"; },
    tcp     => sub { my ($e) = @_; "$e->{LOW}/$e->{HIGH}"; },
    udp     => sub { my ($e) = @_; "$e->{LOW}/$e->{HIGH}"; },
    'tcp-udp' => sub { my ($e) = @_; "$e->{LOW}/$e->{HIGH}"; },
    service => sub { 
        my ($e) = @_;
        my $r = $e->{TYPE};
        if ($e->{TYPE} eq 'icmp') {
            my $s = $e->{SPEC};
            for my $where (qw(TYPE CODE)) {
                my $v = $s->{TYPE};
                $r .= defined $v ? $v : '-';
            }
        }
        elsif ($e->{TYPE} =~ /^(?:tcp|udp)/) {
	    my $port = $e->{PORT};
	    $r .= "$port->{LOW}:$port->{HIGH}";
	}
        $r;
    },
    protocol => sub { my ($e) = @_; $e->{TYPE} },
);

sub sort_object_group {
    my ($group) = @_;
    my $aref = $group->{OBJECT};
    my $type = $group->{TYPE};
    my $sub = $object2key_sub{$type};
    return [ map { $_->[0] }
             sort { $a->[1] cmp $b->[1] }
             map { [ $_, $sub->($_) ] }
             @$aref ];
}

# Return value: Bool, is group-name modified or not.
sub equalize_obj_group {
    my($self, $conf_group, $spoc_group) = @_;

    # Current group from netspoc is already available on device.
    # No need to transfer the group.
    # But access-list must be changed in this situation:
    # conf     spoc
    # g1-drc0  g1
    # g2-drc0  g1
    if(my $other_conf_group_name = $spoc_group->{name_on_dev}) {
	# Change has already been marked.
	if($conf_group->{name} ne $other_conf_group_name) {
	    info(" ACL changes because $conf_group->{name} and",
                 " $other_conf_group_name are merged to $spoc_group->{name}");
	    return 1;
	}
	else {
	    return 0;
	}
    }

    # Current group on device has already been marked as needed.
    # conf     spoc
    # g1-drc0  g1
    # g1-drc0  g2
    # Don't change group on device twice.
    if(my $other_spoc_group = $conf_group->{needed}) {
	$spoc_group->{transfer} = 1;
	$self->mark_as_changed('OBJECT_GROUP');
	info(" ACL changes because $conf_group->{name} is split",
             " into $spoc_group->{name} and $other_spoc_group->{name}");
	return 1;
    }	

    if ($conf_group->{TYPE} ne $spoc_group->{TYPE}) {
	info(" ACL changes because $conf_group->{name} and",
             " $spoc_group->{name} have different type");
	return 1;
    }

    # Sort entries before finding diffs.
    # Order doesn't matter and
    # order is disturbed later by incremental update.
    my $conf_networks = sort_object_group($conf_group);
    my $spoc_networks = sort_object_group($spoc_group);
    my $type = $conf_group->{TYPE};
    my $address2key = $object2key_sub{$type};
    my $diff = Algorithm::Diff->new( $conf_networks, $spoc_networks,  
				     { keyGen => $address2key } );

    # Check, if identical or how many changes needed.
    my $change_lines = 0;
    while($diff->Next()) {
	if($diff->Diff()) {
	    $change_lines += $diff->Items(1);
	    $change_lines += $diff->Items(2);
	}
    }

    # Take group from device.
    if(not $change_lines) {
	$spoc_group->{name_on_dev} = $conf_group->{name};
	$conf_group->{needed} = $spoc_group;
	$self->mark_as_unchanged('OBJECT_GROUP');
	if($spoc_group->{transfer}) {
	    info(" Canceled transfer of $spoc_group->{name},",
                 " because $conf_group->{name} was found on device");
	    undef $spoc_group->{transfer};
	}
	return 0;
    }

    # Take group from netspoc.
    elsif($change_lines >= @$spoc_networks) {
	$spoc_group->{transfer} = 1;
	$self->mark_as_changed('OBJECT_GROUP');
	info(" ACL changes because $spoc_group->{name} is transferred");
	return 1;
    }

    # Change group on device.
    $spoc_group->{name_on_dev} = $conf_group->{name};
    $conf_group->{needed} = $spoc_group;
    $diff->Reset();
    while($diff->Next()) {
	next if($diff->Same());
	push(@{$spoc_group->{del_entries}}, $diff->Items(1));
	push(@{$spoc_group->{add_entries}}, $diff->Items(2));
    }			    
    $self->mark_as_changed('OBJECT_GROUP');
    info(" $conf_group->{name} is changed to values of $spoc_group->{name}");
    if($spoc_group->{transfer}) {
	info(" Canceled transfer of $spoc_group->{name},",
             " because $conf_group->{name} now has its values");
	undef $spoc_group->{transfer};
    }
    return 0;
}

sub check_object_group {
    my ($attr) = @_;
    (ref($attr) && $attr->{GROUP}) ? 'object-group' : undef;
}

# Build textual representation from ACL entry for use with Algorithm::Diff.
# Ignore name of object-group. Object-groups are compared semantically later.
sub acl_entry2key {
    my ($e) = @_;
    my @r;
    push(@r, $e->{MODE});
    for my $where (qw(SRC DST)) {
	my $what = $e->{$where};
	push(@r, check_object_group($what) || "$what->{BASE}/$what->{MASK}");
    }
    push(@r, check_object_group($e->{TYPE}) || $e->{TYPE});
    if ($e->{TYPE} eq 'icmp') {
        my $s = $e->{SPEC};
	for my $where (qw(TYPE CODE)) {
	    my $v = $s->{TYPE};
	    push(@r, defined $v ? $v : '-');
	}
    }
    elsif ($e->{TYPE} eq 'tcp' or $e->{TYPE} eq 'udp') {
	for my $where (qw(SRC_PORT DST_PORT)) {
	    my $port = $e->{$where};
	    push(@r, check_object_group($port) || "$port->{LOW}:$port->{HIGH}");
	}
	push(@r, 'established') if $e->{ESTA};
    }
    if($e->{LOG}) {
	push(@r, 'log');
	push(@r, $e->{LOG_MODE}) if $e->{LOG_MODE};
	push(@r, $e->{LOG_LEVEL}) if $e->{LOG_LEVEL};
	push(@r, "interval $e->{LOG_INTERVAL}") if $e->{LOG_INTERVAL};
    }
    return join(' ', @r);
}

sub equalize_acl {
    my($self, $conf_acl, $spoc_acl) = @_;
    my $conf_entries = $conf_acl->{LIST};
    my $spoc_entries = $spoc_acl->{LIST};
    my $modified;
    my $diff = Algorithm::Diff->new( $conf_entries, $spoc_entries, 
				     { keyGen => \&acl_entry2key } );
    while($diff->Next()) {

	# ACL lines are equal, but object-group may change.
	if($diff->Same()) {
	    my $conf_min = $diff->Min(1);
	    my $count = $diff->Max(1) - $conf_min;
	    my $spoc_min = $diff->Min(2);
	    for my $i (0 .. $count) {
		my $conf_entry = $conf_entries->[$conf_min+$i];
		my $spoc_entry = $spoc_entries->[$spoc_min+$i];
		for my $where (qw(TYPE SRC DST SRC_PORT DST_PORT)) {
                    my $what = $conf_entry->{$where};
		    if(my $conf_group = ref($what) && $what->{GROUP}) {
                        $what = $spoc_entry->{$where};
			my $spoc_group = ref($what) && $what->{GROUP};
			if($self->equalize_obj_group($conf_group, $spoc_group))
			{
			    $modified = 1;
			}
			else {
			    $self->mark_as_unchanged('OBJECT_GROUP');
			}
		    }
		}
	    }
	}

	# ACL lines differ.
	else {
	    $modified = 1;

	    # Mark object-groups referenced by acl lines from spoc 
	    # but not on device.
	    for my $spoc_entry ($diff->Items(2)) {
		for my $where (qw(TYPE SRC DST SRC_PORT DST_PORT)) {
                    my $what = $spoc_entry->{$where};
		    if(my $spoc_group = ref($what) && $what->{GROUP}) {
			if(not $spoc_group->{name_on_dev}) {
			    $spoc_group->{transfer} = 1;
			    $self->mark_as_changed('OBJECT_GROUP');
			}
		    }
		}
	    }

	    if(my $count = $diff->Items(1)) {
		info(" $count extra lines on device");
	    }
	    if(my $count = $diff->Items(2)) {
		info(" $count extra lines from Netspoc");
	    }
	}
    }
    return $modified;
}

# PEER value is IP address.
# DYNAMIC_MAP value is name.
sub by_peer {
    return 
	($a->{PEER} || $a->{DYNAMIC_MAP}) cmp 
	($b->{PEER} || $b->{DYNAMIC_MAP});
}

sub crypto_entry2key {
    my ( $e ) = @_;
    return $e->{PEER} || $e->{DYNAMIC_MAP};
}

# Find next free sequence number in entries of some crypto map on device.
sub get_free_seq_nr {
    my ( $conf_entries, $start, $increment ) = @_;
    while (grep { $_->{SEQ} == $start } @$conf_entries) {
	$start += $increment;
    }
    return $start;
}

sub equalize_crypto {
    my ( $self, $conf, $spoc, $conf_crypto, $spoc_crypto, $structure ) = @_;

    my $conf_entries = [ sort by_peer 
			 map(object_for_name($conf, 'CRYPTO_MAP_SEQ', $_),
			     @{$conf_crypto->{PEERS}}) ];
    my $spoc_entries = [ sort by_peer 
			 map(object_for_name($spoc, 'CRYPTO_MAP_SEQ', $_),
			     @{$spoc_crypto->{PEERS}}) ];

    my $modified;
    
    my $diff = Algorithm::Diff->new( $conf_entries, $spoc_entries, 
				     { keyGen => \&crypto_entry2key } );

    # Try this sequence number for next to be added entry.
    my $peer_seq = 1;
    my $dyn_seq = 65535;
    
    while ( $diff->Next() ) {

	# Peer is equal, but other attributes may have changed.
	if ($diff->Same()) {
	    my $conf_min = $diff->Min(1);
	    my $count = $diff->Max(1) - $conf_min;
	    my $spoc_min = $diff->Min(2);
	    for my $i (0 .. $count) {
		my $conf_entry = $conf_entries->[$conf_min+$i];
		my $spoc_entry = $spoc_entries->[$spoc_min+$i];
		$self->make_equal($conf, $spoc, 'CRYPTO_MAP_SEQ',
				  $conf_entry->{name}, $spoc_entry->{name},
				  $structure);
	    }
	    next;
	}
	
	$modified = 1;

	# On spoc but not on device.
	for my $spoc_entry ( $diff->Items(2) ) {
	    my $spoc_name = $spoc_entry->{name};
	    my ($map_name) = split(/:/, $spoc_name);
	    if ($spoc_entry->{PEER}) {
		$peer_seq = get_free_seq_nr($conf_entries, $peer_seq, +1);
		$spoc_entry->{new_name} = "$map_name:$peer_seq";
		$peer_seq += 1;
	    }
	    else {
		$dyn_seq = get_free_seq_nr($conf_entries, $dyn_seq, -1);
		$spoc_entry->{new_name} = "$map_name:$dyn_seq";
		$dyn_seq -= 1;
	    }
	    $self->make_equal($conf, $spoc, 'CRYPTO_MAP_SEQ',
			      undef, $spoc_name, $structure);
	}
	
	if ( my $count = $diff->Items(1) ) {
	    info(" CRYPTO: $count extra lines on device");
	}
	if ( my $count = $diff->Items(2) ) {
	    info(" CRYPTO: $count extra lines from Netspoc");
	}
    }
    return $modified;
}

sub make_equal {
    my ( $self, $conf, $spoc, $parse_name, $conf_name,
	 $spoc_name, $structure ) = @_;

    return undef unless ( $spoc_name  ||  $conf_name );

#    info("MAKE EQUAL( $parse_name ) => CONF:$conf_name, SPOC:$spoc_name ");

    my $modified;
    my $conf_value = object_for_name( $conf, $parse_name,
				      $conf_name, 'no_err' );
    my $spoc_value = object_for_name( $spoc, $parse_name,
				      $spoc_name, 'no_err' );

    # If object already has been tranfered before, just
    # return the name of the transfered object.
    if ( $spoc_value ) {
	if ( $spoc_value->{transfer} ) {
	    return $spoc_value->{new_name} || $spoc_name;
	}
	elsif( $spoc_value->{name_on_dev} ) {
	    return $spoc_value->{name_on_dev};
	}
    }

    # Transfer object from netspoc
    # - if no matching object is found on device or
    # - if matching object is already needed in other context and 
    #   must not be changed.
    if ( $spoc_value && (!$conf_value || $conf_value && $conf_value->{needed}) ) {

#	info("$parse_name => $spoc_name on spoc but not on dev. ");
	$modified = 1;
	$spoc_value->{transfer} = 1;

	# Mark object-groups referenced by acl lines.
	if ( $parse_name eq 'ACCESS_LIST' ) {

	    for my $spoc_entry (@{ $spoc_value->{LIST} }) {
		for my $where (qw(TYPE SRC DST SRC_PORT DST_PORT)) {
                    my $what = $spoc_entry->{$where};
		    if(my $spoc_group = ref($what) && $what->{GROUP}) {
			if(not $spoc_group->{name_on_dev}) {
			    $spoc_group->{transfer} = 1;
			    $self->mark_as_changed('OBJECT_GROUP');
			}
		    }
		}
	    }
	}

	# Mark referenced CRYPTO_MAP_SEQ elements.
	elsif ( $parse_name eq 'CRYPTO_MAP_LIST' ) {
	    for my $peer_name (@{ $spoc_value->{PEERS} }) {
		$self->make_equal($conf, $spoc, 'CRYPTO_MAP_SEQ',
				  undef, $peer_name, $structure);
	    }	    
	}
    }

    # Compare object on device with object from Netspoc.
    elsif ( $conf_value && $spoc_value ) {
	# On both, compare attributes.
	if ( $parse_name eq 'ACCESS_LIST' ) {
	    info("Comparing $conf_name $spoc_name");
	    if ($modified = $self->equalize_acl($conf_value, $spoc_value)) {
		$spoc_value->{transfer} = 1;
	    }
	    else {
		$conf_value->{needed} = $spoc_value;
		$spoc_value->{name_on_dev} = $conf_name;
	    }
	}
	elsif ( $parse_name eq 'CRYPTO_MAP_LIST' ) {
	    $modified = $self->equalize_crypto( $conf, $spoc, 
						$conf_value, $spoc_value,
						$structure );
	}
	else {
	    # String-compare and mark changed attributes.
	    $modified = $self->equalize_attributes( $conf_value, $spoc_value,
						    $parse_name, $structure );
	    $conf_value->{needed} = $spoc_value;
	    $spoc_value->{name_on_dev} = $conf_name;
	}

	# If this object was previously marked for transfer,
	# remove the mark, because we now know, that the object is already
	# available on device.
	if($spoc_value->{name_on_dev}) {

## Currently dangerous, because {new_name} has already been used.
#	    undef $spoc_value->{transfer};
	}
    }

    # On dev but not on spoc. Unused, will be removed later.
    elsif ( $conf_value  &&  !$spoc_value ) {
#	info("$parse_name => $conf_name on dev but not on spoc. ");
	$modified = 1;
    }

    # Process child nodes recursively.
    if ( my $parse = $structure->{$parse_name} ) {

	# Attention: {next_list} is not handled here, but individually.
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

		# If an object is transfered or changed to an existing object 
		# on device, a new name is used.
		# In the superior object,
		# the corresponding attribute in that superior object
		# has to be altered, so that it carries the name of the
		# transfered or changed object.
		if ( $spoc_next ) {
		    if  ( ! $conf_next || $conf_next ne $new_conf_next ) {
			$spoc_value->{change_attr}->{$next_attr_name} =
				$new_conf_next;
			$modified = 1;
		    }
		}
	    }
	}
    }
    
    if ( $modified ) {
	$self->mark_as_changed( $parse_name );
    }
    else {
	# Create hash entry with false value, so that
	# Device::get_change_status outputs status for
	# unchanged object types, too.
	$self->mark_as_unchanged( $parse_name );
    }
    
    return $spoc_value->{transfer} 

         # acl: take new_name, username: take original name.
         ? ( $spoc_value->{new_name} || $spoc_value->{name} )

	 # ACL may have changed to other one, already on device.
         : $spoc_value->{name_on_dev};
}

sub unify_anchors {
    my ( $self, $conf, $spoc, $structure ) = @_;

    for my $key ( keys %$structure ) {
        my $value = $structure->{$key};
        next if not $value->{anchor};
#	info("Processing anchor $key ... ");
        my $conf_anchor = $conf->{$key};
        my $spoc_anchor = $spoc->{$key};
	my %seen;

	# Iterate over anchors on device.
        for my $conf_key ( sort keys %$conf_anchor ) {
	    $seen{$conf_key} = 1;
	    my $new_conf = 
		$self->make_equal( $conf, $spoc, $key,
				   $conf_key, $conf_key,
				   $structure );
	    if ( $new_conf && $conf_key ne $new_conf ) {
		internal_err "Anchors known so far are made equal by " .
		    "changing their attributes, not by transfer. " .
		    "(Anchor in conf: $key:$conf_key)";
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
	}
    }
}

sub change_modified_attributes {
    my ( $self, $spoc, $parse_name,
	 $spoc_name, $structure ) = @_;

    my $spoc_value =
	object_for_name( $spoc, $parse_name, $spoc_name );

    if ( my $parse = $structure->{$parse_name} ) {

	# Change attributes marked accordingly.
	if ( my $attr = $spoc_value->{change_attr} ) {
	    $self->change_attributes( $parse_name, $spoc_name,
				      $spoc_value, $attr );
	}

	# Enter recursion ...
	for my $pair (get_next_names($parse, $spoc_value)) {
	    my ($next_parse_name, $spoc_next) = @$pair;
	    $self->change_modified_attributes( $spoc, $next_parse_name,
					       $spoc_next, $structure );
	}
    }
}

#
# Transfer marked objects.
#
sub transfer1 {
    my ( $self, $spoc, $parse_name, $spoc_name, $structure ) = @_;

#    info("PROCESS $parse_name:$spoc_name"); 
    my $spoc_value = object_for_name( $spoc, $parse_name,
				      $spoc_name, 'no_err' );

    if ( my $parse = $structure->{$parse_name} ) {
	for my $pair (get_next_names($parse, $spoc_value)) {
	    my ($next_parse_name, $spoc_next) = @$pair;
	    $self->transfer1( $spoc, $next_parse_name,
			      $spoc_next, $structure );
	}

	# Do actual transfer after recursion so
	# that we start with the leaves.
	my $method = $parse->{transfer};
	if ( $spoc_value->{transfer} and $method ) {
	    if ( my $transfered_as = $spoc_value->{transfered_as} ) {
		#info("$spoc_name already transfered as $transfered_as! ");
	    }
	    else {
		$self->$method( $spoc, $structure, $parse_name, $spoc_name );
		$spoc_value->{transfered_as} = $spoc_value->{new_name};
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

    info("Transfer objects to device");

    # Transfer items ...

    # Process object-groups separately, because they are
    # not linked with access-lists.
    for my $parse_name (qw(OBJECT_GROUP)) {
	my $spoc_hash = $spoc->{$parse_name};
	my $parse = $structure->{$parse_name};
	my $method = $parse->{transfer};
	for my $spoc_name ( keys %$spoc_hash ) {
	    my $spoc_value = object_for_name( $spoc, $parse_name, $spoc_name );
	    if ( $spoc_value->{transfer} ) {
		if ( my $transfered_as = $spoc_value->{transfered_as} ) {
		    #info("$spoc_name already transfered as $transfered_as! ");
		}
		else {
		    $self->$method( $spoc, $structure,
				    $parse_name, $spoc_name );
		    $spoc_value->{transfered_as} = $spoc_value->{new_name};
		}
	    }
	}
    }
 
    # Process remaining objects recursively.
    for my $key ( sort keys %$structure ) {
        my $value = $structure->{$key};
        next if not $value->{anchor};

	#info("Iterating over netspoc-anchor $key ... ");
        my $spoc_anchor = $spoc->{$key};

	# Iterate over anchors in netspoc.
        for my $spoc_name ( keys %$spoc_anchor ) {
	    $self->transfer1( $spoc, $key,
			      $spoc_name, $structure );
	}
    }

    info("Modify objects on device");
    # Change attributes of items in place.
    for my $key ( keys %$structure ) {
        my $value = $structure->{$key};
        next if not $value->{anchor};
        my $spoc_anchor = $spoc->{$key};

	# Iterate over objects on device.
        for my $spoc_name ( keys %$spoc_anchor ) {
	    my $spoc_value = object_for_name( $spoc, $key, $spoc_name );
	    $self->change_modified_attributes( $spoc, $key,
			   $spoc_name, $structure );
	}
    }

    # Change list values of objects in place.
    # Add or remove entries to/from lists (access-list, object-group).
    for my $parse_name ( qw( ACCESS_LIST OBJECT_GROUP ) ) {
	my $spoc_hash = $spoc->{$parse_name};
	for my $spoc_name ( keys %$spoc_hash ) {
	    my $spoc_value = object_for_name( $spoc, $parse_name, $spoc_name );
	    if($spoc_value->{add_entries} || $spoc_value->{del_entries}) {
		my $method = $structure->{$parse_name}->{modify};
		my $conf_name = $spoc_value->{name_on_dev};
		$self->$method( $spoc_value, $conf_name );
	    }	    
	}
    }	
}

sub remove_unneeded_on_device {
    my ( $self, $conf, $structure ) = @_;
    
    # Caution: the order is significant in this array!
    my @parse_names = qw( CRYPTO_MAP_SEQ USERNAME CA_CERT_MAP 
			  TUNNEL_GROUP_IPSEC TUNNEL_GROUP_WEBVPN
                          TUNNEL_GROUP 
                          TUNNEL_GROUP_IPNAME_IPSEC TUNNEL_GROUP_IPNAME 
                          GROUP_POLICY
			  ACCESS_LIST IP_LOCAL_POOL OBJECT_GROUP 
			  NO_SYSOPT_CONNECTION_PERMIT_VPN
			  );

    info("Remove unneeded objects from device");
	
    for my $parse_name ( @parse_names ) {
	my $parse = $structure->{$parse_name};
      OBJECT:
	for my $obj_name ( keys %{$conf->{$parse_name}} ) {

	    my $object = object_for_name( $conf, $parse_name, $obj_name );

	    # Do not remove users that have their own explicit
	    # password (e.g. 'netspoc'-user used to access device).
	    next OBJECT if ( $parse_name eq 'USERNAME'  &&
			     not $object->{NOPASSWORD} );

	    # Remove unneeded objects from device.
	    if ( not $object->{needed} ) {
		my $method = $parse->{remove};
		$self->$method( $conf, $structure,
				$parse_name, $obj_name );
	    }

	    # Remove attributes marked for deletion.
	    if ( my $attr = $object->{remove_attr} ) {
		$self->remove_attributes( $parse_name,
					  $obj_name, $attr );
	    }
	}
    }
}

sub remove_spare_objects_on_device {
    my ( $self, $conf, $structure ) = @_;

    # Don't add OBJECT_GROUP, because currently they are not 
    # marked as connected.
    # Spare object groups will be removed later by
    # remove_unneeded_on_device.
    my @parse_names = qw( CRYPTO_MAP_SEQ USERNAME CA_CERT_MAP 
			  TUNNEL_GROUP_IPSEC TUNNEL_GROUP_WEBVPN
                          TUNNEL_GROUP
                          TUNNEL_GROUP_IPNAME_IPSEC TUNNEL_GROUP_IPNAME 
                          GROUP_POLICY
			  ACCESS_LIST IP_LOCAL_POOL
			  NO_SYSOPT_CONNECTION_PERMIT_VPN
			  );
    
    info("Remove SPARE objects from device");

    for my $parse_name ( @parse_names ) {
	my $parse = $structure->{$parse_name};
      OBJECT:
	for my $obj_name ( keys %{$conf->{$parse_name}} ) {
	    
	    my $object = object_for_name( $conf, $parse_name, $obj_name );
	    
	    # Remove spare objects from device.
	    if ( not $object->{connected} ) {
		# So we do not try to remove the object
		# again later. (This is a hack and should be
		# done in a more consistent way! -->TODO)
		$object->{needed} = 1;
		# Remove object ...
		my $method = $parse->{remove};
		$self->$method( $conf, $structure, $parse_name, $obj_name );
	    }
	}
    }
}    

sub mark_connected {
    my ( $self, $conf, $parse_name, $object, $structure ) = @_;

    $object->{connected} = 1;

    if ( my $parse = $structure->{$parse_name} ) {
	for my $pair (get_next_names($parse, $object)) {
	    my ($next_parse_name, $next_name) = @$pair;
	    my $next_obj = $conf->{$next_parse_name}->{$next_name} or
		abort("Can't find $next_parse_name $next_name" .
                      " referenced by $object->{name}");
	    $self->mark_connected( $conf, $next_parse_name,
				   $next_obj, $structure );
	}
    }
}

sub mark_connected_objects {
    my ( $self, $conf, $structure ) = @_;

    for my $key ( keys %$structure ) {
        my $value = $structure->{$key};
        next if not $value->{anchor};

        my $conf_anchor = $conf->{$key};

	# Iterate over anchors in conf.
        for my $object ( values %$conf_anchor ) {
	    $self->mark_connected( $conf, $key, $object, $structure );
	}
    }

    # Show unconnected objects.
    for my $key ( sort keys %$structure ) {

	# Currently not marked.
	next if $key eq 'OBJECT_GROUP';
	my $objects = $conf->{$key};
        for my $object ( values %$objects ) {
	    next if $object->{connected};
	    warn_info("Spare $key: $object->{name}");
	}
    }    
}

sub change_attributes {
    my ( $self, $parse_name, $spoc_name, $spoc_value, $attributes ) = @_;
    my @cmds;

    return if $parse_name =~ /^(CERT_ANCHOR)$/;
    return if ( $spoc_value->{change_done} );

    info("Change attributes of $parse_name -> $spoc_name");
    if ( my $name = $spoc_value->{name_on_dev} ) {
	$spoc_name = $name; 
    }
    elsif ( $spoc_value->{transfer} ) {
	$spoc_name = $spoc_value->{new_name} || $spoc_name;
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
    elsif( $parse_name eq 'IF' ) {
	for my $attr ( keys %$attributes ) {
	    my $value = $attributes->{$attr};
	    my $direction = $attr =~ /_IN/ ? 'in' : 'out';
	    push(@cmds, "access-group $value $direction interface $spoc_name");
	}
    }
    elsif ($parse_name eq 'CA_CERT_MAP') {
        if (my $tg_name = $attributes->{TUNNEL_GROUP}) {
            push @cmds, "tunnel-group-map $spoc_name 10 $tg_name";
        }
        if (my $tg_name = $attributes->{WEB_TUNNEL_GROUP}) {
            push(@cmds, 
                 "webvpn", 
                 "certificate-group-map $spoc_name 10 $tg_name");
        }
    }
    else {
	my $prefix;
	if( $parse_name eq 'CRYPTO_MAP_SEQ' ) {
	    my ($name, $seq) = split(':', $spoc_name);
	    $prefix = "crypto map $name $seq";
	}
	elsif( not $parse_name eq 'DEFAULT_GROUP' ) {
	    push @cmds, item_conf_mode_cmd( $parse_name, $spoc_name );
	}
	
	for my $attr ( keys %$attributes ) {
	    my $value = $attributes->{$attr};

	    # A hash of attributes, read unchanged from device.
	    if(ref $value) {
		for my $cmd (sort keys %$value) {
		    my $args = $value->{$cmd};
		    push @cmds, "no $cmd" if $attr_need_remove{$cmd};
		    my $new_cmd = $cmd;
		    $new_cmd .= " $args" if $args;
		    push @cmds, $new_cmd;
		}
	    }

	    # Single attributes which need to be converted 
	    # back to device syntax.
	    elsif ( my $attr_cmd = cmd_for_attribute( $parse_name, $attr )) {
		if ( $parse_name eq 'DEFAULT_GROUP' ) {
		    $attr_cmd .= " default-group ";
		}
		$attr_cmd = "$prefix $attr_cmd" if($prefix);
		if($attr_need_remove{$attr}) {
		    push @cmds, "no $attr_cmd";
		}
		if(not $attr_no_value{$attr}) {
		    $attr_cmd = "$attr_cmd $value";
		}
		push @cmds, $attr_cmd;
	    }
	}

        # Exit 'username attributes', because 'webvpn' is used as
        # global command and as subcommand of this conf mode.
        push @cmds, 'exit' if $parse_name eq 'USERNAME';
    }
    map { $self->cmd( $_ ) } @cmds;
    $spoc_value->{change_done} = 1;
}

sub remove_attributes {
    my ( $self, $parse_name, $item_name, $attributes ) = @_;

    info("Remove attributes for $item_name");
    my @cmds;
    my $prefix;
    if( $parse_name eq 'CRYPTO_MAP_SEQ' ) {
	my ($name, $seq) = split(':', $item_name);
	$prefix = "crypto map $name $seq";
    }
    else {
	push @cmds, item_conf_mode_cmd( $parse_name, $item_name );
    }

    for my $attr ( keys %{$attributes} ) {
	my $value = $attributes->{$attr};

	# A hash of attributes, read unchanged from device.
	if(ref $value) {
	    for my $cmd (sort keys %$value) {
		my $args = $value->{$cmd};
		my $new_cmd = $cmd;
		$new_cmd = "$new_cmd value" if ($args && $args =~ /^value/);
		push @cmds, "no $new_cmd";
	    }
	}
	elsif (my $attr_cmd = cmd_for_attribute( $parse_name, $attr )) {
	    $attr_cmd = "$prefix $attr_cmd" if($prefix);
	    if(not $attr_no_value{$attr}) {
		$attr_cmd = "$attr_cmd $value";
	    }
	    push @cmds, "no $attr_cmd";
	}
    }

    # Exit 'username attributes', because 'webvpn' is used as
    # global command and as subcommand of this conf mode.
    push @cmds, 'exit' if $parse_name eq 'USERNAME';
    map { $self->cmd( $_ ) } @cmds;
}

sub transfer_interface {
    my ( $self, $spoc, $structure, $parse_name, $intf ) = @_;
    abort("Transfer $intf: Interfaces MUST be same" .
          " on device and in netspoc");
}

sub remove_interface {
    my ( $self, $conf, $structure, $parse_name, $intf ) = @_;
    abort("Remove $intf: Interfaces MUST be same" .
          " on device and in netspoc");
}

sub transfer_crypto_map_seq {
    my ( $self, $spoc, $structure, $parse_name, $name_seq ) = @_;

    my $object = object_for_name( $spoc, $parse_name, $name_seq );
    my @cmds;
    push @cmds, add_attribute_cmds( $structure, $parse_name,
				    $object, 'attributes' );
    map { $self->cmd( $_ ) } @cmds;
}

sub remove_crypto_map_seq {
    my ( $self, $conf, $structure, $parse_name, $name_seq ) = @_;

    my $object = object_for_name( $conf, $parse_name, $name_seq );
    my ($name, $seq) = split(':', $object->{name});
    my $prefix = "crypto map $name $seq";
    my $cmd = "clear configure $prefix";
    $self->cmd( $cmd );
}

sub transfer_ca_cert_map {
    my ( $self, $spoc, $structure, $parse_name, $cert_map ) = @_;

    my $object = object_for_name( $spoc, $parse_name, $cert_map );
    my $new_cert_map = $object->{new_name};
    my @cmds;
    push @cmds, item_conf_mode_cmd( $parse_name, $new_cert_map );
    push @cmds, add_attribute_cmds( $structure, $parse_name, $object, 'attributes' );
    map { $self->cmd( $_ ) } @cmds;
}

sub remove_ca_cert_map {
    my ( $self, $conf, $structure, $parse_name, $cert_map ) = @_;
    my $object = object_for_name( $conf, $parse_name, $cert_map );
    my $cmd = "clear configure crypto ca certificate map $cert_map";
    $self->cmd( $cmd );
}

sub transfer_default_group {
    my ( $self, $spoc, $structure, $parse_name, $default ) = @_;
    my $object = $spoc->{$parse_name}->{$default};
    my $tunnel_group_name = $object->{TUNNEL_GROUP};
    my $tunnel_group = $spoc->{TUNNEL_GROUP}->{$tunnel_group_name};
    my $new_default_group = $tunnel_group->{new_name};
    my $cmd = "tunnel-group-map default-group $new_default_group";
    $self->cmd( $cmd );
}

sub remove_default_group {
    my ( $self, $conf, $structure, $parse_name, $default ) = @_;
    my $object = $conf->{$parse_name}->{$default};
    my @cmds;
    push @cmds, "no " . $object->{orig};
    map { $self->cmd( $_ ) } @cmds;
}

sub transfer_user {
    my ( $self, $spoc, $structure, $parse_name, $username ) = @_;
    my $user = $spoc->{$parse_name}->{$username};
    abort("No user-object found for $username") unless $user;
    my @cmds;
    push @cmds, define_item_cmd( $parse_name, $username );
    push @cmds, item_conf_mode_cmd( $parse_name, $username );
    push @cmds, add_attribute_cmds( $structure, $parse_name, $user, 
                                    'attributes' );
    push @cmds, 'exit' if $parse_name eq 'USERNAME';
    map { $self->cmd( $_ ) } @cmds;
}

sub remove_user {
    my ( $self, $conf, $structure, $parse_name, $username ) = @_;
    my @cmds;
    my $cmd = "clear configure username $username";
    $self->cmd( $cmd );
}

sub transfer_tunnel_group {
    my ( $self, $spoc, $structure, $parse_name, $tg_name ) = @_;

    my $tunnel_group = $spoc->{$parse_name}->{$tg_name} or
	abort("No $parse_name found for $tg_name");
    my $tg = $spoc->{TUNNEL_GROUP}->{$tg_name};
    my $new_tg = is_ip( $tg_name ) 
               ? $tg_name

               # Use same name for tg xxx-attributes if tg is already
               # on device.
               : $tg->{name_on_dev} || $tg->{new_name};
    my @cmds;
    if ( $parse_name =~ /^TUNNEL_GROUP(?:_IPNAME)?$/ ) {
	push @cmds, define_item_cmd($parse_name, $new_tg);
    }
    if ( $parse_name ne 'TUNNEL_GROUP_IPNAME' ) {
	push @cmds, item_conf_mode_cmd( $parse_name, $new_tg );
	push @cmds, add_attribute_cmds( $structure, $parse_name,
				    $tunnel_group, 'attributes' );
    }
    map { $self->cmd( $_ ) } @cmds;
}

sub remove_tunnel_group {
    my ( $self, $conf, $structure, $parse_name, $tg_name ) = @_;
    $self->cmd("clear configure tunnel-group $tg_name");
}

sub remove_tunnel_group_xxx {
    my ( $self, $conf, $structure, $parse_name, $tg_name ) = @_;
    my $cmd = item_conf_mode_cmd($parse_name, $tg_name);
    $self->cmd("no $cmd");
}

sub transfer_group_policy {
    my ( $self, $spoc, $structure, $parse_name, $gp_name ) = @_;
    my $group_policy = $spoc->{$parse_name}->{$gp_name};
    my $new_gp = $group_policy->{new_name};
    abort("No group-policy-object found for $gp_name") unless $group_policy;
    my @cmds;
    push @cmds, define_item_cmd( $parse_name, $new_gp );
    push @cmds, item_conf_mode_cmd( $parse_name, $new_gp );
    push @cmds, add_attribute_cmds( $structure, $parse_name,
				    $group_policy, 'attributes' );
    
    map { $self->cmd( $_ ) } @cmds;
}

sub remove_group_policy {
    my ( $self, $spoc, $structure, $parse_name, $gp_name ) = @_;
    my $cmd = "clear configure group-policy $gp_name";
    $self->cmd( $cmd );
}

sub transfer_ip_local_pool {
    my ( $self, $spoc, $structure, $parse_name, $pool_name ) = @_;
    my $pool = $spoc->{$parse_name}->{$pool_name};
    my $new_name = $pool->{new_name};
    my $cmd = $pool->{orig}; 
    $cmd =~ s/ip local pool $pool_name(?!\S)/ip local pool $new_name/;
    $self->cmd( $cmd );
}

sub remove_ip_local_pool {
    my ( $self, $conf, $structure, $parse_name, $pool_name ) = @_;
    my $pool = $conf->{$parse_name}->{$pool_name};
    my $cmd = "no " . $pool->{orig};
    $self->cmd( $cmd );
}

sub transfer_no_sysopt_connection_permit_vpn {
    my ( $self, $conf, $structure, $parse_name, $obj_name ) = @_;
    $self->cmd('no sysopt connection permit-vpn');
}
 
sub remove_no_sysopt_connection_permit_vpn {
    my ( $self, $conf, $structure, $parse_name, $obj_name ) = @_;
    $self->cmd('sysopt connection permit-vpn');
}
    
sub transfer_object_group {
    my ( $self, $spoc, $structure, $parse_name, $object_group ) = @_;
    my $group = object_for_name( $spoc, $parse_name, $object_group );
    my $new_name = $group->{new_name};
    my $cmd = $group->{orig};
    $cmd =~ s/^(\S+ \S+ )(\S+)(.*)/$1$new_name$3/;
    $self->cmd($cmd);
    map( { $self->cmd( $_->{orig} ) } @{ $group->{OBJECT} } );
}

sub modify_object_group {
    my ( $self, $spoc, $conf_name ) = @_;
    my $cmd = "object-group $spoc->{TYPE} $conf_name";
    $self->cmd($cmd);
    if($spoc->{add_entries}) {
	map( { $self->cmd( $_->{orig} ) } @{ $spoc->{add_entries} } );
    }
    if($spoc->{del_entries}) {
	map( { $self->cmd( "no $_->{orig}" ) } @{ $spoc->{del_entries} } );
    }
}

sub remove_object_group {
    my ( $self, $conf, $structure, $parse_name, $object_group ) = @_;
    my $og = object_for_name( $conf, $parse_name, $object_group );
    my $cmd = "no $og->{orig}";
    $self->cmd( $cmd );
}

sub transfer_acl {
    my ( $self, $spoc, $structure, $parse_name, $acl_name ) = @_;

    my $acl = $spoc->{$parse_name}->{$acl_name};
    my $new_name = $acl->{new_name};
    my @cmds;
    for my $ace ( @{ $acl->{LIST} } ) {
	my $cmd = $ace->{orig};
	$cmd =~ s/^access-list\s+\S+/access-list $new_name/;
	for my $where ( qw( TYPE SRC DST SRC_PORT DST_PORT ) ) {
            my $what = $ace->{$where};
	    if (my $group = ref($what) && $what->{GROUP}) {
                my $gid = $group->{name};
		my $new_gid = $group->{transfered_as} || $group->{name_on_dev} or
		    abort("Expected group $gid already on device");
		$cmd =~ s/object-group $gid(?!\S)/object-group $new_gid/;
		$ace->{$where}->{GROUP} = $new_gid;  
	    }
	}
	push @cmds, $cmd;
    }
    map { $self->cmd( $_ ) } @cmds;
}

sub remove_acl {
    my ( $self, $conf, $structure, $parse_name, $acl ) = @_;
    my $cmd = $self->acl_removal_cmd( $acl );
    $self->cmd( $cmd );
}

sub define_item_cmd {
    my ( $parse_name, $item_name ) = @_;
    my $def = $define_object{$parse_name} or
	internal_err("No definition for $parse_name $item_name");
    my $prefix = $def->{prefix} or
	internal_err("No prefix for $parse_name $item_name");
    return "$prefix $item_name $def->{postfix}";
}

sub item_conf_mode_cmd {
    my ( $parse_name, $item_name ) = @_;
    my $prefix  = $conf_mode_entry{$parse_name}->{prefix} or
	internal_err("No prefix for $parse_name $item_name");
    my $postfix = $conf_mode_entry{$parse_name}->{postfix};
    return "$prefix $item_name $postfix";
}

sub add_attribute_cmds {
    my ( $structure, $parse_name, $object, $attributes ) = @_;

    my @cmds;
    my $prefix;
    if( $parse_name eq 'CRYPTO_MAP_SEQ' ) {
 	my ($name, $seq) = split(':', $object->{new_name} || $object->{name});
	$prefix = "crypto map $name $seq";
    }
  ATTRIBUTE:
    for my $attr ( @{$structure->{$parse_name}->{$attributes}} ) {
	my $value = $object->{$attr};
	if (ref $value) {
	    for my $cmd (sort keys %$value) {
		my $args = $value->{$cmd};
		my $new_cmd = $cmd;
		$new_cmd .= " $args" if $args;
		push @cmds, $new_cmd;
	    }
	}
	elsif (	my $attr_cmd = cmd_for_attribute( $parse_name, $attr )) {

	    # Some attributes are optional.
	    next ATTRIBUTE if not $value;
	    $attr_cmd = "$prefix $attr_cmd" if($prefix);
	    if(not $attr_no_value{$attr}) {
		$attr_cmd = "$attr_cmd $value";
	    }
	    push @cmds, $attr_cmd;
	}
    }
    return @cmds;
}

sub object_for_name {
    my ( $c, $parse_name, $c_name, $no_err ) = @_;

    return if not $c_name;

    if ( $no_err && $no_err ne 'no_err' ) {
	internal_err "Illegal parameter $no_err";
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
	    internal_err "No object found for $c_name";
	}
    }
    return $c_value;
}

sub transfer {
    my ( $self, $conf, $spoc, $structure ) = @_;

    $structure ||= $self->define_structure();

    # Check for matching interfaces.
    $self->checkinterfaces($conf, $spoc);

    $self->process_routing( $conf, $spoc );
    generate_names_for_transfer( $conf, $spoc, $structure );

    info("Mark connected objects of device");
    $self->mark_connected_objects( $conf, $structure );

    # Result isn't needed, but run it anyway to check for consistent references.
    info("Mark connected objects of Netspoc");
    $self->mark_connected_objects( $spoc, $structure );
    $self->unify_anchors( $conf, $spoc, $structure );
    $self->enter_conf_mode();
    $self->remove_spare_objects_on_device( $conf, $structure );
    $self->traverse_netspoc_tree( $spoc, $structure );
    $self->remove_unneeded_on_device( $conf, $structure );

    $self->add_object_lines($conf, $spoc);
    for my $type ( qw( STATIC GLOBAL NAT TWICE_NAT) ) {
        $self->transfer_lines($conf, $spoc, $type);
    }
    $self->delete_object_lines($conf, $spoc);
    $self->leave_conf_mode();

    # Only write memory on device if there have been changes.
    if ( grep { $_ } values %{ $self->{CHANGE} } ) {
	info("Saving config to flash");
	$self->cmd('write memory');
    }
    else {
	info("No changes to save");
    }

    return 1;
}

sub define_structure {
    my $self = shift;

    my $structure = {
	ACCESS_LIST => {
#	    next_list => { LIST => [ { attr_name => [ 'SRC', 'OBJECT_GROUP' ],
#				      parse_name => 'ACCESS_LIST', }, 
#				    { attr_name => [ 'DST', 'OBJECT_GROUP' ],
#				      parse_name => 'ACCESS_LIST', },
#				    ],
#		      },
	    transfer => 'transfer_acl',
	    remove   => 'remove_acl',
	},
	OBJECT_GROUP => {
	    attributes => [],
	    transfer => 'transfer_object_group',
	    remove   => 'remove_object_group',
	    modify   => 'modify_object_group',
	},
	IF => {
	    anchor => 1,
	    next => [ { attr_name  => 'ACCESS_GROUP_IN',
			parse_name => 'ACCESS_LIST', },
		      { attr_name  => 'ACCESS_GROUP_OUT',
			parse_name => 'ACCESS_LIST', },
		      ],
	    attributes => [],
	    transfer => 'transfer_interface',
	    remove   => 'remove_interface',
	},
	CRYPTO_MAP_LIST => {
	    anchor => 1,
	    next_list => [ { attr_name  => 'PEERS',
			     parse_name => 'CRYPTO_MAP_SEQ', },
			   ],
	},
	CRYPTO_MAP_SEQ => {
	    attributes => [ qw(NAT_T_DISABLE PEER DYNAMIC_MAP PFS 
			       REVERSE_ROUTE SA_LIFETIME_SEC SA_LIFETIME_KB 
			       TRANSFORM_SET TRANSFORM_SET_IKEV1 TRUSTPOINT) ],
	    next     => [ { attr_name  => 'MATCH_ADDRESS',
			    parse_name => 'ACCESS_LIST' }
			  ],
	    transfer => 'transfer_crypto_map_seq',
	    remove   => 'remove_crypto_map_seq',
	},
    };

    return $structure;
}

sub get_next_names {
    my ($parse_info, $object) = @_;
    my @result;
    for my $key (qw(next next_list)) {
	if (my $next = $parse_info->{$key}) {
	    for my $next_key ( @$next ) {
		my $next_attr_name  = $next_key->{attr_name};
		my $next_parse_name = $next_key->{parse_name};
		if ( my $conf_next = $object->{$next_attr_name} ) {
		    if ($key eq 'next_list') {
			push @result, 
			map [ $next_parse_name, $_ ], @$conf_next;
		    }
		    else {
			push @result, [ $next_parse_name, $conf_next ];
		    }
		}
	    }
	}
    }
    return @result;
}
			

sub cmd_for_attribute {
    my ( $parse_name, $attr ) = @_;
    $attr2cmd{$parse_name}->{$attr};
}

sub mark_as_changed {
    my ( $self, $parse_name ) = @_;

    return if $parse_name eq 'IF';
    return if $parse_name eq 'CERT_ANCHOR';
    return if $parse_name eq 'DEFAULT_GROUP';
    $self->{CHANGE}->{$parse_name} = 1;
}

sub mark_as_unchanged {
    my ( $self, $parse_name ) = @_;

    return if $parse_name eq 'IF';
    return if $parse_name eq 'CERT_ANCHOR';
    return if $parse_name eq 'DEFAULT_GROUP';
    $self->{CHANGE}->{$parse_name} ||= 0;
}

sub acl_removal_cmd {
    my ( $self, $acl_name ) = @_;
    return "no access-list $acl_name";
}


# Packages must return a true value;
1;

