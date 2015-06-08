
=head1 DESCRIPTION

Base class for Cisco firewalls (ASA, PIX)

=head1 COPYRIGHT AND DISCLAIMER

https://github.com/hknutzen/Netspoc-Approve
(c) 2015 by Heinz Knutzen <heinz.knutzen@gmail.com>
(c) 2011 by Daniel Brunkhorst <daniel.brunkhorst@web.de>
(c) 2007 by Arne Spetzler

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

package Netspoc::Approve::Cisco_FW;

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
         IPSEC_PROPOSAL           => 'set ikev2 ipsec-proposal',
	 TRANSFORM_SET		  => 'set transform-set',
	 TRANSFORM_SET_IKEV1	  => 'set ikev1 transform-set',
	 TRUSTPOINT		  => 'set trustpoint',
     },
     DYNAMIC_MAP => {
	 MATCH_ADDRESS		  => 'match address',
	 NAT_T_DISABLE		  => 'set nat-t-disable',
	 PEER			  => 'set peer',
	 PFS 			  => 'set pfs',
	 REVERSE_ROUTE		  => 'set reverse-route',
	 SA_LIFETIME_SEC	  => 'set security-association lifetime seconds',
	 SA_LIFETIME_KB		  => 'set security-association lifetime kilobytes',
         IPSEC_PROPOSAL           => 'set ikev2 ipsec-proposal',
	 TRANSFORM_SET_IKEV1	  => 'set ikev1 transform-set',
	 TRANSFORM_SET_IKEV1_2nd  => 'set ikev1 transform-set',
     },
     IPSEC_PROPOSAL => {
         ENCRYPTION_LIST          => 'protocol esp encryption',
         INTEGRITY_LIST           => 'protocol esp integrity',
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
			PEER                  => 1,
                        IPSEC_PROPOSAL        => 1,
			TRANSFORM_SET         => 1,
			TRANSFORM_SET_IKEV1   => 1,
			);
		      

sub get_parse_info {
    my ($self) = @_;
    my $null = {
	'BASE' => 0,
	'MASK' => 0
	};
    { 

	# Defines association of a name with an IP address.
	# This interferes with parsing of ACL and object-groups.
	name => {
	    error => "'name' command must not be used",
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
            strict => 'err',
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
            strict => 'err',
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
            strict => 'err',
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
            strict => 'err',
	    subcmd => {
                'service-object' => {
                    store => 'OBJECT',
                    multi => 1,
                    parse => 
                        ['or',
                         ['cond1', { store => 'TYPE', parse => qr/ip/ }, ],
                         ['cond1',
                          { store => 'TYPE', parse => qr/udp|tcp|tcp-udp/ },
                          { parse => qr/destination/, default => 1, },
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
            strict => 'err',
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
		   { parse => qr/compiled/ },

		   ['cond1',
		    { parse => qr/remark/ },
		    { store => 'REMARK', parse => \&get_to_eol } ],
		   
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

                     # Ignore time-range
                     ['cond1',
                      { parse => qr/time-range/ },
                      { parse => \&get_token } ],

		     ['cond1',
		      { store => 'LOG', parse => qr/log/ },
		      ['or',
		       { store => 'LOG_MODE', parse => qr/disable|default/ },
		       ['seq',
			{ store => 'LOG_LEVEL', 
			  parse => \&check_loglevel, default => 6 },
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
	    store => 'CRYPTO_MAP',
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
					 join(' ', $name, $seq);
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
			 ['seq',
			  { parse => qr/set/ },
			  ['or',
			   { parse => qr/nat-t-disable/,
			     store => 'NAT_T_DISABLE', },
			   ['cond1',
			    { parse => qr/peer/ },
			    { parse => \&get_to_eol, store => 'PEER' } ],
			   ['cond1',
			    { parse => qr/pfs/ },
			    { parse => \&check_token,
                              store => 'PFS', default => 'group2' } ],
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
                           ['cond1',
                            { parse => qr/ikev2/ },
                            { parse => qr/ipsec-proposal/ },
                            { parse => \&get_token,
                              store => 'IPSEC_PROPOSAL' } ],
                           ['cond1',
                            { parse => qr/ikev1/ },
                            { parse => qr/transform-set/ },
                            { parse => \&get_token,
                              store => 'TRANSFORM_SET_IKEV1' },
                           ],
                           ['cond1',
                            { parse => qr/transform-set/ },
                            { parse => \&get_token,
                              store => 'TRANSFORM_SET' } ],
			   ['cond1',
			    { parse => qr/trustpoint/ },
			    { parse => \&get_token,
			      store => 'TRUSTPOINT', } ]]]]]]]
	},
	'crypto dynamic-map' => {
	    store => 'DYNAMIC_MAP',
	    named => 'from_parser',
	    merge => 1,
	    parse => ['seq',
		      { store => 'name', parse => \&get_token },
                      { parse => qr/\d+/, store => 'SEQ' },
                      ['or',
                       ['cond1',
                        { parse => qr/match/ },
                        { parse => qr/address/ },
                        { store => 'MATCH_ADDRESS', parse => \&get_token } ],
                       ['seq',
                        { parse => qr/set/ },
                        ['or',
                         { parse => qr/nat-t-disable/,
                           store => 'NAT_T_DISABLE', },
                         ['cond1',
                          { parse => qr/peer/ },
                          { parse => \&get_to_eol, store => 'PEER' } ],
                         ['cond1',
                          { parse => qr/pfs/ },
                          { parse => \&check_token,
                            store => 'PFS', default => 'group2' } ],
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
                         ['cond1',
                          { parse => qr/ikev2/ },
                          { parse => qr/ipsec-proposal/ },
                          { parse => \&get_token,
                            store => 'IPSEC_PROPOSAL' } ],
                         ['cond1',
                          { parse => qr/ikev1/ },
                          { parse => qr/transform-set/ },
                          { parse => \&get_token,
                            store => 'TRANSFORM_SET_IKEV1' },
                          { parse => \&check_token,
                            store => 'TRANSFORM_SET_IKEV1_2nd' }, ]]]]]
        },
	'crypto ipsec ikev2 ipsec-proposal' => {
	    store => 'IPSEC_PROPOSAL',
	    named => 1,
            subcmd => {
                'protocol esp encryption' => {
                    parse => \&get_sorted_encr_list ,
                    store => 'ENCRYPTION_LIST' },
                'protocol esp integrity' => {
                    parse => \&get_sorted_encr_list ,
                    store => 'INTEGRITY_LIST' },
            },
	},
	'crypto ipsec transform-set' => {
	    store => 'TRANSFORM_SET',
	    named => 1,
	    parse => ['seq',
		      { store => 'LIST',
                        parse => \&get_sorted_encr_list }, ],
	},
	'crypto ipsec ikev1 transform-set' => {
	    store => 'TRANSFORM_SET',
	    named => 1,
	    parse => ['seq',
		      { store => 'LIST',
                        parse => \&get_sorted_encr_list }, ],
	},
    }
}

sub postprocess_config {
    my ($self, $p) = @_;

    # ASA has only default VRF.
    $p->{ROUTING_VRF}->{''} = delete $p->{ROUTING} if $p->{ROUTING};

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
            next if $entry->{REMARK};
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
    my @no_crypto_seq = grep { $_ !~ / / } keys %{$p->{CRYPTO_MAP}};
    my $seq = $p->{CRYPTO_MAP_SEQ} = delete $p->{CRYPTO_MAP};
    my $map = $p->{CRYPTO_MAP} = {};
    for my $key (@no_crypto_seq) {
	$map->{$key} = delete $seq->{$key};
    }

    # Add entries of CRYPTO_MAP_SEQ to attribute PEER of artificial
    # anchor CRYPTO_MAP_LIST.
    my $lists = $p->{CRYPTO_MAP_LIST} = {};
    my %peers;
    for my $name (sort keys %$seq) {
	my ($map_name, $seq_nr) = split(/ /, $name);
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

sub parse_object_group  {
    my ($self, $arg) = @_;
    if(check_regex('object-group', $arg)) {
	return { GROUP_NAME => get_token($arg) };
    }
    else {
        return;
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
     # Multi line, expected warning.
     qr /WARNING: L2L tunnel-groups that have names which are not an IP/,
     qr /address may only be used if the tunnel authentication/,
     qr /method is Digital Certificates and\/or The peer is/,
     qr /configured to use Aggressive Mode/,
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

# Check unexpected lines:
# - known status messages
# - known warning messages
# - unknown messages, handled as error messages.
sub cmd_check_error {
    my ($self, $cmd, $lines) = @_;
    my $error;
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
	$error = 1;
    }
    return $error;
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

    $output = $self->shcmd('sh term');
    if ($output !~ /511/) {
        $self->set_terminal_width();
    }
}

sub get_config_from_device {
    my ($self) = @_;
    $self->get_cmd_output('write term');
}

sub attr_eq {
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
    for my $name (sort keys %$spoc_hash) { 
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
    for my $name (sort keys %$conf_hash) { 
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

        # Dynamic crypto map has certificate as name.
	next if $parse_name eq 'DYNAMIC_MAP';
	my $hash = $spoc->{$parse_name};
	for my $name ( keys %$hash ) {
	    if ($parse_name eq 'TUNNEL_GROUP') {
                my $type = $spoc->{TUNNEL_GROUP_DEFINE}->{$name}->{TYPE};
                next if $type eq 'ipsec-l2l';
            }
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
                    #info("Attribute $attr different values ");
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

# Renumber line numbers in mapping from acl entries to line numbers.
sub change_acl_numbers {
    my ($self, $hash, $start, $incr) = @_;
    for my $line (values %$hash) {
        if ($line >= $start) {
            $line += $incr;
        }
    }
}

# ASA ACL lines start at 1, increment by 1.
# When adding lines in front of some line n
# start at n+0 and subsequent lines at n+0+0, n+0+0+0, ...
sub ACL_line_discipline {
    return (1, 1, 0, 0);            
}

# Access to ASA and PIX isn't controlled by ACL.
sub is_device_access {
    my ($self, $conf_entry) = @_;
    return 0;
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
	    my ($map_name) = split(/ /, $spoc_name);
	    if ($spoc_entry->{PEER}) {
		$peer_seq = get_free_seq_nr($conf_entries, $peer_seq, +1);
		$spoc_entry->{new_name} = "$map_name $peer_seq";
		$peer_seq += 1;
	    }
	    else {
		$dyn_seq = get_free_seq_nr($conf_entries, $dyn_seq, -1);
		$spoc_entry->{new_name} = "$map_name $dyn_seq";
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

# Check, if simple objects have identical attribute / value pairs.
# Returns: undef if different, $conf_value if equal.
sub simple_object_equal {
    my ($spoc_value, $conf_value, $attributes) = @_;
    for my $attr (@$attributes) {
        my $spoc_attr = $spoc_value->{$attr};
        my $conf_attr = $conf_value->{$attr};

        # One values is defined, the other is undefined.
        return if defined $spoc_attr xor defined $spoc_attr;

        # Both values are undefined.
        next if not defined $spoc_attr;

        # Defined values are different.
        return if $spoc_attr ne $conf_attr;
    }
    return $conf_value;
}

sub find_simple_object_on_device {
    my ($spoc_value, $conf, $parse_name, $structure) = @_;
    my $attributes   = $structure->{$parse_name}->{attributes};
    my $conf_objects = $conf->{$parse_name};
  OBJ:
    for my $conf_name (sort keys %$conf_objects) {
        my $conf_value = $conf_objects->{$conf_name};
        next if not simple_object_equal($spoc_value, $conf_value, $attributes);
        return $conf_value;
    }
    return;    
}

sub make_equal {
    my ( $self, $conf, $spoc, $parse_name, $conf_name,
	 $spoc_name, $structure ) = @_;

    return unless ( $spoc_name  ||  $conf_name );

#    info("MAKE EQUAL( $parse_name ) => CONF:$conf_name, SPOC:$spoc_name ");

    my $modified;
    my $conf_value = object_for_name( $conf, $parse_name,
				      $conf_name, 'no_err' );
    my $spoc_value = object_for_name( $spoc, $parse_name,
				      $spoc_name, 'no_err' );

    if ( $spoc_value ) {

        # If object already has been transferred before, just return
        # the name of the transferred object.
	if ( $spoc_value->{transfer} ) {
	    return $spoc_value->{new_name} || $spoc_name;
	}
	elsif( $spoc_value->{name_on_dev} ) {
	    return $spoc_value->{name_on_dev};
	}

        # Never modify simple object.
        # Instead, search object with identical attributes on device.
        # If found, take that object.
        # Otherwise transfer object from netspoc.
        if ($structure->{$parse_name}->{simple_object}) {
            my $found_obj;

            # Prefer current value on device, if unchanged.
            if ($conf_value) {
                my $attributes = $structure->{$parse_name}->{attributes};
                if (simple_object_equal($spoc_value, $conf_value, $attributes)) {
                    $found_obj = $conf_value;
                }
            }

            $found_obj ||= find_simple_object_on_device($spoc_value, 
                                                      $conf, $parse_name, 
                                                      $structure);
            if ($found_obj) 
            {
                $found_obj->{needed} = $spoc_value;
                my $name = $found_obj->{name};
                info("Using $parse_name $name on device for $spoc_name");
                $self->mark_as_unchanged( $parse_name );
                return $spoc_value->{name_on_dev} = $name;
            }
            else {
                $spoc_value->{transfer} = 1;
                $self->mark_as_changed( $parse_name );
                return $spoc_value->{new_name} || $spoc_name;
            }
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
            $self->mark_object_group_from_acl($spoc_value);
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
	    my $unchanged = $self->equalize_acl($conf_value, $spoc_value);
            my $modify_cmds = $spoc_value->{modify_cmds};
            $modified = !$unchanged;
            
            if ($modified) {
                if (!$modify_cmds) {
                    $spoc_value->{transfer} = 1;
                }

                # Standard access-list can't be changed incrementally
                # on ASA 8.0 and 8.4
                elsif (grep({ (ref($_) eq 'ARRAY' ? $_->[0] : $_)->{ace}->{orig} 
                              =~ /standard/ } 
                            @$modify_cmds))
                {
                    $spoc_value->{transfer} = 1;
                    $spoc_value->{modify_cmds} = undef;
                }
                else {
                    $conf_value->{needed} = $spoc_value;
                    $spoc_value->{name_on_dev} = $conf_name;
                }
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

## Currently dangerous, because {new_name} has already been used.
	# If this object was previously marked for transfer,
	# remove the mark, because we now know, that the object is already
	# available on device.
#	if($spoc_value->{name_on_dev}) {
#	    undef $spoc_value->{transfer};
#	}
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

		# If an object is transferred or changed to an existing object 
		# on device, a new name is used.
		# In the superior object,
		# the corresponding attribute in that superior object
		# has to be altered, so that it carries the name of the
		# transferred or changed object.
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
	    if ( my $transferred_as = $spoc_value->{transferred_as} ) {
		#info("$spoc_name already transferred as $transferred_as! ");
	    }
	    else {
                info("Transfer $parse_name $spoc_name");
		$self->$method( $spoc, $structure, $parse_name, $spoc_name );
		$spoc_value->{transferred_as} = $spoc_value->{new_name};
	    }
	}

        # Change attributes of items in place.
        $self->change_modified_attributes($spoc, $parse_name, $spoc_name, 
                                          $structure);
    }
}

# Entry point for tree traversal (starting with
# the anchors) in order to transfer,
# remove or modify marked objects.
sub traverse_netspoc_tree {
    my ( $self, $spoc, $structure ) = @_;


    # Transfer items ...

    # Process object-groups separately, because they are
    # not linked with access-lists.
    for my $parse_name (qw(OBJECT_GROUP)) {
	my $spoc_hash = $spoc->{$parse_name};
	my $parse = $structure->{$parse_name};
	my $method = $parse->{transfer};
	for my $spoc_name ( sort keys %$spoc_hash ) {
	    my $spoc_value = object_for_name( $spoc, $parse_name, $spoc_name );
	    if ( $spoc_value->{transfer} ) {
		if ( my $transferred_as = $spoc_value->{transferred_as} ) {
		    #info("$spoc_name already transferred as $transferred_as! ");
		}
		else {
                    info("Transfer $parse_name $spoc_name");
		    $self->$method( $spoc, $structure,
				    $parse_name, $spoc_name );
		    $spoc_value->{transferred_as} = $spoc_value->{new_name};
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
        for my $spoc_name ( sort keys %$spoc_anchor ) {
	    $self->transfer1( $spoc, $key,
			      $spoc_name, $structure );
	}
    }

    # Change list values of objects in place.
    # Add or remove entries to/from lists (access-list, object-group).
    for my $parse_name ( qw( ACCESS_LIST OBJECT_GROUP ) ) {
	my $spoc_hash = $spoc->{$parse_name};
	for my $spoc_name ( sort keys %$spoc_hash ) {
	    my $spoc_value = object_for_name( $spoc, $parse_name, $spoc_name );
	    if($spoc_value->{add_entries} || $spoc_value->{del_entries} 
               || $spoc_value->{modify_cmds}) 
            {
		my $method = $structure->{$parse_name}->{modify};
		my $conf_name = $spoc_value->{name_on_dev};
                info("Modify $parse_name $conf_name");
		$self->$method( $spoc_value, $conf_name );
	    }	    
	}
    }	
}

sub remove_unneeded_on_device {
    my ( $self, $conf, $structure ) = @_;
    
    # Caution: the order is significant in this array!
    my @parse_names = qw( CRYPTO_MAP_SEQ DYNAMIC_MAP USERNAME CA_CERT_MAP 
			  TUNNEL_GROUP_IPSEC TUNNEL_GROUP_WEBVPN
                          TUNNEL_GROUP 
                          TUNNEL_GROUP_IPNAME_IPSEC TUNNEL_GROUP_IPNAME
                          TRANSFORM_SET IPSEC_PROPOSAL
                          GROUP_POLICY
			  ACCESS_LIST IP_LOCAL_POOL OBJECT_GROUP 
			  NO_SYSOPT_CONNECTION_PERMIT_VPN
			  );

    for my $parse_name ( @parse_names ) {
	my $parse = $structure->{$parse_name};
	for my $obj_name ( sort keys %{$conf->{$parse_name}} ) {

	    my $object = object_for_name( $conf, $parse_name, $obj_name );

	    # Remove attributes marked for deletion.
	    if ( my $attr = $object->{remove_attr} ) {
		$self->remove_attributes($object, $parse_name, $obj_name, 
                                         $attr);
	    }

	    # Remove unneeded object from device.
	    next if $object->{needed};

	    # Do not remove users that have their own explicit
	    # password (e.g. 'netspoc'-user used to access device).
	    next if ( $parse_name eq 'USERNAME'  && ! $object->{NOPASSWORD} );

            # Only remove object that either has previously been
            # defined by Netspoc or that has been substituted by new
            # object from Netspoc.
            # This excludes manual ACLs used for eg. BGP.
            if ($parse_name ne 'CRYPTO_MAP_SEQ') {
                next if $obj_name !~ /DRC-\d+$/ and not $object->{connected};
            }

            info("Remove unneeded $parse_name $obj_name");
            my $method = $parse->{remove};
            $self->$method( $conf, $structure, $parse_name, $obj_name );
	}
    }
}

sub remove_spare_objects_on_device {
    my ( $self, $conf, $structure ) = @_;

    my @parse_names = qw( CRYPTO_MAP_SEQ DYNAMIC_MAP USERNAME CA_CERT_MAP 
			  TUNNEL_GROUP_IPSEC TUNNEL_GROUP_WEBVPN
                          TUNNEL_GROUP
                          TUNNEL_GROUP_IPNAME_IPSEC TUNNEL_GROUP_IPNAME 
                          GROUP_POLICY
			  ACCESS_LIST IP_LOCAL_POOL OBJECT_GROUP
			  NO_SYSOPT_CONNECTION_PERMIT_VPN
			  );
    
    for my $parse_name ( @parse_names ) {
	my $parse = $structure->{$parse_name};
      OBJECT:
	for my $obj_name ( sort keys %{$conf->{$parse_name}} ) {
	    
	    my $object = object_for_name( $conf, $parse_name, $obj_name );
	    
	    # Remove spare objects from device.
	    next if $object->{connected};

            # Only remove objects that have been defined by Netspoc.
            next if $parse_name ne 'CRYPTO_MAP_SEQ' and $obj_name !~ /DRC-\d+$/;

            # So we do not try to remove the object again later.
            $object->{needed} = 1;
            info("Remove spare $parse_name $obj_name");
            my $method = $parse->{remove};
            $self->$method( $conf, $structure, $parse_name, $obj_name );
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

    # Mark object-groups referenced by access-list
    if ($parse_name eq 'ACCESS_LIST') {
        for my $entry (@{ $object->{LIST} }) {
            next if $entry->{REMARK};
            for my $where (qw(TYPE SRC DST SRC_PORT DST_PORT)) {
                my $what = $entry->{$where};
                my $group = ref($what) && $what->{GROUP} or next;
                $group->{connected} = 1;
            }
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
    for my $parse_name ( sort keys %$structure ) {
	my $objects = $conf->{$parse_name};
        for my $obj_name ( sort keys %$objects ) {
            my $object = $objects->{$obj_name};
	    next if $object->{connected};

            # Only warn on objects that have been defined by Netspoc.
            next if $parse_name ne 'CRYPTO_MAP_SEQ' and $obj_name !~ /DRC-\d+$/;
	    warn_info("Spare $parse_name: $obj_name");
	}
    }    
}

sub change_attributes {
    my ( $self, $parse_name, $spoc_name, $spoc_value, $attributes ) = @_;
    my @cmds;

    return if $parse_name =~ /^(CERT_ANCHOR)$/;
    return if ( $spoc_value->{change_done} );

    info("Change attributes of $parse_name $spoc_name");
    if ( my $name = $spoc_value->{name_on_dev} ) {
	$spoc_name = $name; 
    }
    elsif ( $spoc_value->{transfer} ) {
	$spoc_name = $spoc_value->{new_name} || $spoc_name;
    }

    if( $parse_name eq 'IF' ) {
	for my $attr ( sort keys %$attributes ) {
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
	    $prefix = "crypto map $spoc_name";
	}
	elsif( $parse_name eq 'DYNAMIC_MAP' ) {
            my $seq = $spoc_value->{SEQ};
	    $prefix = "crypto dynamic-map $spoc_name $seq";
	}
	elsif( not $parse_name eq 'DEFAULT_GROUP' ) {
	    push @cmds, item_conf_mode_cmd( $parse_name, $spoc_name );
	}
	
	for my $attr ( sort keys %$attributes ) {
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
    my ( $self, $obj, $parse_name, $item_name, $attributes ) = @_;

    info("Remove attributes of $parse_name $item_name");
    my @cmds;
    my $prefix;
    if( $parse_name eq 'CRYPTO_MAP_SEQ' ) {
	$prefix = "crypto map $item_name";
    }
    elsif ($parse_name eq 'DYNAMIC_MAP') {
        my $seq = $obj->{SEQ};
        $prefix = "crypto dynamic-map $item_name $seq";
    }
    else {
	push @cmds, item_conf_mode_cmd( $parse_name, $item_name );
    }

    for my $attr ( sort keys %{$attributes} ) {
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
    my $name = $object->{name};
    my $prefix = "crypto map $name";
    my $cmd = "clear configure $prefix";
    $self->cmd( $cmd );
}

sub transfer_dynamic_map {
    my ( $self, $spoc, $structure, $parse_name, $name ) = @_;

    my $object = object_for_name( $spoc, $parse_name, $name );
    my @cmds;
    push @cmds, add_attribute_cmds( $structure, $parse_name,
				    $object, 'attributes' );
    map { $self->cmd( $_ ) } @cmds;
}

sub remove_dynamic_map {
    my ( $self, $conf, $structure, $parse_name, $obj_name ) = @_;

    my $object = object_for_name( $conf, $parse_name, $obj_name );
    my $name = $object->{name};
    my $seq  = $object->{SEQ};
    my $prefix = "crypto dynamic-map $name $seq";
    my $cmd = "clear configure $prefix";
    $self->cmd( $cmd );
}

sub transfer_ca_cert_map {
    my ( $self, $spoc, $structure, $parse_name, $cert_map ) = @_;

    my $object = object_for_name( $spoc, $parse_name, $cert_map );
    my $new_cert_map = $object->{new_name};
    my @cmds;
    push @cmds, item_conf_mode_cmd( $parse_name, $new_cert_map );
    push @cmds, add_attribute_cmds($structure, $parse_name, $object, 
                                   'attributes');
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
    my $new_default_group = $tunnel_group->{new_name} || $tunnel_group->{name};
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
    my ( $self, $spoc, $structure, $parse_name, $obj_name ) = @_;

    my $tunnel_group = $spoc->{$parse_name}->{$obj_name} or
	abort("No $parse_name found for $obj_name");
    my $tg = $spoc->{TUNNEL_GROUP}->{$obj_name};
    my $new_name = is_ip( $obj_name ) 
               ? $obj_name

               # Use same name for tg xxx-attributes if tg is already
               # on device.
               : $tg->{name_on_dev} || $tg->{new_name} || $tg->{name};
    my @cmds;
    if ( $parse_name =~ /^TUNNEL_GROUP(?:_IPNAME)?$/ ) {
        my $define_item = $spoc->{TUNNEL_GROUP_DEFINE}->{$obj_name}->{orig};
        $define_item =~ s/tunnel-group $obj_name(?!\S)/tunnel-group $new_name/;
        push @cmds, $define_item;
    }

    if ( $parse_name ne 'TUNNEL_GROUP_IPNAME' ) {
	push @cmds, item_conf_mode_cmd( $parse_name, $new_name );
	push @cmds, add_attribute_cmds( $structure, $parse_name,
				    $tunnel_group, 'attributes' );
    }
    map { $self->cmd( $_ ) } @cmds;
}

sub remove_tunnel_group {
    my ( $self, $conf, $structure, $parse_name, $obj_name ) = @_;
    $self->cmd("clear configure tunnel-group $obj_name");
}

sub remove_tunnel_group_xxx {
    my ( $self, $conf, $structure, $parse_name, $obj_name ) = @_;
    my $cmd = item_conf_mode_cmd($parse_name, $obj_name);
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

sub transfer_ipsec_proposal {
    my ( $self, $spoc, $structure, $parse_name, $obj_name ) = @_;
    my $obj = $spoc->{$parse_name}->{$obj_name};
    my $new_name = $obj->{new_name};
    my $cmd = $obj->{orig}; 
    $cmd =~ s/proposal $obj_name(?!\S)/proposal $new_name/;
    my @cmds;
    push @cmds, $cmd;
    push @cmds, add_attribute_cmds( $structure, $parse_name,
				    $obj, 'attributes' );
    map { $self->cmd( $_ ) } @cmds;    
}

sub remove_obj {
    my ( $self, $conf, $structure, $parse_name, $obj_name ) = @_;
    my $obj = $conf->{$parse_name}->{$obj_name};
    my $cmd = "no $obj->{orig}";
    $self->cmd( $cmd );
}

sub transfer_transform_set {
    my ( $self, $spoc, $structure, $parse_name, $obj_name ) = @_;
    my $obj = $spoc->{$parse_name}->{$obj_name};
    my $new_name = $obj->{new_name};
    my $cmd = $obj->{orig}; 

    # Handle "crypto ipsec transform-set"
    # and "crypto ipsec ikev1 transform-set"
    $cmd =~ s/transform-set $obj_name(?!\S)/transform-set $new_name/;
    $self->cmd( $cmd );
}

sub transfer_ip_local_pool {
    my ( $self, $spoc, $structure, $parse_name, $obj_name ) = @_;
    my $pool = $spoc->{$parse_name}->{$obj_name};
    my $new_name = $pool->{new_name};
    my $cmd = $pool->{orig}; 
    $cmd =~ s/ip local pool $obj_name(?!\S)/ip local pool $new_name/;
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

sub transfer_acl {
    my ( $self, $spoc, $structure, $parse_name, $acl_name ) = @_;

    my $acl = $spoc->{$parse_name}->{$acl_name};
    my $new_name = $acl->{new_name};
    my @cmds = map({ $self->subst_ace_name_og($_, $new_name) } 
                   @{ $acl->{LIST} });
    map { $self->cmd( $_ ) } @cmds;
}

sub modify_acl {
    my ( $self, $spoc, $conf_name ) = @_;

    my $gen_cmd = sub {
        my ($hash) = @_;
        my $ace = $hash->{ace};
        my $line = $hash->{line};
        my $cmd;
        if ($hash->{delete}) {
            $cmd = "no $ace->{orig}";
        }
        else {
            $cmd = $self->subst_ace_name_og($ace, $hash->{name});
        }

        # Note: 
        # access-list id [line line-number] [extended]
        # access-list id standard [line line-num]
        # (from Cisco Security Appliance Command Reference, Version 8.0(4))
        $cmd =~ s/(access-list\s+\S+(:?\s+standard)?)/$1 line $line/;
        $cmd;
    };
    
    for my $hash (@{ $spoc->{modify_cmds} }) {
        if (ref $hash eq 'ARRAY') {
            my ($hash1, $hash2) = @$hash;
            my $cmd1 = $gen_cmd->($hash1);
            my $cmd2 = $gen_cmd->($hash2);
            $self->two_cmd($cmd1, $cmd2);
        }
        else {
            my $cmd = $gen_cmd->($hash);
            $self->cmd($cmd);
        }
    }
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
 	my $name = $object->{new_name} || $object->{name};
	$prefix = "crypto map $name";
    }
    elsif( $parse_name eq 'DYNAMIC_MAP' ) {
 	my $name = $object->{name};
        my $seq  = $object->{SEQ};
	$prefix = "crypto dynamic-map $name $seq";
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

sub write_mem {
    my ($self) = @_;
    $self->cmd('write memory');
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
            modify => 'modify_acl',
	},
	OBJECT_GROUP => {
	    attributes => [],
	    transfer => 'transfer_object_group',
	    remove   => 'remove_obj',
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
        IPSEC_PROPOSAL => {
            attributes  => [ qw(ENCRYPTION_LIST INTEGRITY_LIST) ],
            simple_object => 1,
	    transfer => 'transfer_ipsec_proposal',
	    remove   => 'remove_obj',
        },
        TRANSFORM_SET => {
            attributes  => [ qw(LIST) ],
            simple_object => 1,
	    transfer => 'transfer_transform_set',
	    remove   => 'remove_obj',
        },
        DYNAMIC_MAP => {
            attributes => [ qw( NAT_T_DISABLE PFS REVERSE_ROUTE 
                                SA_LIFETIME_SEC SA_LIFETIME_KB) ],
            next     => [ { attr_name  => 'MATCH_ADDRESS',
			    parse_name => 'ACCESS_LIST' },
                          { attr_name  => 'IPSEC_PROPOSAL',
			    parse_name => 'IPSEC_PROPOSAL' },
                          { attr_name  => 'TRANSFORM_SET_IKEV1',
			    parse_name => 'TRANSFORM_SET' },
                          { attr_name  => 'TRANSFORM_SET_IKEV1_2nd',
			    parse_name => 'TRANSFORM_SET' },
                ],
	    transfer => 'transfer_dynamic_map',
	    remove   => 'remove_obj',
        },
	CRYPTO_MAP_SEQ => {
	    attributes => [ qw(NAT_T_DISABLE PEER PFS REVERSE_ROUTE
			       SA_LIFETIME_SEC SA_LIFETIME_KB TRUSTPOINT) ],
	    next     => [ { attr_name  => 'MATCH_ADDRESS',
			    parse_name => 'ACCESS_LIST' },  
                          { attr_name  => 'IPSEC_PROPOSAL',
			    parse_name => 'IPSEC_PROPOSAL' },
                          { attr_name  => 'TRANSFORM_SET',
			    parse_name => 'TRANSFORM_SET' },
                          { attr_name  => 'TRANSFORM_SET_IKEV1',
			    parse_name => 'TRANSFORM_SET' },
                          { attr_name  => 'DYNAMIC_MAP',
                            parse_name => 'DYNAMIC_MAP' },
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
    $self->SUPER::mark_as_changed($parse_name);
}

sub mark_as_unchanged {
    my ( $self, $parse_name ) = @_;

    return if $parse_name eq 'IF';
    return if $parse_name eq 'CERT_ANCHOR';
    return if $parse_name eq 'DEFAULT_GROUP';
    $self->SUPER::mark_as_unchanged($parse_name);
}

sub acl_removal_cmd {
    my ( $self, $acl_name ) = @_;
    return "no access-list $acl_name";
}


# Packages must return a true value;
1;

