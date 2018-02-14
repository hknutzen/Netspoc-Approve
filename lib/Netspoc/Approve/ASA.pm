
=head1 DESCRIPTION

Remote configure Cisco ASA.

=head1 COPYRIGHT AND DISCLAIMER

https://github.com/hknutzen/Netspoc-Approve
(c) 2017 by Heinz Knutzen <heinz.knutzen@gmail.com>
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

package Netspoc::Approve::ASA;

use base "Netspoc::Approve::Cisco";
use strict;
use warnings;
use Algorithm::Diff;
use Netspoc::Approve::Helper;
use Netspoc::Approve::Parse_Cisco;

# VERSION: inserted by DZP::OurPkgVersion

# Global variables.

my %conf_mode_entry = (
                       TUNNEL_GROUP_GENERAL => {
                           prefix  => 'tunnel-group',
                           postfix => 'general-attributes',
                       },
                       TUNNEL_GROUP_IPSEC => {
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
     TUNNEL_GROUP_GENERAL => {
         DEFAULT_GROUP_POLICY      => 'default-group-policy',
     },
     DEFAULT_GROUP => {
         TUNNEL_GROUP             => 'tunnel-group-map',
     },
     CA_CERT_MAP => {
         IDENTIFIER                => 'subject-name attr',
     },
     IP_LOCAL_POOL => {
         IP_LOCAL_POOL             => 'ip local pool',
     },
     CRYPTO_MAP_SEQ => {
         DYNAMIC_MAP              => 'ipsec-isakmp dynamic',
         MATCH_ADDRESS            => 'match address',
         NAT_T_DISABLE            => 'set nat-t-disable',
         PEER                     => 'set peer',
         PFS                      => 'set pfs',
         REVERSE_ROUTE            => 'set reverse-route',
         SA_LIFETIME_SEC          => 'set security-association lifetime seconds',
         SA_LIFETIME_KB           => 'set security-association lifetime kilobytes',
         IPSEC_PROPOSAL           => 'set ikev2 ipsec-proposal',
         TRANSFORM_SET            => 'set transform-set',
         TRANSFORM_SET_IKEV1      => 'set ikev1 transform-set',
         TRUSTPOINT               => 'set trustpoint',
     },
     DYNAMIC_MAP => {
         MATCH_ADDRESS            => 'match address',
         NAT_T_DISABLE            => 'set nat-t-disable',
         PEER                     => 'set peer',
         PFS                      => 'set pfs',
         REVERSE_ROUTE            => 'set reverse-route',
         SA_LIFETIME_SEC          => 'set security-association lifetime seconds',
         SA_LIFETIME_KB           => 'set security-association lifetime kilobytes',
         IPSEC_PROPOSAL           => 'set ikev2 ipsec-proposal',
         TRANSFORM_SET_IKEV1      => 'set ikev1 transform-set',
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

    return {

        # Defines association of a name with an IP address.
        # This interferes with parsing of ACL and object-groups.
        name => {
            error => "'name' command must not be used",
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
                      # don't store METRIC, values seem to be arbitrary.
                      { parse => \&check_int } ],
        },

        interface => {
            store => 'HWIF',
            named => 1,
            subcmd => {
                'shutdown' => { store => 'SHUTDOWN', default => 1 },
                'speed'    => { store => 'HW_SPEED', parse => \&get_int },
                'duplex'   => { store => 'DUPLEX', parse => \&get_token },
                'nameif'   => { store => 'IF_NAME', parse => \&get_token },
                'security-level' => { store => 'SECURITY', parse => \&get_int},
                'ip address' => {
                    store => 'ADDRESS',
                    parse => ['or',
                              ['seq',
                               { store => 'DYNAMIC', parse => qr/pppoe|dhcp/, },
                               ['cond1',
                                { parse => qr/setroute/ } ]],
                              ['seq',
                               { store => 'BASE', parse => \&get_ip },
                               { store => 'MASK', parse => \&get_ip },
                               ['cond1',
                                { parse => qr/standby/ },
                                { store => 'STANDBY', parse => \&get_ip } ]]] },
                'management-only' => {
                    store => 'MANAGEMENT_ONLY', default => 1 },
            }
        },

        'no sysopt connection permit-vpn' => {
            store => ['NO_SYSOPT_CONNECTION_PERMIT_VPN', 'name', 'value'],
            default => 1,
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
            strict => 1,
            subcmd => {
                'network-object' => {
                    store => 'OBJECT',
                    multi => 1,
                    parse => 'parse_address',
                },
                'group-object' => {
                    error => 'Nested object group not supported',
                },
                # Ignore description command.
                'description' => { parse => \&skip, },
            }
        },
        'object-group service _skip tcp' => {
            store => 'OBJECT_GROUP',
            named => 1,
            parse => ['seq', { store => 'TYPE', default => 'tcp', },],
            strict => 1,
            subcmd => {
                'port-object' => {
                    store => 'OBJECT',
                    multi => 1,
                    parse => 'parse_port_spec', params => ['tcp'],
                },
                'group-object' => {
                    error => 'Nested object group not supported'
                },
                # Ignore description command.
                'description' => { parse => \&skip, },
            }
        },
        'object-group service _skip udp' => {
            store => 'OBJECT_GROUP',
            named => 1,
            parse => ['seq', { store => 'TYPE', default => 'udp', },],
            strict => 1,
            subcmd => {
                'port-object' => {
                    store => 'OBJECT',
                    multi => 1,
                    parse => 'parse_port_spec', params => ['udp'],
                },
                'group-object' => {
                    error => 'Nested object group not supported'
                },
                # Ignore description command.
                'description' => { parse => \&skip, },
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
                # Ignore description command.
                'description' => { parse => \&skip, },
            }
        },
        'object-group service' => {
            store => 'OBJECT_GROUP',
            named => 1,
            parse => ['seq', { store => 'TYPE', default => 'service', },],
            strict => 1,
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
                # Ignore description command.
                'description' => { parse => \&skip, },
            }
        },
        'object-group protocol' => {
            store => 'OBJECT_GROUP',
            named => 1,
            parse => ['seq', { store => 'TYPE', default => 'protocol', },],
            strict => 1,
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
                },
                # Ignore description command.
                'description' => { parse => \&skip, },
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

# Ignore, don't try to parse as crypto map with sequence number.
        'crypto map _skip client'         => { parse => \&skip, },
        'crypto map _skip interface'      => { parse => \&skip, },

        'crypto map' => {
            store => 'CRYPTO_MAP_SEQ',
            named => 'from_parser',
            merge => 1,
            parse => ['seq',
                      { store => 'name', parse => \&get_token },
                      ['seq',

                       # Combine name and seq-num into attribute name.
                       { parse => sub {
                           my ($arg, $name) = @_;
                           my $seq = get_int($arg);
                           join(' ', $name, $seq);
                         },
                         params => [ '$name' ],
                         store => 'name',
                       },

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
                           { parse => \&get_token_list,
                             store => 'IPSEC_PROPOSAL' } ],
                          ['cond1',
                           { parse => qr/ikev1/ },
                           { parse => qr/transform-set/ },
                           { parse => \&get_token_list,
                             store => 'TRANSFORM_SET_IKEV1' },
                          ],
                          ['cond1',
                           { parse => qr/transform-set/ },
                           { parse => \&get_token_list,
                             store => 'TRANSFORM_SET' } ],
                          ['cond1',
                           { parse => qr/trustpoint/ },
                           { parse => \&get_token,
                             store => 'TRUSTPOINT', } ]]]]]]
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
                          { parse => \&get_token_list,
                            store => 'IPSEC_PROPOSAL' } ],
                         ['cond1',
                          { parse => qr/ikev1/ },
                          { parse => qr/transform-set/ },
                          { parse => \&get_token_list,
                            store => 'TRANSFORM_SET_IKEV1' }, ]]]]]
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

# Handle tunnel-group.
        'tunnel-group _skip type' => {
            store => 'TUNNEL_GROUP_DEFINE',
            named => 1,
            parse => [ 'seq',
                       { store => 'TYPE',
                         parse => \&get_token }, ],
        },

# Handle tunnel-group general attributes.
        'tunnel-group _skip general-attributes' => {
            store => 'TUNNEL_GROUP_GENERAL',
            named => 1,
            subcmd => {
                'default-group-policy' => {
                    store => 'DEFAULT_GROUP_POLICY',
                    parse => \&get_token,
                },

                # '_any' is special word, which matches any token.
                # '_cmd' is replaced by current command name.
                _any => {
                    store => ['ATTRIBUTES', '_cmd'],
                    parse => \&get_to_eol,
                }
            }
        },

        'tunnel-group _skip ipsec-attributes' => {
            store => 'TUNNEL_GROUP_IPSEC',
            named => 1,
            subcmd => {

                # Ignore pre-shared keys. These are set manually.
                'pre-shared-key'       => { parse => \&skip, },
                'ikev1 pre-shared-key' => { parse => \&skip, },
                'ikev2 local-authentication pre-shared-key' => {
                    parse => \&skip,
                },
                'ikev2 remote-authentication pre-shared-key' => {
                    parse => \&skip,
                },

                # '_any' is special word, which matches any token.
                # '_cmd' is replaced by current command name.

                # isakmp ikev1-user-authentication
                # isakmp keepalive
                'isakmp _any' => {
                    store => ['ATTRIBUTES', '_cmd'],
                    parse => \&get_to_eol,
                },
                # ikev1 trust-point
                # ikev1 user-authentication
                'ikev1 _any' => {
                    store => ['ATTRIBUTES', '_cmd'],
                    parse => \&get_to_eol,
                },
                _any => {
                    store => ['ATTRIBUTES', '_cmd'],
                    parse => \&get_to_eol,
                }
            }
        },

        'tunnel-group _skip webvpn-attributes' => {
            store => 'TUNNEL_GROUP_WEBVPN',
            named => 1,
            subcmd => {
                _any => {
                    store => ['ATTRIBUTES', '_cmd'],
                    parse => \&get_to_eol,
                }
            }
        },

# Handle tunnel-group-map.
        'tunnel-group-map' => {
            store => 'TUNNEL_GROUP_MAP',
            named => 'from_parser',
            parse => [ 'or',
                       [ 'cond1',
                         { parse => qr/enable/ },
                         { parse => qr/rules/  },
                       ],
                       [ 'cond1',
                         { parse => qr/default-group/  },
                         { store => 'TUNNEL_GROUP', parse => \&get_token },
                         { store => 'name',
                           parse => sub { return "DEFAULT"; } },
                       ],
                       [ 'seq',
                         { store => 'name',  parse => \&get_token },
                         { store => 'INDEX', parse => \&get_int },
                         { store => 'TUNNEL_GROUP', parse => \&get_token },
                       ],
                ],
        },

# crypto ca certificate map DefaultCertificateMap 20
#  subject-name attr o eq dataport
# crypto ca certificate map MAP-certificate_PermisA.dataport.de 100
#  subject-name attr ea co @permisa.dataport.de

# Handle crypto ca certificates.
        'crypto ca certificate map' => {
            store => 'CA_CERT_MAP',
            named => 1,
            parse => [ 'seq',
                       { store => 'INDEX', parse => \&get_int },
                ],
            subcmd => {
                'subject-name attr' => {
                    store => 'IDENTIFIER',
                    parse => \&get_to_eol
                },
            }
        },

# Handle username.
        'username _skip nopassword' => {
            store   => 'USERNAME_NOPASSWORD',
            named   => 1,
            default => 1,
        },
        'username _skip attributes' => {
            store => 'USERNAME',
            named => 1,
            subcmd => {
                'vpn-filter value' => {
                    store => 'VPN_FILTER',
                    parse => \&get_token,
                },
                'vpn-group-policy' => {
                    store => 'VPN_GROUP_POLICY',
                    parse => \&get_token,
                },

                # '_any' is special word, which matches any token.
                # '_cmd' is replaced by current command name.
                _any => {
                    store => ['ATTRIBUTES', '_cmd'],
                    parse => \&get_to_eol,
                }
            }
        },

# Handle group policies.
        'group-policy _skip internal' => {
            store   => 'GROUP_POLICY_INTERNAL',
            named   => 1,
            default => 1,
        },
        'group-policy _skip attributes' => {
            store => 'GROUP_POLICY',
            named => 1,
            subcmd => {
                'vpn-filter value' => {
                    store => 'VPN_FILTER',
                    parse => \&get_token,
                },
                'split-tunnel-network-list value' => {
                    store => 'SPLIT_TUNNEL_NETWORK_LIST',
                    parse => \&get_token,
                },
                'address-pools value' => {
                    store => 'ADDRESS_POOL',
                    parse => \&get_token,
                },

                # This command is ignored.
                # But declare it, because it has subcommands.
                'webvpn' => { subcmd => {} },

                # '_any' is special word, which matches any token.
                # '_cmd' is replaced by current command name.
                _any => {
                    store => ['ATTRIBUTES', '_cmd'],
                    parse => \&get_to_eol,
                }
            }
        },

# Handle local IP-pools.
        'ip local pool' => {
            store => 'IP_LOCAL_POOL',
            named => 1,
            parse => [ 'seq',
                       { store_multi => ['RANGE_FROM', 'RANGE_TO'],
                         parse => \&get_ip_pair },
                       { parse => qr/mask/ },
                       { store => 'MASK', parse => \&get_ip },
                ],
        },

# Handle global webvpn mode.
# webvpn
#  certificate-group-map <cert_map> <index> <tunnel_group_map>
        webvpn => {
            store => 'WEBVPN',
            subcmd => {
                'certificate-group-map' => {
                    store => 'CERT_GROUP_MAP',
                    named => 1,
                    parse => [ 'seq',
                               { store => 'INDEX', parse => \&get_int },
                               { store => 'TUNNEL_GROUP',
                                 parse => \&get_token },
                        ],
                }
            }
        },

# We don't use the certificates, but lexical analyser needs to know
# that this is a multi line command.
        'crypto ca certificate chain' => {
            named => 1,
            subcmd => {
                'certificate' => { banner => qr/^\s*quit\s*$/,
                                   parse => \&skip },
            }
        },
    };
}

my %default_tunnel_groups = (
    DefaultL2LGroup => 'ipsec-l2l',
    DefaultRAGroup  => 'remote-access',
    DefaultWEBVPNGroup => 'webvpn',
    );

sub get_tunnel_group_define {
    my ($self, $p, $tg_name) = @_;
    if (my $tg = $p->{TUNNEL_GROUP_DEFINE}->{$tg_name}) {
        return $tg;
    }
    elsif (my $type = $default_tunnel_groups{$tg_name}) {
        return $p->{TUNNEL_GROUP_DEFINE}->{$tg_name} = { name => $tg_name,
                                                         TYPE => $type };
    }
    else {
        return;
    }
}

sub postprocess_config {
    my ( $self, $p ) = @_;

    # Propagate ip address and shutdown status from hardware interface
    # to logical interface.
    for my $entry ( values %{ $p->{HWIF} } ) {
        my $name = $entry->{IF_NAME} or next;
        my $intf = $p->{IF}->{$name} = { name => $name };
        if( my $address = $entry->{ADDRESS} ) {
            $intf->{BASE} = $address->{BASE};
            $intf->{MASK} = $address->{MASK};
        }
        $intf->{SHUTDOWN} = $entry->{SHUTDOWN};
    }
    delete $p->{HWIF};

    for my $what (qw(TUNNEL_GROUP_GENERAL TUNNEL_GROUP_IPSEC TUNNEL_GROUP_WEBVPN))
    {
        for my $name (keys %{$p->{$what}}) {
            my $base = $self->get_tunnel_group_define($p, $name) or
                abort("Missing type definition for tunnel-group $name");

            # Add links to related commands.
            $base->{$what} = $name;
        }
    }

    # TUNNEL_GROUP_MAP
    # - copy as attribute to CA_CERT_MAP
    # - for default-group copy to artificial DEFAULT_GROUP
    # - create artificial name: "default"
    my %TG_used_by_TG_map;
    for my $tgm ( values %{$p->{TUNNEL_GROUP_MAP}} ) {
        my $tgm_name = $tgm->{name};
        my $tg_name = $tgm->{TUNNEL_GROUP};
        my $anchor;
        if ($tgm_name eq 'DEFAULT') {
            $anchor = { name => 'default'};
            $p->{DEFAULT_GROUP}->{default} = $anchor;
        }
        else {
            $anchor = $p->{CA_CERT_MAP}->{$tgm_name} or
                abort("'$tgm->{orig}' references unknown" .
                      " ca cert map '$tgm_name'");
        }

        $anchor->{TUNNEL_GROUP_DEFINE} = $tg_name;
        if ($self->get_tunnel_group_define($p, $tg_name)) {
            $TG_used_by_TG_map{$tg_name} = 1;
        }
        else {
            abort("'$tgm->{orig}' references unknown tunnel-group $tg_name");
        }
    }

    # Not needed any longer.
    delete $p->{TUNNEL_GROUP_MAP};

    # Move tunnel_group with IP as name to IP_TUNNEL_GROUP_DEFINE as anchor.
    # But not for elements of %TG_used_by_TG_map.
    for my $name ( keys %{$p->{TUNNEL_GROUP_DEFINE}} ) {
        next if $TG_used_by_TG_map{$name};
        my $tg = $p->{TUNNEL_GROUP_DEFINE}->{$name};
        if ($name =~ /^\d+[.]\d+[.]\d+[.]\d+$/) {
            $p->{IP_TUNNEL_GROUP_DEFINE}->{$name} = $tg;
            delete $p->{TUNNEL_GROUP_DEFINE}->{$name};
        }
    }

    # WEBVPN, CERT_GROUP_MAP
    # - copy as attribute to CA_CERT_MAP
    if ($p->{WEBVPN} && (my $hash = $p->{WEBVPN}->{CERT_GROUP_MAP})) {
        for my $cgm (values %$hash) {
            my $ca_map_name = $cgm->{name};
            my $cert = $p->{CA_CERT_MAP}->{$ca_map_name} or
                abort("'$cgm->{orig}' references unknown" .
                      " ca cert map '$ca_map_name'");
            my $tg_name = $cgm->{TUNNEL_GROUP};
            $self->get_tunnel_group_define($p, $tg_name) or
                abort("'$cgm->{orig}' references unknown" .
                      " tunnel-group $tg_name");
            $cert->{WEB_TUNNEL_GROUP} = $tg_name;
        }

        # Move to toplevel.
        $p->{CERT_GROUP_MAP} = $hash;
    }

    # Create artificial certificate-anchor CERT_ANCHOR,
    # IDENTIFIER as name, corresponding CA_CERT_MAP
    # as attribute CA_CERT_MAP.
    # Convert IDENTIFIER to lower-case, because it gets
    # stored on device in lower-case anyway.
    for my $ca_map_name (sort keys %{$p->{CA_CERT_MAP}}) {
        my $cert = $p->{CA_CERT_MAP}->{$ca_map_name};
        my $id = $cert->{IDENTIFIER} or next;
        $id = lc( $id );
        $cert->{IDENTIFIER} = $id;
        if(my $old_cert = $p->{CERT_ANCHOR}->{$id}) {
            my $old_name = $old_cert->{CA_CERT_MAP};
            my $new_name = $cert->{name};
            abort("Two ca cert map items use" .
                  " identical subject-name: '$old_name', '$new_name'");
        }
        $p->{CERT_ANCHOR}->{$id} = { CA_CERT_MAP => $cert->{name},
                                     name => $id };
    }

    # Make 'nopassword'-property of a user an attribute of
    # corresponding user.
    for my $nopasswd_user ( keys %{$p->{USERNAME_NOPASSWORD}} ) {
        $p->{USERNAME}->{$nopasswd_user}->{NOPASSWORD} = 1;
    }

    # Make 'internal'-property of a group-policy an
    # attribute of corresponding group-policy.
    for my $gp_internal ( keys %{$p->{GROUP_POLICY_INTERNAL}} ) {
        my $gp =
            $p->{GROUP_POLICY}->{$gp_internal} ||= { name => $gp_internal };
        $gp->{INTERNAL} = 1;
    }

    # Not needed any longer.
    delete $p->{GROUP_POLICY_INTERNAL};

    # 'DfltGrpPolicy' must not be removed, even if not referenced.
    my $dflt_gp = 'DfltGrpPolicy';
    if($p->{GROUP_POLICY}->{$dflt_gp}) {
        $p->{GROUP_POLICY_ANCHOR}->{$dflt_gp} = { name => $dflt_gp,
                                                  GROUP_POLICY => $dflt_gp };
    }

    # Connect elements referenced by default tunnel groups.
    for my $tg_name (keys %default_tunnel_groups) {
        $p->{TUNNEL_GROUP_DEFINE}->{$tg_name} or next;
        $p->{DEFAULT_TUNNEL_GROUP}->{$tg_name} = { name => $tg_name,
                                                   TUNNEL_GROUP => $tg_name };
    }

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

    # Add entries of CRYPTO_MAP_SEQ to attribute PEER of artificial
    # anchor CRYPTO_MAP_LIST.
    my $seq = $p->{CRYPTO_MAP_SEQ};
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
    for my $key (sort keys %$p) {
        my $v = $p->{$key};
        my $count = (ref $v eq 'ARRAY') ? @$v : keys %$v;
        info("Found $count $key") if $count;
    }
}

sub set_pager {
    my ($self) = @_;
    $self->device_cmd('terminal pager 0');
}

# Max. terminal width for ASA is 511.
sub set_terminal_width {
    my ($self) = @_;
    $self->device_cmd('configure terminal');
    $self->device_cmd('terminal width 511');
    $self->device_cmd('end');
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
     # Multi line, expected warning.
     qr /^WARNING: (For IKEv1, )?L2L tunnel-groups that have names which are not an IP/,
     qr /^address may only be used if the tunnel authentication/,
     qr /^method is Digital Certificates and\/or The peer is/,
     qr /^configured to use Aggressive Mode/,
     # Expected warning from "managed=local"
     qr/^WARNING: Same object-group is used more than once in one config line[.] This config is redundant[.] Please use seperate object-groups/,
     # ASA: general info
     qr/^INFO:/,
      );

my @known_warning =
    (
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
    if(my ($hardware) = $output =~ /Hardware:\s+(\S+)/i) {
        $hardware =~ s/,$//;
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
        next if $parse_name eq 'IP_TUNNEL_GROUP_DEFINE';

        my $hash = $spoc->{$parse_name};
        for my $name ( keys %$hash ) {
            if ($parse_name =~ /^TUNNEL_GROUP/) {
                next if $name =~ /^\d+[.]\d+[.]\d+[.]\d+$/;
            }
            next if $parse_name eq 'GROUP_POLICY' and $name eq 'DfltGrpPolicy';
            my $obj = $hash->{$name};
            $obj->{new_name} =
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
        # uncoverable statement
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
    for my $key (qw(next next_list)) {
        my $next = $parse->{$key} or next;
        for my $next_key (@$next) {
            my $next_attr_name = $next_key->{attr_name};
            my $conf_next = $conf_value->{$next_attr_name} or next;
            my $spoc_next = $spoc_value->{$next_attr_name};
            if ( not $spoc_next ) {
                $modified = 1;
                $conf_value->{remove_attr}->{$next_attr_name} = $conf_next;
            }
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

# Access to ASA isn't controlled by ACL.
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
                         map($conf->{CRYPTO_MAP_SEQ}->{$_},
                             @{$conf_crypto->{PEERS}}) ];
    my $spoc_entries = [ sort by_peer
                         map($spoc->{CRYPTO_MAP_SEQ}->{$_},
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

    $spoc_name or $conf_name or return;

#    info("MAKE EQUAL( $parse_name ) => CONF:$conf_name, SPOC:$spoc_name ");

    my $modified;
    my $conf_value = $conf_name && $conf->{$parse_name}->{$conf_name};
    my $spoc_value = $spoc_name && $spoc->{$parse_name}->{$spoc_name};

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
        elsif ($structure->{$parse_name}->{need_eq_attr}
               and $conf_value and $spoc_value)
        {
            my $attributes = $structure->{$parse_name}->{attributes};
            simple_object_equal($spoc_value, $conf_value, $attributes) or
                abort("Can't change type of $parse_name $conf_name");
        }
    }

    # Transfer object from netspoc
    # - if no matching object is found on device or
    # - if matching object is already needed in other context and
    #   must not be changed.
    if ( $spoc_value && (!$conf_value || $conf_value && $conf_value->{needed}) ) {

#       info("$parse_name => $spoc_name on spoc but not on dev. ");
        $modified = 1;
        $spoc_value->{transfer} = 1;

        # Mark object-groups referenced by acl lines.
        if ( $parse_name eq 'ACCESS_LIST' ) {
            $self->mark_object_group_from_acl($spoc_value);
        }
    }

    # Compare object on device with object from Netspoc.
    elsif ( $conf_value && $spoc_value ) {

        # On both, compare attributes.
        if ( $parse_name eq 'ACCESS_LIST' ) {
            info("Comparing $conf_name $spoc_name");
            my $unchanged = $self->equalize_acl($conf_value, $spoc_value);
            $modified = !$unchanged;

            if ($modified) {
                my $modify_cmds = $spoc_value->{modify_cmds};
                if (!$modify_cmds) {

                    # This should never happen, because ACLs are
                    # always changed incrementally for ASA.
                    $spoc_value->{transfer} = 1; # uncoverable statement
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
#       if($spoc_value->{name_on_dev}) {
#           undef $spoc_value->{transfer};
#       }
    }

    # On dev but not on spoc. Unused, will be removed later.
    elsif ( $conf_value  &&  !$spoc_value ) {
#       info("$parse_name => $conf_name on dev but not on spoc. ");
        $modified = 1;
    }

    # Process child nodes recursively.
    if ( my $parse = $structure->{$parse_name} ) {

        for my $key (qw(next next_list)) {
            my $next = $parse->{$key} or next;
            for my $next_key ( @$next ) {
                my $next_attr_name  = $next_key->{attr_name};
                my $next_parse_name = $next_key->{parse_name};
                my $is_not_attr     = $next_key->{is_not_attr};
                my $conf_next;
                $conf_next = $conf_value->{$next_attr_name} if $conf_value;
                my $spoc_next;
                $spoc_next = $spoc_value->{$next_attr_name} if $spoc_value;

                if ($key eq 'next') {

                    my $new_conf_next =
                        $self->make_equal( $conf, $spoc, $next_parse_name,
                                           $conf_next, $spoc_next,
                                           $structure );

                    # If an object is transferred or changed to an
                    # existing object on device, a new name is used.
                    # In the superior object,
                    # the corresponding attribute in that superior object
                    # has to be altered, so that it carries the name of the
                    # transferred or changed object.
                    if ( $spoc_next and not $is_not_attr) {
                        if ( ! $conf_next || $conf_next ne $new_conf_next ) {
                            $spoc_value->{change_attr}->{$next_attr_name} =
                                $new_conf_next;
                            $modified = 1;
                        }
                    }
                }

                # 'next_list'
                else {
                    $conf_next ||= [];
                    $spoc_next ||= [];
                    my $max_list = max(scalar @$conf_next, scalar @$spoc_next);
                    my @new_list;
                    my $modified_list;
                    for my $index (0 .. $max_list) {
                        my $conf_name = $conf_next->[$index];
                        my $spoc_name = $spoc_next->[$index];
                        my $new_conf_name =
                            $self->make_equal( $conf, $spoc, $next_parse_name,
                                               $conf_name, $spoc_name,
                                               $structure );
                        push @new_list, $new_conf_name if $new_conf_name;
                        if ( $spoc_name ) {
                            if (! $conf_name || $conf_name ne $new_conf_name) {
                                $modified_list = 1;
                            }
                        }
                    }
                    if ($modified_list and not $is_not_attr) {
                        $spoc_value->{change_attr}->{$next_attr_name} =
                            \@new_list;
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
    my %seen;

    # Iterate over anchors on device.
    for my $key (sort keys %$structure) {
        my $value = $structure->{$key};
        $value->{anchor} or next;
#       info("Processing conf anchor $key ... ");
        my $conf_anchor = $conf->{$key};
        for my $conf_key (sort keys %$conf_anchor) {
            $seen{$key}->{$conf_key} = 1;
            my $new_conf = $self->make_equal( $conf, $spoc, $key,
                                              $conf_key, $conf_key,
                                              $structure );
            if ( $new_conf && $conf_key ne $new_conf ) {
                # uncoverable statement
                internal_err "Anchors known so far are made equal by " .
                    "changing their attributes, not by transfer. " .
                    "(Anchor in conf: $key:$conf_key)";
            }
        }
    }

    # Iterate over anchors in netspoc (without those already
    # processed iterating over anchors on device).
    for my $key (sort keys %$structure) {
        my $value = $structure->{$key};
        $value->{anchor} or next;
#       info("Processing spoc anchor $key ... ");
        my $spoc_anchor = $spoc->{$key};
        for my $spoc_key (sort keys %$spoc_anchor) {
            next if $seen{$key}->{$spoc_key};
            $self->make_equal( $conf, $spoc, $key,
                               $spoc_key, $spoc_key,
                               $structure );
        }
    }
}

sub change_modified_attributes {
    my ($self, $spoc, $parse_name, $spoc_name, $structure) = @_;
    my $parse = $structure->{$parse_name} or return;
    my $spoc_value = $spoc->{$parse_name}->{$spoc_name};

    # Change attributes marked accordingly.
    if ( my $attr = $spoc_value->{change_attr} ) {
        $self->change_attributes( $parse_name, $spoc_name, $spoc_value, $attr );
    }

    # Enter recursion ...
    for my $pair (get_next_names($parse, $spoc_value)) {
        my ($next_parse_name, $spoc_next) = @$pair;
        $self->change_modified_attributes( $spoc, $next_parse_name,
                                           $spoc_next, $structure );
    }
}

# Transfer marked objects.
sub transfer1 {
    my ( $self, $spoc, $parse_name, $spoc_name, $structure ) = @_;
    my $parse = $structure->{$parse_name} or return;
    my $spoc_value = $spoc->{$parse_name}->{$spoc_name};

    my @postponed;
    for my $pair (get_next_names($parse, $spoc_value)) {
        my ($next_parse_name, $spoc_next) = @$pair;

        # Child object must be defined, but must only be
        # transferred after parent object has been defined.
        if ($structure->{$next_parse_name}->{postpone}) {
            push @postponed, $pair;
        }
        else {
            $self->transfer1( $spoc, $next_parse_name,
                              $spoc_next, $structure );
        }
    }

    # Do actual transfer after recursion so that we start with leaves.
    my $method = $parse->{transfer};
    if ( $spoc_value->{transfer} and $method ) {
        if ( not $spoc_value->{transferred_as} ) {
#           info("Transfer1 $parse_name $spoc_name");
            $spoc_value->{transferred_as} =
                $spoc_value->{new_name} || $spoc_value->{name};
            $self->$method( $spoc, $structure, $parse_name, $spoc_name );
        }
    }

    # Process postponed objects.
    for my $pair (@postponed) {
        my ($next_parse_name, $spoc_next) = @$pair;
        $self->transfer1( $spoc, $next_parse_name, $spoc_next, $structure );
    }


    # Change attributes of items in place.
#   info("Change $parse_name $spoc_name");
    $self->change_modified_attributes($spoc, $parse_name, $spoc_name,
                                      $structure);
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
            my $spoc_value = $spoc->{$parse_name}->{$spoc_name};
            $spoc_value->{transfer} or next;
            next if $spoc_value->{transferred_as};
            info("Transfer $parse_name $spoc_name");
            $self->$method( $spoc, $structure, $parse_name, $spoc_name );
            $spoc_value->{transferred_as} = $spoc_value->{new_name};
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
            $self->transfer1( $spoc, $key, $spoc_name, $structure );
        }
    }

    # Change list values of objects in place.
    # Add or remove entries to/from lists (access-list, object-group).
    for my $parse_name ( qw( ACCESS_LIST OBJECT_GROUP ) ) {
        my $spoc_hash = $spoc->{$parse_name};
        for my $spoc_name ( sort keys %$spoc_hash ) {
            my $spoc_value = $spoc->{$parse_name}->{$spoc_name};
            $spoc_value->{add_entries} or
                $spoc_value->{del_entries} or
                $spoc_value->{modify_cmds} or
                next;
            my $method = $structure->{$parse_name}->{modify};
            my $conf_name = $spoc_value->{name_on_dev};
            info("Modify $parse_name $conf_name");
            $self->$method( $spoc_value, $conf_name );
        }
    }
}

sub remove_unneeded_on_device {
    my ( $self, $conf, $structure ) = @_;

    # Caution: the order is significant in this array!
    my @parse_names = qw( CRYPTO_MAP_SEQ DYNAMIC_MAP USERNAME CA_CERT_MAP
                          TUNNEL_GROUP_IPSEC TUNNEL_GROUP_WEBVPN
                          TUNNEL_GROUP_GENERAL TUNNEL_GROUP_DEFINE
                          IP_TUNNEL_GROUP_DEFINE
                          TRANSFORM_SET IPSEC_PROPOSAL
                          GROUP_POLICY
                          ACCESS_LIST IP_LOCAL_POOL OBJECT_GROUP
                          NO_SYSOPT_CONNECTION_PERMIT_VPN
                          );

    for my $parse_name ( @parse_names ) {
        my $parse = $structure->{$parse_name};
        for my $obj_name ( sort keys %{$conf->{$parse_name}} ) {

            my $object = $conf->{$parse_name}->{$obj_name};

            # Remove attributes marked for deletion.
            if ( my $attr = $object->{remove_attr} ) {
                $self->remove_attributes($object, $parse_name, $obj_name,
                                         $attr);
            }

            # Remove unneeded object from device.
            next if $object->{needed};

            # Only remove object that has been substituted by new
            # object from Netspoc.
            next if not $object->{connected};

            # Do not remove users that have their own explicit
            # password (e.g. 'netspoc'-user used to access device).
            next if ( $parse_name eq 'USERNAME'  && ! $object->{NOPASSWORD} );

            info("Remove unneeded $parse_name $obj_name");
            my $method = $parse->{remove};
            $self->$method( $conf, $parse_name, $obj_name );
        }
    }
}

sub remove_spare_objects_on_device {
    my ( $self, $conf, $structure ) = @_;

    my @parse_names = qw( CRYPTO_MAP_SEQ DYNAMIC_MAP USERNAME CA_CERT_MAP
                          TUNNEL_GROUP_IPSEC TUNNEL_GROUP_WEBVPN
                          TUNNEL_GROUP_GENERAL TUNNEL_GROUP_DEFINE
                          IP_TUNNEL_GROUP_DEFINE
                          GROUP_POLICY
                          ACCESS_LIST IP_LOCAL_POOL OBJECT_GROUP
                          NO_SYSOPT_CONNECTION_PERMIT_VPN
                          );

    for my $parse_name ( @parse_names ) {
        my $parse = $structure->{$parse_name};
      OBJECT:
        for my $obj_name ( sort keys %{$conf->{$parse_name}} ) {

            my $object = $conf->{$parse_name}->{$obj_name};

            # Remove spare objects from device.
            next if $object->{connected};

            # Only remove objects that have been defined by Netspoc.
            next if $parse_name ne 'CRYPTO_MAP_SEQ' and $obj_name !~ /DRC-\d+$/;

            # So we do not try to remove the object again later.
            $object->{needed} = 1;
            info("Remove spare $parse_name $obj_name");
            my $method = $parse->{remove};
            $self->$method( $conf, $parse_name, $obj_name );
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
                      " referenced by $parse_name $object->{name}");
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
        $value->{anchor} or next;

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

    return if $parse_name =~ /^(CERT_ANCHOR|CRYPTO_MAP_LIST|GROUP_POLICY_ANCHOR)$/;
    return if $parse_name =~ /^(?:IP_)?TUNNEL_GROUP_DEFINE$/;
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
        if (my $tg_name = $attributes->{TUNNEL_GROUP_DEFINE}) {
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
            if(ref($value) eq 'HASH') {
                for my $cmd (sort keys %$value) {
                    my $args = $value->{$cmd};
                    push @cmds, "no $cmd" if $attr_need_remove{$cmd};
                    my $new_cmd = $cmd;
                    $new_cmd .= " $args" if $args;
                    push @cmds, $new_cmd;
                }
            }

            # Single or list of attributes which need to be converted
            # back to device syntax.
            elsif ( my $attr_cmd = cmd_for_attribute( $parse_name, $attr )) {

                # Multiple values of 'next_list' attribute.
                if(ref($value) eq 'ARRAY') {
                    $value = join(' ', @$value);
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
    $self->cmd( $_ ) for @cmds;
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
    elsif ($parse_name eq 'TUNNEL_GROUP_DEFINE' or
           $parse_name eq 'IP_TUNNEL_GROUP_DEFINE')
    {
    }
    else {
        push @cmds, item_conf_mode_cmd( $parse_name, $item_name );
    }

    for my $attr ( sort keys %{$attributes} ) {
        my $value = $attributes->{$attr};

        # A hash of attributes, read unchanged from device.
        if(ref($value) eq 'HASH') {
            for my $cmd (sort keys %$value) {
                my $args = $value->{$cmd};
                my $new_cmd = $cmd;
                $new_cmd = "$new_cmd value" if ($args && $args =~ /^value/);
                push @cmds, "no $new_cmd";
            }
        }
        elsif (my $attr_cmd = cmd_for_attribute( $parse_name, $attr )) {

            # Multiple values of 'next_list' attribute.
            if(ref($value) eq 'ARRAY') {
                $value = join(' ', @$value);
            }

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
    $self->cmd( $_ ) for @cmds;
}

sub transfer_crypto_map_seq {
    my ( $self, $spoc, $structure, $parse_name, $name_seq ) = @_;

    my $object = $spoc->{$parse_name}->{$name_seq};
    my @cmds = add_attribute_cmds( $structure, $parse_name, $object );
    $self->cmd( $_ ) for @cmds;
}

sub remove_crypto_map_seq {
    my ( $self, $conf, $parse_name, $name_seq ) = @_;
    $self->cmd("clear configure crypto map $name_seq");
}

sub transfer_dynamic_map {
    my ( $self, $spoc, $structure, $parse_name, $name ) = @_;

    my $object = $spoc->{$parse_name}->{$name};
    my @cmds = add_attribute_cmds( $structure, $parse_name, $object );
    $self->cmd( $_ ) for @cmds;
}

sub remove_dynamic_map {
    my ( $self, $conf, $parse_name, $obj_name ) = @_;
    my $object = $conf->{$parse_name}->{$obj_name};
    my $name = $object->{name};
    my $seq  = $object->{SEQ};
    $self->cmd("clear configure crypto dynamic-map $name $seq");
}

sub transfer_ca_cert_map {
    my ( $self, $spoc, $structure, $parse_name, $cert_map ) = @_;

    my $object = $spoc->{$parse_name}->{$cert_map};
    my $new_cert_map = $object->{new_name};
    my @cmds;
    push @cmds, item_conf_mode_cmd( $parse_name, $new_cert_map );
    push @cmds, add_attribute_cmds($structure, $parse_name, $object);
    $self->cmd( $_ ) for @cmds;
}

sub remove_ca_cert_map {
    my ( $self, $conf, $parse_name, $cert_map ) = @_;
    $self->cmd("clear configure crypto ca certificate map $cert_map");
}

sub transfer_default_group {
    my ( $self, $spoc, $structure, $parse_name, $default ) = @_;
    my $object = $spoc->{$parse_name}->{$default};
    my $tunnel_group_name = $object->{TUNNEL_GROUP_DEFINE};
    my $tunnel_group = $spoc->{TUNNEL_GROUP_DEFINE}->{$tunnel_group_name};
    my $new_default_group = $tunnel_group->{new_name} || $tunnel_group->{name};
    my $cmd = "tunnel-group-map default-group $new_default_group";
    $self->cmd( $cmd );
}

sub transfer_user {
    my ( $self, $spoc, $structure, $parse_name, $username ) = @_;
    my $user = $spoc->{$parse_name}->{$username};
    my @cmds;
    push @cmds, "username $username nopassword";
    push @cmds, item_conf_mode_cmd( $parse_name, $username );
    push @cmds, add_attribute_cmds( $structure, $parse_name, $user );
    push @cmds, 'exit';
    $self->cmd( $_ ) for @cmds;
}

sub remove_user {
    my ( $self, $conf, $parse_name, $username ) = @_;
    $self->cmd("clear configure username $username");
}

sub transfer_tunnel_group {
    my ( $self, $spoc, $structure, $parse_name, $obj_name ) = @_;
    my $obj = $spoc->{$parse_name}->{$obj_name};
    my $def =
        $spoc->{TUNNEL_GROUP_DEFINE}->{$obj_name} ||
        $spoc->{IP_TUNNEL_GROUP_DEFINE}->{$obj_name};
    my $new_name = $def->{name_on_dev} || $def->{new_name} || $def->{name};
    my @cmds;
    if ($parse_name eq 'TUNNEL_GROUP_DEFINE' or
        $parse_name eq 'IP_TUNNEL_GROUP_DEFINE')
    {
        my $define_item = $obj->{orig};
        $define_item =~ s/tunnel-group $obj_name(?!\S)/tunnel-group $new_name/;
        push @cmds, $define_item;
    }

    else {
        push @cmds, item_conf_mode_cmd( $parse_name, $new_name );
        push @cmds, add_attribute_cmds( $structure, $parse_name, $obj );
    }
    $self->cmd( $_ ) for @cmds;
}

sub remove_tunnel_group {
    my ( $self, $conf, $parse_name, $obj_name ) = @_;

    # Default tunnel groups must not be removed, even if not referenced.
    return if $default_tunnel_groups{$obj_name};

    $self->cmd("clear configure tunnel-group $obj_name");
}

sub transfer_group_policy {
    my ( $self, $spoc, $structure, $parse_name, $obj_name ) = @_;
    my $obj = $spoc->{$parse_name}->{$obj_name};
    my $new_name = $obj->{new_name} || $obj->{name};
    my @cmds;
    if ($new_name ne 'DfltGrpPolicy') {
        push @cmds, "group-policy $new_name internal";
    }
    push @cmds, item_conf_mode_cmd( $parse_name, $new_name );
    push @cmds, add_attribute_cmds( $structure, $parse_name, $obj );

    $self->cmd( $_ ) for @cmds;
}

sub remove_group_policy {
    my ( $self, $conf, $parse_name, $obj_name ) = @_;
    $self->cmd("clear configure group-policy $obj_name");
}

sub transfer_ipsec_proposal {
    my ( $self, $spoc, $structure, $parse_name, $obj_name ) = @_;
    my $obj = $spoc->{$parse_name}->{$obj_name};
    my $new_name = $obj->{new_name};
    my $cmd = $obj->{orig};
    $cmd =~ s/proposal $obj_name(?!\S)/proposal $new_name/;
    my @cmds;
    push @cmds, $cmd;
    push @cmds, add_attribute_cmds( $structure, $parse_name, $obj );
    $self->cmd( $_ ) for @cmds;
}

sub remove_obj {
    my ( $self, $conf, $parse_name, $obj_name ) = @_;
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
    my ( $self, $conf, $parse_name, $obj_name ) = @_;
    $self->cmd('sysopt connection permit-vpn');
}

sub transfer_object_group {
    my ( $self, $spoc, $structure, $parse_name, $object_group ) = @_;
    my $group = $spoc->{$parse_name}->{$object_group};
    my $new_name = $group->{new_name};
    my $cmd = $group->{orig};
    $cmd =~ s/^(\S+ \S+ )(\S+)(.*)/$1$new_name$3/;
    $self->cmd($cmd);
    $self->cmd( $_->{orig} ) for @{ $group->{OBJECT} };
}

sub modify_object_group {
    my ( $self, $spoc, $conf_name ) = @_;
    my $cmd = "object-group $spoc->{TYPE} $conf_name";
    $self->cmd($cmd);
    if($spoc->{add_entries}) {
        $self->cmd( $_->{orig} ) for @{ $spoc->{add_entries} };
    }
    if($spoc->{del_entries}) {
        $self->cmd( "no $_->{orig}" ) for @{ $spoc->{del_entries} };
    }
}

sub transfer_acl {
    my ( $self, $spoc, $structure, $parse_name, $acl_name ) = @_;

    my $acl = $spoc->{$parse_name}->{$acl_name};
    my $new_name = $acl->{new_name};
    my @cmds = map({ $self->subst_ace_name_og($_, $new_name) }
                   @{ $acl->{LIST} });
    $self->cmd( $_ ) for @cmds;
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
    my ( $self, $conf, $parse_name, $acl_name ) = @_;
    $self->cmd("clear configure access-list $acl_name");
}

sub item_conf_mode_cmd {
    my ( $parse_name, $item_name ) = @_;
    my $prefix  = $conf_mode_entry{$parse_name}->{prefix} or
        internal_err("No prefix for $parse_name $item_name");
    my $postfix = $conf_mode_entry{$parse_name}->{postfix};
    return "$prefix $item_name $postfix";
}

sub add_attribute_cmds {
    my ( $structure, $parse_name, $object ) = @_;

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
    for my $attr ( @{$structure->{$parse_name}->{attributes}} ) {
        my $value = $object->{$attr};
        if (ref $value) {
            for my $cmd (sort keys %$value) {
                my $args = $value->{$cmd};
                my $new_cmd = $cmd;
                $new_cmd .= " $args" if $args;
                push @cmds, $new_cmd;
            }
        }
        elsif ( my $attr_cmd = cmd_for_attribute( $parse_name, $attr )) {

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

sub write_mem {
    my ($self) = @_;
    $self->cmd('write memory');
}

sub get_next_names {
    my ($parse_info, $object) = @_;
    my @result;
    for my $key (qw(next next_list)) {
        my $next = $parse_info->{$key} or next;
        for my $next_key ( @$next ) {
            my $next_attr_name  = $next_key->{attr_name};
            my $next_parse_name = $next_key->{parse_name};
            my $conf_next = $object->{$next_attr_name} or next;
            if ($key eq 'next_list') {
                push @result, map [ $next_parse_name, $_ ], @$conf_next;
            }
            else {
                push @result, [ $next_parse_name, $conf_next ];
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
    return if $parse_name eq 'CRYPTO_MAP_LIST';
    $self->SUPER::mark_as_changed($parse_name);
}

sub mark_as_unchanged {
    my ( $self, $parse_name ) = @_;

    return if $parse_name eq 'IF';
    return if $parse_name eq 'CERT_ANCHOR';
    return if $parse_name eq 'DEFAULT_GROUP';
    return if $parse_name eq 'CRYPTO_MAP_LIST';
    $self->SUPER::mark_as_unchanged($parse_name);
}

sub define_structure {
    my $self = shift;

    return {
        ACCESS_LIST => {
#           next_list => { LIST => [ { attr_name => [ 'SRC', 'OBJECT_GROUP' ],
#                                     parse_name => 'ACCESS_LIST', },
#                                   { attr_name => [ 'DST', 'OBJECT_GROUP' ],
#                                     parse_name => 'ACCESS_LIST', },
#                                   ],
#                     },
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

            # No attributes 'transfer' and 'remove' needed.
            # New interface from Netspoc will abort with
            # "Interface from Netspoc not known on device".
            # Additional interface from device will be silently ignored.
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
            ],
            next_list => [ { attr_name  => 'TRANSFORM_SET_IKEV1',
                            parse_name => 'TRANSFORM_SET' },
                           { attr_name  => 'IPSEC_PROPOSAL',
                             parse_name => 'IPSEC_PROPOSAL' },
            ],
            transfer => 'transfer_dynamic_map',
            remove   => 'remove_dynamic_map',
        },
        CRYPTO_MAP_SEQ => {
            attributes => [ qw(NAT_T_DISABLE PEER PFS REVERSE_ROUTE
                               SA_LIFETIME_SEC SA_LIFETIME_KB TRUSTPOINT) ],
            next     => [ { attr_name  => 'MATCH_ADDRESS',
                            parse_name => 'ACCESS_LIST' },
                          { attr_name  => 'DYNAMIC_MAP',
                            parse_name => 'DYNAMIC_MAP' },
            ],
            next_list => [ { attr_name  => 'TRANSFORM_SET',
                             parse_name => 'TRANSFORM_SET' },
                           { attr_name  => 'TRANSFORM_SET_IKEV1',
                             parse_name => 'TRANSFORM_SET' },
                           { attr_name  => 'IPSEC_PROPOSAL',
                             parse_name => 'IPSEC_PROPOSAL' },
            ],
            transfer => 'transfer_crypto_map_seq',
            remove   => 'remove_crypto_map_seq',
        },

        CERT_ANCHOR => {
            anchor => 1,
            next => [ { attr_name  => 'CA_CERT_MAP',
                        parse_name => 'CA_CERT_MAP',
                    } ],
            transfer => sub {},
            remove   => sub {},
        },

        CA_CERT_MAP => {
            next => [ { attr_name  => 'TUNNEL_GROUP_DEFINE',
                        parse_name => 'TUNNEL_GROUP_DEFINE', },
                      { attr_name  => 'WEB_TUNNEL_GROUP',
                        parse_name => 'TUNNEL_GROUP_DEFINE', },
                      ],
            attributes => [ qw( IDENTIFIER ) ],
            transfer    => 'transfer_ca_cert_map',
            remove      => 'remove_ca_cert_map',
        },

        DEFAULT_GROUP => {
            anchor => 1,
            next => [ { attr_name  => 'TUNNEL_GROUP_DEFINE',
                        parse_name => 'TUNNEL_GROUP_DEFINE',
                        is_not_attr => 1, },
                      { attr_name  => 'TUNNEL_GROUP_IPSEC',
                        parse_name => 'TUNNEL_GROUP_IPSEC',
                        is_not_attr => 1, },
                      { attr_name  => 'TUNNEL_GROUP_WEBVPN',
                        parse_name => 'TUNNEL_GROUP_WEBVPN',
                        is_not_attr => 1, },
                      ],
            transfer => 'transfer_default_group',
            remove   => 'remove_obj',
        },

        USERNAME => {
            anchor => 1,
            next => [ { attr_name  => 'VPN_GROUP_POLICY',
                        parse_name => 'GROUP_POLICY',
                    },
                      { attr_name  => 'VPN_FILTER',
                        parse_name => 'ACCESS_LIST',
                    } ],
            attributes => [ qw( ATTRIBUTES ) ],
            transfer   => 'transfer_user',
            remove     => 'remove_user',
        },

        IP_TUNNEL_GROUP_DEFINE => {
            anchor => 1,
            next => [ { attr_name  => 'TUNNEL_GROUP_GENERAL',
                        parse_name => 'TUNNEL_GROUP_GENERAL',
                      },
                      { attr_name  => 'TUNNEL_GROUP_IPSEC',
                        parse_name => 'TUNNEL_GROUP_IPSEC',
                      },
                      { attr_name  => 'TUNNEL_GROUP_WEBVPN',
                        parse_name => 'TUNNEL_GROUP_WEBVPN',
                      },
                    ],
            attributes => [ qw( ATTRIBUTES ) ],
            transfer => 'transfer_tunnel_group',
            remove   => 'remove_tunnel_group',
        },
        TUNNEL_GROUP_DEFINE => {
            next => [ { attr_name  => 'TUNNEL_GROUP_GENERAL',
                        parse_name => 'TUNNEL_GROUP_GENERAL',
                      },
                      { attr_name  => 'TUNNEL_GROUP_IPSEC',
                        parse_name => 'TUNNEL_GROUP_IPSEC',
                      },
                      { attr_name  => 'TUNNEL_GROUP_WEBVPN',
                        parse_name => 'TUNNEL_GROUP_WEBVPN',
                      },
                ],
            need_eq_attr => 1,
            attributes => [ qw(TYPE) ],
            transfer => 'transfer_tunnel_group',
            remove   => 'remove_tunnel_group',
        },
        TUNNEL_GROUP_GENERAL => {
            postpone => 1,
            next => [ { attr_name  => 'DEFAULT_GROUP_POLICY',
                        parse_name => 'GROUP_POLICY',
                      } ],
            attributes => [ qw( ATTRIBUTES ) ],
            transfer => 'transfer_tunnel_group',
            remove   => 'remove_obj',
        },

        TUNNEL_GROUP_IPSEC => {
            postpone => 1,
            next => [],
            attributes => [ qw( ATTRIBUTES ) ],
            transfer => 'transfer_tunnel_group',
            remove   => 'remove_obj',
        },

        TUNNEL_GROUP_WEBVPN => {
            postpone => 1,
            next => [],
            attributes => [ qw( ATTRIBUTES ) ],
            transfer => 'transfer_tunnel_group',
            remove   => 'remove_obj',
        },

        GROUP_POLICY => {
            next => [ { attr_name  => 'VPN_FILTER',
                        parse_name => 'ACCESS_LIST',
                    },
                      { attr_name  => 'SPLIT_TUNNEL_NETWORK_LIST',
                        parse_name => 'ACCESS_LIST',
                    },
                      { attr_name  => 'ADDRESS_POOL',
                        parse_name => 'IP_LOCAL_POOL',
                    } ],
            attributes => [qw( ATTRIBUTES )],
            transfer => 'transfer_group_policy',
            remove   => 'remove_group_policy',
        },

        GROUP_POLICY_ANCHOR => {
            anchor => 1,
            next => [ { attr_name => 'GROUP_POLICY',
                        parse_name => 'GROUP_POLICY',
                    } ],
            transfer => sub {},
            remove   => sub {},
        },

        DEFAULT_TUNNEL_GROUP => {
            anchor => 1,
            next => [ { attr_name  => 'TUNNEL_GROUP',
                        parse_name => 'TUNNEL_GROUP_DEFINE', },
                      ],
            transfer => sub {},
            remove   => sub {},
        },

        IP_LOCAL_POOL => {
            attributes => [ qw( RANGE_FROM RANGE_TO MASK ) ],
            simple_object => 1,
            transfer => 'transfer_ip_local_pool',
            remove   => 'remove_obj',
        },

        NO_SYSOPT_CONNECTION_PERMIT_VPN => {
            anchor => 1,
            attributes => [ qw( value ) ],
            transfer => 'transfer_no_sysopt_connection_permit_vpn',
            remove => 'remove_no_sysopt_connection_permit_vpn',
        },
    };
}

sub transfer {
    my ( $self, $conf, $spoc ) = @_;

    my $structure = $self->define_structure();

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

    $self->leave_conf_mode();
}

# Packages must return a true value;
1;
