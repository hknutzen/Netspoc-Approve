
=head1 DESCRIPTION

Remote configure Cisco ASA and PIX version 7.x.

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

package Netspoc::Approve::ASA;

use base "Netspoc::Approve::Cisco_FW";
use strict;
use warnings;
use Netspoc::Approve::Helper;
use Netspoc::Approve::Parse_Cisco;

our $VERSION = '1.105'; # VERSION: inserted by DZP::OurPkgVersion

sub get_parse_info {
    my ($self) = @_;
    my $info = $self->SUPER::get_parse_info();
    $info->{interface} = {
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
    };

    $info->{'no sysopt connection permit-vpn'} = {
	store => ['NO_SYSOPT_CONNECTION_PERMIT_VPN', 'name', 'value'],
	default => 1,
    };

    # Handle tunnel-group.
    # 
    $info->{'tunnel-group _skip type'} = {
	store => 'TUNNEL_GROUP_DEFINE',
	named => 1,
	parse => [ 'seq',
		   { store => 'TYPE',
		     parse => \&get_token
		     },
		   ],
    };

    # Handle tunnel-group general attributes.
    $info->{'tunnel-group _skip general-attributes'} = {
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

    };

    $info->{'tunnel-group _skip ipsec-attributes'} = {
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
    };

    $info->{'tunnel-group _skip webvpn-attributes'} = {
	store => 'TUNNEL_GROUP_WEBVPN',
	named => 1,
 	subcmd => {
	    _any => {
		store => ['ATTRIBUTES', '_cmd'],
		parse => \&get_to_eol,
	    }
	}
    };

    # Handle tunnel-group-map.
    $info->{'tunnel-group-map'} = {
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
    };

#crypto ca certificate map DefaultCertificateMap 20
# subject-name attr o eq dataport
#crypto ca certificate map MAP-certificate_PermisA.dataport.de 100
# subject-name attr ea co @permisa.dataport.de

    # Handle crypto ca certificates.
    $info->{'crypto ca certificate map'} = {
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
    };

    # Handle username.
    $info->{'username _skip nopassword'} = {
	store   => 'USERNAME_NOPASSWORD',
	named   => 1,
	default => 1,
    };
    $info->{'username _skip attributes'} = {
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
    };

    # Handle group policies.
    $info->{'group-policy _skip internal'} = {
	store   => 'GROUP_POLICY_INTERNAL',
	named   => 1,
	default => 1,
    };
    $info->{'group-policy _skip attributes'} = {
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
    };

    # Handle local IP-pools.
    $info->{'ip local pool'} = {
	store => 'IP_LOCAL_POOL',
	named => 1,
	parse => [ 'seq',
		   { store_multi => ['RANGE_FROM', 'RANGE_TO'], 
		     parse => \&get_ip_pair },
		   { parse => qr/mask/ },
		   { store => 'MASK', parse => \&get_ip },
		   ],
    };

    # Handle global webvpn mode.
    # webvpn
    #  certificate-group-map <cert_map> <index> <tunnel_group_map>
    $info->{webvpn} = {
        store => 'WEBVPN',
        subcmd => {
            'certificate-group-map' => {
                store => 'CERT_GROUP_MAP',
                named => 1,
                parse => [ 'seq',
                           { store => 'INDEX', parse => \&get_int }, 
                           { store => 'TUNNEL_GROUP', parse => \&get_token },
                    ],
            }
        }
    };

    # We don't use the certificates, but lexical analyser needs to know
    # that this is a multi line command.
    $info->{'crypto ca certificate chain'} = {
	named => 1,
	subcmd => {
	    'certificate' => { banner => qr/^\s*quit\s*$/, parse => \&skip },
	}
    };

    return $info;
}

sub postprocess_config {
    my ( $self, $p ) = @_;

    for my $name (keys %{$p->{OBJECT}}) {

        # Objects generated by Netspoc have special names.
        # Ignore all other objects.
        if ($name !~ /^\d+\.\d+\.\d+\.\d+(?:[-_]\d+\.\d+\.\d+\.\d+)$/) {
            delete $p->{OBJECT}->{$name};
            next;
        }

        my $entry = $p->{OBJECT}->{$name};
        my ($s, $r, $h) = @{$entry}{qw(SUBNET RANGE HOST)};
        if (!($s || $r || $h) || $s && $r || $s && $h || $r && $h) {
            abort("Must use exactly one subcmd of subnet|range|host in" .
                  " $entry->{orig}");
        }
    }        

    # Propagate ip address and shutdown status from hardware interface 
    # to logical interface.
    for my $entry ( values %{ $p->{HWIF} } ) {
	if (my $name = $entry->{IF_NAME}) {
	    my $intf = $p->{IF}->{$name} = { name => $name };
	    if( my $address = $entry->{ADDRESS} ) {
		$intf->{BASE} = $address->{BASE};
		$intf->{MASK} = $address->{MASK};
	    }
	    $intf->{SHUTDOWN} = $entry->{SHUTDOWN};
	}
    }
    delete $p->{HWIF};

    for my $what (qw(TUNNEL_GROUP_GENERAL TUNNEL_GROUP_IPSEC TUNNEL_GROUP_WEBVPN)) {
        for my $name (keys %{$p->{$what}}) {
            my $base = $p->{TUNNEL_GROUP_DEFINE}->{$name} or 
                abort("Missing type definition for tunnel-group $name");

            # Add links to related commands.
            $base->{$what} = $name;
        }
    }

    # Create artificial anchor TUNNEL_GROUP_ANCHOR for tunnel_group
    # with IP as name.
    for my $name ( keys %{$p->{TUNNEL_GROUP_DEFINE}} ) {
        my $tg = $p->{TUNNEL_GROUP_DEFINE}->{$name};
	my $type = $tg->{TYPE};
	$type eq 'ipsec-l2l' or next;
        $p->{TUNNEL_GROUP_ANCHOR}->{$name} = { TUNNEL_GROUP => $name };
    }

    # TUNNEL_GROUP_MAP
    # - copy as attribute to CA_CERT_MAP
    # - for default-group copy to artificial DEFAULT_GROUP
    # - create artificial name: "default"
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
		abort("'$tgm->{orig}' references unknown ca cert map '$tgm_name'");
	}
        
        $anchor->{TUNNEL_GROUP_DEFINE} = $tg_name;
	if ($p->{TUNNEL_GROUP_DEFINE}->{$tg_name}) {
        }
        elsif($tg_name =~ /^(?:DefaultL2LGroup)$/) {
            $p->{TUNNEL_GROUP_DEFINE}->{$tg_name} ||= { name => $tg_name,
                                                        type => 'ipsec-l2l'};
        }
        else {
            abort("'$tgm->{orig}' references unknown tunnel-group $tg_name");
	}
    }

    # Not needed any longer.
    delete $p->{TUNNEL_GROUP_MAP};

    # WEBVPN, CERT_GROUP_MAP
    # - copy as attribute to CA_CERT_MAP
    if ($p->{WEBVPN} && (my $hash = $p->{WEBVPN}->{CERT_GROUP_MAP})) {
        for my $cgm (values %$hash) {
            my $ca_map_name = $cgm->{name};
            my $cert = $p->{CA_CERT_MAP}->{$ca_map_name} or 
                abort("'$cgm->{orig}' references unknown ca cert map '$ca_map_name'");
            my $tg_name = $cgm->{TUNNEL_GROUP};
            $p->{TUNNEL_GROUP_DEFINE}->{$tg_name} or
                abort("'$cgm->{orig}' references unknown tunnel-group $tg_name");
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
    for my $cert ( values %{$p->{CA_CERT_MAP}} ) {
	if ( my $id = $cert->{IDENTIFIER} ) {
	    $id = lc( $id );
	    $cert->{IDENTIFIER} = $id;
	    if(my $old_cert = $p->{CERT_ANCHOR}->{$id}) {
		my $old_name = $old_cert->{name};
		my $new_name = $cert->{name};
		abort("Two ca cert map items use" .
                      " identical subject-name: '$old_name', '$new_name'");
	    }
	    $p->{CERT_ANCHOR}->{$id} = { CA_CERT_MAP => $cert->{name},
					 name => $id };
	}
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

    # 'DefaultWEBVPNGroup' must not be removed, even if not referenced.
    $dflt_gp = 'DefaultWEBVPNGroup';
    if ( $p->{TUNNEL_GROUP_DEFINE}->{$dflt_gp} ) {
	$p->{DEFAULT_WEBVPN_GROUP}->{$dflt_gp} = { name => $dflt_gp,
						   TUNNEL_GROUP => $dflt_gp };
    }
    
    $self->SUPER::postprocess_config($p);
}


# This is different for PIX and ASA, so we have this method in both
# modules Cisco_FW.pm and here. Inheritance is your friend :-) .
sub acl_removal_cmd {
    my ( $self, $acl_name ) = @_;
    return "clear configure access-list $acl_name";
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


sub transfer {
    my ( $self, $conf, $spoc ) = @_;
    
    my $structure = $self->define_structure();

    $self->SUPER::transfer( $conf, $spoc, $structure );
}

sub define_structure {
    my $self = shift;

    my $structure = {
	%{$self->SUPER::define_structure()},
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
			parse_name => 'TUNNEL_GROUP_DEFINE', },
		      { attr_name  => 'TUNNEL_GROUP_IPSEC',
			parse_name => 'TUNNEL_GROUP_IPSEC', },
		      { attr_name  => 'TUNNEL_GROUP_WEBVPN',
			parse_name => 'TUNNEL_GROUP_WEBVPN', },
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
	
	TUNNEL_GROUP_ANCHOR => {
	    anchor => 1,
	    next => [ { attr_name  => 'TUNNEL_GROUP',
			parse_name => 'TUNNEL_GROUP_DEFINE',
		    } ],
	    transfer => sub {},
	    remove   => sub {},
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
	    attributes => [ qw( ATTRIBUTES ) ],
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
	    next => [ {	attr_name  => 'VPN_FILTER',
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
	
	DEFAULT_WEBVPN_GROUP => {
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

    return $structure;
}



# Packages must return a true value;
1;

