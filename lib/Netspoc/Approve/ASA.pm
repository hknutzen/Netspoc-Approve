
package Netspoc::Approve::ASA;

# Authors: Arne Spetzler, Heinz Knutzen, Daniel Brunkhorst
#
# Description:
# Remote configure Cisco ASA and PIX version 7.x.
#

'$Id$ ' =~ / (.+),v (.+?) /;

my $id = "$1 $2";

sub version_drc2_asa() {
    return $id;
}

use base "Netspoc::Approve::Cisco_FW";
use strict;
use warnings;
use Netspoc::Approve::Helper;
use Netspoc::Approve::Parse_Cisco;
#use Data::Dumper;



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
		    parse => ['seq',
			      { store => 'BASE', parse => \&get_ip },
			      { store => 'MASK', parse => \&get_ip },
			      ['seq',
			       { parse => qr/standby/ },
			       { store => 'STANDBY', parse => \&get_ip } ]] },
		'management-only' => { 
		    store => 'MANAGEMENT_ONLY', default => 1 },
	    }
    };
    $info->{'nat-control'} = {
	store => 'NAT_CONTROL',
	default => 1,
    };

    $info->{'no sysopt connection permit-vpn'} = {
	store => ['NO_SYSOPT_CONNECTION_PERMIT_VPN', 'name', 'value'],
	default => 1,
    };

    # Handle tunnel-group.
    # 
    $info->{'tunnel-group'} = {
	store => 'TUNNEL_GROUP_INTERNAL',
	named => 1,
	parse => [ 'seq',
		   { parse => qr/type/ },
		   { store => 'TYPE',
		     parse => \&get_token
		     },
		   ],
    };

    # Handle tunnel-group general attributes.
    $info->{'tunnel-group _skip general-attributes'} = {
	store => 'TUNNEL_GROUP',
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

	    # '_any' is special word, which matches any token.
	    # '_cmd' is replaced by current command name.

	    # isakmp ikev1-user-authentication
	    # isakmp keepalive
	    'isakmp _any' => {
		store => ['ATTRIBUTES', '_cmd'],
		parse => \&get_to_eol,
	    },
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

    # We don't use the certificates, but lexical analyser needs to know
    # that this is a multi line command.
    $info->{'crypto ca certificate chain'} = {
	named => 1,
	subcmd => {
	    'certificate' => { banner => qr/^\s*quit$/, parse => \&skip },
	}
    };

    return $info;
}

sub postprocess_config {
    my ( $self, $p ) = @_;

    if( $p->{NAT_CONTROL} ) {
	errpr "Please disable 'nat-control'";
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

    # For tunnel-groups with an IP as name create new
    # TUNNEL_GROUP_IP_NAME-object.
    for my $tg_intern ( values %{$p->{TUNNEL_GROUP_INTERNAL}} ) {
	my $int_name = $tg_intern->{name};
	if ( is_ip( $int_name ) ) {
	    $p->{TUNNEL_GROUP_IP_NAME}->{$int_name} = {
		name => $int_name,
		orig => $tg_intern->{orig},
		TYPE => $tg_intern->{TYPE},
	    };
	}
    }

    # For tunnel-groups that only have ipsec-attributes and do
    # not have an IP-address as name, create
    # a tunnel-group with the same name.
    # For those that DO have an IP-address as name, create a
    # separate TUNNEL_GROUP_IPSEC_IP_NAME-object (that is an anchor)
    # and delete the original TUNNEL_GROUP_IPSEC-object.
    my $tunnel_groups = $p->{TUNNEL_GROUP} ||= {};
    for my $tg_ipsec_name ( keys %{$p->{TUNNEL_GROUP_IPSEC}} ) {
	if ( is_ip( $tg_ipsec_name ) ) {
	    $p->{TUNNEL_GROUP_IPSEC_IP_NAME}->{$tg_ipsec_name} = 
		$p->{TUNNEL_GROUP_IPSEC}->{$tg_ipsec_name};
	    delete $p->{TUNNEL_GROUP_IPSEC}->{$tg_ipsec_name};
	}
	else {
	    $p->{TUNNEL_GROUP}->{$tg_ipsec_name} ||= { name => $tg_ipsec_name };
	}
    }

    # TUNNEL_GROUP_MAP
    # - copy as attribute to CA_CERT_MAP
    # - for default-group copy to artificial DEFAULT_GROUP
    # - create artificial name: "default"
    for my $tgm ( values %{$p->{TUNNEL_GROUP_MAP}} ) {
	my $tgm_name = $tgm->{name};
	my $tg_name = $tgm->{TUNNEL_GROUP};
	my $tg_ipsec = $p->{TUNNEL_GROUP_IPSEC}->{$tg_name};
	if ($tgm_name eq 'DEFAULT') {
	    my $default = { name => 'default', TUNNEL_GROUP => $tg_name, };
	    $default->{TUNNEL_GROUP_IPSEC} = $tg_name if $tg_ipsec;
	    $p->{DEFAULT_GROUP}->{default} = $default;
	}
	else {
	    if ( my $cert = $p->{CA_CERT_MAP}->{$tgm_name} ) {
		$cert->{TUNNEL_GROUP} = $tg_name;
		$cert->{TUNNEL_GROUP_IPSEC} = $tg_name if $tg_ipsec;
	    }
	    else {
		errpr "'$tgm->{orig}' references unknown ca cert map '$tgm_name'\n";
	    }
	}
	if (not $p->{TUNNEL_GROUP}->{$tg_name}) {
	    if($tg_name =~ /^(?:DefaultL2LGroup)$/) {
		$p->{TUNNEL_GROUP}->{$tg_name} ||= { name => $tg_name };
	    }
	    else {
		errpr "'$tgm->{orig}' references unknown tunnel-group $tg_name\n";
	    }
	}
    }

    # Not needed any longer.
    delete $p->{TUNNEL_GROUP_MAP};

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
		errpr "Two ca cert map items use" .
		    " identical subject-name: '$old_name', '$new_name'\n";
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
	    next => [ { attr_name  => 'TUNNEL_GROUP',
			parse_name => 'TUNNEL_GROUP', },
		      { attr_name  => 'TUNNEL_GROUP_IPSEC',
			parse_name => 'TUNNEL_GROUP_IPSEC', }
		      ],
	    attributes => [ qw( IDENTIFIER ) ],
	    transfer    => 'transfer_ca_cert_map',
	    remove      => 'remove_ca_cert_map',
	},
	
	DEFAULT_GROUP => {
	    anchor => 1,
	    next => [ { attr_name  => 'TUNNEL_GROUP',
			parse_name => 'TUNNEL_GROUP', },
		      { attr_name  => 'TUNNEL_GROUP_IPSEC',
			parse_name => 'TUNNEL_GROUP_IPSEC', }
		      ],
	    transfer => 'transfer_default_group',
	    remove   => 'remove_default_group',
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
	
	TUNNEL_GROUP => {
	    next => [ { attr_name  => 'DEFAULT_GROUP_POLICY',
			parse_name => 'GROUP_POLICY',
		    } ],
	    attributes => [ qw( ATTRIBUTES ) ],
	    transfer => 'transfer_tunnel_group',
	    remove   => 'remove_tunnel_group',
	},
	
	TUNNEL_GROUP_IP_NAME => {
	    anchor => 1,
	    next => [],
	    attributes => [ qw( ATTRIBUTES ) ],
	    transfer => 'transfer_tunnel_group',
	    remove   => 'remove_tunnel_group',
	},
	
	TUNNEL_GROUP_IPSEC => {
	    next => [],
	    attributes => [ qw( ATTRIBUTES ) ],
	    transfer => 'transfer_tunnel_group',
	    remove   => 'remove_tunnel_group_ipsec',
	},
		
	TUNNEL_GROUP_IPSEC_IP_NAME => {
	    anchor => 1,
	    next => [],
	    attributes => [ qw( ATTRIBUTES ) ],
	    transfer => 'transfer_tunnel_group',
	    remove   => 'remove_tunnel_group_ipsec',
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
	
	IP_LOCAL_POOL => {
	    attributes => [ qw( RANGE_FROM RANGE_TO MASK ) ],
	    transfer => 'transfer_ip_local_pool',
	    remove   => 'remove_ip_local_pool',
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

