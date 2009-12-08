
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
use Data::Dumper;



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


    # Handle tunnel-group.
    $info->{'tunnel-group +general-attributes'} = {
	store => 'TUNNEL_GROUP',
	named => 1,
	subcmd => {
	    'username-from-certificate' => {
		store => 'CERTIFICATE_FROM',
		parse => \&get_token,
	    },
	    'authorization-server-group' => {
		store => 'AUTHZ_SERVER_GROUP',
		parse => \&get_token,
	    },
	    'authentication-server-group' => {
		store => 'AUTHEN_SERVER_GROUP',
		parse => \&get_token,
	    },
	    'authorization-required' => {
		store => 'AUTHZ_REQUIRED',
		parse => sub { return ' '; },
	    },
	    'default-group-policy' => {
		store => 'DEFAULT_GROUP_POLICY',
		parse => \&get_token,
	    },
	}
    };

    $info->{'tunnel-group +ipsec-attributes'} = {
	store => 'TUNNEL_GROUP_IPSEC',
	named => 1,
	subcmd => {
	    'peer-id-validate' => {
		store => 'PEER_ID_VALIDATE',
		parse => \&get_token,
	    },
	    'chain' => {
		store => 'CHAIN',
	    },
	    'trust-point' => {
		store => 'TRUST_POINT',
		parse => \&get_token,
	    },
	    'isakmp ikev1-user-authentication' => {
		store => 'ISAKMP',
		parse => \&get_token,
	    },
	}
    };

    # Handle tunnel-group-map.
    $info->{'tunnel-group-map'} = {
	store => 'TUNNEL_GROUP_MAP',
	named => 'from_parser',
	parse => [ 'or',
		   [ 'seq',
		     { parse => qr/enable/ },
		     { parse => qr/rules/  },
		     ],
		   [ 'seq',
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
    $info->{'username +nopassword'} = {
	store   => 'USERNAME_NOPASSWORD',
	named   => 1,
	default => 1,
    };
    $info->{'username +attributes'} = {
	store => 'USERNAME',
	named => 1,
	subcmd => {
	    'vpn-framed-ip-address' => {
		store => 'VPN_FRAMED_IP_ADDRESS',
		parse => \&get_to_eol,
	    },
	    'vpn-filter value' => {
		store => 'VPN_FILTER',
		parse => \&get_token,
	    },
	    'vpn-group-policy' => {
		store => 'VPN_GROUP_POLICY',
		parse => \&get_token,
	    },
	    'service-type' => {
		store => 'SERVICE_TYPE',
		parse => \&get_token,
	    },
	}
    };

    # Handle group policies.
    $info->{'group-policy +internal'} = {
	store   => 'GROUP_POLICY_INTERNAL',
	named   => 1,
	default => 1,
    };
    $info->{'group-policy +attributes'} = {
	store => 'GROUP_POLICY',
	named => 1,
	subcmd => {
	    'banner value' => {
		store => 'BANNER',
		parse => \&get_to_eol,
	    },
	    'split-tunnel-policy' => {
		store => 'SPLIT_TUNNEL_POLICY',
		parse => \&get_token,
	    },
	    'split-tunnel-network-list value' => {
		store => 'SPLIT_TUNNEL_NETWORK_LIST',
		parse => \&get_token,
	    },
	    'vpn-idle-timeout' => {
		store => 'VPN_IDLE_TIMEOUT',
		parse => \&get_token,
	    },
	    'vpn-tunnel-protocol' => {
		store => 'VPN_TUNNEL_PROTOCOL',
		parse => \&get_to_eol,
	    },
	    'address-pools value' => {
		store => 'ADDRESS_POOL',
		parse => \&get_token,
	    },
	    'vpn-filter value' => {
		store => 'VPN_FILTER',
		parse => \&get_token,
	    },
	    'nem' => {
		store => 'NEM',
		parse => \&get_token,
	    },
	    'password-storage' => {
		store => 'PASSWORD_STORAGE',
		parse => \&get_token,
	    },
	    'pfs' => {
		store => 'PFS',
		parse => \&get_token,
	    },
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

    return $info;
}

sub postprocess_config {
    my ( $self, $p ) = @_;

    if( $p->{NAT_CONTROL} ) {
	errpr "Please disable 'nat-control'";
    }

    # Link hardware interface with logical interface.
    # Propagate ip address and shutdown status from hardware interface 
    # to logical interface.
    for my $entry ( values %{ $p->{HWIF} } ) {
	next if $entry->{SHUTDOWN};
	if (my $name = $entry->{IF_NAME}) {
	    if( my $address = $entry->{ADDRESS} ) {
		$p->{IF}->{$name}->{BASE} = $address->{BASE};
		$p->{IF}->{$name}->{MASK} = $address->{MASK};
	    }
	}
    }

    # For tunnel-groups that only have ipsec-attributes, create
    # a tunnel-group with the same name.
    # Copy ipsec-attributes to tunnel-group.
    my $tunnel_groups = $p->{TUNNEL_GROUP} ||= {};
    for my $tg_ipsec_name ( keys %{$p->{TUNNEL_GROUP_IPSEC}} ) {
	my $tg_ipsec = $p->{TUNNEL_GROUP_IPSEC}->{$tg_ipsec_name};
	my $tg = 
	    $tunnel_groups->{$tg_ipsec_name} ||= { name => $tg_ipsec_name };
	for my $attr ( keys %{$tg_ipsec} ) {
	    $tg->{$attr} = $tg_ipsec->{$attr} if $attr !~ /^(name|orig|line)$/;
	}
    }

    # TUNNEL_GROUP_MAP
    # - copy as attribute to CA_CERT_MAP
    # - for default-group copy to artificial DEFAULT_GROUP
    # - create artificial name: "default"
    for my $tgm ( values %{$p->{TUNNEL_GROUP_MAP}} ) {
	my $tgm_name = $tgm->{name};
	if ( $tgm_name eq 'DEFAULT' ) {
	    $p->{DEFAULT_GROUP}->{default} = { name => 'default',
					       TUNNEL_GROUP => 
						   $tgm->{TUNNEL_GROUP},
					       };
	}
	else {
	    if ( my $cert = $p->{CA_CERT_MAP}->{$tgm_name} ) {
		$cert->{TUNNEL_GROUP} = $tgm->{TUNNEL_GROUP};
	    }
	    else {
		errpr "'$tgm->{orig}' references unknown ca cert map '$tgm_name'\n";
	    }
	}
	my $tg_name = $tgm->{TUNNEL_GROUP};
	if(not $p->{TUNNEL_GROUP}->{$tg_name}) {
	    if($tg_name =~ /^(?:DefaultL2LGroup)$/) {
		$tunnel_groups->{$tg_name} ||= { name => $tg_name };
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
			parse_name => 'TUNNEL_GROUP',
		    } ],
	    attributes => [ qw( IDENTIFIER ) ],
	    transfer    => 'transfer_ca_cert_map',
	    remove      => 'remove_ca_cert_map',
	},
	
	DEFAULT_GROUP => {
	    anchor => 1,
	    next => [ { attr_name  => 'TUNNEL_GROUP',
			parse_name => 'TUNNEL_GROUP',
		    } ],
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
	    attributes => [ qw( VPN_FRAMED_IP_ADDRESS SERVICE_TYPE ) ],
	    transfer   => 'transfer_user',
	    remove     => 'remove_user',
	},
	
	TUNNEL_GROUP => {
	    next => [ { attr_name  => 'DEFAULT_GROUP_POLICY',
			parse_name => 'GROUP_POLICY',
		    } ],
	    attributes => [ qw( CERTIFICATE_FROM AUTHZ_REQUIRED
				AUTHZ_SERVER_GROUP AUTHEN_SERVER_GROUP ) ],
	    ipsec_attributes => [ qw( ISAKMP PEER_ID_VALIDATE TRUST_POINT ) ],
	    transfer => 'transfer_tunnel_group',
	    remove   => 'remove_tunnel_group',
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
	    attributes => [qw( BANNER SPLIT_TUNNEL_POLICY VPN_IDLE_TIMEOUT 
			       VPN_TUNNEL_PROTOCOL NEM PASSWORD_STORAGE PFS)],
	    transfer => 'transfer_group_policy',
	    remove   => 'remove_group_policy',
	},

	GROUP_POLICY_ANCHOR => {
	    anchor => 1,
	    next => [ { attr_name => 'GROUP_POLICY',
			parse_name => 'GROUP_POLICY',
		    } ],
	},
	
	IP_LOCAL_POOL => {
	    attributes => [ qw( RANGE_FROM RANGE_TO MASK ) ],
	    transfer => 'transfer_ip_local_pool',
	    remove   => 'remove_ip_local_pool',
	},
    };
    my $super = $self->SUPER::define_structure();
    for my $k (%$super) {
	$structure->{$k} = $super->{$k};
    }

    return $structure;
}



# Packages must return a true value;
1;

