
package Netspoc::Approve::PIX;

# Authors: Arne Spetzler, Heinz Knutzen, Daniel Brunkhorst
#
# Description:
# Remote configure Cisco PIX up to version 6.3
#

use base "Netspoc::Approve::Cisco_FW";
use strict;
use warnings;
use Netspoc::Approve::Helper;
use Netspoc::Approve::Parse_Cisco;

our $VERSION = '1.074'; # VERSION: inserted by DZP::OurPkgVersion

sub get_parse_info {
    my ($self) = @_;
    my $info = $self->SUPER::get_parse_info();

# interface <hardware_id> [<hardware_speed> [shutdown]]
    $info->{interface} = {
	store => 'HWIF',
	named => 1,
	parse => ['cond1',
		  { store => 'HW_SPEED', parse => \&check_token },
		  { store => 'SHUTDOWN', parse => qr/shutdown/ } ]
    };		  

# nameif {<hardware_id>|<vlan_id>} <if_name> <security_level>
    $info->{nameif} =  {
	store => 'NAMEIF',
	named => 1,
	parse => ['seq',
		  { store => 'IF_NAME', parse => \&get_token },
		  { store => 'SECURITY', parse => \&get_token } ]
    };

# ip address <if_name> <ip-address> <netmask>
    $info->{'ip address'} = {
	store => 'ADDRESS',
	named => 1,
	parse => ['seq',
		  { store => 'BASE', parse => \&get_ip },
		  { store => 'MASK', parse => \&get_ip } ]
    };

    return $info;
}

# Link hardware interface with logical interface.
# Propagate ip address and shutdown status from hardware interface 
# to logical interface.
sub postprocess_config {
    my ($self, $p) = @_;
    for my $hw_id (keys %{ $p->{NAMEIF} }) {
	my $name = $p->{NAMEIF}->{$hw_id}->{IF_NAME};
	my $address = $p->{ADDRESS}->{$name};
	my $interface = $p->{HWIF}->{$hw_id};
	$p->{IF}->{$name}->{SHUTDOWN} = $interface->{SHUTDOWN};
	$p->{IF}->{$name}->{BASE} = $address->{BASE};
	$p->{IF}->{$name}->{MASK} = $address->{MASK};
    }
    $self->SUPER::postprocess_config($p);
}

sub checkbanner {
    my ($self) = @_;
    if($self->{VERSION} < 6.3) {
	info("Banner check disabled for PIX $self->{VERSION}");
    }
    else {
	$self->SUPER::checkbanner;
    }
}

sub set_pager {
    my ($self) = @_;
    abort("Pager is not disabled - issue 'no pager' manually to continue");
}

sub set_terminal_width {
    my ($self) = @_;
    abort("Set terminal width to 511 manually");
}

# PIX doesn't like 'end'.
sub leave_conf_mode {
    my($self) = @_;
    $self->cmd('exit');
}

# Packages must return a true value;
1;

