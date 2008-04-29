
package Netspoc::Approve::Device::Cisco::Firewall::PIX;

# Authors: Arne Spetzler, Heinz Knutzen, Daniel Brunkhorst
#
# Description:
# module to remote configure cisco PIX up to version 6.3
#

'$Id$ ' =~ / (.+),v (.+?) /;

my $id = "$1 $2";

use strict;
use warnings;

use base "Netspoc::Approve::Device::Cisco::Firewall";

sub version_drc2_pix() {
    return $id;
}

use Netspoc::Approve::Helper;
use Netspoc::Approve::Device::Cisco::Parse;

sub get_parse_info {
    my ($self) = @_;
    my $info = $self->SUPER::get_parse_info();
    $info->{interface} = ['parse_interface', 'HWIF'];
    $info->{nameif} = ['parse_nameif', 'NAMEIF'];
    $info->{'ip address'} = ['parse_ip_address', 'ADDRESS'];
    return $info;
}

#############################################
#
# up to pix os 6.3
#
# interface <hardware_id> [<hardware_speed> [shutdown]]
#
# ->{<hardware_id>}->{SHUTDOWN}
# ->{<hardware_id>}->{HW_SPEED}
#
sub parse_interface {
    my ($self, $arg) = @_;
    my $result;

    my $id = get_token($arg);
    $result->{HW_SPEED} = check_token($arg)
	and $result->{SHUTDOWN} = check_regex('shutdown', $arg);
    return($result, $id);
}

#############################################
#
# nameif {<hardware_id>|<vlan_id>} <if_name> <security_level>
#
sub parse_nameif {
    my ($self, $arg) = @_;
    my $result;

    my $id = get_token($arg);
    $result->{IF_NAME}  = get_token($arg);
    $result->{SECURITY} = get_token($arg);
    return($result, $id);
}

#############################################
#
# ip address <if_name> <ip-address> <netmask>
#
sub parse_ip_address {
    my ($self, $arg) = @_;
    my $result;

    my $name = get_token($arg);
    $result->{BASE} = get_ip($arg);
    $result->{MASK} = get_ip($arg);
    return($result, $name);
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

# Packages must return a true value;
1;

