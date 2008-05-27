
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


sub get_parse_info {
    my ($self) = @_;
    my $info = $self->SUPER::get_parse_info();
    $info->{interface} = {
	    store => 'HWIF',
	    named => 1,
	    subcmd => {
		'shutdown' => { store => 'SHUTDOWN', default => 1 },
		'speed' => {store => 'HW_SPEED', parse => \&get_int },
		'duplex' => { store => 'DUPLEX', parse => \&get_token },
		'nameif' => { store => 'IF_NAME', parse => \&get_token },
		'security-level' => { store => 'SECURITY', parse => \&get_int },
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
    return $info;
}

# Link hardware interface with logical interface.
# Propagate ip address and shutdown status from hardware interface 
# to logical interface.
sub postprocess_config {
    my ($self, $p) = @_;
    if($p->{NAT_CONTROL}) {
	errpr("Please disable 'nat-control'");
    }
    for my $entry (values %{ $p->{HWIF} }) {
	if (my $name = $entry->{IF_NAME}) {
	    $p->{IF}->{$name}->{SHUTDOWN} = $entry->{SHUTDOWN};
	    if(my $address = $entry->{ADDRESS}) {
		$p->{IF}->{$name}->{BASE} = $address->{BASE};
		$p->{IF}->{$name}->{MASK} = $address->{MASK};
	    }
	}
    }
    $self->SUPER::postprocess_config($p);
}

sub set_pager {
    my ($self) = @_;
    $self->cmd('terminal pager 0');
}
   
# Packages must return a true value;
1;

