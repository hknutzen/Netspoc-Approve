
package Netspoc::Approve::Device::Cisco::Firewall::PIX;

# Authors: Arne Spetzler, Heinz Knutzen, Daniel Brunkhorst
#
# Description:
# module to remote configure cisco pix
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

#
# pix parser up to 6.3
#
sub write_term_config($$$){
    my ($self, $ah, $al) = @_;
    $self->{func} = \&write_term_config;
    if($self->{PRINT}){
	$$al = "";
	$self->parse_old_interface($ah->{HWIF},$al);
	$self->parse_nameif($ah->{HWIF},$al);
	$self->parse_object_group($ah->{OBJECT_GROUP},$al); 
	$self->parse_write_term_acl($ah->{ACCESS_LIST},$al);
	$self->parse_ip_address($ah->{IP},$al);
	$self->parse_global_lines($ah->{GLOBAL},$al);
	$self->parse_nat_lines($ah->{NAT},$al);
	$self->parse_static_lines($ah->{STATIC},$al);	
	$self->parse_access_group($ah->{ACCESS_GROUP},$al);
	$self->parse_route_lines($ah->{ROUTING},$al);
	$self->parse_crypto($ah->{CRYPTO},$al);
    }
    else{
	if($self->{func} eq \&write_term_config){
	    pos($$al) = 0;
	    $self->{RESULT} = $ah; # needed in parse_error()
	}
	$ah->{HWIF} = {};
	$ah->{ACCESS_LIST} = {}; # old implementation: 'ACCESS'
	$ah->{OBJECT_GROUP} = {};
	$ah->{IP} = {};
	$ah->{GLOBAL} = [];
	$ah->{NAT} = [];
	$ah->{STATIC} = [];
	$ah->{ACCESS_GROUP} = {};
	$ah->{ROUTING} = [];
	$ah->{CRYPTO} = {};
	while(
	      $self->parse_old_interface($ah->{HWIF},$al) ||
	      $self->parse_nameif($ah->{HWIF},$al) ||
	      $self->parse_object_group($ah->{OBJECT_GROUP},$al) ||
	      $self->parse_write_term_acl($ah->{ACCESS_LIST},$al) ||
	      $self->parse_ip_address($ah->{IP},$al) ||
	      $self->parse_global_lines($ah->{GLOBAL},$al) ||
	      $self->parse_nat_lines($ah->{NAT},$al) ||
	      $self->parse_static_lines($ah->{STATIC},$al) ||
	      $self->parse_access_group($ah->{ACCESS_GROUP},$al) ||
	      $self->parse_route_lines($ah->{ROUTING},$al) ||
	      $self->parse_crypto($ah->{CRYPTO},$al) ||
	      $self->parse_dummy_lines($ah,$al)
	      )
	{  
	    #my $p = pos($$al);
	    #$$al =~ /\G(\n*|.*)$ts/cgxo;
	    #print "--> $p $1 <--\n";
	    #print ".";
	    #pos($$al) = $p;
	}
    }
}

# Packages must return a true value;
1;

