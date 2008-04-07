
package Netspoc::Approve::Device::Cisco::Firewall::ASA;

use strict;
use warnings;


use base "Netspoc::Approve::Device::Cisco::Firewall";

#
# Parser ASA / PIX version 7.x, 8.x
#
sub write_term_config($$$$){
    my ($self, $ah, $al) = @_;
    if($self->{PRINT}){
	$$al = "";
	$self->parse_interface($ah->{HWIF},$al);
	$self->parse_object_group($ah->{OBJECT_GROUP},$al); 
	$self->parse_write_term_acl($ah->{ACCESS_LIST},$al);
	$self->parse_global_lines($ah->{GLOBAL},$al);
	$self->parse_nat_lines($ah->{NAT},$al);
	$self->parse_static_lines($ah->{STATIC},$al);	
	$self->parse_access_group($ah->{ACCESS_GROUP},$al);
	$self->parse_route_lines($ah->{ROUTING},$al);
	$self->parse_crypto($ah->{CRYPTO},$al);
    }
    else{
	$ah->{HWIF} = {};
	$ah->{ACCESS_LIST} = {}; # old implementation: 'ACCESS'
	$ah->{OBJECT_GROUP} = {};
	$ah->{GLOBAL} = [];
	$ah->{NAT} = [];
	$ah->{STATIC} = [];
	$ah->{ACCESS_GROUP} = {};
	$ah->{ROUTING} = [];
	$ah->{CRYPTO} = {};
	while(
	      $self->parse_interface($ah->{HWIF},$al) ||
	      $self->parse_object_group($ah->{OBJECT_GROUP},$al) ||
	      $self->parse_write_term_acl($ah->{ACCESS_LIST},$al) ||
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

