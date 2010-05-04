
package Netspoc::Approve::IOS_FW;

# Authors: Arne Spetzler, Heinz Knutzen, Daniel Brunkhorst
#
# Description:
# Remote configure cisco IOS router with firewall feature set.
#

'$Id$ ' =~ / (.+),v (.+?) /;

my $id = "$1 $2";

use base "Netspoc::Approve::IOS";
use strict;
use warnings;
use Netspoc::Approve::Helper;

sub version_drc2_IOS_FW() {
    return $id;
}


sub check_firewall ( $$ ) {
    my ($self, $conf) = @_;

    mypr "Check for CBAC at IOS firewall...\n";
    my $cbac_ok = 1;
    for my $intf (keys %{$conf->{IF}}){
	next if($conf->{IF}->{$intf}->{SHUTDOWN});
	mypr "   $intf";
	if(exists $conf->{IF}->{$intf}->{SWITCHPORT}){
	    mypr " - is a switchport - OK\n";
	}
	elsif($intf eq "Loopback0"){
	    mypr " - is a loopback device - OK\n";
	}
	elsif(exists $conf->{IF}->{$intf}->{INSPECT}){
	    mypr " - CBAC enabled - OK\n";
	}
	else{
	    mypr " - no CBAC found\n";
	    $cbac_ok = 0;
	}
    }
    $cbac_ok or errpr "missing CBAC configuration\n";
}


# Packages must return a true value;
1;


