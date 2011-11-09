
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

# Packages must return a true value;
1;


