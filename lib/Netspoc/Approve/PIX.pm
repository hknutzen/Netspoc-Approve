
=head1 DESCRIPTION

Remote configure Cisco PIX up to version 6.3

=head1 COPYRIGHT AND DISCLAIMER

https://github.com/hknutzen/Netspoc-Approve
(c) 2015 by Heinz Knutzen <heinz.knutzen@gmail.com>
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

package Netspoc::Approve::PIX;

use base "Netspoc::Approve::Cisco_FW";
use strict;
use warnings;
use Netspoc::Approve::Helper;
use Netspoc::Approve::Parse_Cisco;

our $VERSION = '1.106'; # VERSION: inserted by DZP::OurPkgVersion

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

#  global [(<ext_if_name>)] <nat_id>
#         {<global_ip>[-<global_ip>] [netmask <global_mask>]} | interface
#
    $info->{'global'} = {
        store => 'GLOBAL',
        multi => 1,
        parse => ['seq',
                  { store => 'EXT_IF_NAME', parse => \&get_paren_token },
                  { store => 'NAT_ID', parse => \&get_token },
                  ['or',
                   { store => 'INTERFACE', parse => qr/interface/ },
                   ['seq',
                    { store_multi => ['BEGIN', 'END'], 
                      parse => \&get_ip_pair },
                    ['cond1',
                     { parse => qr/netmask/ },
                     { store => 'NETMASK', parse => \&get_ip } ]]]] 
    };

####
# nat [(<real_ifc>)] <nat-id>
#     {<real_ip> [<mask>]} | {access-list <acl_name>}
#     [dns] [norandomseq] [outside] [<max_conn> [<emb_limit>]] 
    $info->{'nat'} = {
        store => 'NAT',
        multi => 1,
        parse => ['seq',
                  { store => 'IF_NAME', parse => \&get_paren_token },
                  { store => 'NAT_ID', parse => \&get_token },
                  ['or',
                   ['cond1',
                    { parse => qr/access-list/ },
                    { store => 'ACCESS_LIST', parse => \&get_token } ],
                   ['seq',
                    { store => 'BASE', parse => \&get_ip },
                    { store => 'MASK', parse => \&get_ip } ]],
                  { store => 'DNS', parse => qr/dns/ },
                  { store => 'OUTSIDE', parse => qr/outside/ },
                  ['seq',
                   { store => 'MAX_CONS', 
                     parse => \&check_int,
                     default => 0 },
                   { store => 'EMB_LIMIT', 
                     parse => \&check_int,
                     default => 0 } ],
                  { store => 'NORANDOMSEQ', parse => qr/norandomseq/ } ] 
    };

# static [(local_ifc,global_ifc)] {global_ip | interface} 
#        {local_ip [netmask mask] | access-list acl_name} 
#        [dns] [norandomseq] [max_conns [emb_limit]]
# static [(local_ifc,global_ifc)] {tcp | udp} {global_ip | interface} 
#        global_port 
#        {local_ip local_port [netmask mask] | access-list acl_name}
#        [dns] [norandomseq] [max_conns [emb_limit]]
    $info->{'static'} = {
        store => 'STATIC',
        multi => 1,
        parse => ['seq',
                  { store_multi => ['LOCAL_IF', 'GLOBAL_IF'], 
                    parse => \&get_paren_token },
                  { store => 'TYPE', 
                    parse => qr/tcp|udp/, default => 'ip' },
                  ['or',
#		       { store => 'INTERFACE', parse => qr/interface/ },
                   { store => 'GLOBAL_IP', parse => \&get_ip } ],
                  ['cond1',
                   { parse => \&test_ne, params => ['ip', '$TYPE'] },
                   { store => 'GLOBAL_PORT', 
                     parse => 'parse_port', params => ['$TYPE'] } ],
                  ['or',
#		       ['cond1',
#			{ parse => qr/access-list/ },
#			{ store => 'ACCESS_LIST', parse => \&get_token } ],
                   ['seq',
                    { store => 'LOCAL_IP', parse => \&get_ip },
                    ['cond1',
                     { parse => \&test_ne, params => ['ip', '$TYPE'] },
                     { store => 'LOCAL_PORT', 
                       parse => 'parse_port', params => ['$TYPE'] } ],
                    ['cond1',
                     { parse => qr/netmask/ },
                     { store => 'NETMASK', 
                       parse => \&get_ip, 
                       default => 0xffffffff } ]]],
                  ['seq',
                   { store => 'MAX_CONS', 
                     parse => \&check_int,
                     default => 0 },
                   { store => 'EMB_LIMIT', 
                     parse => \&check_int,
                     default => 0 } ],
                  { store => 'DNS', parse => qr/dns/ },
                  { store => 'NORANDOMSEQ', parse => qr/norandomseq/ } ],
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

# Read hostname from prompt
sub get_identity {
    my ($self) = @_;

    # Force new prompt by issuing empty command.
    my $result = $self->issue_cmd('');
    $result->{MATCH} =~ m/^\r\n\s*(\S+)\#\s?$/;
    return $1;
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

