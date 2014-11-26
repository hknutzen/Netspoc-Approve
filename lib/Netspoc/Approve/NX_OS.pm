
=head1 DESCRIPTION

Configure Cisco Nexus devices

=head1 COPYRIGHT AND DISCLAIMER

https://github.com/hknutzen/Netspoc-Approve
(c) 2014 by Heinz Knutzen <heinz.knutzen@gmail.com>

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

package Netspoc::Approve::NX_OS;

use base "Netspoc::Approve::Cisco_Router";
use strict;
use warnings;
use Netspoc::Approve::Helper;
use Netspoc::Approve::Parse_Cisco;

our $VERSION = '1.094'; # VERSION: inserted by DZP::OurPkgVersion

sub get_parse_info {
    my ($self) = @_;
    my $result =
    { 
        # interface Ethernet2/1
	'interface' => {
            store => 'IF',
            named => 1,
            subcmd => {
                'ip address' => {
                    parse =>  ['seq',
                               { parse => \&get_ip_prefix, 
                                 store_multi => ['BASE', 'MASK'] }],
                    store => 'ADDRESS',
                },
                'ip address _skip secondary' =>  { 
                    parse => \&skip }, # ignore
                'ip unnumbered' => {
                    parse => \&get_token,
                    store => ['ADDRESS', 'UNNUMBERED'], 
                },
                'ip access-group _skip in' => {
                    parse => \&get_token, 
                    store => 'ACCESS_GROUP_IN', 
                },
                'ip access-group _skip out' => {
                    parse => \&get_token, 
                    store => 'ACCESS_GROUP_OUT', 
                },
                'vrf member' => {
                    parse => \&get_token,
                    store => 'VRF',
                },
                'mpls ip' => {
                    default => 1,
                    store => 'MPLS',
                },
            },
        },

# subcmd 'ip route' will be copied from toplevel 'ip route' command.
        'vrf context' => {
            store => 'VRF_CONTEXT',
            named => 1,
        },

# ip route ip/prefix {[interface] next-hop} 
#          [preference] [tag id] [name nexthop-name] 
	'ip route' => { 
	    store => 'ROUTING',
	    multi => 1,
	    parse => ['seq',
		      { parse => \&get_ip_prefix, 
			store_multi => ['BASE', 'MASK'] },
		      ['or',
		       { store => 'NEXTHOP', parse => \&check_ip, },
		       ['seq',
			{ store => 'NIF',  parse => \&get_token, },
			{ store => 'NEXTHOP', parse => \&check_ip, },],],
                      { parse => \&check_int, store => 'PREFERENCE' },
                      ['cond1',
                       { parse => qr/tag/, },
                       { parse => \&get_token, store => 'TAG' }],
                      ['cond1',
                       { parse => qr/name/, },
                       { parse => \&get_token, store => 'HOPNAME' }],],
        },
        'object-group ip address' => {
            store => 'OBJECT_GROUP',
	    named => 1,
            parse => ['seq', { store => 'TYPE', default => 'network', },],
            strict => 'err',
            subcmd => {
                '_any' => {
                    leave_cmd_as_arg => 1,
		    store => 'OBJECT', 
		    multi => 1,
		    parse =>  'parse_numbered_address',
                }
            }
        },
        'object-group ip port' => {
            store => 'OBJECT_GROUP',
	    named => 1,
            parse => ['seq', { store => 'TYPE', default => 'tcp-udp', },],
            strict => 'err',
            subcmd => {
                '_any' => {
                    leave_cmd_as_arg => 1,
		    store => 'OBJECT', 
		    multi => 1,
		    parse => 'parse_numbered_port_spec',
                }
            }
        },

# permit protocol source destination
#        [dscp dscp | precedence precedence] 
#        [fragments] [log] [time-range time-range-name] 
#        [packet-length operator packet-length [packet-length]]
# permit icmp source destination [icmp-message | icmp-type [icmp-code]]
# permit igmp source destination [igmp-message]
# permit ip source destination
# permit tcp source [operator port [port] | portgroup portgroup] 
#            destination [operator port [port] | portgroup portgroup]
#        [flags] [established]
# permit udp source [operator port [port] | portgroup portgroup] 
#            destination [operator port [port] | portgroup portgroup]
	'ip access-list' => {
	    store =>  'ACCESS_LIST',
	    named => 1,
            strict => 'err',
	    subcmd => {
                '_skip remark' => {
		    store => 'LIST',
		    multi => 1,
		    parse => [
                        'seq',
                        { parse => \&get_int, },
                        { store => 'REMARK', parse => \&get_to_eol } ] },
                '_skip permit' => {
		    store => 'LIST',
		    multi => 1,
		    parse => [
                        'seq',
                        { parse => \&get_int, },
                        { store => 'MODE', default => 'permit' },
                        ['or',
                         ['cond1',
                          { store => 'TYPE', parse => qr/ip/ },
                          { store => 'SRC', parse => 'parse_address' },
                          { store => 'DST', parse => 'parse_address' } ],
                         ['cond1',
                          { store => 'TYPE', parse => qr/udp|tcp/ },
                          { store => 'SRC', parse => 'parse_address' },
                          { store => 'SRC_PORT', 
                            parse => 'parse_og_port_spec', 
                            params => ['$TYPE'] },
                          { store => 'DST', parse => 'parse_address' },
                          { store => 'DST_PORT', 
                            parse => 'parse_og_port_spec', 
                            params => ['$TYPE'] },
                          { store => 'ESTA', 
                            parse => qr/established/ }, ],
                         ['cond1',
                          { store => 'TYPE', parse => qr/icmp/ },
                          { store => 'SRC', parse => 'parse_address' },
                          { store => 'DST', parse => 'parse_address' },
                          { store => 'SPEC', 
                            parse => 'parse_icmp_spec' }, ],
                         ['seq',
                          { store => 'TYPE', parse => \&get_token },
                          { store => 'TYPE' ,
                            parse => 'normalize_proto', 
                            params => [ '$TYPE' ] },
                          { store => 'SRC', parse => 'parse_address' },
                          { store => 'DST', parse => 'parse_address' } ]],
                        { store => 'LOG', parse => qr/log/ } 
                        ],
		},
	    },
	},
    };

    # Copy 'permit' entry and substitute 'permit' by 'deny';
    my $entry = $result->{'ip access-list'}->{subcmd};
    $entry = $entry->{'_skip deny'} = { %{$entry->{'_skip permit'}} };
    $entry = $entry->{parse} = [ @{$entry->{parse}} ];
    $entry = $entry->[1] = { %{$entry->[1]} };
    $entry->{default} = 'deny';

    # Copy 'ip route' entry as subcmd to 'vrf context'
    $result->{'vrf context'}->{subcmd}->{'ip route'} = $result->{'ip route'};

    $result;
}
                
# addrgroup <name>
# ip/prefixlen
# host <ip>
# any
sub parse_address {
    my ($self, $arg) = @_;
    my ($ip, $mask);
    if (check_regex('addrgroup', $arg)) {
        return { GROUP_NAME => get_token($arg) };
    }
    elsif (check_regex('any', $arg)) {
        $ip = $mask = 0;
    }
    elsif (check_regex('host', $arg)) {
        $ip   = get_ip($arg);
        $mask = 0xffffffff;
    }
    else {
        ($ip, $mask) = get_ip_prefix($arg);
    }
    return ({ BASE => $ip, MASK => $mask });
}

sub parse_og_port_spec {
    my ($self, $arg, $type) = @_;
    if(check_regex('portgroup', $arg)) {
	return { GROUP_NAME => get_token($arg) };
    }
    return $self->SUPER::parse_port_spec($arg, $type);
}

# <line_nr> <ip>/<prefixlen>
# <line_nr> host <ip>
# <line_nr> any
sub parse_numbered_address {
    my ($self, $arg) = @_;
    get_int($arg);
    $self->parse_address($arg);
}

# <line_nr> <port_spec>
sub parse_numbered_port_spec {
    my ($self, $arg) = @_;
    get_int($arg);
    $self->parse_port_spec($arg, 'tcp-udp');
}

sub postprocess_config {
    my ($self, $p) = @_;

    # Collect routing of default VRF and explicit VRFs.
    $p->{ROUTING_VRF}->{''} = delete $p->{ROUTING} if $p->{ROUTING};
    if ($p->{VRF_CONTEXT}) {
        for my $entry (values %{ delete $p->{VRF_CONTEXT} }) {
            my $vrf = $entry->{name};
            $_->{VRF} = $vrf for @{ $entry->{ROUTING} };
            $p->{ROUTING_VRF}->{$vrf} = $entry->{ROUTING};
        }
    }

    # Remove line numbers from {orig} of ACL entries.
    # Change object-group NAME to object-group OBJECT in ACL entries.
    my $access_lists = $p->{ACCESS_LIST};
    my $object_groups =  $p->{OBJECT_GROUP};
    for my $acl (values %$access_lists) {
        for my $entry (@{ $acl->{LIST} }) {
            $entry->{orig} =~ s/^\d+ //;
            for my $where (qw(SRC DST)) {
                my $what = $entry->{$where};
                my $group_name = ref($what) && $what->{GROUP_NAME} or next;
                my $group = $object_groups->{$group_name} or
                    abort("Can't find OBJECT_GROUP $group_name" .
                          " referenced by $acl->{name}");
                $what->{GROUP} = $group;
            }
        }
    }

    # Remove line numbers from {orig} of object-group entries.
    for my $acl (values %$object_groups) {
        for my $entry (@{ $acl->{OBJECT} }) {
            $entry->{orig} =~ s/^\d+ //;
        }
    }

    # Interface mgmt0 is located in management VRF by default.
    if (my $intf = $p->{IF}->{mgmt0}) {
        $intf->{VRF} ||= 'management';
    }
}
        
sub get_config_from_device {
    my ($self) = @_;
    $self->get_cmd_output('show running-config');
}

my %known_status = 
    (
     'configure terminal' =>
     [ 'Enter configuration commands, one per line.  End with CNTL/Z.', ],
     'configure session Netspoc' => 
     [ qr/^Config Session started, Session ID is/, 
       'Enter configuration commands, one per line.  End with CNTL/Z.', ],
     'verify' => [ 'Verification Successful', ],
     'commit' => [ 'Commit Successful', ],
     'copy running-config startup-config' => [
         qr/^\[.*\] +\d+%$/, qr/^Copy complete/ ],
     );

my %known_warning = 
(
 );

# Check unexpected lines:
# - known status messages
# - known warning messages
# - unknown messages, handled as error messages.
sub cmd_check_error {
    my ($self, $cmd, $lines) = @_;
    my $error;
  LINE:
    for my $line (@$lines) {
        
        # Ignore empty line
        next LINE if $line =~ /^\s*$/;

	for my $pattern (@{ $known_status{$cmd} }) {
	    if(ref($pattern) ? $line =~ $pattern : $line eq $pattern) {
		next LINE;
	    }
	}
	for my $regex (@{ $known_warning{$cmd} }) {
	    if($line =~ $regex) {
                warn_info($line);
		next LINE;
	    }
	}
	$error = 1;
    }
    return $error;
}

sub parse_version {
    my ($self) = @_;
    my $output = $self->shcmd('show version');
    # system:    version 4.0(1a) [gdb]
    if($output =~ /system: \s+ version \s+ (\S+)/ix) {
	$self->{VERSION} = $1;
    }
    # cisco Nexus7000 C7010 (10 Slot) Chassis ("Supervisor module-1X")
    if($output =~ /(cisco \s+ Nexus\S* \s+ \S+)/ix) {	
	$self->{HARDWARE} = $1;
    }
}

sub set_terminal {
    my ($self) = @_;
    $self->device_cmd('terminal length 0');
    $self->device_cmd('terminal width 511');
}

sub enter_conf_mode {
    my($self, $session) = @_;
    if ($session) {
        $self->cmd('configure session Netspoc');
        $self->{CONF_MODE} = 'session';
    }
    else {
        $self->SUPER::enter_conf_mode();
    }
}

sub leave_conf_mode {
    my($self) = @_;
    if ($self->{CONF_MODE} eq 'session') {
        my $cmd = 'verify';
        if($self->{COMPARE}) {
            $self->cmd($cmd);
        }
        else {
            my $lines = $self->get_cmd_output($cmd);
            if ($self->cmd_check_error($cmd, $lines)) {
                $self->cmd('abort');
                abort("Can't 'verify' configuration session", @$lines);
            }
        }

        $self->cmd('commit');
        $self->{CONF_MODE} = 0;
    }
    else {
        $self->SUPER::leave_conf_mode();
    }
}

sub check_session {
    my($self) = @_;
    return if $self->{COMPARE};
    my $lines = $self->get_cmd_output('show configuration session');
    return if !@$lines;
    if ($lines->[-1] =~ /^Number of active configuration sessions/) {
        abort("There already is an open configuration session", @$lines);
    }
    return;
}
    
# No op; we can't lock out from Netspoc,
# because we use "configure session xx". 
sub is_device_access {
    my ($self, $conf_entry) = @_;
}

sub resequence_cmd {
    my ($self, $acl_name, $start, $incr) = @_;
    $self->cmd("resequence ip access-list $acl_name $start $incr");
}

sub vrf_route_mode {
    my ($self, $vrf) = @_;
    $self->cmd("vrf context $vrf") if $vrf;
}

sub route_add {
    my($self, $entry, $vrf) = @_;
    my $indent = $vrf ? ' ' : '';
    return("$indent$entry->{orig}");
}

sub route_del {
    my($self, $entry, $vrf) = @_;
    my $indent = $vrf ? ' ' : '';
    return("${indent}no $entry->{orig}");
}

sub write_mem {
    my ($self) = @_;
    $self->cmd('copy running-config startup-config');
}

sub transfer {
    my ($self, $conf, $spoc) = @_;
    $self->check_session();
    $self->SUPER::transfer($conf, $spoc);
}

# Packages must return a true value;
1;

