
=head1 DESCRIPTION

Configure Cisco ACE board

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

package Netspoc::Approve::ACE;

use base "Netspoc::Approve::Cisco_Router";
use strict;
use warnings;
use Netspoc::Approve::Helper;
use Netspoc::Approve::Parse_Cisco;

our $VERSION = '1.099'; # VERSION: inserted by DZP::OurPkgVersion

sub get_parse_info {
    my ($self) = @_;
    return
    { 
# interface vlan 3029
	'interface' => {
            store => 'IF',
            named => 'from_parser',
            parse => [
                'seq',
                { parse => sub { 
                    my ($arg) = @_;
                    
                    # Use concatenation "vlan 3029" as name.
                    return(get_token($arg) . ' ' . get_token($arg));
                  },
                  store => 'name', } ],
            subcmd => {
                'ip address' => {
                    parse =>  ['seq',
                               { store => 'BASE', parse => \&check_ip, },
                               { store => 'MASK', parse => \&check_ip, } ],
                    store => 'ADDRESS',
                },
                'ip address _skip _skip secondary' =>  { 
                    parse => \&skip,	# ignore
                },
                'access-group input' => {
                    parse => \&get_token, 
                    store => 'ACCESS_GROUP_IN', 
                },
            },
        },

# ip route ip mask next-hop
	'ip route' => { 
	    store => 'ROUTING',
	    multi => 1,
	    parse => ['seq',
		      { store => 'BASE', parse => \&get_ip, },
		      { store => 'MASK', parse => \&get_ip, },,
                      { store => 'NEXTHOP', parse => \&get_ip, },],
        },

        'object-group network' => {
            store => 'OBJECT_GROUP',
	    named => 1,
            parse => ['seq', { store => 'TYPE', default => 'network', },],
            strict => 'err',
            subcmd => {
                '_any' => {
                    leave_cmd_as_arg => 1,
		    store => 'OBJECT', 
		    multi => 1,
		    parse =>  'parse_address',
                }
            }
        },

        # ignore
        'access-list _skip ethertype' => { parse => \&skip },

	'access-list' => {
	    store => 'ACCESS_LIST', 
	    multi => 1,
	    named => 1,
            strict => 'err',
	    parse => [
                'or',
                ['cond1',
                 { parse => qr/remark/ },
                 { store => 'REMARK', parse => \&get_to_eol } ],
                ['seq',
                 ['cond1',
                  { parse => qr/line/ },
                  { parse => qr/\d+/  },
                 ],
                 ['seq',
                  { store => 'ACL_TYPE',
                    parse => qr/extended/, default => 'extended' },
                  { store => 'MODE', parse => qr/permit|deny/ },
                  ['or',
                   ['cond1',
                    { store => 'TYPE', parse => qr/ip/ },
                    { store => 'SRC', parse => 'parse_address' },
                    { store => 'DST', parse => 'parse_address' } ],
                   ['cond1',
                    { store => 'TYPE', parse => qr/udp|tcp/ },
                    { store => 'SRC', parse => 'parse_address' },
                    { store => 'SRC_PORT',
                      parse => 'parse_port_spec', params => ['$TYPE'] },
                    { store => 'DST', parse => 'parse_address' },
                    { store => 'DST_PORT', 
                      parse => 'parse_port_spec', params => ['$TYPE'] } ],
                   ['cond1',
                    { store => 'TYPE', parse => qr/icmp/ },
                    { store => 'SRC', parse => 'parse_address' },
                    { store => 'DST', parse => 'parse_address' },
                    { store => 'SPEC', parse => 'parse_icmp_spec' }, ],
                   ['seq',
                    { store => 'TYPE', parse => \&get_token },
                    { store => 'TYPE' ,
                      parse => 'normalize_proto', params => [ '$TYPE' ] },
                    { store => 'SRC', parse => 'parse_address' },
                    { store => 'DST', parse => 'parse_address' } ]]]]],
        },
    };
}
 
sub parse_object_group  {
    my ($self, $arg) = @_;
    if(check_regex('object-group', $arg)) {
	return { GROUP_NAME => get_token($arg) };
    }
    else {
        return;
    }
}

sub parse_address {
    my ($self, $arg) = @_;
    return 
        $self->parse_object_group($arg) || $self->SUPER::parse_address($arg);
}

my %PORT_Names_TCP = (
    aol       => 5190,
    ctiqbe    => 2748,
    kerberos  => 88,
    'matip-a' => 350,
    skinny    => 2000,
);

sub tcp_name2num {
    my ($self, $name) = @_;
    return ($PORT_Names_TCP{$name} || $self->SUPER::tcp_name2num($name));
}

my %PORT_Names_UDP = (
    biff           => 512,
    bootpc         => 68,
    bootps         => 69,
    dnsix          => 195,
    kerberos       => 88,
    'netbios-ssn'  => 139,
    wsp            => 9200,
    'wsp-wtls'     => 9202,
    'wsp-wtp'      => 9201,
    'wsp-wtp-wtls' => 9203,
);

sub udp_name2num {
    my ($self, $name) = @_;
    return ($PORT_Names_UDP{$name} || $self->SUPER::udp_name2num($name));
}

sub postprocess_config {
    my ($self, $p) = @_;

    # ACE has only default VRF.
    $p->{ROUTING_VRF}->{''} = delete $p->{ROUTING} if $p->{ROUTING};

    # For each access list, change array of access list entries to
    # hash element with attribute 'LIST'.
    my $access_lists = $p->{ACCESS_LIST};
    my $object_groups =  $p->{OBJECT_GROUP};
    for my $acl_name (keys %$access_lists) {
	my $entries = $access_lists->{$acl_name};
	$access_lists->{$acl_name} = { name => $acl_name, LIST => $entries };

        # Remove line numbers from {orig} of ACL entries.
        # Change object-group NAME to object-group OBJECT in ACL entries.
        for my $entry (@$entries) {
            $entry->{orig} =~ s/ line \d+ / /;
            for my $where (qw(SRC DST)) {
                my $what = $entry->{$where};
                my $group_name = ref($what) && $what->{GROUP_NAME} or next;
                my $group = $object_groups->{$group_name} or
                    abort("Can't find OBJECT_GROUP $group_name" .
                          " referenced by $acl_name");
                $what->{GROUP} = $group;
            }
        }
    }
}

# Read hostname from prompt.
sub get_identity {
    my ($self) = @_;

    # Force new prompt by issuing empty command.
    my $result = $self->issue_cmd('');
    $result->{MATCH} =~ m/^\r\n\s*(\S+)\#\s?$/;
    my $name = $1;

    # Remove leading name in front of context name.
    $name =~ s|^.*[/]||;
    return $name;
}

sub get_config_from_device {
    my ($self) = @_;
    $self->get_cmd_output('show running-config');
}

my %known_status = 
    (
     'configure terminal' => [ 
         'Enter configuration commands, one per line.  End with CNTL/Z.', ],
     'copy running-config startup-config' => [
         'Generating configuration....', 
         qr/^running config of context \S+ saved$/ ],
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
    # system:    Version A5(2.1e)
    if($output =~ /system: \s+ version \s+ (\S+)/ix) {
	$self->{VERSION} = $1;
    }
    # Cisco ACE (slot: 3)
    if($output =~ /(Cisco \s+ ACE\S*)/ix) {	
	$self->{HARDWARE} = $1;
    }
}

sub set_terminal {
    my ($self) = @_;
    $self->device_cmd('terminal length 0');
    $self->device_cmd('terminal width 511');
}

# No op; curently not checked.
sub is_device_access {
    my ($self, $conf_entry) = @_;
    return;
}

# Handle message "Configuration clean up in progress, retry again".
sub resequence_cmd {
    my ($self, $acl_name, $start, $incr) = @_;
    my $cmd = "access-list $acl_name resequence $start $incr";
    
    if ($self->{COMPARE}) {
        $self->cmd($cmd);
        return; 
    }

    while (1) {
        my $lines = $self->get_cmd_output(
            "access-list $acl_name resequence $start $incr");

        # Success.
        last if not @$lines;

        # Try again.
        if (@$lines == 1 &&
            $lines->[0] eq 
            'Error: Configuration clean up in progress, retry again') {
            info('ACL resequence command failed - trying again');
            sleep(4);
            next;
        }

        # Failure.
        abort("ACL resequence: unexpected output:", @$lines);
    }
}

# Generate ACL entry from attributes 
# - ace, the parsed ACL entry
# - line, the new / current line number
# - name, the name for newly created entry.
# - delete, the line is to be deleted
sub gen_ace_cmd {
    my ($self, $hash) = @_;
    my $line = $hash->{line};
    my $cmd;
    if ($hash->{delete}) {
        $cmd = $hash->{ace}->{orig};
        $self->mark_unneeded_object_group_from_acl_entry($hash->{ace});
    }
    else {
        $cmd = $self->subst_ace_name_og($hash->{ace}, $hash->{name});
    }
    $cmd =~ s/^(\S+ \S+)/$1 line $line/;
    $cmd = "no $cmd" if $hash->{delete};
    return $cmd;
}

sub remove_acl {
    my ($self, $acl) = @_;
    my $name = $acl->{name};
    $self->cmd("no access-list $name");
}

sub assign_acl {
    my ($self, $intf, $acl_name, $in_out) = @_;
    my $direction = $in_out eq 'IN' ? 'input' : 'output';
    $self->cmd($intf->{orig});
    $self->cmd("ip access-group $direction $acl_name");
}

sub unassign_acl   {
    my ($self, $intf, $acl_name, $in_out) = @_;
    my $direction = $in_out eq 'IN' ? 'input' : 'output';
    $self->cmd($intf->{orig});
    $self->cmd("no ip access-group $direction $acl_name");
}

sub write_mem {
    my ($self) = @_;
    $self->cmd('copy running-config startup-config');
}

# Packages must return a true value;
1;

