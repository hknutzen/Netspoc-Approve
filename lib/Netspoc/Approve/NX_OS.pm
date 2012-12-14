
package Netspoc::Approve::NX_OS;

# Authors: Heinz Knutzen
#
# Description:
# Configure Cisco Nexus devices
#

use base "Netspoc::Approve::Cisco_Router";
use strict;
use warnings;
use Netspoc::Approve::Helper;
use Netspoc::Approve::Parse_Cisco;

# VERSION: inserted by DZP::OurPkgVersion

sub get_parse_info {
    my ($self) = @_;
    my $result =
    { 
        # interface Ethernet2/1
	'interface' => {
            store => 'IF',
            named => 1,
            subcmd => {
                'ip access-group _skip in' => {
                    parse => \&get_token, 
                    store => 'ACCESS_GROUP_IN', 
                },
                'ip access-group _skip out' => {
                    parse => \&get_token, 
                    store => 'ACCESS_GROUP_OUT', 
                },
            },
        },

# ip route ip-prefix/mask {[interface] next-hop} 
#          [preference] [tag id] [name nexthop-name] 
	'ip route' => { 
	    store => 'ROUTING',
	    multi => 1,
	    parse => ['seq',
		      { parse => \&get_ip_prefix, 
			store_multi => ['BASE', 'MASK'] },
                      # [interface] isn't implemeted
                      { parse => \&get_ip, store => 'NEXTHOP' },
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
            parse => ['seq', { store => 'TYPE', default => 'address', },],
            subcmd => {
                '_any' => {
		    store => 'OBJECT', 
		    multi => 1,
		    parse =>  'parse_numbered_address', params => [ '_cmd' ],
                }
            }
        },
        'object-group ip port' => {
            store => 'OBJECT_GROUP',
	    named => 1,
            parse => ['seq', { store => 'TYPE', default => 'port', },],
            subcmd => {
                '_any' => {
		    store => 'OBJECT', 
		    multi => 1,
		    parse => 'parse_numbered_port_spec', params => [ '_cmd' ],
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
	    subcmd => {
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

sub check_line_nr {
    my ($arg, $line_nr) = @_;
    if ($line_nr !~ /^\d+/) {
        unread($arg);
        err_at_line($arg, "Missing line number");
    }
}

# <line_nr> <ip>/<prefixlen>
# <line_nr> host <ip>
# <line_nr> any
sub parse_numbered_address {
    my ($self, $arg, $line_nr) = @_;
    check_line_nr($arg, $line_nr);
    $self->parse_address($arg);
}

# <line_nr> <port_spec>
sub parse_numbered_port_spec {
    my ($self, $arg, $line_nr) = @_;
    check_line_nr($arg, $line_nr);
    $self->parse_port_spec($arg, 'tcp-udp');
}

sub postprocess_config {
    my ($self, $p) = @_;

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
     );

my %known_warning = 
(
 );

# Check unexpected lines:
# - known status messages
# - known warning messages
# - unknown messages, handled as error messages.
sub cmd_check_error($$) {
    my ($self, $cmd, $lines) = @_;
    my $error;
  LINE:
    for my $line (@$lines) {
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
    if ($error) {
	$self->abort_cmd("Unexpected output of '$cmd'", @$lines);
    }
}

sub parse_version {
    my ($self) = @_;
    my $output = $self->shcmd('show version');
    # system:    version 4.0(1a) [gdb]
    if($output =~ /system: \s+ version \s+ (\S+)/ix) {
	$self->{VERSION} = $1;
    }
    # cisco Nexus7000 C7010 (10 Slot) Chassis ("Supervisor module-1X")
    if($output =~ /(cisco \s+ Nexus\S* \S+)/ix) {	
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
        $self->cmd('verify');
        $self->cmd('commit');
        $self->{CONF_MODE} = 0;
    }
    else {
        $self->SUPER::leave_conf_mode();
    }
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

sub write_mem {
    my ($self) = @_;
    $self->cmd('copy startup-config running-config');
}

# Packages must return a true value;
1;

