
=head1 DESCRIPTION

Remote configure Cisco IOS router

=head1 COPYRIGHT AND DISCLAIMER

https://github.com/hknutzen/Netspoc-Approve
(c) 2016 by Heinz Knutzen <heinz.knutzen@gmail.com>
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

package Netspoc::Approve::IOS;

use base "Netspoc::Approve::Cisco_Router";
use strict;
use warnings;
use Netspoc::Approve::Helper;
use Netspoc::Approve::Parse_Cisco;

# VERSION: inserted by DZP::OurPkgVersion

# Parse info.
# Key is a single or multi word command.
# Argument position may be skiped using word "_skip".
# Any argument may be added to command using word "_any".
#
# Value is a hash with attributes:
# - store: name of attribute where result is stored or
#   array of names which are used to access sub-hash: {name1}->{name2}->..
# - named: first argument is name which is used as key when storing result
# - multi: multiple occurences of this command may occur
#          and are stored as an array.
# - leave_cmd_as_arg: This attribute will be used together with "_any".
#          If set, the command will be left as an argument to be parsed.
# - parse: description how to parse arguments of command; possible values:
#   - regexp, used as argument for check_regex
#   - function ref. which parses one or more arguments and returns a value
#   - string: like function ref, but used as a method name
#   - array ref with first element is a string and multiple elements following
#     - string 'seq': all elements are evaluated.
#     - string 'cond1': all elements are evaluated, if the first element
#                     returns a defined value
#     - string 'or': elements are evaluated until a defined value is returned.
#   no parse attribute is given, if command has no (further) arguments.
# - default: take this value if value of parse function was undef
#            or if no parse function is given.
# - subcmd: parse info for subcommands of current command.
sub get_parse_info {
    my ($self) = @_;
    my $result =
    {
	interface =>
	{ store => 'IF',
	  named => 1,
	  parse => ['or',
                    ['cond1',
                     { parse => qr/type/ },
                     { parse => qr/tunnel/ } ],
                    ['cond1',
                     { parse => qr/point-to-point|multipoint/ } ]],
	  subcmd =>
	  { 'ip address' => {
	      store => 'ADDRESS',
	      parse => ['or',
			{ store => 'DYNAMIC', parse => qr/negotiated/, },
			{ store => 'DYNAMIC', parse => qr/dhcp/, },
			['seq',
			 { store => 'BASE', parse => \&check_ip, },
			 { store => 'MASK', parse => \&check_ip, } ]] },
	    'ip address _skip _skip secondary' =>  {
		parse => \&skip }, # ignore
	    'ip unnumbered' => {
	      parse => \&get_token,
	      store => 'UNNUMBERED',
            },
	    'shutdown' => {
		store => 'SHUTDOWN', default => 1, },
	    'ip access-group _skip in' => {
		store => 'ACCESS_GROUP_IN', parse => \&get_token, },
	    'ip access-group _skip out' => {
		store => 'ACCESS_GROUP_OUT', parse => \&get_token, },
	    'ip inspect _skip in' => {
		store => 'INSPECT', parse => \&get_token, },

            # Both commands are assumed to be equivalent.
	    'ip vrf forwarding' => {
		store => 'VRF', parse => \&get_token, },
	    'vrf forwarding' => {
		store => 'VRF', parse => \&get_token, },
            'mpls ip' => {
                store => 'MPLS', default => 1, },
            #
	    'crypto map' => {
		store => 'CRYPTO_MAP', parse => \&get_token, },
	    'crypto ipsec client ezvpn' => {
		store => 'EZVPN',
		parse =>
		    ['seq',
		     { store => 'NAME',
		       parse => \&get_token, },
		     { store => 'LOCATION',
		       parse => \&check_token,
		       default => 'outside', }, ], },
	  },
	},

# ip route [vrf name] destination-prefix destination-prefix-mask
#          [interface-type card/subcard/port] forward-addr
#          [metric | permanent | track track-number | tag tag-value]
#
	'ip route' => {
	    store => 'ROUTING',
	    multi => 1,
	    parse => ['seq',
		      ['cond1',
		       { parse => qr/vrf/, },
		       { store => 'VRF', parse => \&get_token, },],
		      { store => 'BASE', parse => \&get_ip, },
		      { store => 'MASK', parse => \&get_ip, },
		      ['or',
		       { store => 'NEXTHOP', parse => \&check_ip, },
		       ['seq',
			{ store => 'NIF',  parse => \&get_token, },
			{ store => 'NEXTHOP', parse => \&check_ip, },],],
		      ['seq',
		       { store => 'METRIC',
			 parse => \&check_int,
			 default => 1 },
                       ['cond1',
                         # Ignore name.
                        { parse => qr/name/, }, { parse => \&get_token },],
		       ['cond1',
			{ parse => qr/track/, },
			{ store => 'TRACK', parse => \&get_token, },],
		       ['cond1',
			{ parse => qr/tag/, },
			{ store => 'TAG', parse => \&get_token, },],
		       { store => 'PERMANENT', parse => qr/permanent/, },],],
	},
	'object-group network' => {
	    store => 'OBJECT_GROUP',
	    named => 1,
            parse => ['seq', { store => 'TYPE', default => 'network', },],
            strict => 'err',
	    subcmd => {
		'group-object' => {
		    error => 'Nested object group not supported'
                },
		'_any' => {
                    leave_cmd_as_arg => 1,
		    store => 'OBJECT',
		    multi => 1,
		    parse => 'parse_address',
		},
            }
        },
	'ip access-list extended' => {
	    store =>  'ACCESS_LIST',
	    named => 1,
	    subcmd => {
                remark => {
		    store => 'LIST',
		    multi => 1,
		    parse => [
                        'seq',
                        { store => 'REMARK', parse => \&get_to_eol } ] },

		# 'deny' is mostly identical to 'permit',
		# it will be automatically copied from 'permit'.
		permit => {
		    store => 'LIST',
		    multi => 1,
		    parse => ['seq',
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
				  parse => 'parse_port_spec',
				  params => ['$TYPE'] },
				{ store => 'DST', parse => 'parse_address' },
				{ store => 'DST_PORT',
				  parse => 'parse_port_spec',
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
			      { store => 'LOG', parse => qr/log-input|log/ },

                              # Skip unknown keywords and mark line as unknown.
                              ['cond1',
                               { store => 'UNKNOWN', parse => \&check_token },
                               { parse => \&skip } ],
                        ]
		},

	    },
	},

	'crypto ipsec client ezvpn' => {
	    store => 'CRYPTO_IPSEC_CLIENT_EZVPN',
	    named => 1,
	    subcmd => {
		'virtual-interface' => {
		    store => 'V_INTERFACE', parse => \&get_int, },},
	},

# Ignore, don't try to parse as crypto map with sequence number.
	'crypto map _skip client'         => { parse => \&skip, },
	'crypto map _skip gdoi'           => { parse => \&skip, subcmd => {} },
	'crypto map _skip isakmp'         => { parse => \&skip, },
	'crypto map _skip isakmp-profile' => { parse => \&skip, },
	'crypto map _skip local-address'  => { parse => \&skip, },
	'crypto map _skip redundancy'     => { parse => \&skip, },
	'crypto map ipv6'                 => { parse => \&skip, subcmd => {} },

# crypto map <name> <seq> ipsec-isakmp
#  <sub commands>
#
# Result: Add multiple values to named crypto map.
	'crypto map' => {
	    store => 'CRYPTO_MAP',
	    named => 1,
	    multi => 1,
	    parse => ['seq',
		      { store => 'SEQU', parse => \&get_int, },
		      ['or',
		       { parse => qr/ipsec-isakmp/, },
		       { parse => qr/gdoi/, store => 'GDOI', } ]],
	    subcmd => {
		'set ip access-group _skip in' => {
		    store => 'ACCESS_GROUP_IN', parse => \&get_token, },
		'set ip access-group _skip out' => {
		    store => 'ACCESS_GROUP_OUT', parse => \&get_token, },
	    },
	},

	# We don't use these commands, but lexical analyser needs to know
	# that these are multi line commands.
	banner => { banner => qr/^\^/, parse => \&skip },

	'crypto pki certificate chain' => {
	    named => 1,
	    subcmd => {
		'certificate' => { parse => \&skip,
                                   banner => qr/^\s*quit\s*$/ },
	    }
	},
    };

    # Copy 'permit' entry and substitute 'permit' by 'deny';
    my $entry = $result->{'ip access-list extended'}->{subcmd};
    $entry = $entry->{deny} = { %{$entry->{permit}} };
    $entry = $entry->{parse} = [ @{$entry->{parse}} ];
    $entry = $entry->[1] = { %{$entry->[1]} };
    $entry->{default} = 'deny';

    $result;
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

sub adjust_mask {
    my ($self, $mask) = @_;
    return ~$mask & 0xffffffff;
}

sub postprocess_config {
    my ($self, $p) = @_;

    # Store routing separately for each VRF
    if ($p->{ROUTING}) {
        my $hash;
        for my $entry (@{ delete $p->{ROUTING} }) {
            my $vrf = $entry->{VRF} || '';
            push @{ $hash->{$vrf} }, $entry;
        }
        $p->{ROUTING_VRF} = $hash if keys %$hash;
    }

    # Change object-group NAME to object-group OBJECT in ACL entries.
    my $access_lists = $p->{ACCESS_LIST};
    my $object_groups =  $p->{OBJECT_GROUP};
    for my $acl (values %$access_lists) {
        for my $entry (@{ $acl->{LIST} }) {
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

    if (my $ezvpn = $p->{CRYPTO_IPSEC_CLIENT_EZVPN}) {
        for my $ez_name (keys %$ezvpn) {
            my $entry = $ezvpn->{$ez_name};
            my $num = $entry->{V_INTERFACE} or
                abort("EZVPN: virtual-interface missing for $ez_name");
            my $intf = "Virtual-Template$num";
            $p->{IF}->{$intf} or
                abort("EZVPN: virtual-interface $intf not found");
        }
    }

    if (my $crypto_maps = $p->{CRYPTO_MAP}) {
        for my $cm_name (keys %$crypto_maps) {
            my $cm = $p->{CRYPTO_MAP}->{$cm_name};
	    $cm = [ sort { $a->{SEQU} <=> $b->{SEQU} } @$cm ];
	    $p->{CRYPTO_MAP}->{$cm_name} = $cm;
            for my $entry (@$cm) {
		next if $entry->{GDOI};
                my $sequ = $entry->{SEQU};

                # Check access list for crypto map.
                for my $what (qw(IN OUT)) {
                    my $acl_name = $entry->{"ACCESS_GROUP_$what"} or next;
                    $p->{ACCESS_LIST}->{$acl_name} or
                        abort("Crypto: ACL $acl_name does not exist");
                }
            }
        }
    }

    for my $intf (values %{ $p->{IF} }) {
        if (my $imap = $intf->{CRYPTO_MAP}) {
            $p->{CRYPTO_MAP}->{$imap} or
                abort("Missing definition for crypto map '$imap' used at"
                      . " interface '$intf->{name}'");
        }
        elsif ($intf->{EZVPN}) {
            my $ezvpn = $intf->{EZVPN}->{NAME};
            $p->{CRYPTO_IPSEC_CLIENT_EZVPN}->{$ezvpn} or
                abort("Missing definition for ezvpn client '$ezvpn' at"
                      . " interface '$intf->{name}'");
        }
    }
}

# Read hostname from prompt
sub get_identity {
    my ($self) = @_;

    # Force new prompt by issuing empty command.
    my $result = $self->issue_cmd('');
    $result->{MATCH} =~ m/^\r\n\s*(\S+)\#\s?$/;
    return $1;
}

sub get_config_from_device {
    my ($self) = @_;
    $self->get_cmd_output('sh run');
}

my %known_status =
    (
     'configure terminal' => [ qr/^Enter configuration commands/, ],
     );

# Check unexpected lines:
# - known status messages
# - unknown messages, handled as error messages.
sub cmd_check_error {
    my ($self, $cmd, $lines) = @_;
    my $error;
  LINE:
    for my $line (@$lines) {
	for my $regex (@{ $known_status{$cmd} }) {
	    if($line =~ $regex) {
		next LINE;
	    }
	}
	$error = 1;
    }
    return $error;
}

sub parse_version {
    my ($self) = @_;
    my $output = $self->shcmd('sh ver');
    if($output =~ /Software .* Version +(\d+\.\d+[\w\d\(\)]+)/) {
	$self->{VERSION} = $1;
    }
    if($output =~ /(cisco\s+\S+) .*memory/i) {
	$self->{HARDWARE} = $1;
    }
}

# Set terminal length and width
sub set_terminal {
    my ($self) = @_;
    $self->device_cmd('term len 0');

    # Max. term width is 512 for IOS.
    $self->device_cmd('term width 512');
}


sub prepare_device {
    my ($self) = @_;
    $self->SUPER::prepare_device();

    unless ($self->{COMPARE}) {
        $self->enter_conf_mode();

	# Don't slow down the system by looging to console.
        $self->cmd('no logging console');
        info("Disabled 'logging console'");

        # Enable logging synchronous to get a fresh prompt after
        # a reload banner is shown.
	# Older IOS has only vty 0 4.
	my $lines = $self->get_cmd_output('line vty 0 15');
	@$lines && $self->cmd('line vty 0 4');
	$self->cmd('logging synchronous level all');
        info("Enabled 'logging synchronous'");

	# Needed for default route to work as expected.
        $self->cmd('ip subnet-zero');
        info("Enabled 'ip subnet-zero'");

	# Needed for default route to work as expected.
        $self->cmd('ip classless');
        info("Enabled 'ip classless'");
        $self->leave_conf_mode();
    }
}

# Output of "write mem":
# 1.
# Building configuration...
# Compressed configuration from 22772 bytes to 7054 bytes[OK]
# 2.
# Building configuration...
# [OK]
# 3.
# Warning: Attempting to overwrite an NVRAM configuration previously written
# by a different version of the system image.
# Overwrite the previous NVRAM configuration?[confirm]
# Building configuration...
# Compressed configuration from 10194 bytes to 5372 bytes[OK]
sub write_mem {
    my ($self) = @_;
    my $cmd = 'write memory';

    # 2 retries, 3 seconds interval
    my ($retries, $seconds) = (2, 3);
    info("Writing config to nvram");
    $retries++;
    local $self->{ENAPROMPT} = qr/$self->{ENAPROMPT}|\[confirm\]/;
    while ($retries--) {
        my $lines = $self->get_cmd_output($cmd);

        # Handle case 3.
        if ($lines->[-1] =~ /Overwrite the previous NVRAM configuration/) {

            # Confirm with empty command.
            $lines = $self->get_cmd_output('');
            info('write mem: confirmed overwrite');

            # Ignore leading empty line.
            shift @$lines if not $lines->[0];
        }
	if ($lines->[0] =~ /^Building configuration/) {
	    if ($lines->[-1] =~ /\[OK\]/) {
		info("write mem: found [OK]");
		last;
	    }
	    else {
		abort("write mem: failed, config may be truncated");
	    }
        }
        elsif (grep { $_ =~ /startup-config file open failed/i } @$lines) {
            if (not $retries) {
                abort("write mem: startup-config open failed - giving up");
            }
            else {
                warn_info(
                    "write mem: startup-config open failed - trying again");
                sleep $seconds;
            }
        }
        else {
            abort("write mem: unexpected result:", @$lines);
        }
    }
}

sub schedule_reload {
    my ($self, $minutes) = @_;
    return if $self->{COMPARE};

    my $psave = $self->{ENAPROMPT};
    $self->{ENAPROMPT} = qr/\[yes\/no\]:\ |\[confirm\]/;
    my $cmd = "reload in $minutes";
    $cmd = "do $cmd" if $self->check_conf_mode();
    my $out = $self->shcmd($cmd);

    # System configuration has been modified. Save? [yes/no]:
    if ($out =~ /save/i) {
	$self->{ENAPROMPT} = qr/\[confirm\]/;

        # Leave our changes unsaved, to be sure that a reload
	# gets last good configuration.
        $self->shcmd('n');
    }

    # Confirm the reload with empty command, wait for the standard prompt.
    $self->{RELOAD_SCHEDULED} = 1;
    $self->{ENAPROMPT} = $psave;
    $self->shcmd('');

    # Banner message is handled by method "cmd" when issuing next command.

    info("Reload scheduled in $minutes minutes");
}

sub cancel_reload {
    my ($self, $force) = @_;
    return if not $self->{RELOAD_SCHEDULED};

    # If $force is set, don't trust result of $self->check_conf_mode(),
    # but use command 'end' to reliably go out of conf mode.
    # Once there was an issue, where a reload banner garbled the output
    # of "conf t" and this script didn't know any longer which mode was active.
    if ($force) {
	$self->issue_cmd('end');	# Don't check command output.
	$self->{CONF_MODE} = 0;
    }

    info("Try to cancel reload");

    # Wait for the
    # ***
    # *** --- SHUTDOWN ABORTED ---
    # ***
    my $psave = $self->{ENAPROMPT};
    $self->{ENAPROMPT} = qr/--- SHUTDOWN ABORTED ---/;
    my $cmd = 'reload cancel';
    $cmd = "do $cmd" if $self->check_conf_mode();
    $self->shcmd($cmd);
    $self->{ENAPROMPT} = $psave;

    # Because of 'logging synchronous' we are sure to get another prompt.
    my $con = $self->{CONSOLE};
    $con->con_wait($self->{ENAPROMPT});
    $self->{RELOAD_SCHEDULED} = 0;

    # synchronize expect buffers with empty command.
    $self->shcmd('');
}

# If a reload is scheduled or aborted, a banner message will be inserted into
# the expected command output:
# <three empty lines>
# ***
# *** --- <message> ---
# ***
# Known messages are:
# Some time before the actual reload takes place:
# - SHUTDOWN in 00:05:00
# - SHUTDOWN in 00:01:00
sub handle_reload_banner {
    my ($self, $output_ref) = @_;


    # Substitute banner with empty string.
    # Find message inside banner.
    # We expect end of line as \r\n.
    # But for IOS 12.2(18)SXF6 and 12.2(52)SE we saw: \r\n\n\r\n\r\n
    if ($$output_ref =~
	m/
	^ (.*?)		       # Prefix from original command
  	(?:\r\n{1,2}){3}       # 3 empty lines
  	\x07 [*]{3}\r\n        # BELL + ***
  	[*]{3} ([^\r\n]+) \r\n # *** Message
  	[*]{3}\r\n             # ***
	(.*) $                 # Postfix from original command
 	/xs)
    {
	my $prefix = $1;
	my $msg = $2;
	my $postfix = $3;
	info("Found reload banner: $msg");
#	info("Prefix: $prefix");
#	info("Postfix: $postfix");

	# Ignore $postfix if it's only a newline added by 'logging synchronous'
	if ($prefix =~ / \n $/msx and $postfix eq '\r\n') {
	    $$output_ref = $prefix;
	}

	# Because of 'logging synchronous' we are sure to get another prompt
	# if the banner is the only output before current prompt.
	# Read next prompt and set $$output_ref to next output.
	elsif(not $prefix and $postfix =~ /^ [\r\n]* $/sx) {
	    info("Expecting prompt after banner");
	    my $con = $self->{CONSOLE};
	    $con->con_wait($self->{ENAPROMPT});
	    info("- Found prompt");
	    $$output_ref = $con->{RESULT}->{BEFORE};
	}

	# Remove banner from output.
	else {
	    $$output_ref = $prefix.$postfix;
	}

	# Check, if renew of running reload process is needed.
	return ($msg =~ /SHUTDOWN in 00:01:00/);
    }
}

# Read my vty and my IP by command "sh users"
# Output of command:
# *  7 vty 1     netspoc   idle                 00:00:00 10.11.12.13
# Output seen from IOS 12.4(3f):
# * vty 322      netspoc   idle                 00:00:00 10.11.12.13
# ==> take first number as vty and IP at end of line
# and return found vty number and ip address.
sub read_vty_and_remote_ip {
    my ($self) = @_;
    my $cmd = 'sh users | incl ^\*';
    $cmd = "do $cmd" if $self->check_conf_mode() && !$self->{COMPARE};
    my $lines = $self->get_cmd_output($cmd);
    my $line = $lines->[0] or return;
    chomp $line;
    my ($vty, $s_ip);
    $line =~ /^\*\D*(\d+).*?([\d.]+)$/ or return;
    return ($1, $2);
}

# Read tcp details of current vty.
# Return local IP and local port.
sub read_vty_details {
    my ($self, $vty) = @_;
    my $cmd = "sh tcp $vty | incl Local host:";
    $cmd = "do $cmd" if $self->check_conf_mode() && !$self->{COMPARE};
    my $lines = $self->get_cmd_output($cmd);
    my $line = $lines->[0] or return;
    my ($port, $d_ip);
    $line =~ /Local host:\s([\d.]+),\sLocal port:\s(\d+)/i or return;
    return ($1, $2);
}

sub get_my_connection {
    my ($self) = @_;
    if (my $cached = $self->{CONNECTION}) {
	return @$cached;
    }

    # In file compare mode use IP from netspoc file or 1.2.3.4 if not available.
    if (not $self->{CONSOLE}) {
	my $any = { BASE => 0, MASK => 0 };
	my $ip = quad2int($self->{IP} || '1.2.3.4');
	my $dst = $ip ? { BASE => $ip, MASK => 0xffffffff } : $any;
	my $range = { TYPE => 'tcp',
		      SRC_PORT => { LOW => 0, HIGH => 0xffff },
		      DST_PORT => { LOW => 22, HIGH => 23 } };
	my $cached = $self->{CONNECTION} = [ $any, $dst, $range ];
	return @$cached;
    }

    # With real device, read IP from device, because IP from netspoc may have
    # been changed by NAT.
    my ($vty, $s_ip) = $self->read_vty_and_remote_ip() or
	abort("Can't determine my vty");
    my $src_ip = quad2int($s_ip) or abort("Can't parse src ip: $s_ip");

    my ($d_ip, $port) = $self->read_vty_details($vty) or
	abort("Can't determine remote ip and port of my TCP session");
    my $dst_ip = quad2int($d_ip) or abort("Can't parse remote ip: $d_ip");
    info("My connection: $s_ip -> $d_ip:$port");
    my $src = { BASE => $src_ip, MASK => 0xffffffff };
    my $dst = { BASE => $dst_ip, MASK => 0xffffffff };
    my $range = { TYPE => 'tcp',
		  SRC_PORT => { LOW => 0, HIGH => 0xffff },
		  DST_PORT => { LOW => $port, HIGH => $port } };
    my $cached = $self->{CONNECTION} = [ $src, $dst, $range ];
    return @$cached;
}

sub is_device_access {
    my ($self, $conf_entry) = @_;
    return 0 if $conf_entry->{MODE} eq 'deny';

    # Encrypted traffic may be used to access this device.
    my $proto = $conf_entry->{TYPE};
    return 1 if $proto eq "50" || $proto eq "51";

    my ($device_src, $device_dst, $device_proto) = $self->get_my_connection();
    return
	$self->ip_netz_a_in_b($device_src, $conf_entry->{SRC}) &&
	$self->ip_netz_a_in_b($device_dst, $conf_entry->{DST}) &&
	$self->services_a_in_b($device_proto, $conf_entry);
}

sub resequence_cmd {
    my ($self, $acl_name, $start, $incr) = @_;
    $self->cmd("ip access-list resequence $acl_name $start $incr");
}

###############################
# Crypto processing
###############################

# Compare and equalize ACLs of crypto map entries.
sub compare_crypto_maps {
    my ($self, $conf, $spoc, $conf_map, $spoc_map) = @_;
    if (@$conf_map != @$spoc_map) {
        warn_info("Crypto maps $conf_map->{name} and $spoc_map->{name} differ");
        return;
    }

    # Find pairs of corresponding crypto map entries.
    my @crypto_entry_pairs;
    for (my $i = 0 ; $i < @$conf_map ; $i++) {
        my $conf_entry = $conf_map->[$i];
        my $spoc_entry = $spoc_map->[$i];
        push @crypto_entry_pairs, [ $conf_entry, $spoc_entry ];
    }

    $self->enter_conf_mode();

    # Analyze changes in all ACLs bound to crypto map entries.
    # Try to change ACLs incrementally.
    # Get list of ACL pairs, that need to be redefined, added or removed.
    my @acl_update_info =
        $self->equalize_acls_of_objects($conf, $spoc, \@crypto_entry_pairs);

    for my $info (@acl_update_info) {
        my ($entry, $in_out, $conf_acl, $spoc_acl) = @$info;
        my $name = $entry->{name};
        my $sequ = $entry->{SEQU} or internal_err "Missing SEQU";
        $self->{CHANGE}->{ACCESS_LIST} = 1;

        # Add ACL to device.
        if ($spoc_acl) {

            # Add new ACL
            $self->schedule_reload(5);
            my $aclname = $self->define_acl($conf, $spoc, $spoc_acl->{name});

            # Assign new acl to crypto map
            $self->cmd("crypto map $name $sequ");
            $self->cmd("set ip access-group $aclname $in_out");
            $self->cancel_reload();
        }

        # Remove ACL from device.
        if ($conf_acl) {
            if (not $spoc_acl) {
                $self->cmd("crypto map $name $sequ");
                $self->cmd("no set ip access-group $conf_acl->{name} $in_out");
            }
            $self->remove_acl($conf_acl);
        }
    }
    $self->leave_conf_mode();
}

sub crypto_processing {
    my ($self, $conf, $spoc) = @_;
    $spoc->{CRYPTO_MAP} or return;

    my $spoc_interfaces = $spoc->{IF};
    my $conf_interfaces = $conf->{IF};

    # Compare crypto config which is bound to interfaces.
    for my $name (keys %$spoc_interfaces) {
        my $spoc_intf = $spoc_interfaces->{$name};
        my $conf_intf = $conf_interfaces->{$name};
        my $spoc_map_name = $spoc_intf->{CRYPTO_MAP};
        my $conf_map_name = $conf_intf->{CRYPTO_MAP};
        if (not $spoc_map_name) {
            if ($conf_map_name) {
                warn_info("Missing crypto map at $name from Netspoc");
            }
            next;
        }
        if (not $conf_map_name) {
            warn_info("Missing crypto map at $name from device");
            next;
        }
        my $conf_map = $conf->{CRYPTO_MAP}->{$conf_map_name};
        my $spoc_map = $spoc->{CRYPTO_MAP}->{$spoc_map_name};
        $self->compare_crypto_maps($conf, $spoc, $conf_map, $spoc_map);
    }
}

###############################
# END crypto processing
###############################

sub transfer {
    my ($self, $conf, $spoc) = @_;
    $self->SUPER::transfer($conf, $spoc);
    $self->crypto_processing($conf, $spoc);
}

# Packages must return a true value;
1;
