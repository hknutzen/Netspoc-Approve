
package Netspoc::Approve::IOS;

# Authors: Arne Spetzler, Heinz Knutzen, Daniel Brunkhorst
#
# Description:
# Remote configure cisco ios router
#

use base "Netspoc::Approve::Cisco";
use strict;
use warnings;
use Algorithm::Diff;
use Netspoc::Approve::Helper;
use Netspoc::Approve::Parse_Cisco;

our $VERSION = '1.063'; # VERSION: inserted by DZP::OurPkgVersion

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
	  parse => ['cond1',
		    { parse => qr/type/ },
		    { parse => qr/tunnel/ } ],
	  subcmd =>
	  { 'ip address' => { 
	      store => 'ADDRESS',
	      parse => ['or', 
			{ store => 'DYNAMIC', parse => qr/negotiated/, },
			['seq',
			 { store => 'BASE', parse => \&check_ip, },
			 { store => 'MASK', parse => \&check_ip, } ]] },
	    'ip address _skip _skip secondary' =>  { 
		parse => \&skip }, # ignore
	    'ip unnumbered' => {
		store => ['ADDRESS', 'UNNUMBERED'], parse => \&get_token, },
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
	    'switchport mode' => { 
		store => ['SWITCHPORT', 'MODE'], parse => \&get_token, },
	    'switchport access vlan' => {
		store => ['SWITCHPORT', 'ACCESS_VLAN'], multi => 1, 
		parse => \&get_token, },
	    'switchport nonegotiate' => {
		store => ['SWITCHPORT', 'NONEGOTIATE'], default => 1, },
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
			{ parse => qr/track/, },
			{ store => 'TRACK', parse => \&get_token, },],
		       ['cond1',
			{ parse => qr/tag/, },
			{ store => 'TAG', parse => \&get_token, },],
		       { store => 'PERMANENT', parse => qr/permanent/, },],],
	},
	'ip access-list extended' => {
	    store =>  'ACCESS_LIST',
	    named => 1,
	    subcmd => {

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
			      { store => 'LOG', parse => qr/log-input|log/ } ]
		},

	    },
	},

# Currently ignored
#	'crypto isakmp identity' => {
#	    store => [ 'CRYPTO', 'ISAKMP', 'IDENTITY' ],
#	    parse => \&get_token,
#	},

# crypto isakmp policy <priority>
#  <subcommands> 
#  ..
# return one hash for each priority
	'crypto isakmp policy' => {
	    named => 1,
	    store => [ 'CRYPTO', 'ISAKMP', 'POLICY' ],
	    subcmd => {
		'authentication' => {
		    parse => \&get_token, store => 'AUTHENTICATION', },
		'encryption' => {
		    parse => \&parse_encryption, store => 'ENCRYPTION', },
		'encr' => {
		    parse => \&parse_encryption, store => 'ENCRYPTION', },
		'hash' => {
		    parse => \&get_token, store => 'HASH', },
		'group' => {
		    parse => \&get_token, store => 'GROUP', },
		'lifetime' => {
		    parse => \&get_token, store => 'LIFETIME', },
	    },
	},
	'crypto ipsec transform-set' => {
	    store => [ 'CRYPTO', 'IPSEC', 'TRANSFORM' ],
	    named => 1,
	    parse => ['seq',
		      { store => 't1', parse => \&get_token, },
		      { store => 't2', parse => \&get_token, },
		      { store => 't3', parse => \&check_token, }, ],
	},
	'crypto ipsec client ezvpn' => {
	    store => [ 'CRYPTO', 'IPSEC', 'CLIENT_EZVPN' ],
	    named => 1,
	    subcmd => {
		'acl' => { 
		    store => 'ACL', parse => \&get_token, },
		'peer' => {
		    multi => 1, store => 'PEER', parse => \&get_ip, },
		'connect' => {
		    store => 'CONNECT', parse => \&get_token, },
		'mode' => {
		    store => 'MODE', parse => \&get_token, },
		'virtual-interface' => {
		    store => 'V_INTERFACE', parse => \&get_int, },
	    },
	},	      

# Ignore, don't try to parse as crypto map with sequence number.
	'crypto map _skip client'         => { parse => \&skip, },
	'crypto map _skip gdoi'           => { parse => \&skip, subcmd => {} },
	'crypto map _skip isakmp'         => { parse => \&skip, },
	'crypto map _skip isakmp-profile' => { parse => \&skip, },
	'crypto map _skip local-address'  => { parse => \&skip, },
	'crypto map _skip redundancy'     => { parse => \&skip, },

# crypto map <name> <seq> ipsec-isakmp
#  <sub commands>
#
# Result: Add multiple values to named crypto map.
	'crypto map' => {
	    store => [ 'CRYPTO', 'MAP' ],
	    named => 1,
	    multi => 1,
	    parse => ['seq',
		      { store => 'SEQU', parse => \&get_int, },
		      ['or',
		       { parse => qr/ipsec-isakmp/, }, 
		       { parse => qr/gdoi/, store => 'GDOI', } ]],
	    subcmd => {
		'match address' => {
		    store => 'MATCH_ADDRESS', parse => \&get_token, },
		'set ip access-group _skip in' => {
		    store => 'ACCESS_GROUP_IN', parse => \&get_token, },
		'set ip access-group _skip out' => {
		    store => 'ACCESS_GROUP_OUT', parse => \&get_token, },
		'set peer' => {
		    multi => 1, store => 'PEER', parse => \&get_ip, },
		'set security-association lifetime' => {
		    store => 'SA_LIFETIME',
		    named => 1,
		    parse => \&get_int,
		},
		'set transform-set' => {
		    store => 'TRANSFORM', parse => \&get_token, },
		'set pfs' => {
		    store => 'PFS', parse => \&get_token, },
	    },
	},

	# We don't use these commands, but lexical analyser needs to know
	# that these are multi line commands.
	banner => { banner => qr/^\^/, parse => \&skip },

	'crypto pki certificate chain' => {
	    named => 1,
	    subcmd => {
		'certificate' => { banner => qr/^\s*quit$/, parse => \&skip },
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

sub parse_encryption { 
    my ($arg) = @_;
    my $name = get_token($arg);
    if(defined(my $bits = check_int($arg))) {
	$name = "$name $bits";
    }
    $name;
}

sub dev_cor {
    my ($self, $addr) = @_;
    return ~$addr & 0xffffffff;
}

sub postprocess_config {
    my ($self, $p) = @_;

    my $crypto_map_found   = 0;
    my $ezvpn_client_found = 0;
    my %map_used;
    my %ezvpn_used;

    # Set default value for subcommand 'hash' of 'crypto isakmp policy'
    # because it isn't shown in some (all ?) IOS versions.
    if ($p->{CRYPTO}->{ISAKMP} && 
	(my $policies = $p->{CRYPTO}->{ISAKMP}->{POLICY})) 
    {
	for my $policy (values %$policies) {
	    $policy->{HASH} ||= 'sha';
	}
    }

    for my $intf (values %{ $p->{IF} }) {
        if (my $imap = $intf->{CRYPTO_MAP}) {
            $crypto_map_found = 1;
            if (my $map = $p->{CRYPTO}->{MAP}->{$imap}) {
		$map_used{$imap} = 1;
            }
            else {
                abort("No definition found for crypto map '$imap' at"
                      . " interface '$intf->{name}'");
            }
        }
        elsif ($intf->{EZVPN}) {
            $ezvpn_client_found = 1;
            my $ezvpn = $intf->{EZVPN}->{NAME};
            if (my $def = $p->{CRYPTO}->{IPSEC}->{CLIENT_EZVPN}->{$ezvpn}) {
                $ezvpn_used{$ezvpn} = 1;
            }
            else {
                abort("No definition for ezvpn client '$ezvpn' at"
                      . " interface '$intf->{name}' found");
            }
        }
    }
    if ($crypto_map_found and $ezvpn_client_found) {
        abort("ezvpn and crypto map at interfaces found -" 
              . " only one of them allowed");
    }
    if ($crypto_map_found) {
        for my $cm_name (keys %{ $p->{CRYPTO}->{MAP} }) {
            unless ($map_used{$cm_name}) {
                warn_info("Spare crypto map '$cm_name' found");
                next;
            }
            my $cm = $p->{CRYPTO}->{MAP}->{$cm_name};
	    $cm = [ sort { $a->{SEQU} <=> $b->{SEQU} } @$cm ];
	    $p->{CRYPTO}->{MAP}->{$cm_name} = $cm;
            for my $entry (@$cm) {
                my $sequ = $entry->{SEQU};
		next if $entry->{GDOI};
                if (my $acl_name = $entry->{MATCH_ADDRESS}) {
                    if (my $acl = $p->{ACCESS_LIST}->{$acl_name}) {

                        # bind match address to crypto map
                        $entry->{MATCH_ACL} = $acl;
                    }
                    else {
                        abort("Crypto: ACL $acl_name does not exist");
                    }
                }
                else {
                    abort("Crypto: no match-address entry found");
                }

                # Bind access group to crypto map
                for my $what (qw(IN OUT)) {
                    if (my $acl_name = $entry->{"ACCESS_GROUP_$what"}) {
                        if ( my $acl = $p->{ACCESS_LIST}->{$acl_name}) {
                            $entry->{FILTER_ACL} = $acl;
                        }
                        else {
                            abort("Crypto: ACL $acl_name does not exist");
                        }
                    }
                }
		if (my $peers = $entry->{PEER}) {
		    $entry->{PEER} = [ sort { $a <=> $b } @$peers ];
		}
		else {
		    abort("Crypto: no peer found");
		}
                if (my $trans_name = $entry->{TRANSFORM}) {
                    if (my $trans = 
			$p->{CRYPTO}->{IPSEC}->{TRANSFORM}->{$trans_name})
                    {

                        # bind transform set to crypto map
                        $entry->{TRANSFORM_BIND} = $trans;
                    }
                    else {
                        abort(
                            "Crypto: transform set $trans_name does not exist");
                    }
                }
            }
        }
    }
    elsif ($ezvpn_client_found) {
        my $ezvpn = $p->{CRYPTO}->{IPSEC}->{CLIENT_EZVPN};
        for my $ez_name (keys %{$ezvpn}) {
            unless ($ezvpn_used{$ez_name}) {
                warn_info("Spare crypto ipsec ezvpn client '$ez_name' found");
                next;
            }
            my $entry = $ezvpn->{$ez_name};

            # checking for traffic match acl
            if (my $acl_name = $entry->{ACL}) {
                if (my $acl = $p->{ACCESS_LIST}->{$acl_name}) {

                    # bind match address to crypto map
                    $entry->{MATCH_ACL} = $acl
                }
                else {
                    abort("Crypto: ACL $acl_name does not exist");
                }
            }
            else {
                abort("Crypto: no match-acl entry found");
            }

            # checking for virtual interface
            if (my $num = $entry->{V_INTERFACE}) {
		my $intf = "Virtual-Template$num";
                if ($p->{IF}->{$intf}) {
                }
                else {
                    abort("Crypto: virtual-interface $intf not found");
                }
            }
            else {
                abort("Crypto: virtual-interface missing for $ez_name");
            }
	    if (my $peers = $entry->{PEER}) {
		$entry->{PEER} = [ sort { $a <=> $b } @$peers ];
	    }
	    else {
		abort("Crypto: no peer found");
	    }
        }
    }
}

sub get_config_from_device {
    my ($self) = @_;
    $self->get_cmd_output('sh run');
}

my %known_status = 
    (
     'configure terminal' => [ qr/^Enter configuration commands/, ],
     );

my %known_warning = 
(
 );

sub cmd_check_error($$) {
    my ($self, $cmd, $lines) = @_;

    # Check unexpected lines:
    # - known status messages
    # - known warning messages
    # - unknown messages, handled as error messages.
    my $error;
  LINE:
    for my $line (@$lines) {
	for my $regex (@{ $known_status{$cmd} }) {
	    if($line =~ $regex) {
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
	err_info($cmd);
	for my $line (@$lines) {
	    err_info($line);
	}
	$self->abort_cmd("Unexpected output for '$cmd'");
    }
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
# Building configuration...
# Compressed configuration from 22772 bytes to 7054 bytes[OK]
#
# Building configuration...
# [OK]

sub write_mem {
    my ($self, $retries, $seconds) = @_;
    info("Writing config to nvram");
    $retries++;
    while ($retries--) {
        my $lines = $self->get_cmd_output('write memory');
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
            abort("write mem: unexpected result");
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
	# if the banner is the only output befor current prompt.
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

    # Read my vty and my IP by command "sh users"
    # Output:
    # *  7 vty 1     netspoc   idle                 00:00:00 10.11.12.13
    # Output seen from IOS 12.4(3f):
    # * vty 322      netspoc   idle                 00:00:00 10.11.12.13
    # ==> take first number as vty and IP at end of line.
    my $lines = $self->get_cmd_output('sh users | incl ^\*');
    my $line = $lines->[0];
    chomp $line;
    my ($vty, $s_ip);
    if ($line =~ /^\*\D*(\d+).*?([\d.]+)$/) {
	($vty, $s_ip) = ($1, $2);
    }
    else {
	abort("Can't determine my vty");
    }
    my $src_ip = quad2int($s_ip) or abort("Can't parse src ip: $s_ip");

    # Read tcp details for my connection.
    $lines = $self->get_cmd_output("sh tcp $vty | incl Local host:");
    $line = $lines->[0];
    my ($port, $d_ip);
    if ($line =~ /Local host:\s([\d.]+),\sLocal port:\s(\d+)/i) {
	($d_ip, $port) = ($1, $2);
    }
    else {
	abort("Can't determine remote ip and port of my TCP session");
    }
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
    my ($device_src, $device_dst, $device_proto) = $self->get_my_connection();
    return
	$self->ip_netz_a_in_b($device_src, $conf_entry->{SRC}) &&
	$self->ip_netz_a_in_b($device_dst, $conf_entry->{DST}) &&
	$self->services_a_in_b($device_proto, $conf_entry);
}

# Build textual representation from ACL entry for use with Algorithm::Diff.
sub acl_entry2key {
    my ($e) = @_;
    my @r;
    push(@r, $e->{MODE});
    for my $where (qw(SRC DST)) {
	my $what = $e->{$where};
	push(@r, "$what->{BASE}/$what->{MASK}");
    }
    push @r, $e->{TYPE};
    if ($e->{TYPE} eq 'icmp') {
        my $s = $e->{SPEC};
	for my $where (qw(TYPE CODE)) {
	    my $v = $s->{TYPE};
	    push(@r, defined $v ? $v : '-');
	}
    }
    elsif ($e->{TYPE} eq 'tcp' or $e->{TYPE} eq 'udp') {
	for my $where (qw(SRC_PORT DST_PORT)) {
	    my $port = $e->{$where};
	    push(@r, "$port->{LOW}:$port->{HIGH}");
	}
	push(@r, 'established') if $e->{ESTA};
    }
    if(my $log = $e->{LOG}) {
	push(@r, $log);
    }
    return join(' ', @r);
}

# Incrementally convert an ACL on device to the new ACL from netspoc.
# Algorithm::Diff finds ACL lines which need to be added or to be deleted.
# But an ACL line, which is already present on device can't be added again. 
# Therefore we have add, delete and move operations.
# We distinguish between move_up (from bottom to top) and
# move_down (from top to bottom).
#
# The move operation is implemented specially:
# The delete and add command are transferred together in one packet 
# to prevent accidental lock out from device.
# But this doesn't work reliably. Hence we abort the operation,
# if that ACL line is moved, which allows netspoc to access the device.
#
# ACL is changed on device in 2 passes:
# 1. Add new ACL entries and move entries upwards, top entries first.
#  a) add new entries which are not already present on device.
#  b) move entries upwards
# 2. Delete old ACL entries and move entries downward, bottom entries first.
#  a) delete entry which isn't used any longer.
#  b) move entry downwards
#
# Return value:
# 1: ACL has been updated successfully
# 0: ACL can't be updated; a new ACL needs to be defined and assigned.
sub equalize_acl {
    my($self, $conf_acl, $spoc_acl) = @_;
    my $conf_entries = $conf_acl->{LIST};
    my $spoc_entries = $spoc_acl->{LIST};
    my $acl_name = $conf_acl->{name};

    my $diff = Algorithm::Diff->new( $conf_entries, $spoc_entries, 
				     { keyGen => \&acl_entry2key } );

    # Hash for finding duplicates when comparing old and new entries.
    my %dupl;

    # ACL lines which are moved upwards. 
    # Mapping from spoc entry to conf entry.
    my %move_up;

    # ACL lines which are moved downwards. 
    # Mapping from conf entry to spoc entry.
    my %move_down;

    # Entry needs not to be deleted because it was moved early.
    my %moved;

    # Collect entries 
    # - do be added on device (includes move_up)
    # - to be deleted on device (includes move_down).
    my (@add, @delete);

    # Cisco lines of ACL entries.
    my %cisco_line;

    # Add new line numbers to ACL entries read from device.
    for (my $i = 0; $i < @$conf_entries; $i++) {
	$cisco_line{$conf_entries->[$i]} = 10000 + $i * 10000;
    }
    $cisco_line{LAST} = 10000 + @$conf_entries * 10000;

    # 1. Process to be deleted entries.
    while($diff->Next()) {
	if ($diff->Diff() & 1) {
	    for my $conf_entry ($diff->Items(1)) {
		my $key = acl_entry2key($conf_entry);
		$dupl{$key} and internal_err "Duplicate ACL entry on device";
		$dupl{$key} = $conf_entry;
		push @delete, $conf_entry;
	    }
	}
    }

    # 2. Process to be added entries.
    $diff->Reset();
    while($diff->Next()) {
	if ($diff->Diff() & 2) {
	    my $conf_next = $diff->Min(1);
	    my $next_conf_entry = $conf_entries->[$conf_next] || 'LAST';
	    my $line = $cisco_line{$next_conf_entry} - 9999;
	    for my $spoc_entry ($diff->Items(2)) {
		$cisco_line{$spoc_entry} = $line++;

		# Find lines already present on device
		my $key = acl_entry2key($spoc_entry);
		if (my $conf_entry = $dupl{$key}) {
		    
		    # Abort move operation, if this ACL line permits
		    # our access to this device
		    if ($self->is_device_access($conf_entry)) {
			info("Can't modify $acl_name.");
			info("Some entry must be moved and is assumed",
                             " to allow device access:");
			info(" $conf_entry->{orig}");
			return 0;
		    }

		    # Move upwards.
		    if ($cisco_line{$spoc_entry} < $cisco_line{$conf_entry}) {
			$move_up{$spoc_entry} = $conf_entry;
			$moved{$conf_entry} = 1;
			push @add, $spoc_entry;
		    }

		    # Move downwards.
		    else {
			$move_down{$conf_entry} = $spoc_entry;
		    }
		}

		# Add.
		else {
		    push @add, $spoc_entry;
		}
	    }
	}
    }
    
    return 1 if not (@add || @delete);

    if (@$conf_entries >= 10000) {
	abort("Can't handle device ACL $acl_name with 10000 or more entries");
    }
    if (@$spoc_entries >= 10000) {
	my $spoc_name = $spoc_acl->{name};
	abort("Can't handle netspoc ACL $spoc_name with 10000 or more entries");
    }

    $self->{CHANGE}->{ACL} = 1;

    # Change line numbers of ACL entries on device to the same values 
    # as used above.
    # Do resequence before schedule reload, because it may abort
    # if this command isn't available on old IOS version.
    $self->enter_conf_mode();
    $self->cmd("ip access-list resequence $acl_name 10000 10000");

    $self->schedule_reload(5);
    $self->cmd("ip access-list extended $acl_name");

    # 1. Add lines from netspoc and move lines upwards.
    for my $spoc_entry (@add) {
	my $line = $cisco_line{$spoc_entry};
	my $cmd  = "$line $spoc_entry->{orig}";
	if (my $conf_entry = $move_up{$spoc_entry}) {
	    my $line1 = $cisco_line{$conf_entry};
	    my $cmd1  = "no $line1";
	    $self->two_cmd($cmd1, $cmd);
	}
	else {
	    $self->cmd($cmd);
	}
    }

    # 2. Delete lines on device and move lines downwards.
    # Work from bottom to top. Otherwise 
    # - we could lock out ourselves
    # - permit too much traffic for a short time.
    for my $conf_entry (reverse @delete) {
	my $line = $cisco_line{$conf_entry};
	my $cmd1 = "no $line";
	if (my $spoc_entry = $move_down{$conf_entry}) {
	    my $line2 = $cisco_line{$spoc_entry};
	    my $cmd2  = "$line2 $spoc_entry->{orig}";
	    $self->two_cmd($cmd1, $cmd2);
	}
	elsif (not $moved{$conf_entry}) {
	    $self->cmd($cmd1);
	}
    }

    $self->cmd('exit');
    $self->cancel_reload();
    $self->cmd("ip access-list resequence $acl_name 10 10");
    $self->leave_conf_mode();
    return 1;
}

sub define_acl {
    my ($self, $name, $entries) = @_;
    $self->enter_conf_mode();

    # Possibly there is an old acl with $aclname:
    # first remove old entries because acl should be empty - 
    # otherwise new entries would be appended only.
    $self->cmd("no ip access-list extended $name");
    $self->cmd("ip access-list extended $name");
    for my $c (@$entries) {
        my $acl = $c->{orig};
        $self->cmd($acl);
    }
    $self->leave_conf_mode();
}

sub process_interface_acls( $$$ ){
    my ($self, $conf, $spoc) = @_;
    $self->{CHANGE}->{ACL} = 0;
    for my $intf (values %{$spoc->{IF}}){
	my $name = $intf->{name};
        my $conf_intf = $conf->{IF}->{$name}
	   or abort("Interface not found on device: $name");
	for my $in_out (qw(IN OUT)) {
	    my $direction = lc($in_out);
	    my $confacl_name = $conf_intf->{"ACCESS_GROUP_$in_out"} || '';
	    my $spocacl_name = $intf->{"ACCESS_GROUP_$in_out"} || '';
	    my $conf_acl = $conf->{ACCESS_LIST}->{$confacl_name};
	    my $spoc_acl = $spoc->{ACCESS_LIST}->{$spocacl_name};
	    my $ready;
	    
	    # Try to change existing ACL at device.
	    if ($conf_acl and $spoc_acl) {
		$ready = $self->equalize_acl($conf_acl, $spoc_acl);
	    }
	    next if $ready;

	    # Add ACL to device.
	    if ($spoc_acl) {
		$self->{CHANGE}->{ACL} = 1;

		# New and old ACLs must use different names.
		# We toggle between -DRC-0 and DRC-1.
		my $aclindex = 0;
		if ($conf_acl) {
		    if ($confacl_name =~ /-DRC-([01])$/) {
			$aclindex = (not $1) + 0;
		    }
		}
		my $aclname = "$spocacl_name-DRC-$aclindex";
		$self->define_acl($aclname, $spoc_acl->{LIST});

		# Assign new acl to interface.
		info("Assigning new $in_out ACL $aclname to interface $name");
		$self->schedule_reload(5);
		$self->enter_conf_mode();
		$self->cmd("interface $name");
		$self->cmd("ip access-group $aclname $direction");
		$self->leave_conf_mode();
		$self->cancel_reload();
	    }

	    # Remove ACL from device.
	    if ($conf_acl) {
		$self->{CHANGE}->{ACL} = 1;
		$self->schedule_reload(5);
		$self->enter_conf_mode();
		if (not $spoc_acl) {
		    info("Unassigning $in_out ACL from interface $name");
		    $self->cmd("interface $name");
		    $self->cmd("no ip access-group $confacl_name $direction");
		}
		$self->cancel_reload();
		$self->cmd("no ip access-list extended $confacl_name");
		$self->leave_conf_mode();
	    }		
	}
    }
}

###############################
#
# Crypto processing
#
###############################

sub crypto_struct_equal {
    my ($self, $conf, $spoc, $changes, $indent) = @_;
    $indent = " $indent";

    #print "-$conf--$spoc-\n";
    if (!ref $conf) {
        if (!ref $spoc) {
            ($conf eq $spoc) and return 1;
        }
        else {
            my $type = ref $spoc;
            internal_err "Can't compare scalar $conf with type $type\n";
        }
        info("${indent}diff $conf <=> $spoc");
        return 0;
    }
    elsif (ref $conf eq 'SCALAR') {
        if (ref $spoc eq 'SCALAR') {
            $self->crypto_struct_equal($$conf, $$spoc, $changes, $indent)
              and return 1;
        }
        else {
            my $type = ref $spoc;
            internal_err "Can't compare scalar ref $conf with type $type\n";
        }
        info("${indent}diff $conf <=> $spoc");
        return 0;
    }
    elsif (ref $conf eq 'ARRAY') {
        if (ref $spoc eq 'ARRAY') {

            # arrays are equal iff have same elements in same order
            if (@$conf == @$spoc) {
                my $equal         = 1;
                for (my $i = 0 ; $i < scalar @$conf ; $i++) {
                    unless (
                        $self->crypto_struct_equal(
                            $conf->[$i], $spoc->[$i], $changes, $indent
                        )
                      )
                    {
                        info("${indent}diff array element $i");
                        $equal = 0;
                    }
                }
                return $equal;
            }
            else {
                info("${indent}diff array lenght");
            }
        }
        else {
            my $type = ref $spoc;
            internal_err "Can't compare array with type $type\n";
        }
        return 0;
    }
    elsif (ref $conf eq 'HASH') {
        if (ref $spoc eq 'HASH') {
            my $equal = 1;
            for my $key (keys %$conf) {
                if ($key =~ /^ACCESS_GROUP_(IN|OUT)$/) {
		    my $sequ = $conf->{SEQU} or internal_err "Missing SEQU";
		    my $conf_acl = $conf->{$key};
		    my $spoc_acl = $spoc->{$key};

                    # special handling for this entry because it
                    # is subject of change by netspoc
                    if ($spoc_acl) {
                        if (not $self->acl_equal(
						 $conf->{FILTER_ACL}->{LIST},  
						 $spoc->{FILTER_ACL}->{LIST},
						 $conf_acl, $spoc_acl, $key
						 )
			    )
                        {

                            $changes->{$key}->{$sequ}->{CONF} = $conf_acl;
                            $changes->{$key}->{$sequ}->{SPOC} = $spoc_acl;

                            # differences between ACLs handled elsewhere!
                            # $equal = 0;
                        }
                    }
                    else {
                        $changes->{$key}->{$sequ}->{CONF} = $conf_acl;
                    }
                }
		elsif ($key =~ /^(?:name|orig|line|
				  FILTER_ACL|MATCH_ACL|SEQU|TRANSFORM)$/x)
		{
		    # Do not check these artificial keys.
		}
                elsif (exists $spoc->{$key}) {
                    if ($key eq "MATCH_ADDRESS") {

                        # postprocess_config checked that match ACL is present.
                        unless (
				$self->acl_equal(
						 $conf->{MATCH_ACL}->{LIST},  
						 $spoc->{MATCH_ACL}->{LIST},
						 $conf->{$key}, 
						 $spoc->{$key}, $key
						 )
				)
                        {
                            info("${indent}diff ACL of $key");
                            $equal = 0;
                        }
                    }
                    else {
                        unless (
                            $self->crypto_struct_equal(
                                $conf->{$key}, $spoc->{$key},
                                $changes,     $indent
                            )
                          )
                        {
                            info("${indent}diff hash element $key");
                            $equal = 0;
                        }
                    }
                }
                else {
                    info("${indent}missing hash-key $key in device config");
                    $equal = 0;
                }
            }
            for my $key (keys %$spoc) {
		if (exists $conf->{$key}) {

		    # OK, has been compared above.
		}
                elsif ($key =~ /^ACCESS_GROUP_(IN|OUT)$/) {
		    my $sequ = $conf->{SEQU} or internal_err "Missing SEQU";
		    my $spoc_acl = $spoc->{$key};
		    $changes->{$key}->{$sequ}->{SPOC} = $spoc_acl;
		}
		elsif ($key =~ /^(?:name|orig|line|
				  FILTER_ACL|MATCH_ACL|SEQU|TRANSFORM)$/x)
		{
		    # Do not check these artificial keys.
		}
                else {
                    info("${indent}missing hash-key $key in netspoc config");
                    $equal = 0;
                }
            }
            return $equal;
        }
        else {
            my $type = ref $spoc;
            internal_err "Can't compare hash with type $type\n";
        }
        return 0;
    }
    else {
        internal_err "unsupported type: " . ref($conf);

    }
    return 0;
}

sub crypto_processing {
    my ($self, $conf, $spoc) = @_;

    # Only proceed if netspoc crypto config present
    $spoc->{CRYPTO} or return;

    info("Spocfile contains crypto definitions");
    $self->{CHANGE}->{CRYPTO} = 0;
    if (my $spoc_isakmp = $spoc->{CRYPTO}->{ISAKMP}) {
        info(" Compare crypto isakmp");
	my $changes;
        if (my $conf_isakmp = $conf->{CRYPTO}->{ISAKMP}) {
            if (
                $self->crypto_struct_equal(
                    $conf_isakmp, $spoc_isakmp, $changes, ''
                )
              )
            {
                info("    no diffs found");
            }
            else {
                abort("Severe diffs in crypto isakmp detected");
            }
        }
        else {
            abort("Missing isakmp config at device");
        }
        info(" --- end compare crypto isakmp ---");
    }
    if ($spoc->{CRYPTO}->{MAP}) {
        my %remove_acls;

        # Compare crypto config which is bound to interfaces.
        for my $intf (keys %{ $spoc->{IF} }) {

            my $changes = {};
            info(" --- interface $intf ---");
            if ($spoc->{IF}->{$intf}->{CRYPTO_MAP}) {
                info(" crypto map in spocfile found");
            }
            else {
                info(" no crypto map in spocfile found");
                if ($conf->{IF}->{$intf}->{CRYPTO_MAP}) {
                    warn_info(" crypto map at device found");
                    $self->{CHANGE}->{CRYPTO} = 1;
                }
                next;
            }
            my $spoc_map_name = $spoc->{IF}->{$intf}->{CRYPTO_MAP};

            # ok. There should be a crypto map on this interface
            my $conf_map_name = $conf->{IF}->{$intf}->{CRYPTO_MAP};
            unless ($conf_map_name) {
                warn_info("no crypto map at device");
                $self->{CHANGE}->{CRYPTO}   = 1;
                next;
            }
            info(" --- begin compare crypto maps---");
            info(" $spoc_map_name <-> $conf_map_name");
            unless (
                $self->crypto_struct_equal(
                    $conf->{CRYPTO}->{MAP}->{$conf_map_name},
                    $spoc->{CRYPTO}->{MAP}->{$spoc_map_name}, 
		    $changes, ''
                )
              )
            {
                abort("Severe diffs in crypto map detected");
		$self->{CHANGE}->{CRYPTO} = 1;
                next;
            }
            info(" --- end compare crypto maps---");

	    # process crypto filter ACLs.
	    for my $access_group (keys %$changes) {
		$self->{CHANGE}->{CRYPTO} = 1;
		my $inout = $access_group =~ /_IN$/ ? 'in' : 'out';
		for my $sequ (keys %{ $changes->{$access_group} }) {
		    info("Processing crypto filter changes at crypto map",
                         " $conf_map_name $sequ");
		    my $change = $changes->{$access_group}->{$sequ};
		    my $conf_acl = $change->{CONF};
		    my $spoc_acl = $change->{SPOC};
		    my $aclindex;
		    if ($conf_acl) {
			$remove_acls{$conf_acl} = 1;
			
			if ($conf_acl =~ /-DRC-([01])$/) {

			    # Active ACL matches name convention
			    $aclindex = (not $1) + 0;
			}
		    }
		    if ($spoc_acl) {
			$aclindex ||= 0;
			my $new_acl = "$spoc_acl-DRC-$aclindex";

			$self->schedule_reload(5);

			# begin transfer
			info("Creating new ACL");
			$self->define_acl($new_acl,
					  $spoc->{ACCESS_LIST}
					  ->{$spoc_acl}->{LIST});

			# assign new acl to interfaces
			info("Assigning new acl");
			$self->enter_conf_mode();
			$self->cmd("crypto map $conf_map_name $sequ");
			$self->cmd("set ip access-group $new_acl $inout");
			$self->leave_conf_mode();
			$self->cancel_reload();
		    }
		    else {
			$self->cmd("no set ip access-group $conf_acl $inout");
		    }
		}
	    }
        }

	if (keys %remove_acls) {
	    info("Removing old ACLs");
	
	    $self->schedule_reload(3);
	    $self->enter_conf_mode();
	    for my $name (keys %remove_acls) {
		$self->cmd("no ip access-list extended $name");
	    }
	    $self->leave_conf_mode();
	    $self->cancel_reload();
	}
    }

    if (exists $spoc->{CRYPTO}->{IPSEC}) {

        # In ezvpn mode we grant that the tunnel is terminated at some
        # virtual interface. This interface holds an ACL.
        # The ACL is checked by standard ACL code
        info(" --- begin compare crypto ezvpn ---");
        if (exists $conf->{CRYPTO}->{IPSEC}) {
	    my $changes;
            if (
                $self->crypto_struct_equal(
                    $conf->{CRYPTO}->{IPSEC},
                    $spoc->{CRYPTO}->{IPSEC},
                    $changes, ''
                )
              )
            {
                info("    no diffs found");
            }
            else {
                abort("Severe diffs in crypto ipsec detected");
		$self->{CHANGE}->{CRYPTO} = 1;
            }
        }
        else {
            abort("Missing ezvpn config at device");
        }
        info(" --- end compare crypto ezvpn ---");
    }
}

###############################
#
# END crypto processing
#
###############################

sub transfer {
    my ($self, $conf, $spoc) = @_;

    # Check for matching interfaces.
    $self->checkinterfaces($conf, $spoc);

    # *** BEGIN TRANSFER ***
    $self->process_interface_acls($conf, $spoc);
    $self->crypto_processing($conf, $spoc);
    $self->process_routing($conf, $spoc);

    #
    # *** CLEANUP
    #
    if (!$self->{COMPARE}) {
        if (grep { $_ } values %{ $self->{CHANGE} }) {

            # Save config.
            info("Configuration changed");
            $self->write_mem(5, 3);    # 5 retries, 3 seconds intervall
        }
        else {
            info("No changes to save");
        }
    }
    return 1;
}

# Packages must return a true value;
1;

