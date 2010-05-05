
package Netspoc::Approve::IOS;

# Authors: Arne Spetzler, Heinz Knutzen, Daniel Brunkhorst
#
# Description:
# Remote configure cisco ios router
#

'$Id$' =~ / (.+),v (.+?) /;

my $id = "$1 $2";

sub version_drc2_ios() {
    return $id;
}

use base "Netspoc::Approve::Cisco";
use strict;
use warnings;
use Netspoc::Approve::Helper;
use Netspoc::Approve::Parse_Cisco;

# Parse info.
# Key is a single or multi word command.
# If the last word of a multi word command has a leading '+' 
# it is a suffix of the command line.
# Value is a has with attributes:
# - store: name of attribute where result is stored or
#   array of names which are used to access sub-hash: {name1}->{name2}->..
# - named: first argument is name which is used as key when storing result
# - multi: multiple occurences of this command may occur 
#          and are stored as an array.
# - parse: description how to parse arguments of command; possible values:
#   - regexp, used as argument for check_regex
#   - function ref. which parses one or more arguments and returns a value
#   - string: like function ref, but used as a method name
#   - array ref with first element is
#     - string 'seq': multiple parse info hashes or seq arrays are following, 
#                     all elements are evaluated, if the first element 
#                     returns a defined value
#     - string 'or': two or more parse info hashes are following,
#                    they are evaluated until a defined value is returned.
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
	  parse => ['seq',
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
	    'ip address +secondary' =>  { parse => \&skip },	# ignore
	    'ip unnumbered' => {
		store => ['ADDRESS', 'UNNUMBERED'], parse => \&get_token, },
	    'shutdown' => { 
		store => 'SHUTDOWN', default => 1, },
	    'ip access-group +in' => {
		store => 'ACCESS_GROUP_IN', parse => \&get_token, },
	    'ip access-group +out' => {
		store => 'ACCESS_GROUP_OUT', parse => \&get_token, },
	    'ip inspect +in' => { 
		store => 'INSPECT', parse => \&get_token, },
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

# ip route destination-prefix destination-prefix-mask
#          [interface-type card/subcard/port] forward-addr
#          [metric | permanent | track track-number | tag tag-value]
#
	'ip route' => { 
	    store => 'ROUTING',
	    multi => 1,
	    parse => ['seq',
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
		       ['seq',
			{ parse => qr/track/, },
			{ store => 'TRACK', parse => \&get_token, },],
		       ['seq',
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
			       ['seq',
				{ store => 'TYPE', parse => qr/ip/ },
				{ store => 'SRC', parse => 'parse_address' },
				{ store => 'DST', parse => 'parse_address' } ],
			       ['seq',
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
			       ['seq',
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
	'router ospf' => {
	    store => 'OSPF',
	    parse => \&get_token,	# <1-65535>  Process ID
	    subcmd => {},		# Has subcommands, but ignore them all.
	},
	'crypto isakmp identity' => {
	    store => [ 'CRYPTO', 'ISAKMP', 'IDENTITY' ],
	    parse => \&get_token,
	},

# crypto isakmp policy <priority>
#  <subcommands> 
#  ..
# return one hash for each priority
	'crypto isakmp policy' => {
	    named => 1,
	    store => [ 'CRYPTO', 'ISAKMP', 'POLICY' ],
	    subcmd => {
		'authentication' => {
		    store => 'AUTHENTICATION', parse => \&get_token, },
		'encryption' => {
		    store => 'ENCRYPTION', parse => \&get_token, },
		'encr' => {
		    store => 'ENCRYPTION', parse => \&get_token, },
		'hash' => {
		    store => 'HASH', parse => \&get_token, },
		'group' => {
		    store => 'GROUP', parse => \&get_token, },
		'lifetime' => {
		    store => 'LIFETIME', parse => \&get_token, },
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
		      { parse => qr/ipsec-isakmp/, }, ],
	    subcmd => {
		'match address' => {
		    store => 'MATCH_ADDRESS', parse => \&get_token, },
		'set ip access-group +in' => {
		    store => 'ACCESS_GROUP_IN', parse => \&get_token, },
		'set ip access-group +out' => {
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

	# We don't use the banner, but lexical analyser needs to know
	# that this is a multi line command.
	banner => { banner => 1, parse => \&skip },
    };

    # Copy 'permit' entry and substitute 'permit' by 'deny';
    my $entry = $result->{'ip access-list extended'}->{subcmd};
    $entry = $entry->{deny} = { %{$entry->{permit}} };
    $entry = $entry->{parse} = [ @{$entry->{parse}} ];
    $entry = $entry->[1] = { %{$entry->[1]} };
    $entry->{default} = 'deny';
    $result;
}

sub dev_cor {
    my ($self, $addr) = @_;
    return ~$addr & 0xffffffff;
}

sub postprocess_config {
    my ($self, $p) = @_;

    mypr meself(0) . "*** begin ***\n";
    my $crypto_map_found   = 0;
    my $ezvpn_client_found = 0;
    my %map_used;
    my %ezvpn_used;
    for my $intf (values %{ $p->{IF} }) {

	# Check for outgoing ACL.
        if (my $acl = $intf->{ACCESS_GROUP_OUT} and not $intf->{SHUTDOWN}) {
            warnpr "interface $intf->{name}: outgoing acl $acl detected\n";
        }

        if (my $imap = $intf->{CRYPTO_MAP}) {
            $crypto_map_found = 1;
            if (my $map = $p->{CRYPTO}->{MAP}->{$imap}) {
		$map_used{$imap} = 1;
                mypr " crypto map '$imap' bound to interface '$intf->{name}'\n";
            }
            else {
                errpr "No definition found for crypto map '$imap' at"
		    . " interface '$intf->{name}'\n";
            }
        }
        elsif ($intf->{EZVPN}) {
            $ezvpn_client_found = 1;
            my $ezvpn = $intf->{EZVPN}->{NAME};
            if (my $def = $p->{CRYPTO}->{IPSEC}->{CLIENT_EZVPN}->{$ezvpn}) {
                $ezvpn_used{$ezvpn} = 1;
                mypr " crypto ipsec client '$ezvpn' bound to"
		    . " interface '$intf->{name}'\n";
            }
            else {
                errpr "No definition for ezvpn client '$ezvpn' at"
		    . " interface '$intf->{name}' found\n";
            }
        }
    }
    if ($crypto_map_found and $ezvpn_client_found) {
        errpr
          "ezvpn and crypto map at interfaces found - only one of them allowed\n";
    }
    if ($crypto_map_found) {
        for my $cm_name (keys %{ $p->{CRYPTO}->{MAP} }) {
            unless ($map_used{$cm_name}) {
                warnpr "Unattached crypto map '$cm_name' found\n";
                next;
            }
            my $cm = $p->{CRYPTO}->{MAP}->{$cm_name};
            mypr " found crypto map '$cm_name' (instances:" 
		. scalar @$cm . ")\n";
	    $cm = [ sort { $a->{SEQU} <=> $b->{SEQU} } @$cm ];
	    $p->{CRYPTO}->{MAP}->{$cm_name} = $cm;
            for my $entry (@$cm) {
                my $sequ = $entry->{SEQU};
                mypr "  seq: $sequ\n";
                if (my $acl_name = $entry->{MATCH_ADDRESS}) {
                    mypr "   match-address: $acl_name\n";
                    if (my $acl = $p->{ACCESS_LIST}->{$acl_name}) {

                        # bind match address to crypto map
                        $entry->{MATCH_ACL} = $acl;
                    }
                    else {
                        errpr "Crypto: ACL $acl_name does not exist!\n";
                    }
                }
                else {
                    errpr "Crypto: no match-address entry found\n";
                }
                if (my $acl_name = $entry->{ACCESS_GROUP_IN}) {
                    mypr "   access-group:  $acl_name\n";
                    if ( my $acl = $p->{ACCESS_LIST}->{$acl_name}) {

                        # bind access group to crypto map
                        $entry->{FILTER_ACL} = $acl;
                    }
                    else {
                        errpr "Crypto: ACL $acl_name does not exist!\n";
                    }
                }
                if (my $acl_name = $entry->{ACCESS_GROUP_OUT}) {
                    warnpr "Crypto: outgoing filter-acl '$acl_name' found\n";
                }
		if (my $peers = $entry->{PEER}) {
		    $entry->{PEER} = [ sort { $a <=> $b } @$peers ];
		}
		else {
		    errpr "Crypto: no peer found\n";
		}
                if (my $trans_name = $entry->{TRANSFORM}) {
                    if (my $trans = 
			$p->{CRYPTO}->{IPSEC}->{TRANSFORM}->{$trans_name})
                    {

                        # bind transform set to crypto map
                        $entry->{TRANSFORM_BIND} = $trans;
                        mypr "   transform set: $trans_name\n";
                    }
                    else {
                        errpr
                          "Crypto: transform set $trans_name does not exist!\n";
                    }
                }
            }
        }
    }
    elsif ($ezvpn_client_found) {
        my $ezvpn = $p->{CRYPTO}->{IPSEC}->{CLIENT_EZVPN};
        for my $ez_name (keys %{$ezvpn}) {
            unless ($ezvpn_used{$ez_name}) {
                warnpr
                  "Unattached crypto ipsec ezvpn client '$ez_name' found\n";
                next;
            }
            mypr " found crypto ipsec client ezvpn '$ez_name'\n";
            my $entry = $ezvpn->{$ez_name};

            # checking for traffic match acl
            if (my $acl_name = $entry->{ACL}) {
                mypr "  match-acl: $acl_name\n";
                if (my $acl = $p->{ACCESS_LIST}->{$acl_name}) {

                    # bind match address to crypto map
                    $entry->{MATCH_ACL} = $acl
                }
                else {
                    errpr "Crypto: ACL $acl_name does not exist!\n";
                }
            }
            else {
                errpr "Crypto: no match-acl entry found\n";
            }

            # checking for virtual interface
            if (my $num = $entry->{V_INTERFACE}) {
		my $intf = "Virtual-Template$num";
                if ($p->{IF}->{$intf}) {
                    mypr "  client terminates at \'$intf\'\n";
                }
                else {
                    errpr "Crypto: virtual-interface $intf not found\n";
                }
            }
            else {
                errpr "Crypto: virtual-interface missing for ez_name\n";
            }
	    if (my $peers = $entry->{PEER}) {
		$entry->{PEER} = [ sort { $a <=> $b } @$peers ];
	    }
	    else {
		errpr "Crypto: no peer found\n";
	    }
        }
    }
    mypr meself(0) . "*** end ***\n";
}

sub get_config_from_device {
    my ($self) = @_;
    my $cmd = 'sh run';
    my $output = $self->shcmd($cmd);
    my @conf = split(/\r\n/, $output);
    my $echo = shift(@conf);
    $echo =~ /^\s*$cmd\s*$/ or 
	errpr "Got unexpected echo in response to '$cmd': '$echo'\n";
    return(\@conf);
}

##############################################################
# rawdata processing
##############################################################
sub merge_rawdata {
    my ($self, $spoc, $raw_conf) = @_;

    $self->merge_routing($spoc, $raw_conf);
    $self->merge_acls($spoc, $raw_conf);
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
    my @err_lines;
  LINE:
    for my $line (@$lines) {
	for my $regex (@{ $known_status{$cmd} }) {
	    if($line =~ $regex) {
		next LINE;
	    }
	}
	for my $regex (@{ $known_warning{$cmd} }) {
	    if($line =~ $regex) {
                warnpr $line, "\n";
		next LINE;
	    }
	}
	push @err_lines, "$cmd: $line\n";
    }
    for my $err_line (@err_lines) {
	errpr $err_line;
    }
}

sub checkinterfaces {
    my ($self, $conf, $spoc) = @_;

    # Some interfaces must be ignored.
    # Mark them as 'shutdown', which is handled by the superclass.
    for my $intf (values %{ $conf->{IF} }) {
	my $name = $intf->{name};
        if ($name eq 'Null0' 
	    or $name =~ /^Loopback\d+$/ 
	    or
	    $intf->{SWITCHPORT}
            and $intf->{SWITCHPORT}->{MODE}
            and $intf->{SWITCHPORT}->{MODE} eq "trunk") 
	{
	    $intf->{SHUTDOWN} = 1;
	}
    }
    $self->SUPER::checkinterfaces($conf, $spoc);
}

sub check_firewall {
    my ($self, $conf) = @_;
    for my $interface (values %{ $conf->{IF} }) {
        if (exists $interface->{INSPECT}) {
            errpr "CBAC detected at $interface for non-Firewall-Router\n";
        }
    }

}

#######################################################
# telnet login, check CHECKHOSTname and set convenient options
#######################################################
sub prepare {
    my ($self) = @_;
    my $name = $self->SUPER::prepare();

    $self->device_cmd('term len 0');
    my $output = $self->shcmd('sh ver');
    $output =~ /Software .* Version +(\d+\.\d+[\w\d\(\)]+)/i
      or errpr "Could not identify version number from 'sh ver'\n";
    $self->{VERSION} = $1;
    $output =~ /(cisco\s+\S+) .*memory/i
      or die "could not identify Hardware Info $output\n";
    $self->{HARDWARE} = $1;

    # max. term width is 511 for pix, 512 for ios
    $self->device_cmd('term width 512');
    unless ($self->{COMPARE}) {
        $self->cmd('configure terminal');
        $self->cmd('no logging console');
        mypr "console logging is now disabled!\n";

	# Needed for default route to work as expected.
        $self->cmd('ip subnet-zero');
        mypr "ip subnet-zero is now enabled!\n";

	# Needed for default route to work as expected.
        $self->cmd('ip classless');
        mypr "ip classless is now enabled!\n";
        $self->cmd('end');

    }

    mypr "-----------------------------------------------------------\n";
    mypr " DINFO: $self->{HARDWARE} $self->{VERSION}\n";
    mypr "-----------------------------------------------------------\n";
}

#######################################################
# *** ios transfer ***
#######################################################

# Output of "write mem":
# Building configuration...
# Compressed configuration from 22772 bytes to 7054 bytes[OK]
#
# Building configuration...
# [OK]

sub write_mem {
    my ($self, $retries, $seconds) = @_;
    mypr "writing config to nvram\n";
    $retries++;
    while ($retries--) {
        my $lines = $self->get_cmd_output('write memory');
	if ($lines->[0] =~ /^Building configuration/) {
	    if ($lines->[1] =~ /\[OK\]/) {
		mypr "seems ok\n";
	    }
	    else {
		errpr "'write mem' failed. Config may be truncated!\n";
	    }
        }
        elsif (grep { $_ =~ /startup-config file open failed/i } @$lines) {
            if (not $retries) {
                errpr "startup-config file open failed - giving up\n";
            }
            else {
                warnpr "startup-config file open failed - sleeping "
		    . "$seconds seconds then trying again\n";
                sleep $seconds;
            }
        }
        else {
            errpr "Unexpected result for write memory. Check *.tel file\n";
        }
    }
}

sub compare_ram_with_nvram {
    my ($self) = @_;

    # *** FETCH CONFIGS ***
    mypr "fetch running config from device again ";

    # Do not show content of certificates.
    my $out = $self->shcmd('show run brief');

    # Some devices have no 'brief' option.
    if ($out =~ /^\s*%\s+invalid/im) {
        $out = $self->shcmd('show run');
    }
    my @conf = split /\n/, $out;
    mypr "... done\n";
    mypr "fetch startup config from device again ";
    $out = $self->shcmd('show start');
    my @start = split /\n/, $out;
    mypr "... done\n";

    # *** COMPARE ***
    my $compare_run   = 0;
    my $startup_index = 0;
    my @startup_certs = ();
    my @running_certs = ();
    for (my $i = 0 ; $i < scalar @start ; $i++) {
        if ($start[$i] =~ /version/i) {
            $startup_index = $i;
            last;
        }
    }
    for my $line (@conf) {
        if ($line =~ /version/i) {
            $compare_run = 1;
        }
        next if (not $compare_run);

        # ignore patterns in running config
        if (
               $line =~ /\A\s*!/
            or $line =~ /ntp clock-period/
            or $line =~ /\A(\s+[A-F0-9]{8})+/
            or    # match certificate contents
            $line =~ /\A\s*quit\s*\Z/ or    # match certificate contents
            $line =~ /^\s*certificate/
            or $line =~ /no scheduler allocate/
            or $line =~
            /boot system flash:/ # at some devices this is not included by 'sh run brief'
          )
        {
            if ($line =~ /certificate/) {

                # mask out nvram file info for certificates
                $line =~ s/\snvram:\S*//;

                # collect cert IDs in running
                push @running_certs, $line;
            }
            next;
        }

        # ignore patterns in startup config
        while (
               $start[$startup_index] =~ /\A\s*!/
            or $start[$startup_index] =~ /ntp clock-period/
            or $start[$startup_index] =~ /\A(\s+[A-F0-9]{8})+/
            or    # match certificate contents
            $start[$startup_index] =~ /\A\s*quit\s*\Z/
            or    # match certificate contents
            $start[$startup_index]    =~ /^\s*certificate/
            or $start[$startup_index] =~ /no scheduler allocate/
            or $start[$startup_index] =~ /boot system flash:/
          )
        {
            if ($start[$startup_index] =~ /certificate/) {

                # mask out nvram file info for certificates
                $start[$startup_index] =~ s/\snvram:\S*//;

                # collect cert IDs in startup
                push @startup_certs, $start[$startup_index];
            }
            $startup_index++;
        }
        if ($line ne $start[$startup_index]) {
            warnpr "Diff found   RUN: $line\n";
            warnpr "Diff found START: $start[$startup_index]\n";
            return 0;
        }
        $startup_index++;
    }

    # compare certificate lines
    my @sc = sort @startup_certs;
    my @rc = sort @running_certs;
    if (scalar @sc != scalar @rc) {
        warnpr "Diff found for certificate IDs\n";
        warnpr "startup " . scalar @sc . " ID(s) found\n";
        warnpr "running " . scalar @rc . " ID(s) found\n";
        return 0;
    }
    for (my $i = 0 ; $i < scalar @sc ; $i++) {
        if ($sc[$i] ne $rc[$i]) {
            warnpr "START: $startup_certs[$i]\n";
            warnpr "RUN:   $running_certs[$i]\n";
            return 0;
        }
    }

    #check if any residual non-space lines in startup config
    while (scalar @start > $startup_index) {
        $startup_index++;

        # ignore patterns in startup config
        my $t = scalar @start;

        #mypr "$t $startup_index\n";
        if ($start[$startup_index] !~ /\A\s*!/) {
            warnpr
              "Residual pattern in startup-config found: $start[$startup_index]\n";
            return 0;
        }
    }
    return 1;
}

sub schedule_reload {
    my ($self, $minutes) = @_;
    return if $self->{COMPARE};
    mypr "schedule reload in $minutes minutes\n";
    my $psave = $self->{ENAPROMPT};
    $self->{ENAPROMPT} = qr/\[yes\/no\]:\ |\[confirm\]/;
    my $out = $self->shcmd("reload in $minutes");

    # System configuration has been modified. Save? [yes/no]: 
    if ($out =~ /save/i) {
	$self->{ENAPROMPT} = qr/\[confirm\]/;

        # Someone has fiddled with the router.
        $self->issue_cmd('n');
    }
    $self->{ENAPROMPT} = $psave;
    $self->issue_cmd('');
    $self->{RELOAD_SCHEDULED} = 1;
    mypr "reload scheduled\n";
}

sub cancel_reload {
    my ($self) = @_;
    return if $self->{COMPARE};
    if ($self->{RELOAD_SCHEDULED})
    {
        mypr "cancel reload ";

        # workaround: wait longer
        my $con = $self->{CONSOLE};
        my $tt  = $con->{TIMEOUT};
        $con->{TIMEOUT} = 2 * $tt;
        mypr "(timeout temporary set from $tt sec to $con->{TIMEOUT} sec)\n";

        # wait for the
        # ***
        # *** --- SHUTDOWN ABORTED ---
        # ***
	my $psave = $self->{ENAPROMPT};
	$self->{ENAPROMPT} = qr/--- SHUTDOWN ABORTED ---/;
        $self->shcmd('reload cancel');
        $con->{TIMEOUT} = $tt;
	$self->{ENAPROMPT} = $psave;

	# Newer IOS versions give an additional prompt after printing 
	# the "ABORTED" message
	$con->{TIMEOUT} = 1;
	$con->con_wait($psave);
        $con->{TIMEOUT} = $tt;
	
        # Check, if "reload cancel" succeeded.
        my $out = $self->shcmd('sh reload');
        unless ($out =~ /No reload is scheduled/) {
            warnpr "could not cancel reload\n";
        }
        else {
            $self->{RELOAD_SCHEDULED} = 0;
        }
    }
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
    if($e->{LOG}) {
	push(@r, 'log');
	push(@r, $e->{LOG_MODE}) if $e->{LOG_MODE};
	push(@r, $e->{LOG_LEVEL}) if $e->{LOG_LEVEL};
	push(@r, "interval $e->{LOG_INTERVAL}") if $e->{LOG_INTERVAL};
    }
    return join(' ', @r);
}

# Incrementally convert an ACL on device to the new ACL from netspoc.
sub equalize_acl {
    my($self, $conf_acl, $spoc_acl) = @_;
    my $conf_entries = $conf_acl->{LIST};
    my $spoc_entries = $spoc_acl->{LIST};

    my $diff = Algorithm::Diff->new( $conf_entries, $spoc_entries, 
				     { keyGen => \&acl_entry2key } );

    # Check differences in detail.
    # Change ACL on device in 2 passes:
    # 1. Add new ACL entries
    #    which are not already present on device.
    #    Remember other entries which can't be added, 
    #    because same entry has not been deleted yet.
    # 2. Delete old ACL entries
    #  a) If same entry will be added at other position
    #     transfer delete and add command together in one packet to device,
    #     to prevent accidental lock out from device.
    #  b) Simply delete, if entry isn't used any longer.

    # Hash for finding duplicates when comparing old and new entries.
    my %dupl;

    # Mapping from to be deleted conf entry to to be added spoc entry.
    my %add_later;

    # Collect entries 
    # - without duplicates, which can be added immediately,
    # - to be deleted on device,
    # - to be added, after lines have been deleted on device.
    my (@add, @delete, @add_later);

    # Cisco lines of ACL entries.
    my %cisco_line;

    # Add new line numbers to ACL entries read from device.
    for (my $i = 0; $i < @$conf_entries; $i++) {
	$cisco_line{$conf_entries->[$i]} = 10000 + $i * 10000;
    }

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
	    my $line = $cisco_line{$conf_entries->[$conf_next]} - 9999;
	    for my $spoc_entry ($diff->Items(2)) {
		$cisco_line{$spoc_entry} = $line++;
		my $key = acl_entry2key($spoc_entry);
		if (my $conf_entry = $dupl{$key}) {
		    $add_later{$conf_entry} = $spoc_entry;
		}
		else {
		    push @add, $spoc_entry;
		}
	    }
	}
    }
    
    return if not (@add || @delete);

    my $acl_name = $conf_acl->{name};

    if (@$conf_entries >= 10000) {
	errpr "Can't handle device ACL $acl_name with 10000 or more entries\n";
    }
    if (@$spoc_entries >= 10000) {
	my $spoc_name = $spoc_acl->{name};
	errpr "Can't handle netspoc ACL $spoc_name with 10000 or more entries\n";
    }

    $self->{CHANGE}->{ACL} = 1;

    # Add same line numbers as above to ACL entries on device.
    # Do resequence before schedule reload, because it may abort
    # if this command isn't available on old IOS version.
    $self->cmd('configure terminal');
    $self->cmd("ip access-list resequence $acl_name 10000 10000");
    $self->cmd('end');

    $self->schedule_reload(10);
    $self->cmd('configure terminal');
    $self->cmd("ip access-list extended $acl_name");

    # 1. Add lines from netspoc which have no duplicates on device.
    for my $spoc_entry (@add) {
	my $line = $cisco_line{$spoc_entry};
	my $cmd  = "$line $spoc_entry->{orig}";
	$self->cmd($cmd);
    }

    # 2. Delete lines on device and add same line again if needed.
    for my $conf_entry (@delete) {
	my $line = $cisco_line{$conf_entry};
	my $cmd1 = "no $line";
	if (my $spoc_entry = $add_later{$conf_entry}) {
	    my $line2 = $cisco_line{$spoc_entry};
	    my $cmd2  = "$line2 $spoc_entry->{orig}";
	    $self->two_cmd($cmd1, $cmd2);
	}
	else {
	    $self->cmd($cmd1);
	}
    }

    $self->cmd('exit');
    $self->cmd("ip access-list resequence $acl_name 10 10");
    $self->cmd('end');
    $self->cancel_reload();
}

sub append_acl_entries {
    my ($self, $name, $entries) = @_;
    $self->cmd('configure terminal');
    $self->cmd("ip access-list extended $name");
    for my $c (@$entries) {
        my $acl = $c->{orig};
        $self->cmd($acl);
    }
    $self->cmd('end');
}

sub process_interface_acls( $$$ ){
    my ($self, $conf, $spoc) = @_;
    mypr "======================================================\n";
    mypr "SMART: establish new acls for device\n";
    mypr "======================================================\n";

    $self->{CHANGE}->{ACL} = 0;
    for my $intf (values %{$spoc->{IF}}){
	my $name = $intf->{name};
        my $conf_intf = $conf->{IF}->{$name}
	   or errpr "interface not found on device: $name\n";
	my $confacl_name = $conf_intf->{ACCESS_GROUP_IN} || '';
	my $spocacl_name = $intf->{ACCESS_GROUP_IN};
	my $conf_acl = $conf->{ACCESS_LIST}->{$confacl_name};
	my $spoc_acl = $spoc->{ACCESS_LIST}->{$spocacl_name};
	if($confacl_name and $conf_acl){
	    $self->equalize_acl($conf_acl, $spoc_acl);
	}
	else {
	    $self->{CHANGE}->{ACL} = 1;
	    warnpr "no access-list configured at interface $name\n";
	    my $aclname = "$spocacl_name-DRC";

	    # begin transfer
	    mypr "create *new* acl $aclname on device\n";
	    #
	    # maybe there is an old acl with $aclname:
	    # first remove old entries because acl should be empty - otherwise
	    # new entries are only appended - bad
	    #
	    $self->cmd('configure terminal');
	    $self->cmd("no ip access-list extended $aclname");
	    $self->cmd('end');
	    $self->append_acl_entries($aclname, $spoc_acl->{LIST});

	    # Assign new acl to interface.
	    mypr "assign new acl:\n";
	    $self->schedule_reload(5);
	    $self->cmd('configure terminal');
	    $self->cmd("interface $name");
	    $self->cmd("ip access-group $aclname in");
	    $self->cmd('end');
	    $self->cancel_reload();
	}
    }

    mypr "======================================================\n";
    mypr "SMART: done\n";
    mypr "======================================================\n";
}

###############################
#
# Crypto processing
#
###############################

#
# possible names are (per name convention):
#
# <spoc-name>-DRC-0
# <spoc-name>-DRC-1
#
# because the spoc-name may change unexpected drc.pl scans for "-DRC-x" to
# identify spoc-related acls
#

sub crypto_struct_equal {
    my ($self, $conf, $spoc, $context, $changes, $ident) = @_;
    $ident = " $ident";

    #print "-$conf--$spoc-\n";
    if (!ref $conf) {
        if (!ref $spoc) {
            ($conf eq $spoc) and return 1;
        }
        else {
            my $type = ref $spoc;
            errpr "could not compare scalar $conf with type $type\n";
        }
        mypr "${ident}diff $conf <=> $spoc\n";
        return 0;
    }
    elsif (ref $conf eq 'SCALAR') {
        if (ref $spoc eq 'SCALAR') {
            $self->crypto_struct_equal($$conf, $$spoc, $context, $changes, $ident)
              and return 1;
        }
        else {
            my $type = ref $spoc;
            errpr "could not compare scalar ref $conf with type $type\n";
        }
        mypr "${ident}diff $conf <=> $spoc\n";
        return 0;
    }
    elsif (ref $conf eq 'ARRAY') {
        if (ref $spoc eq 'ARRAY') {

            # arrays are equal iff have same elements in same order
            if (@$conf == @$spoc) {
                my $equal         = 1;
                my $upper_context = $context;
                for (my $i = 0 ; $i < scalar @$conf ; $i++) {
                    unless (
                        $self->crypto_struct_equal(
                            $conf->[$i], $spoc->[$i], $context, $changes, $ident
                        )
                      )
                    {
                        mypr "${ident}diff array element $i\n";
                        $equal = 0;
                    }
                }
                return $equal;
            }
            else {
                mypr "${ident}diff array lenght\n";
            }
        }
        else {
            my $type = ref $spoc;
            errpr "could not compare array with type $type\n";
        }
        return 0;
    }
    elsif (ref $conf eq 'HASH') {
        if (ref $spoc eq 'HASH') {
            my $equal = 1;
            for my $key (keys %$conf) {
                if ($key eq "ACCESS_GROUP_IN") {
		    my $conf_acl = $conf->{$key};

                    # special handling for this entry because it
                    # is subject of change by netspoc
                    if (my $spoc_acl = $spoc->{$key}) {
                        unless (
				$self->acl_equal(
						 $conf->{FILTER_ACL}->{LIST},  
						 $spoc->{FILTER_ACL}->{LIST},
						 $conf_acl, $spoc_acl, $key
						 )
				)
                        {

                            # $context holds sequence number of map
                            $changes->{$key}->{$context}->{CONF} = $conf_acl;
                            $changes->{$key}->{$context}->{SPOC} = $spoc_acl;

                            # differences in the contents of these ACLs handled elsewhere!
                            # $equal = 0;
                        }
                    }
                    else {
                        warnpr "no crypto filter ACL found\n";
                        $changes->{$key}->{$context}->{CONF} = $conf_acl;
                        $changes->{$key}->{$context}->{SPOC} = '';
                    }
                }
                elsif (exists $spoc->{$key}) {
                    if ($key eq "MATCH_ADDRESS") {

                        # Parser already checked that match address is present.
                        unless (
				$self->acl_equal(
						 $conf->{MATCH_ACL}->{LIST},  
						 $spoc->{MATCH_ACL}->{LIST},
						 $conf->{$key}, 
						 $spoc->{$key}, $key
						 )
				)
                        {
                            $equal = 0;
                        }
                    }
                    elsif ($key eq 'name' or $key eq 'orig' or $key eq 'line' or
			   $key eq 'FILTER_ACL' or $key eq 'MATCH_ACL' or
			   $key eq 'SEQU' or $key eq 'TRANSFORM')
                    {

                        # do not check this !
                    }
                    else {
                        unless (
                            $self->crypto_struct_equal(
                                $conf->{$key}, $spoc->{$key}, $context,
                                $changes,     $ident
                            )
                          )
                        {
                            mypr "${ident}diff hash element $key\n";
                            $equal = 0;
                        }
                    }
                }
                else {
                    mypr "${ident}missing hash-key $key in device config\n";
                    $equal = 0;
                }
            }
            for my $key (keys %$spoc) {
                unless (exists $conf->{$key}) {
                    mypr "${ident}missing hash-key $key in netspoc config\n";
                    $equal = 0;
                }
            }
            return $equal;
        }
        else {
            my $type = ref $spoc;
            errpr "could not compare hash with type $type\n";
        }
        return 0;
    }
    else {
        errpr meself(0) . "unsupported type" . ref($conf) . "\n";

    }
    return 0;
}

sub crypto_processing {
    my ($self, $conf, $spoc) = @_;
    my $context = {};
    my $changes = {};
    mypr "====                         ====\n";
    mypr "==== begin crypto processing ====\n";
    mypr "====                         ====\n";

    # only proceed if netspoc crypto config present!!!
    if (exists $spoc->{CRYPTO}) {
        mypr " +++ spocfile contains crypto definitions!\n";
    }
    else {
        mypr " +++ no crypto definitions in spocfile - skipping\n";
        return;
    }
    $self->{CHANGE}->{CRYPTO} = 0;
    if (my $spoc_isakmp = $spoc->{CRYPTO}->{ISAKMP}) {
        mypr " --- begin compare crypto isakmp ---\n";
        if (my $conf_isakmp = $conf->{CRYPTO}->{ISAKMP}) {
            if (
                $self->crypto_struct_equal(
                    $conf_isakmp, $spoc_isakmp, $context, $changes, ''
                )
              )
            {
                mypr "    no diffs found\n";
            }
            else {
                errpr "severe diffs in crypto isakmp detected!\n";
		$self->{CHANGE}->{CRYPTO} = 1;
            }
        }
        else {
            errpr "missing isakmp config at device\n";
        }
        mypr " --- end compare crypto isakmp ---\n";
        my %surplus_acls = ();

        # Compare crypto config which is bound to interfaces.
        for my $intf (keys %{ $spoc->{IF} }) {

            $context = {};
            $changes = {};
            mypr " --- interface $intf ---\n";
            if ($spoc->{IF}->{$intf}->{CRYPTO_MAP}) {
                mypr " crypto map in spocfile found\n";

            }
            else {
                mypr " no crypto map in spocfile found\n";
                if ($conf->{IF}->{$intf}->{CRYPTO_MAP}) {
                    warnpr " crypto map at device found\n";
                    $self->{CHANGE}->{CRYPTO}   = 1;
                }
                next;
            }
            my $spoc_map_name = $spoc->{IF}->{$intf}->{CRYPTO_MAP};

            # ok. There should be a crypto map on this interface
            my $conf_map_name = $conf->{IF}->{$intf}->{CRYPTO_MAP};
            unless ($conf_map_name) {
                errpr "no crypto map at device - leaving crypto untouched\n";
                $self->{CHANGE}->{CRYPTO}   = 1;
                next;
            }
            mypr " --- begin compare crypto maps---\n";
            mypr " $spoc_map_name <-> $conf_map_name\n";
            unless (
                $self->crypto_struct_equal(
                    $conf->{CRYPTO}->{MAP}->{$conf_map_name},
                    $spoc->{CRYPTO}->{MAP}->{$spoc_map_name},
                    $context, $changes, ''
                )
              )
            {
                errpr
                  "severe diffs in crypto map detected - leaving crypto untouched\n";
		$self->{CHANGE}->{CRYPTO} = 1;
                next;
            }
            mypr " --- end compare crypto maps---\n";
            if (exists $changes->{ACCESS_GROUP_IN}) {
                mypr " --- processing results ---\n";
                $self->{CHANGE}->{CRYPTO} = 1;
                for my $sequ (keys %{ $changes->{ACCESS_GROUP_IN} }) {
                    mypr
                      "Interface \'$intf\': Crypto map: \'$conf_map_name\' instance $sequ *** filter ACL changed ***\n";
                    my $conf_acl_name =
                      $changes->{ACCESS_GROUP_IN}->{$sequ}->{CONF};
                    my $spoc_acl_name =
                      $changes->{ACCESS_GROUP_IN}->{$sequ}->{SPOC};
                    mypr
                      " incoming device  ACL '$conf_acl_name' differs from\n";
                    mypr " incoming netspoc ACL '$spoc_acl_name'\n";
                    unless ($self->{COMPARE}) {

                        # process crypto filter acls
                        my $aclindex;
                        if ($conf_acl_name =~ /\S+-DRC-([01])/) {

                            # active acls matches name convention
                            $aclindex = (not $1) * 1;
                        }
                        else {
                            if ($conf_acl_name) {
                                warnpr
                                  "unexpected filter-acl-name $conf_acl_name at $conf_map_name $sequ\n";
                            }
                            else {
                                warnpr
                                  "no filter-acl found at $conf_map_name $sequ\n";
                            }
                            $aclindex = 0;
                        }
                        my $new_acl_name = "$spoc_acl_name-DRC-$aclindex";

                        # *** SCHEDULE RELOAD ***
                        # TODO: check if 10 minutes are OK
                        $self->schedule_reload(10);

                        # begin transfer
                        mypr "create *new* acl $new_acl_name on device\n";

                        # maybe there is an old acl with $aclname:
                        # first remove old entries because acl should be empty 
			# - otherwise new entries are only appended - bad
                        $self->cmd('configure terminal');
                        $self->cmd("no ip access-list extended $new_acl_name");
                        $self->cmd('end');
                        $self->append_acl_entries($new_acl_name,
                            $spoc->{ACCESS_LIST}->{$spoc_acl_name}->{LIST});

                        #
                        # assign new acl to interfaces
                        #
                        mypr "assign new acl:\n";
                        $self->cmd('configure terminal');
                        mypr " crypto map $conf_map_name $sequ\n";
                        $self->cmd("crypto map $conf_map_name $sequ");
                        mypr " set ip access-group $new_acl_name in\n";
                        $self->cmd("set ip access-group $new_acl_name in");
                        $self->cmd('end');
                        $self->cancel_reload();
                        mypr "---\n";

                        # New acl established - old one should be removed:
                        $surplus_acls{$conf_acl_name} = 1;
                    }
                }
                mypr " --- done processing results ---\n";
            }
        }

        # Remove surplus ACLs if still present
        unless ($self->{COMPARE}) {
            mypr " --- begin remove surplus acls ---\n";

            $self->schedule_reload(3);
            for my $name (keys %surplus_acls) {
                $self->cmd('configure terminal');
                if ($name and exists $conf->{ACCESS_LIST}->{$name}) {
		    my $cmd =  "no ip access-list extended $name";
		    mypr "$cmd\n";
                    $self->cmd($cmd);
                }
                $self->cmd('end');
            }
            $self->cancel_reload();
            mypr " --- done remove surplus acls ---\n";
        }
    }
    elsif (exists $spoc->{CRYPTO}->{IPSEC}->{CLIENT_EZVPN}) {

        # In ezvpn mode we grant that the tunnel is terminated at some
        # virtual interface. This interface holds an ACL.
        # The ACL is checked by standard ACL code
        ##################################################
        mypr " --- begin compare crypto ezvpn ---\n";
        if (exists $conf->{CRYPTO}->{IPSEC}->{CLIENT_EZVPN}) {
            if (
                $self->crypto_struct_equal(
                    $conf->{CRYPTO}->{IPSEC},
                    $spoc->{CRYPTO}->{IPSEC},
                    $context, $changes, ''
                )
              )
            {
                mypr "    no diffs found\n";
            }
            else {
                errpr "severe diffs in crypto ipsec detected!\n";
		$self->{CHANGE}->{CRYPTO} = 1;
            }
        }
        else {
            errpr "missing ezvpn config at device\n";
        }
        mypr " --- end compare crypto ezvpn ---\n";
    }

    mypr "====                       ====\n";
    mypr "==== end crypto processing ====\n";
    mypr "====                       ====\n";
}
###############################
#
# END crypto processing
#
###############################

sub transfer {
    my ($self, $conf, $spoc) = @_;

    # *** BEGIN TRANSFER ***
    $self->process_interface_acls($conf, $spoc);
    $self->crypto_processing($conf, $spoc);
    $self->process_routing($conf, $spoc);

    #
    # *** CLEANUP
    #
    if ($self->{COMPARE}) {

	# No CONSOLE available when called by compare_files
        if ($self->{CONSOLE} and not grep { $_ } values %{ $self->{CHANGE} }) {
            mypr "no changes in running config -"
              . " check if startup is uptodate:\n";
	    $self->{CHANGE}->{STARTUP_CONFIG} = 0;
            if ($self->compare_ram_with_nvram()) {
                mypr "comp: Startup is uptodate\n";
            }
            else {
                mypr "Startup not uptodate ***\n";
                warnpr "Write memory recommended!\n";
                $self->{CHANGE}->{STARTUP_CONFIG} = 1;
            }
        }
    }
    else {
        if (grep { $_ } values %{ $self->{CHANGE} }) {

            # Save config.
            mypr "ok\n";
            $self->write_mem(5, 3);    # 5 retries, 3 seconds intervall

	    # Check if write to startup config succeeded.
            if (not $self->compare_ram_with_nvram()) {
 		errpr "Problem with config size:"
		    . " startup config was written but is not correct!\n";
	    }
        }
        else {
            mypr "no changes to save - check if startup is uptodate:\n";

            # Handle recent problems with write mem.
            # Compare running with startup config
            if ($self->compare_ram_with_nvram()) {
                mypr "Startup is uptodate\n";
            }
            else {
                warnpr "Startup is *NOT* uptodate - trying to fix:\n";
                $self->write_mem(5, 3);
            }
        }
    }
    return 1;
}

# Packages must return a true value;
1;

