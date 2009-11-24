
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
		store => ['ADDRESS', 'DYNAMIC'], default => 'unnumbered', },
	    'shutdown' => { 
		store => 'SHUTDOWN', default => 1, },
	    'ip access-group +in' => {
		store => 'ACCESS_GROUP_IN', parse => \&get_token, },
	    'ip access-group +out' => {
		store => 'ACCESS_GROUP_OUT', parse => \&get_token, },
	    'ip inspect' => { 
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

sub dev_cor ($$) {
    my ($self, $addr) = @_;
    return ~$addr & 0xffffffff;
}

# remark ...
# permit|deny (a.b.c.d [a.b.c.d] | any) [log]
sub parse_simple_acl_entry {
    my ($self, $arg) = @_;
    my $result;

    if(check_regex('remark', $arg)) {
	$result->{REMARK} = get_token($arg);
    }
    else {
	$result->{MODE} = get_regex('permit|deny', $arg);
	my($base, $mask);
	if(defined($base = check_ip($arg))) {
	    if(defined($mask = check_ip($arg))) {
		$mask = $self->dev_cor($mask);
	    }
	    else {
		$mask = 0xffffffff;
	    }
	}
	else {
	    get_regex('any', $arg);
	    $base = $mask = 0;
	}
	$result->{SRC} = { BASE => $base, MASK => $mask };
	if(my $log = check_regex('log', $arg)) {
	    $result->{LOG} = $log;
	}
	$result->{TYPE} = 'ip';
	$result->{DST} = { BASE => 0, MASK => 0 };
    }
    return $result;
}

# Only used if called by method 'check_acl'.
sub parse_access_list {
    my ($self, $arg) = @_;
    my $result;
    my $name = get_int($arg);
    if (100 <= $name && $name < 200) {
	$result = $self->parse_acl_entry($arg);
    }
    elsif (0 < $name && $name < 100) {
	$result = $self->parse_simple_acl_entry($arg);
    }
    return $result, $name, 'push';
}

# checking, binding  and info printing of parsed crypto config
sub postprocess_config( $$ ) {
    my ($self, $p) = @_;

    mypr meself(0) . "*** begin ***\n";
    my $crypto_map_found   = 0;
    my $ezvpn_client_found = 0;
    my %map_used;
    my %ezvpn_used;
    for my $intf (values %{ $p->{IF} }) {
        if (my $imap = $intf->{CRYPTO_MAP}) {
            $crypto_map_found = 1;
            if (my $map = $p->{CRYPTO}->{MAP}->{$imap}) {
		$map_used{$imap} = 1;
                mypr " crypto map '$imap' bound to interface '$intf->{name}'\n";
            }
            else {
                errpr "No definition found for crypto map '$imap' at"
		    . " interface '$intf->{name}'\n";
                return 0;
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
                return 0;
            }
        }
    }
    if ($crypto_map_found and $ezvpn_client_found) {
        errpr
          "ezvpn and crypto map at interfaces found - only one of them allowed\n";
        return 0;
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
                        return 0;
                    }
                }
                else {
                    errpr "Crypto: no match-address entry found\n";
                    return 0;
                }
                if (my $acl_name = $entry->{ACCESS_GROUP_IN}) {
                    mypr "   access-group:  $acl_name\n";
                    if ( my $acl = $p->{ACCESS_LIST}->{$acl_name}) {

                        # bind access group to crypto map
                        $entry->{FILTER_ACL} = $acl;
                    }
                    else {
                        errpr "Crypto: ACL $acl_name does not exist!\n";
                        return 0;
                    }
                }
                if (my $acl_name = $entry->{ACCESS_GROUP_OUT}) {
                    warnpr "Crypto: outgoing filter-acl '$acl_name' found\n";
                }
                $entry->{PEER} or errpr "Crypto: no peer found\n";
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
                        return 0;
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
                    return 0;
                }
            }
            else {
                errpr "Crypto: no match-acl entry found\n";
                return 0;
            }

            # checking for virtual interface
            if (my $num = $entry->{V_INTERFACE}) {
		my $intf = "Virtual-Template$num";
                if ($p->{IF}->{$intf}) {
                    mypr "  client terminates at \'$intf\'\n";
                }
                else {
                    errpr "Crypto: virtual-interface $intf not found\n";
                    return 0;
                }
            }
            else {
                errpr "Crypto: virtual-interface missing for ez_name\n";
                return 0;
            }
            $entry->{PEER} or errpr "Crypto: no peer found\n";
        }
    }
    mypr meself(0) . "*** end ***\n";
    return 1;
}

sub get_config_from_device( $ ) {
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
    my ($self, $spoc_conf, $raw_conf) = @_;

    $self->merge_routing($spoc_conf, $raw_conf);
    $self->merge_acls($spoc_conf, $raw_conf);
}


##############################################################
# issue command
##############################################################
sub cmd_check_error($$) {
    my ($self, $out) = @_;

    if ($$out =~ /^\s*%\s*/m) {
        #### hack start ###
        if ($$out =~ /Delete failed. NV generation of acl in progress/) {
            ### probably slow acl proccessing
            my @pre = split(/\n/, $$out);
            for my $line (@pre) {
                warnpr $line, "\n";
            }
            return 1;
        }
        ### hack end ###
        my @pre = split(/\n/, $$out);
        errpr_info "+++ ", $pre[0], "\n";
        for (my $i = 0 ; $i < @pre ; $i++) {
            if ($pre[$i] =~ /%/) {
                if ($pre[$i] =~ /'\^'/) {
                    errpr_info "+++ ", $pre[ $i - 2 ], "\n";
                    errpr_info "+++ ", $pre[ $i - 1 ], "\n";
                }
                errpr_info "+++ ", $pre[$i], "\n";
            }
        }
        errpr "+++\n";
        return 0;
    }
    return 1;
}

#
#    *** some checking ***
#
sub checkinterfaces($$) {
    my ($self, $devconf, $spocconf) = @_;
    mypr " === check for unknown or missconfigured interfaces at device ===\n";
    my $ports_in_vlan_1 = 0;
    my $check_vlan1     = 1;
    for my $intf (values %{ $devconf->{IF} }) {
	my $name = $intf->{name};
        next if ($intf->{SHUTDOWN});
        next if ($name eq 'Null0');
        next
          if (  $intf->{SWITCHPORT}
            and $intf->{SWITCHPORT}->{MODE}
            and $intf->{SWITCHPORT}->{MODE} eq "trunk");
        if (my $spoc_intf = $spocconf->{IF}->{$name}) {
            if (my $addr = $intf->{ADDRESS}) {
                if (my $base = $addr->{BASE}) {
                    mypr "$name ip: " . int2quad($base) . "\n";
                }
                elsif (my $dynamic = $addr->{DYNAMIC}) {
                    mypr "$name ip: $dynamic\n";
                }
            }
            else {
                warnpr
                  "$name: no address found at netspoc configured interface\n";
            }
            next;
        }

        #
        # interface name *not* known by netspoc!
        #
        if (my $addr = $intf->{ADDRESS}) {
            if (my $base = $addr->{BASE}) {
                warnpr "unknown interface $name with ip: "
                  . int2quad($base) . " detected!\n";
            }
            elsif (my $dynamic = $addr->{DYNAMIC}) {
                warnpr "unknown interface $name with ip: $dynamic\n";
            }
            next;
        }

        # check known harmless interfaces
        if ($name =~ /^(BRI|Loopback|Vlan|ATM)\d+$/) {
            mypr "$name without ip detected - OK\n";
            next;
        }

        # the interface has to be bound to a vlan!
        if (not $intf->{SWITCHPORT}) {

            # Ethernet without vlan def located in vlan1 as default!
            push @{ $intf->{SWITCHPORT}->{ACCESS_VLAN} }, 1;
            mypr "$name assigned to vlan1 for further checks\n";
        }
        my $switchportconf = $intf->{SWITCHPORT};
	my $mode = $switchportconf->{MODE};
	my $access_vlan = $switchportconf->{ACCESS_VLAN};

        # Some IOS routers have switchport modules with slightly different config:
        #
        # no 'nonegotiate' command
        # no 'switchport mode' entry in access mode  for WIC Switch-Modules
        #
        if ($self->{HARDWARE} =~ 
	    /^cisco *(831|836|1721|1712|1812|2801|2811|2821)$/i) 
	{

            # vlan1 checking only necessary for *real* switches due to
            # conventions in dataport silan
            $check_vlan1 = 0;
        }
        else {
            if (not $mode) {
                errpr "missing switchport mode config at interface $name\n";
            }
            elsif ( $mode ne "access" and $mode ne "trunk") {
                errpr "$name wrong switchport mode: $mode\n";
                errpr " only 'access' and 'trunk' allowed\n";
            }
            else {
                mypr "$name switchport mode: $mode\n";
            }
            if (!$switchportconf->{NONEGOTIATE}) {
                errpr "missing 'switchport nonegotiate' at interface $name\n";
            }
        }

        # ok now check if switchport config is well shaped
        #
        # TODO: check trunks
        #
        if ($mode and $mode eq "access" or $access_vlan) {
            if (not $access_vlan) {
                $ports_in_vlan_1++;
            }
            elsif (@$access_vlan  > 1) {
                errpr "$name: member of more than one vlan ("
                  . scalar @$access_vlan. ") - forbidden!\n";
            }
            for my $vlan (@$access_vlan) {
                if ($vlan eq 99) {
                    errpr "active interface $name at vlan 99 - forbidden!\n";
                }
                if ($vlan eq 1) {
                    $ports_in_vlan_1++;
                }
            }
        }
    }
    if ($ports_in_vlan_1 > 1 and $check_vlan1) {
        for my $name (keys %{ $devconf->{IF} }) {
            if ($name =~ /vlan1\Z/i) {
                errpr
                  "Admin Vlan(1) has $ports_in_vlan_1 switchports - only 1 allowed\n";
            }
        }
    }
    mypr " === done ===\n";
}

sub check_firewall ( $$ ) {
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

    # max. term width is 511 for pix 512 for ios
    $self->device_cmd('term width 512');
    unless ($self->{COMPARE}) {
        $self->cmd('conf t');
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

# *** small helpers (ios) ***

sub write_mem( $$$ ) {
    my ($self, $retries, $seconds) = @_;
    mypr "writing config to nvram\n";
    my $output;
    my $written = 0;
    my $tries   = 0;
    while (not $written) {
        $output = $self->shcmd('write memory');
        $tries++;
        if ($output =~ /Building configuration/) {
            mypr "seems ok\n";
            $written = 1;
        }
        elsif ($output =~ /startup-config file open failed/i) {
            if ($tries > $retries) {
                errpr
                  "startup-config file open failed $tries times - giving up\n";
            }
            else {
                warnpr
                  "startup-config file open failed $tries times - sleeping "
                  . "$seconds seconds then trying again\n";
                sleep $seconds;
            }
        }
        else {
            errpr "Unexpected result for write memory. Check *.tel file\n";
        }
    }
}

sub compare_ram_with_nvram( $ ) {
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

sub schedule_reload ( $$ ) {
    my ($self, $minutes) = @_;
    mypr "schedule reload in $minutes minutes\n";
    my $psave = $self->{ENAPROMPT};
    $self->{ENAPROMPT} = qr/\[yes\/no\]:|\[confirm\]/;
    my $out = $self->shcmd("reload in $minutes");

    #$tel->buffer_empty;
    $self->{ENAPROMPT} = qr/\[confirm\]/;
    if ($out =~ /ave/) {

        # someone has fiddled with the router ;)
        $self->device_cmd('n');
    }
    $self->{ENAPROMPT} = $psave;
    $self->device_cmd('');
    $self->{RELOAD_SCHEDULED} = 1;
    mypr "reload scheduled\n";
}

sub cancel_reload ( $ ) {
    my ($self) = @_;
    if (exists $self->{RELOAD_SCHEDULED}
        and $self->{RELOAD_SCHEDULED} == 1)
    {
        mypr "cancel reload ";

        # workaround: wait longer
        my $con = $self->{CONSOLE};
        my $tt  = $con->{TIMEOUT};
        $con->{TIMEOUT} = 2 * $tt;
        mypr "(timeout temporary set from $tt sec to $con->{TIMEOUT} sec)\n";
        $self->device_cmd('reload cancel');
        $con->{TIMEOUT} = $tt;

        # we have to wait for the

        # ***
        # *** --- SHUTDOWN ABORTED ---
        # ***

        # lines, hopefully
        unless ($con->con_wait("--- SHUTDOWN ABORTED ---", $con->{TIMEOUT})) {
            warnpr "*** --- SHUTDOWN ABORTED --- $con->{RESULT}->{ERROR}\n";
        }
        unless ($con->con_wait(qr/\*\*\*/, $con->{TIMEOUT})) {
            warnpr "***  $con->{RESULT}->{ERROR}\n";
        }

        # really no reload scheduled?
        my $out = $self->shcmd('sh reload');
        unless ($out =~ /No reload is scheduled/) {
            warnpr "could not cancel reload\n";
        }
        else {
            $self->{RELOAD_SCHEDULED} = 0;
        }
    }
}

#
# check for existence of (spoc)interface on device
# and check for textual identical acls
#
sub compare_interface_acls {
    my ($self, $conf, $spoc_conf) = @_;

    mypr "===== compare (incoming) acls =====\n";
    for my $intf (values %{ $spoc_conf->{IF} }) {
	my $name = $intf->{name};
        unless ($intf->{ACCESS_GROUP_IN}) {
            warnpr "no spoc-acl for interface $name\n";
            next;
        }

        # there *is* an access-list
        my $conf_intf = $conf->{IF}->{$name};
	if(not $conf_intf) {
            errpr "interface not found on device: $name\n";
            next;
        }
        if ($self->{FORCE_TRANSFER}) {
            $intf->{TRANSFER} = 1;
            warnpr "Interface $name: transfer of ACL forced!\n";
            next;
        }
        my $sa_name = $intf->{ACCESS_GROUP_IN};
        my $ca_name;
        if (my $ca_name = $conf_intf->{ACCESS_GROUP_IN}) {
            if ($conf->{ACCESS_LIST}->{$ca_name}) {
                mypr "interface $name - spoc: $sa_name, actual: $ca_name\n";
		if (not 
		    $self->acl_equal(
			$conf->{ACCESS_LIST}->{$ca_name}->{LIST},
			$spoc_conf->{ACCESS_LIST}->{$sa_name}->{LIST},
			$ca_name, $sa_name, "interface $name"
		    )
		    )
		{
		    $intf->{TRANSFER} = 1;
		}
            }
            else {
                $intf->{TRANSFER} = 1;
                warnpr "acl $ca_name does not exist on device!\n";
                next;
            }
        }
        else {
            $intf->{TRANSFER} = 1;
            warnpr "no incoming acl found at interface $name\n";
            next;
        }
    }
    mypr "===== done ====\n";
}

sub append_acl_entries( $$$ ) {
    my ($self, $name, $entries) = @_;
    $self->cmd('configure terminal');
    $self->cmd("ip access-list extended $name");
    my $counter = 0;
    for my $c (@$entries) {
        my $acl = $c->{orig};
        $self->cmd($acl);
        $counter++;
        mypr " $counter";
    }
    mypr "\n";
    $self->cmd('end');
}

#
# *** access-lists processing ***
#
sub process_interface_acls ( $$$ ) {
    my ($self, $conf, $spoc_conf) = @_;
    mypr "======================================================\n";
    mypr "establish new acls for device\n";
    mypr "======================================================\n";

    #
    # possible acl-names are (per name convention):
    #
    # <spoc-name>-DRC-0
    # <spoc-name>-DRC-1
    #
    # because the spoc-name may change unexpected drc.pl scans for "-DRC-x" to
    # identify spoc-related acls
    #
    for my $intf (values %{ $spoc_conf->{IF} }) {
	my $name = $intf->{name};
        $intf->{ACCESS_GROUP_IN} and $intf->{TRANSFER} or next;
        my $confacl =  $conf->{IF}->{$name}->{ACCESS_GROUP_IN} || '';

        # check acl-names
        my $aclindex;
        if ($confacl =~ /\S+-DRC-([01])/) {

            # active acls matches name convention
            $aclindex = (not $1) * 1;
        }
        else {
            if ($confacl) {
                warnpr "unexpected acl-name $confacl at interface $name\n";
            }
            else {
                warnpr "no acl found at interface $name\n";
            }
            $aclindex = 0;
        }

        # generate *new* access-list entries
        my $spocacl = $intf->{ACCESS_GROUP_IN};
        my $aclname = "$spocacl-DRC-$aclindex";
        $self->{CHANGE}->{ACL} = 1;

        #
        # *** SCHEDULE RELOAD ***
        #
        $self->schedule_reload(5);

        #
        # begin transfer
        #
        mypr "create *new* acl $aclname on device\n";

        #
        # maybe there is an old acl with $aclname:
        # first remove old entries because acl should be empty - otherwise
        # new entries are only appended - bad
        #
        $self->cmd('configure terminal');
        $self->cmd("no ip access-list extended $aclname");
        $self->cmd('end');
        $self->cancel_reload();

        # hopefully this is not critical!
        $self->append_acl_entries($aclname, 
				  $spoc_conf->{ACCESS_LIST}->{$spocacl}->{LIST});

        #
        # *** SCHEDULE RELOAD ***
        #
        $self->schedule_reload(5);

        #
        # assign new acl to interfaces
        #
        mypr "assign new acl:\n";
        $self->cmd('configure terminal');
        mypr " interface $name\n";
        $self->cmd("interface $name");
        mypr " ip access-group $aclname in\n";
        $self->cmd("ip access-group $aclname in");
        $self->cmd('end');

        #
        # delete old ACL (if present)
        #
        $self->cmd('configure terminal');
        if ($confacl && exists $conf->{ACCESS_LIST}->{$confacl}) {
            mypr "no ip access-list extended $confacl\n";
            $self->cmd("no ip access-list extended $confacl");
        }
        $self->cmd('end');
        $self->cancel_reload();
        mypr "---\n";
    }
    mypr "======================================================\n";
    mypr "done\n";
    mypr "======================================================\n";
}

sub generic_interface_acl_processing ( $$$ ) {
    my ($self, $conf, $spoc_conf) = @_;

    # check if anything to do
    unless ($spoc_conf->{IF}) {
        warnpr "no interfaces specified - leaving access-lists untouched\n";
        return 1;
    }

    # check for outgoing ACLS
    for my $intf (values %{ $conf->{IF} }) {
        if (my $acl = $intf->{ACCESS_GROUP_OUT} and not $intf->{SHUTDOWN})
        {
            warnpr
              "interface $intf->{name}: outgoing acl $acl detected\n";
        }
    }
    $self->{CHANGE}->{ACL} = 0;
    $self->compare_interface_acls($conf, $spoc_conf) or return 0;

    # check which spocacls really have to be transfered
    if ($self->{COMPARE}) {
        for my $if (keys %{ $spoc_conf->{IF} }) {
            if ($spoc_conf->{IF}->{$if}->{TRANSFER}) {
                $self->{CHANGE}->{ACL} = 1;
                last;
            }
        }
        return 1;
    }
    else {

	# transfer
	$self->process_interface_acls($conf, $spoc_conf) or return 0;
    }
}

###############################
#
# BEGIN crypto processing
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
sub crypto_struct_equal( $$$$$ );

sub crypto_struct_equal( $$$$$ ) {
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
                    if ($upper_context eq "INSTANCES") {

                        # this MUSTbe the sequence number from DEVICE!!!!
                        $context = $spoc->[$i]->{SEQU};
                    }
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
						 $conf->{$key}, $spoc->{$key}, $key
						 )
				)
                        {
                            $equal = 0;
                        }
                    }
                    elsif ($key eq "name" or $key eq 'orig' or
			   $key eq 'FILTER_ACL' or $key eq 'MATCH_ACL')
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

sub crypto_processing( $$$ ) {
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
                warnpr "severe diffs in crypto isakmp detected!\n";
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
                    'INSTANCES', $changes, ''
                )
              )
            {
                errpr
                  "severe diffs in crypto map detected - leaving crypto untouched\n";
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

                        #new acl established - old one should be removed:
                        $surplus_acls{$conf_acl_name} = 1;
                    }
                }
                mypr " --- done processing results ---\n";
            }
        }

        # Remove surplus ACLs if still present
        unless ($self->{COMPARE}) {
            mypr " --- begin remove surplus acls ---\n";

            # *** SCHEDULE RELOAD ***
            # TODO: check if 3 minutes are OK
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
        ##################################################
        # in ezvpn mode we grant that the tunnel is terminatet at some
        # virtual interface. this interface holds an ACL
        # the ACL is checked by standard ACL code
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
                warnpr "severe diffs in crypto ipsec detected!\n";
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

sub transfer() {
    my ($self, $conf, $spoc_conf) = @_;

    # *** BEGIN TRANSFER ***
    $self->generic_interface_acl_processing($conf, $spoc_conf) or return 0;
    $self->crypto_processing($conf, $spoc_conf);
    $self->process_routing($conf, $spoc_conf);

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
        $self->cancel_reload();
        if (grep { $_ } values %{ $self->{CHANGE} }) {

            # check config size
            mypr "re-read config\n";
	    my $result = $self->issue_cmd('show running');
            $self->cmd_check_error(\$result->{BEFORE}) or 
		errpr "Possible Problem with config size:"
		. " config was NOT written!\n";

            # save config
            mypr "ok\n";
            $self->write_mem(5, 3);    # 5 retries, 3 seconds intervall
        }
        else {
            mypr "no changes to save - check if startup is uptodate:\n";

            #
            # Handle past problems with write mem compare
            # running  with startup config
            #
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

