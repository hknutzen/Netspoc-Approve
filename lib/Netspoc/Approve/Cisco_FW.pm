
package Netspoc::Approve::Device::Cisco::Firewall;

# Authors: Arne Spetzler, Heinz Knutzen, Daniel Brunkhorst
#
# Description:
# module to remote configure cisco firewalls (PIX, ASA, Fwsm)
#

'$Id$ ' =~ / (.+),v (.+?) /;

my $id = "$1 $2";

use strict;
use warnings;
use base "Netspoc::Approve::Device::Cisco";
use IO::Socket ();
use Netspoc::Approve::Helper;
use Netspoc::Approve::Device::Cisco::Parse;

sub version_drc2_Firewall() {
    return $id;
}

sub dev_cor ($$) {
    my ($self, $addr) = @_;
    return $addr;
}

sub parse_address {
    my ($self, $arg) = @_;

    if(check_regex('object-group', $arg)) {
	my $result;
	$result->{OBJECT_GROUP} = get_token($arg);
	return $result;
    }
    else {
	return $self->SUPER::parse_address($arg);
    }
}

#############################################
#
#  global [(<ext_if_name>)] <nat_id>
#         {<global_ip>[-<global_ip>] [netmask <global_mask>]} | interface
#
sub parse_global {
    my ($self, $arg) = @_;
    my $result;

    my $token = get_token($arg);
    $token =~ /\((.*)\)/ or err_at_line($arg, "Parenthesis expected");
    $result->{EXT_IF_NAME} = $1;
    $result->{NAT_ID} = get_token($arg);
    if(check_regex('interface', $arg)) {
	$result->{INTERFACE} = 1;
    }
    else {
	my $range = get_token($arg);
	my ($begin, $end) = split(/-/, $token);
	$result->{BEGIN} = quad2int($begin) or err_at_line($arg, 'IP expected');
	if($end) {
	    $result->{END} = quad2int($end) or err_at_line($arg, 'IP range expected');
	}
    }
    return $result;
}

#############################################
#
# nat [(<real_ifc>)] <nat-id>
#                {<real_ip> [<mask>]} | {access-list <acl_name>}
#                [dns] [norandomseq] [outside] [<max_conn> [<emb_limit>]]
#
sub parse_nat {
    my ($self, $arg) = @_;
    my $result;

    my $token = get_token($arg);
    $token =~ /\((.*)\)/ or err_at_line($arg, "Parenthesis expected");
    $result->{IF_NAME} = $1;
    $result->{NAT_ID} = get_token($arg);
    if(check_regex('access-list', $arg)) {
	$result->{ACCESS_LIST} = get_token($arg);
    }
    else{
	$result->{BASE} = get_ip($arg);
	$result->{MASK} = get_ip($arg);
    }
    $result->{DNS} = check_regex('dns', $arg);
    $result->{OUTSIDE} = check_regex('outside', $arg);
    if($result->{MAX_CONS} = check_int($arg)) {
	$result->{EMB_LIMIT} = check_int($arg);
    }
    $result->{NORANDOMSEQ} = check_regex('norandomseq', $arg);
    return $result;
}

#############################################
#
# static syntax from pix OS 6.3 documentation:
#
# static [(local_ifc,global_ifc)] {global_ip | interface} {local_ip [netmask mask] | access-list acl_name} [dns] [norandomseq] [max_conns [emb_limit]]
# static [(local_ifc,global_ifc)] {tcp | udp} {global_ip | interface} global_port {local_ip local_port [netmask mask] | access-list acl_name} [dns] [norandomseq] [max_conns [emb_limit]]
#
###     static_line:  local_global  translation [dns] [norandomseq] [max_conns]
#
# [dns] disabled due to documentation flaw!!!
# -> instead parse dns in trans_nat and trans_pat
#
# => another flaw: order of last two item weired
sub parse_static {
    my ($self, $arg) = @_;
    my $result;

    my $local_global = get_token($arg);
    $local_global =~ /\((\S+),(\S+)\)/ or err_at_line($arg, 'Syntax');
    $result->{LOCAL_IF}  = $1;
    $result->{GLOBAL_IF} = $2;
    my $global = $result->{GLOBAL} = {};
    my $local  = $result->{LOCAL}  = {};
    my $type = $result->{TYPE} = check_regex('tcp|udp', $arg) || 'ip';
    if(my $ip = get_ip($arg)) {
	$global->{BASE} = $ip;
    }
    else {
	get_regex('interface', $arg);
	$global->{INTERFACE} = 1;
    }
    $type ne 'ip' and $global->{PORT} = $self->parse_port($type, $arg);
    if(my $ip = get_ip($arg)) {
	$local->{BASE} = $ip;
	$type ne 'ip' and  $local->{PORT} = $self->parse_port($type, $arg);
	$local->{DNS} = check_regex('dns', $arg);
	if(check_regex('netmask', $arg)) {
	    $local->{NETMASK} = get_ip($arg);
	}
    }
    else {
	check_regex('access-list', $arg);
	$local->{ACCESS_LIST} = get_token($arg);
	$local->{DNS} = check_regex('dns', $arg);
    }
    if(defined($result->{MAX_CONS} = check_int($arg))) {
	$result->{EMB_LIMIT} = check_int($arg);
    }
    $result->{NORANDOMSEQ} = check_regex('norandomseq', $arg);
    return $result;
}

#
#  pix os 7.x and FWSM
#
# interface <hardware_id>
#
sub parse_interface_section {
    my ($self, $arg) = @_;
    my $result;

    my $id = get_token($arg);
    for my $arg (@{ $arg->{sub} }) {
	my $cmd = get_token($arg);
	if($cmd eq 'shutdown') {
	    $result->{SHUTDOWN} = 1;
	}
	elsif($cmd eq 'speed') {
	    $result->{HW_SPEED} = get_int($arg);
	}
	elsif($cmd eq 'duplex') {
	    $result->{DUPLEX} = get_token($arg);
	}
	elsif($cmd eq 'nameif') {
	    $result->{IF_NAME} = get_token($arg);
	}
	elsif($cmd =~ /^(:?no (:?nameif|security-level|ip address))$/) {

	    # ignore; don't set attribute
	}
	elsif($cmd eq 'security-level') {
	    $result->{SECURITY} = get_int($arg);
	}
	elsif($cmd eq 'ip address') {
	    $result->{BASE} = get_ip($arg);
	    $result->{MASK} = get_ip($arg);
	    if(check_regex('standby', $arg)) {
		$result->{STANDBY} = get_ip($arg);
	    }
	}
	elsif($cmd eq 'management-only') {
	    $result->{MANAGEMENT_ONLY} = 1;
	}
	else {

	    # Ignore other commands.
	    while(check_token($arg)) {};
	}
	$self->get_eol($arg);
    }

    # postprocess defaults
    $result->{HW_SPEED} ||= 'auto';
    $result->{DUPLEX}   ||= 'auto';

    return($result, $id);
}

#############################################
#
# access-group <access_list_name> in interface <if_name>
#
sub parse_access_group {
    my ($self, $arg) = @_;
    my $result;

    my $name = get_token($arg);
    get_regex('in', $arg);
    check_regex('interface', $arg);
    $result->{IF_NAME} = get_token($arg);
    return($result, $name);
}

#############################################
#
# route  syntax from pix OS 6.3 documentation:
#
# route if_name ip_address netmask gateway_ip [metric]
#
sub parse_route {
    my ($self, $arg) = @_;
    my $result;

    $result->{IF}      = get_token($arg);
    $result->{BASE}    = get_ip($arg);
    $result->{MASK}    = get_ip($arg);
    $result->{NEXTHOP} = get_ip($arg);
    $result->{METRIC}  = check_int($arg);
    return $result;
}


#   crypto map map-name client [token] authentication aaa-server-name
#   crypto map map-name client configuration address initiate | respond
#   crypto map map-name interface interface-name
#   crypto map map-name seq-num ipsec-isakmp | ipsec-manual [dynamic dynamic-map-name]
#-> crypto map map-name seq-num match address acl_name
#   crypto map map-name seq-num set peer {ip_address | hostname}
#   crypto map map-name seq-num set pfs [group1 | group2]
#   crypto map map-name seq-num set security-association lifetime seconds seconds |kilobytes kilobytes
#   crypto map map-name seq-num set session-key inbound | outbound ah spi hex-key-string
#   crypto map map-name seq-num set session-key inbound | outbound esp spi cipher hex-key-string [authenticator hex-key-string]
#   crypto map map-name seq-num set transform-set transform-set-name1 [... transform-set-name6]
#
# (only subset '->' implemented yet)
#
# ->{MAP}->{<map-name>}->{SEQ_NUM}->{<seq-num>}->{MATCH_ADDRESS}



#############################################
#
# object-group  syntax from pix OS 6.3 documentation:
#
#
# [no] object-group icmp-type grp_id
#   ICMP type group subcommands:
#   description description_text
#   icmp-object icmp_type
#   group-object grp_id
# [no] object-group network grp_id
#   network group subcommands:
#   description description_text
#   network-object host host_addr
#   network-object host_addr mask
#   group-object grp_id
# [no] object-group protocol grp_id
#   protocol group subcommands:
#   description description_text
#   protocol-object protocol
#   group-object grp_id
# [no] object-group service grp_id {tcp | udp | tcp-udp}
#   service group subcommands:
#   description description_text
#   port-object range begin_service end_service
#   port-object eq service
#   group-object grp_id
# clear object-group [grp_type]
# show object-group [id grp_id | grp_type]
#
#
# *** only type 'network' implemented ***
#
sub parse_object_group {
    my ($self, $arg) = @_;
    my $result;

    my $type = $result->{TYPE} = get_token($arg);
    $type eq 'network' or err_at_line($arg, "Not implemented: $type");
    my $name = get_token($arg);
    for my $arg (@{ $arg->{sub} }) {
	my $cmd = get_token($arg);
	if($cmd eq 'description') {
	    $result->{DESCRIPTION} = get_token($arg);
	}
	elsif($cmd eq 'network-object') {
	    push @{ $result->{NETWORK_OBJECT} }, $self->parse_address($arg);
	}
	elsif($cmd eq 'group-object') {
	    err_at_line('Nested object group not supported');
	}
	else {
	    err_at_line($arg, 'Unknown subcommand');
	}
	get_eol($arg);

    }
    return($result, $name);
}

##################################################################
##################################################################

# access-list deny-flow-max n
#
# access-list alert-interval secs
#
# access-list [id] compiled
#
# access-list id [line line-num] remark text
#
# access-list id [line line-num] {deny  | permit }{protocol | object-group protocol_obj_grp_id
#  {source_addr | local_addr} {source_mask | local_mask} | object-group network_obj_grp_id
#  [operator port [port] | interface if_name | object-group service_obj_grp_id]
#  {destination_addr | remote_addr} {destination_mask | remote_mask} | object-group
#  network_obj_grp_id [operator port [port] | object-group service_obj_grp_id]} [log [[disable
#  | default] | [level] [interval secs]]
#
# access-list id [line line-num] {deny  | permit } icmp  {source_addr | local_addr} {source_mask
#  | local_mask} | interface if_name | object-group network_obj_grp_id {destination_addr |
#  remote_addr} {destination_mask | remote_mask} | interface if_name | object-group
#  network_obj_grp_id [icmp_type | object-group icmp_type_obj_grp_id] [log [[disable |
#  default] | [level] [interval secs]]

#
# fill arrays (do not expand object-group lines)
#
#      ->{<acl-name>}->{RAW_ARRAY}
#
# up to pix os 6.3
#
#   ... with extension for pix os 7.x (keyword 'extended')
#
#
sub parse_access_list {
    my ($self, $arg) = @_;
    my $result;

    my $name = get_token($arg);
    if($name eq 'compiled') {
	
	# ignore access-list compiled
    }
    elsif($name =~ /(:?deny-flow-max|alert-interval)/) {
	get_int($arg);
    }
    elsif(check_regex('compiled', $arg)) {

	# ignore access-list id compiled
    }
    elsif(my $remark = check_regex('remark', $arg)) {
	$result->{REMARK} = get_token($arg);
    }	
    else {
	check_regex('extended', $arg);
	$result->{MODE} = get_regex('permit|deny', $arg);
	my $proto = get_token($arg);
	$proto eq 'object-group' and err_at_line($arg, 'Unsupported');
	if($proto eq 'ip') {
	    $result->{SRC} = $self->parse_address($arg);
	    $result->{DST} = $self->parse_address($arg);
	}
	elsif($proto eq 'udp' || $proto eq 'tcp') {

	    # Combine keys of both results.
	    $result->{SRC} = { %{$self->parse_address($arg)}, 
			       %{$self->parse_port_spec($proto, $arg)} };
	    $result->{DST} = { %{$self->parse_address($arg)}, 
			       %{$self->parse_port_spec($proto, $arg)} };
	}
	elsif($proto eq 'icmp') {
	    $result->{SRC} = $self->parse_address($arg);
	    $result->{DST} = $self->parse_address($arg);
	    $result->{SPEC} = $self->parse_icmp_spec($arg);
	}
	else {
	    $proto = $IP_Trans{$proto} || $proto;
	    $proto =~ /^\d+$/ 
		or $self->err_at_line($arg, "Expected numeric proto '$proto'");
	    $proto =~ /^(1|6|17)$/
		and $self->err_at_line($arg, "Don't use numeric proto for", 
				       " icmp|tcp|udp: '$proto'");
	    $result->{SRC} = $self->parse_address($arg);
	    $result->{DST} = $self->parse_address($arg);
	}
	$result->{TYPE} = $proto;
	if(my $set = check_regex('log', $arg)) {
	    my $log = $result->{LOG} = { SET => 1};
	    if(my $mode = check_regex('disable|default', $arg)) {
		$log->{MODE} = $mode;
	    }
	    else {
		if (my $level = get_int($arg)) {
		    $log->{LEVEL} = $level;
		}
		if (check_regex('interval', $arg)) {
		    $log->{INTERVAL} = get_int($arg);
		}
	    }
	}
    }
    return $result, $name, 'push';
}

sub static_global_local_match_a_b( $$$ ) {

    #
    # this is for raw processing: we want to kick out the netspoc static,
    # if the raw entrys covers the netspoc entry totally.
    #
    #        - used to overwrite netspoc generated statics
    #
    # possible results:
    #
    #        0 - no match
    #        1 -  match or inclusion
    #        2 -  match with intersection
    #        3 -  warning
    #
    my ($self, $a, $b) = @_;
    my $result = 0;
    $a->{LOCAL_IF} eq $b->{LOCAL_IF} && $a->{GLOBAL_IF} eq $b->{GLOBAL_IF}
      or return 0;

    # global
    my $ga = $a->{GLOBAL};
    my $gb = $b->{GLOBAL};
    unless (defined $ga->{'INTERFACE'} xor defined $gb->{'INTERFACE'}) {
        defined $ga->{'INTERFACE'}
          and do { $ga->{'INTERFACE'} eq $gb->{'INTERFACE'} and return 3 }
    }

    # local
    my $la = $a->{LOCAL};
    my $lb = $b->{LOCAL};
    unless ($la->{ACCESS_LIST} xor $lb->{ACCESS_LIST}) {
        $la->{ACCESS_LIST} and do {
            $la->{ACCESS_LIST}->{NAME} eq $lb->{ACCESS_LIST}->{NAME}
              or return 3;
        };
    }

    # masks
    (defined $la->{NETMASK} and defined $lb->{NETMASK})
      or return 3;    # pix uses some kind of mask detection
                      # so we force hand crafted masks here ;)
    my $amask = defined $la->{NETMASK} ? $la->{NETMASK} : 0xffffffff;
    my $bmask = defined $lb->{NETMASK} ? $lb->{NETMASK} : 0xffffffff;

    #local
    $result = ip_netz_a_in_b(
        { 'MASK' => $amask, 'BASE' => $la->{BASE} },
        { 'MASK' => $bmask, 'BASE' => $lb->{BASE} }
    ) and return $result;

    #global
    $result = ip_netz_a_in_b(
        { 'MASK' => $amask, 'BASE' => $ga->{BASE} },
        { 'MASK' => $bmask, 'BASE' => $gb->{BASE} }
    ) and return $result;
}

sub static_line_a_eq_b( $$$ ) {
    my ($self, $a, $b) = @_;
    $a->{LOCAL_IF}       eq $b->{LOCAL_IF}
      && $a->{GLOBAL_IF} eq $b->{GLOBAL_IF}
      && $a->{TYPE}      eq $b->{TYPE}
      or return 0;
    my @keylist;

    # global spec
    my $ga = $a->{GLOBAL};
    my $gb = $b->{GLOBAL};
    if ($a->{TYPE} eq 'ip') {
        @keylist = ('BASE', 'INTERFACE');
    }
    else {
        @keylist = ('BASE', 'INTERFACE', 'PORT');
    }
    for my $key (@keylist) {
        (defined $ga->{$key} xor defined $gb->{$key}) and return 0;
        defined $ga->{$key} and do { $ga->{$key} eq $gb->{$key} or return 0 }
    }

    # local spec
    my $la = $a->{LOCAL};
    my $lb = $b->{LOCAL};
    if ($a->{TYPE} eq 'ip') {
        @keylist = ('BASE', 'NETMASK', 'DNS');
    }
    else {
        @keylist = ('BASE', 'PORT', 'NETMASK', 'DNS');
    }
    for my $key (@keylist) {
        (defined $la->{$key} xor defined $lb->{$key}) and return 0;
        defined $la->{$key} and do { $la->{$key} eq $lb->{$key} or return 0 }
    }
    ($la->{ACCESS_LIST} xor $lb->{ACCESS_LIST}) and return 0;
    $la->{ACCESS_LIST}                          and do {
        $la->{ACCESS_LIST}->{NAME} eq $lb->{ACCESS_LIST}->{NAME}
          or return 0;
    };

    # general param
    for my $key ('NORANDOMSEQ', 'MAX_CONS', 'EMB_LIMIT') {
        ($a->{$key} xor $b->{$key}) and return 0;
        $a->{$key} and do { $a->{$key} eq $b->{$key} or return 0; }
    }
    return 1;
}

sub nat_line_a_eq_b( $$$ ) {
    my ($self, $a, $b) = @_;
    $a->{NAT_ID} eq $b->{NAT_ID} && $a->{IF_NAME} eq $b->{IF_NAME}
      or return 0;
    my @keylist = (
        'BASE',        'MASK',     'ACCESS_LIST', 'OUTSIDE',
        'NORANDOMSEQ', 'MAX_CONS', 'EMB_LIMIT'
    );
    for my $key (@keylist) {
        (defined $a->{$key} xor defined $b->{$key}) and return 0;
        defined $a->{$key} and do { $a->{$key} eq $b->{$key} or return 0 }
    }
    return 1;
}

sub global_line_a_eq_b( $$$ ) {
    my ($self, $a, $b) = @_;
    $a->{NAT_ID} eq $b->{NAT_ID} && $a->{EXT_IF_NAME} eq $b->{EXT_IF_NAME}
      or return 0;
    my @keylist = ('BEGIN', 'END');
    for my $key (@keylist) {
        (defined $a->{$key}->{BASE} xor defined $b->{$key}->{BASE}) and return 0;
        defined $a->{$key}->{BASE}
          and do { $a->{$key}->{BASE} eq $b->{$key}->{BASE} or return 0 }
    }
    @keylist = ('INTERFACE', 'NETMASK');
    for my $key (@keylist) {
        (defined $a->{$key} xor defined $b->{$key}) and return 0;
        defined $a->{$key} and do { $a->{$key} eq $b->{$key} or return 0 }
    }
    return 1;
}

##############################################################
# issue command
##############################################################
sub cmd_check_error($$) {
    my ($self, $out) = @_;

    # do ERROR if unexpected line appears
    if ($$out =~ /\n.*\n/m) {
        #### hack start ###
        ($$out =~ /\[OK\]/m) and return 1;    ### for write memory
        ($$out =~ /will be identity translated for outbound/)
          and return 1;                       # identity nat
        ($$out =~ /nat 0 0.0.0.0 will be non-translated/)
          and return 1;                       # identity nat
        ($$out =~ /Global \d+\.\d+\.\d+\.\d+ will be Port Address Translated/)
          and return 1;                       # PAT
        if ($$out =~ /overlapped\/redundant/) {
            ### overlapping statics from netspoc
            my @pre = split(/\n/, $$out);
            for my $line (@pre) {
                warnpr $line, "\n";
            }
            return 1;
        }
        if ($$out =~ /static overlaps/) {
            ### overlapping statics with global from netspoc
            my @pre = split(/\n/, $$out);
            for my $line (@pre) {
                warnpr $line, "\n";
            }
            return 1;
        }
        if ($$out =~ /Route already exists/) {
            ### route warnings
            my @pre = split(/\n/, $$out);
            for my $line (@pre) {
                warnpr $line, "\n";
            }
            return 1;
        }
        if ($$out =~ /ACE not added. Possible duplicate entry/) {
            ### ace warnings
            my @pre = split(/\n/, $$out);
            for my $line (@pre) {
                warnpr $line, "\n";
            }
            return 1;
        }
        ### hack end ###
        my @pre = split(/\n/, $$out);
        for my $line (@pre) {
            errpr_info "+++ ", $line, "\n";
        }
        errpr "+++\n";
        return 0;
    }
    return 1;
}

#
#    *** some checking ***
#
sub checkinterfaces($$$) {
    my ($self, $devconf, $spocconf) = @_;
    mypr " === check for unknown or missconfigured interfaces at device ===\n";
    for my $intf (sort keys %{ $devconf->{IF} }) {
        next if ($devconf->{IF}->{$intf}->{SHUTDOWN} == 1);
        if (not $spocconf->{IF}->{$intf}) {
            warnpr "unknown interface detected: $intf\n";
        }
    }
    mypr " === done ===\n";
}

sub checkbanner {
    my ($self) = @_;
    if ($self->{VERSION} < 6.3) {
        mypr "banner checking disabled for $self->{VERSION}\n";
    }
    else {
	$self->SUPER::checkbanner()
    }
}

sub check_firewall( $$ ) {
    my ($self, $conf) = @_; 

    # NoOp
    # ToDo: check for active fixup
}

#######################################################
# telnet login, check name and set convenient options
#######################################################
sub prepare($) {
    my ($self) = @_;
    $self->{PROMPT}    = qr/\n.*[\%\>\$\#]\s?$/;
    $self->{ENAPROMPT} = qr/\n.*#\s?$/;
    $self->{ENA_MODE}  = 0;
    $self->login_enable() or exit -1;
    mypr "logged in\n";
    $self->{ENA_MODE} = 1;
    my @output = $self->shcmd('') or exit -1;
    $output[1] =~ m/^\n\s?(\S+)\#\s?$/;
    my $name = $1;

    unless ($self->{CHECKHOST} eq 'no') {
        $self->checkidentity($name) or exit -1;
    }
    else {
        mypr "hostname checking disabled!\n";
    }

    # setting Enableprompt again for pix because of performance impact of
    # standard prompt
    $self->{ENAPROMPT} = qr/\x0d$name\S*#\s?$/;

    #
    # set/check  pager settings
    #
    my @tmp = $self->shcmd('sh pager');
    if ($tmp[0] !~ /no pager/) {

        # pix OS 7.x needs conf mode for setting this - because of IDS do
        # not configure automatically
        errpr "pager not disabled - issue \'no pager\' by hand to continue\n";
    }
    mypr "---\n";

    # max. term width is 511 for pix 512 for ios
    @tmp = $self->shcmd('sh ver');
    $tmp[0] =~ /Version +(\d+\.\d+)/i
      or die "fatal error: could not identify PIX Version from $tmp[0]\n";
    $self->{VERSION} = $1;
    if($tmp[0] =~ /Hardware:\s+(\S+),/i) {
	$self->{HARDWARE} = $1;
    }
    else {
	warnpr "could not identify PIX Hardware from $tmp[0]\n";
	$self->{HARDWARE} = 0;	# We compare version _numbers_ later.
    }
    @tmp = $self->shcmd('sh term');
    if ($tmp[0] !~ /511/) {

        if ($self->{VERSION} >= 6.3) {

            # only warn.  otherwise the generated configure message triggers IDS at night
            if ($tmp[0] =~ /idth\s+=\s+(\d+)/) {
                warnpr "Wrong terminal width: $1\n";
            }
            else {
                warnpr "Wrong terminal width: $tmp[0]\n";
            }
            warnpr "terminal width should be 511\n";
        }
        else {
            $self->cmd('term width 511') or exit -1;
        }
    }
    @tmp = $self->shcmd('sh fixup');
    if ($tmp[0] =~ /\n\s*fixup\s+protocol\s+smtp\s+25/) {
        unless ($self->{COMPARE}) {
            $self->cmd('configure terminal') or exit -1;
            $self->cmd('no fixup protocol smtp 25')
              or exit -1;    # needed for enhanced smtp faetures
            mypr "fixup for protocol smtp at port 25 now disabled!\n";
            $self->cmd('quit') or exit -1;
        }
    }
    mypr "-----------------------------------------------------------\n";
    mypr " DINFO: $self->{HARDWARE} $self->{VERSION}\n";
    mypr "-----------------------------------------------------------\n";
}

sub get_config_from_device( $ ) {
    my ($self) = @_;

    my @out = $self->shcmd('wr t') or exit -1;
    my @conf = split /(?=\n)/, $out[0];
    mypr "got config from device\n";
    return (\@conf);
}

##############################################################
# rawdata processing
##############################################################
sub merge_rawdata {
    my ($self, $spoc_conf, $raw_conf) = @_;

    # Routing
    $self->SUPER::merge_rawdata($spoc_conf, $raw_conf);

    # access-list 
    keys %{$raw_conf->{OBJECT_GROUP}} and 
	die "Raw config must not use object-groups";
    $self->merge_acls($spoc_conf, $raw_conf, 'ACCESS_LIST');

    #static 
    my @std_static = ();
    if ($raw_conf->{STATIC}) {
	my @remove = ();
	for my $s (@{ $raw_conf->{STATIC} }) {
	    my $covered = 0;
	    for (my $i = 0 ; $i < scalar @{ $spoc_conf->{STATIC} } ; $i++) {
		my $spoc  = $spoc_conf->{STATIC}[$i];
		my $match = 0;
		if ($self->static_line_a_eq_b($spoc, $s)) {
		    warnpr "RAW: ignoring useless: '$s->{orig}'\n";
		    $covered = 1;
		}
		elsif ($match =
		       $self->static_global_local_match_a_b($spoc, $s))
		{
		    unless ($match == 3) {
			mypr "RAW: spoc static \'",
			$spoc->{orig},
			" replaced by \'",
			$s->{orig}, "\'\n";
			push @remove, $i;
		    }
		    else {
			warnpr "RAW: weired match RAW: \'",
			$s->{orig}, "\'\n";
			warnpr "RAW: weired match SPOC: \'",
			$spoc->{orig}, "\'\n";
			warnpr "RAW: static discarded!\n";
			$covered = 1;
		    }
		}
	    }
	    $covered or push @std_static, $s;
	}
	for my $r (reverse sort @remove) {
	    splice @{ $spoc_conf->{STATIC} }, $r, 1;
	}
	@{ $spoc_conf->{STATIC} } = (@{ $spoc_conf->{STATIC} }, @std_static),
	mypr " attached static entries: " . scalar @std_static . "\n";
    }

    # global + nat 
    for my $x (qw(GLOBAL NAT)) {
	my $raw_x = $raw_conf->{$x} or next;
	my $cmp_method = $x eq 'NAT' ? 'nat_line_eq_a_b' : 'global_line_a_eq_b';
	my @add = ();
	for my $raw (@$raw_x) {
	    my $covered = 0;
	    for my $spoc (@{ $spoc_conf->{$x} }) {
		if ($self->$cmp_method($spoc, $raw)) {
		    warnpr "RAW: ignoring useless: '$raw->{orig}'\n";
		    $covered = 1;
		}
	    }
	    $covered or push @add, $raw;
	}
	push(@{ $spoc_conf->{$x} }, @add);
	mypr " attached $x entries: " . scalar @add . "\n";
    }
}


# Supports only object-group type 'network', no nested groups.
sub expand_acl_entry($$$$) {
    my ($self, $ace, $parsed, $acl_name) = @_;

    my $groups = $parsed->{OBJECT_GROUP};
    my $replace;
    my @expanded;
    for my $adr ('SRC', 'DST') {
        if (my $obj_id = $ace->{$adr}->{OBJECT_GROUP}) {
            my $group = $groups->{$obj_id} or
		errpr meself(1), "no group name '$obj_id' found\n";
            $group->{TYPE} eq 'network' or
                errpr meself(1),
                  "unsupported object type '$group->{TYPE}'\n";
	    push(@{ $replace->{$adr} }, @{ $group->{NETWORK_OBJECT} });

            # Remember that group $obj_id is referenced by ACL $acl 
	    # and vice versa.
            $parsed->{group2acl}->{$obj_id}->{$acl_name} = 1;
            $parsed->{acl2group}->{$acl_name}->{$obj_id} = 1;
        }
        else {
            push @{ $replace->{$adr} }, $ace->{$adr};
        }
    }
    for my $src (@{ $replace->{SRC} }) {
        for my $dst (@{ $replace->{DST} }) {
            my $copy = { %$ace };
            $copy->{SRC} = $src;
            $copy->{DST} = $dst;
            push @expanded, $copy;
        }
    }
    return \@expanded;
}

sub get_parse_info {
    my ($self) = @_;
    { 'global' => ['parse_global', 'GLOBAL'],
      'nat' => ['parse_nat', 'NAT'],
      'static' => ['parse_static', 'STATIC'],
      'route' => ['parse_route', 'ROUTING'],
      'access-group' => ['parse_access_group', 'ACCESS_GROUP'],
      'object-group' => ['parse_object_group', 'OBJECT_GROUP'],
      'access-list' => ['parse_access_list', 'ACCESS_LIST'],
      'crypto' => ['parse_crypto', 'CRYPTO'],
      'interface' => ['parse_interface_section', 'HWIF'],
    };
}

sub postprocess_config {
    my ($self, $p) = @_;

    # Expand object-groups in access-lists.
    for my $acl_name (keys %{ $p->{ACCESS_LIST} }) {
        my %seen_acl;
        for my $entry (@{ $p->{ACCESS_LIST}->{$acl_name} }) {

	    # Filter out 'remark'.
            next if not $entry->{MODE}; 

            my $e_acl = $self->expand_acl_entry($entry, $p, $acl_name);
	    push @{$p->{ACCESS}->{$acl_name}},@$e_acl;
        }
    }

    # access-group
    for my $acl_name (keys %{ $p->{ACCESS_GROUP} }) {
        my $if_name = $p->{ACCESS_GROUP}->{$acl_name}->{IF_NAME};
        $p->{IF}->{$if_name}->{ACCESS} = $acl_name;
        if (my $acl = $p->{ACCESS_LIST}->{$acl_name}) {
	    $p->{is_filter_acl}->{$acl_name} = 1;
        }
    }

    for my $if (sort keys %{ $p->{IF} }) {
	my $entry = $p->{IF}->{$if};
        if ($entry->{SHUTDOWN}) {
            mypr meself(1) . "Interface $if: shutdown\n";
        }
        else {
            if (my $base = $entry->{BASE}) {
		mypr meself(1)
		    . "Interface $if: IP: "
		    . int2quad($base) . "/"
		    . int2quad($entry->{MASK}) . "\n";
	    }
	    else {
		warnpr
		    "undefined address for non-shutdown interface \'$if\'\n";
	    }
	}
    }

    # crypto maps
    for my $map_name (keys %{ $p->{CRYPTO}->{MAP} }) {
	my $map = $p->{CRYPTO}->{MAP}->{$map_name};
        for my $seq_num (keys %{ $map->{SEQ_NUM} }) {
	    my $entry = $map->{SEQ_NUM}->{$seq_num};
            if (my $acl_name = $entry->{MATCH_ADDRESS}) {
                if ($p->{ACCESS_LIST}->{$acl_name}) {
		    $p->{is_crypto_acl}->{$acl_name} = 1;
                }
                else {
                    warnpr
                      "crypto map match address acl $acl_name does not exist\n";
                }
            }
        }
    }
    mypr meself(1)
      . ": CRYPTO MAPS found: "
      . scalar(keys %{ $p->{CRYPTO}->{MAP} }) . "\n";

    #
    # ****** TO DO: more consistency checking
    #
    mypr meself(1)
      . ": OBJECT GROUPS found: "
      . scalar(keys %{ $p->{OBJECT_GROUP} }) . "\n";
    mypr meself(1)
      . ": ACCESS LISTS found: "
      . scalar(keys %{ $p->{ACCESS_LIST} }) . "\n";
    my $c_acl_counter = 0;
    for my $acl_name (sort keys %{ $p->{ACCESS_LIST} }) {
        if ($p->{is_crypto_acl}->{$acl_name}) {
            $c_acl_counter++;
        }
        elsif ($p->{is_filter_acl}->{$acl_name}) {
            mypr meself(1)
              . ": $acl_name "
              . scalar @{ $p->{ACCESS_LIST}->{$acl_name} } . "\n";
        }
        else {
            mypr meself(1)
              . ": $acl_name "
              . scalar @{ $p->{ACCESS_LIST}->{$acl_name} }
              . " *** SPARE ***\n";
        }
    }
    ($c_acl_counter)
      and mypr "--> found $c_acl_counter acls referenced by crypto maps\n";
    for my $what (qw(GLOBAL NAT STATIC ROUTING)) {
	next if not $p->{$what};
	mypr meself(1) . ": $what found: " . scalar @{ $p->{$what} } . "\n";
    }
}

sub transfer_lines( $$$$$ ) {
    my ($self, $compare, $spoc_lines, $device_lines) = @_;
    my $counter;
    my $change = 0;
    $spoc_lines ||= [];
    $device_lines ||= [];
    mypr "compare device entries with netspoc:\n";
    scalar @{$device_lines} or mypr "-";
    for my $d (@{$device_lines}) {    # from device
        $counter++;
        mypr " $counter";
        for my $s (@{$spoc_lines}) {    # from netspoc
                                        #($s) or next;
            if ($self->$compare($d, $s)) {
                $d->{DELETE} = $s->{DELETE} = 1;
                last;
            }
        }
    }
    mypr "\n";
    unless ($self->{COMPARE}) {
        mypr "deleting non matching entries from device:\n";
        $counter = 0;
        for my $d (@{$device_lines}) {
            ($d->{DELETE}) and next;
            $counter++;
            my $tr = join(' ', "no", $d->{orig});
            $self->cmd($tr) or exit -1;
            mypr " $counter";
        }
        $counter and $change = 1;
        mypr " $counter\n";
        mypr "transfer entries to device:\n";
        $counter = 0;
        for my $s (@{$spoc_lines}) {
            ($s->{DELETE}) and next;
            $counter++;
            $self->cmd($s->{orig}) or exit -1;
            mypr " $counter";
        }
        $counter and $change = 1;
        mypr " $counter\n";
    }
    else {

        # show compare results
        mypr "non matching entries on device:\n";
        $counter = 0;
        for my $d (@{$device_lines}) {
            ($d->{DELETE}) and next;
            $counter++;
            mypr $d->{orig} . "\n";
        }
        mypr "total: " . $counter, "\n";
        ($counter) and $change = 1;
        mypr "additional entries from spoc:\n";
        $counter = 0;
        for my $s (@{$spoc_lines}) {
            ($s->{DELETE}) and next;
            $counter++;
            mypr $s->{orig}, "\n";
        }
        mypr "total: ", $counter, "\n";
        ($counter) and $change = 1;
    }
    return $change;
}

sub acls_identical {
    my ($self, $confacl, $spocacl, $intf) = @_;
    mypr "check for textual identity\n";
    if (@$spocacl != @$confacl) {
        mypr "lenght of acls differ: at device ", scalar @{$confacl},
          " from netspoc ", scalar @{$spocacl}, "\n";
        return 0;
    }
    mypr " acls have equal lenght: ", scalar @$spocacl, "\n";
    mypr " compare line by line: ";
    for (my $i = 0 ; $i < scalar @{$spocacl} ; $i++) {
	if ($self->acl_line_a_eq_b($$spocacl[$i], $$confacl[$i])) {
	    next;
	}
	else {
	    mypr "equal lenght acls (", scalar @{$spocacl}, ") differ at ",
	    ++$i, "!\n";
	    return 0;
	}
    }
    mypr "no diffs\n";

    if ($self->{COMPARE}) {

        # show compare results
        mypr "#### BEGIN NEW in OLD - interface $intf\n";
        my $newinold =
          $self->acl_array_compare_a_in_b($spocacl, $confacl);
        mypr "#### END   NEW in OLD - interface $intf\n";
        mypr "#### BEGIN OLD in NEW - interface $intf\n";
        my $oldinnew =
          $self->acl_array_compare_a_in_b($confacl, $spocacl);
        mypr "#### END   OLD in NEW - interface $intf\n";
        if ($newinold && $oldinnew) {
            mypr "#### ACLs equal for interface $intf\n";
            return 1;
        }
        else {
            mypr "#### ACLs differ - at interface $intf ####\n";
            return 0;
        }
    }
    else {
        mypr "  do semantic compare - at interface $intf:\n";
        if (
            $self->acl_array_compare_a_in_b($spocacl, $confacl)  
            && $self->acl_array_compare_a_in_b($confacl, $spocacl)
          )
        {
            mypr "   -> interface $intf: acls identical\n";
            return 1;
        }
        else {
            mypr "   -> interface $intf: acls differ\n";
            return 0;
        }
    }
}

sub transfer () {
    my ($self, $conf, $spoc_conf) = @_;

    $self->process_routing($conf, $spoc_conf) or return 0;

    if (not $self->{COMPARE}) {
        $self->cmd('configure terminal') or exit -1;
    }

    #
    # *** access-lists ***
    #
    my $get_acl_names_and_objects = sub {
        my ($intf)  = @_;
        my $sa_name = $spoc_conf->{IF}->{$intf}->{ACCESS};
        my $spocacl = $spoc_conf->{ACCESS}->{$sa_name};
        my $ca_name = $conf->{IF}->{$intf}->{ACCESS} || '';
        my $confacl = $ca_name ? $conf->{ACCESS}->{$ca_name} : '';
        return ($confacl, $spocacl, $ca_name, $sa_name);
    };

    # generate new names for transfer
    #
    # possible names are (per name convention):  <spoc-name>-DRC-<index>
    #
    my $generate_names_for_transfer = sub {
        my ($obj_id, $objects) = @_;
        my $new_id_prefix = "$obj_id-DRC-";
        my $new_id_index  = 0;
        while ($objects->{"$new_id_prefix$new_id_index"}) {
            $new_id_index++;
        }
        return "$new_id_prefix$new_id_index";
    };

    my %acl_need_transfer;
    my %group_need_transfer;

    my $mark_for_transfer;
    $mark_for_transfer = sub {
        my ($acl_name) = @_;
	return if $acl_need_transfer{$acl_name};
	$acl_need_transfer{$acl_name} = 1;
        mypr "marked acl $acl_name for transfer\n";
        for my $gid (keys %{ $spoc_conf->{acl2group}->{$acl_name} }) {
            unless ($group_need_transfer{$gid}) {
                $group_need_transfer{$gid} = 1;
                print "marked group $gid for transfer\n";
            }
            for my $name (keys %{ $spoc_conf->{group2acl}->{$gid} }) {
                &$mark_for_transfer($name);
            }
        }
    };

    my %acl_need_remove;
    my %group_need_remove;

    my $mark_for_remove = sub {
        my ($acl_name) = @_;
	$acl_need_remove{$acl_name} and errpr "unexpected REMOVE mark\n";
        $acl_need_remove{$acl_name} = 1;
        mypr "marked acl $acl_name for remove\n";
        for my $gid (keys %{ $conf->{acl2group}->{$acl_name} }) {
            next if $group_need_remove{$gid};
            my $remove_group = 1;
            for my $name (keys %{ $conf->{group2acl}->{$gid} }) {

                # Only remove group from PIX if all ACLs that reference
                # this group are renewed by netspoc.
                unless ($spoc_conf->{ACCESS_LIST}->{$name}->{TRANSFER}) {
                    $remove_group = 0;
                    last;
                }
            }
            if ($remove_group) {
                $group_need_remove{$gid} = 1;
                mypr "marked group $gid for remove\n";
            }
        }
    };
    unless ($spoc_conf->{IF}) {
        warnpr " no interfaces specified - leaving access-lists untouched\n";
    }
    else {
        mypr "processing access-lists\n";

        mypr keys %{ $spoc_conf->{IF} };
        mypr "+++\n";

        for my $intf (keys %{ $spoc_conf->{IF} }) {
            $conf->{IF}->{$intf} or
                die 
		"netspoc configured interface '$intf' not found on device\n";
	}

        # detect diffs
        if ($self->{COMPARE}) {
            for my $intf (keys %{ $spoc_conf->{IF} }) {
                mypr "interface $intf\n";
                my ($confacl, $spocacl, $confacl_name, $spocacl_name) =
                  &$get_acl_names_and_objects($intf);

                if ($confacl_name && $confacl) {
                    $self->acl_equal($confacl, $spocacl, 
				     $confacl_name, $spocacl_name, 
				     "interface $intf")
                        or $self->{CHANGE}->{ACL} = 1;
                }
                else {

                    $self->{CHANGE}->{ACL} = 1;
                    mypr "#### OOPS:  $spocacl_name at interface $intf:\n";
                    mypr "#### OOPS:  no corresponding acl on device\n";
                }
                mypr "-------------------------------------------------\n";
            }
        }
        else {

            # mark objects to transfer
            for my $intf (keys %{ $spoc_conf->{IF} }) {
                mypr "interface $intf\n";
                my ($confacl, $spocacl, $confacl_name, $spocacl_name) =
                  &$get_acl_names_and_objects($intf);
                if ($acl_need_transfer{$spocacl_name}) {
                    mypr " ...already marked for transfer\n";
                    next;
                }
                if (!$confacl) {
                    warnpr "interface $intf no acl on device - new acl has ",
                      scalar @{ $spoc_conf->{ACCESS}->{$spocacl_name} },
                      " entries\n";
                    $self->{CHANGE}->{ACL} = 1;
                    &$mark_for_transfer($spocacl_name);
                }
                elsif (not $self->acl_equal($confacl, $spocacl, 
					    $confacl_name, $spocacl_name, 
					    "interface $intf"))
                {

                    # Either there is no acl on $intf or the acl differs.
                    # Mark groups and interfaces recursive for transfer 
		    # of spocacls
                    $self->{CHANGE}->{ACL} = 1;
                    &$mark_for_transfer($spocacl_name);
                }
                elsif ($self->{FORCE_TRANSFER}) {
                    warnpr "Interface $intf: transfer of ACL forced!\n";
                    $self->{CHANGE}->{ACL} = 1;
                    &$mark_for_transfer($spocacl_name);
                }
                mypr "-------------------------------------------------\n";
            }

            # Mark objects for removal.
            for my $intf (keys %{ $spoc_conf->{IF} }) {
                my ($confacl, $spocacl, $confacl_name, $spocacl_name) =
                  &$get_acl_names_and_objects($intf);
                next if not $acl_need_transfer{$spocacl_name};
                $confacl and $mark_for_remove->($confacl_name);
            }

            # Generate names for transfer.
	    my %new_group_id;
	    my %new_acl_name;
            for my $obj_id (keys %{ $spoc_conf->{OBJECT_GROUP} }) {
                next if not $group_need_transfer{$obj_id};
                $new_group_id{$obj_id} =
                  $generate_names_for_transfer->($obj_id, $conf->{OBJECT_GROUP});
            }
            for my $obj_id (keys %{ $spoc_conf->{ACCESS_LIST} }) {
                next if not $acl_need_transfer{$obj_id};
		$new_acl_name{$obj_id} =
                  $generate_names_for_transfer->($obj_id, $conf->{ACCESS_LIST});
            }

            # Transfer groups.
            mypr "transfer object-groups to device\n";
            for my $obj_id (keys %{ $spoc_conf->{OBJECT_GROUP} }) {
		my $group = $spoc_conf->{OBJECT_GROUP}->{$obj_id};
                next if not $group_need_transfer{$obj_id};
		my $new_id = $new_group_id{$obj_id};
                mypr "object-group $new_id\n";
		my @cmd_array;
		push(@cmd_array,
		     "object-group $group->{TYPE} $new_id",
		     map { $_->{orig} } @{ $group->{sub} },
		     'exit');

                for (@cmd_array) {
		    $self->cmd($_) or exit -1;
                }
            }

            # Transfer ACLs.
            mypr "transfer access-lists to device\n";
            for my $obj_id (keys %{ $spoc_conf->{ACCESS_LIST} }) {
                next if not $acl_need_transfer{$obj_id};
                my $new_id = $new_acl_name{$obj_id};
                mypr "access-list $new_id\n";
                my $cmd;
                for my $ace (@{ $spoc_conf->{ACCESS_LIST}->{$obj_id} }) {
		    $cmd = $ace->{orig};
		    for my $where (qw(src dst)) {
			if (my $gid = $ace->{$where}->{OBJECT_GROUP}) {
			    my $new_gid = $new_group_id{$gid};
			    $cmd =~ s/object-group $gid/object-group $new_gid/;
			}
		    }
		    $cmd =~ s/access-list $obj_id/access-list $new_id/;
                    $self->cmd($cmd) or exit -1;
                }
                mypr "\n";

                # Assign list to interface.
                my $intf = $spoc_conf->{ACCESS_GROUP}->{$obj_id}->{IF_NAME};
                mypr "access-group $new_id in interface $intf\n";
                $self->cmd("access-group $new_id in interface $intf")
                  or exit -1;
            }

            # Remove ACLs.
	    # Do it first, because otherwise group remove would not work.
            mypr "remove spare acls from device\n";
            for my $acl_name (keys %{ $conf->{ACCESS_LIST} }) {
                if (    $conf->{acl2remove}->{$acl_name}
		    and not $conf->{is_filter_acl}->{$acl_name}
		    and not $conf->{is_crypto_acl}->{$acl_name})
                {
		    my $cmd = ($self->{VERSION} >= 7.0) 
  			    ? "clear configure access-list $acl_name"
			    : "no access-list $acl_name";
		    mypr " $cmd\n";
                        $self->cmd($cmd) or exit -1;
                }
            }

            # Remove groups.
            mypr "remove spare object-groups from device\n";
            for my $gid (keys %{ $conf->{OBJECT_GROUP} }) {
                my $type = $conf->{OBJECT_GROUP}->{$gid}->{TYPE};
                if (not $conf->{group2acl}->{$gid}
                    and $conf->{group2remove}->{$gid})
                {
		    my $cmd = "no object-group $type $gid";
                    mypr " $cmd\n";
                    $self->cmd($cmd) or exit -1;
                }
            }
        }
    }

    # STATIC, GLOBAL, NAT
    my %control = (STATIC => static_line_a_eq_b,
		   GLOBAL => global_line_a_eq_b,
		   NAT => nat_line_a_eq_b);
    while(my($type, $method) = each %control) {
	mypr " === processing $type ===\n";
	$self->transfer_lines($method, $spoc_conf->{$type}, $conf->{$type}) and 
	    $self->{CHANGE}->{$type} = 1;
    }

    if (not $self->{COMPARE}) {
        if ($self->{CHANGE})
        {
            mypr "saving config to flash\n";
            $self->cmd('write memory') or exit -1;
            mypr "...done\n";
        }
        else {
            mypr "no changes to save\n";
        }
    }
    else {
        mypr "compare finish\n";
    }
    return 1;
}

# Packages must return a true value;
1;

