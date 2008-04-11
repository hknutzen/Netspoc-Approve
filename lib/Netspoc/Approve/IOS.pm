
package Netspoc::Approve::Device::Cisco::IOS;

# Authors: Arne Spetzler, Heinz Knutzen, Daniel Brunkhorst
#
# Description:
# Remote configure cisco ios router
# 

'$Id$' =~ / (.+),v (.+?) /;  

my $id = "$1 $2";

sub version_drc2_ios(){
    return $id;
}


use base "Netspoc::Approve::Device::Cisco";

use strict;
use warnings;
use FindBin;
use lib $FindBin::Bin;
use Fcntl;
use SDBM_File;
use IO::Socket ();
use Netspoc::Approve::Helper;


sub dev_cor ($$) {
    my ($self, $addr) = @_;
    return ~$addr & 0xffffffff;
}

############################################################
# --- parsing ---
############################################################

#
# ios only
#
# ip inspect name inspection-name ...
#
# only subset implemented !!!!!
#
sub parse_ip_inspect_line( $$$ ) {
    my ($self, $il, $ih) = @_;
    my $p = 0;    # progress indicator
    for (split " ", $il) {
        if ($p == 0) {
            ($_ eq 'ip') && do { $p++; next; };
            die "unexpected token while parsing 'ip' in $il\n";
        }
        if ($p == 1) {
            ($_ eq 'inspect') && do { $p++; next; };
            die "unexpected token while parsing 'inspect' in $il\n";
        }
        if ($p == 2) {
            ($_ eq 'name') && do { $p++; next; };
            if ($_ eq 'audit-trail') {
                $ih->{AUDIT_TRAIL} = 1;
                last;
            }
            elsif ($_ eq 'tcp') {

                # the eats up 'tcp idle-time'
                last;
            }
            die "unexpected token while parsing 'name' in $il\n";
        }
        if ($p == 3) {
            $ih->{NAME} = $_;
            $p++;
            next;
        }
        if ($p == 4) {
            $ih->{SPEC} = $_;
            $p++;
            next;
        }
        if ($p == 5) {
            ($ih->{SPEC} eq "rpc")
              or die "unexpected token $_ in $il\n";
            $ih->{PROG} = $_;
            $p++;
            next;
        }
        if ($p == 6) {
            ($ih->{SPEC} eq "rpc")
              or die "unexpected token $_ in $il\n";
            $ih->{NUM} = $_;
            $p++;
            next;
        }
        if ($p == 7) {
            die "unexpected token $_ in  $il\n";
        }
    }
    return 1;
}

sub parse_route_line ($$$) {
    my ($self, $rl, $rh) = @_;
    my $p = 0;    # progress indicator
                  # ip route destination-prefix destination-prefix-mask
                  #          [interface-type card/subcard/port] forward-addr
         #          [metric | permanent | track track-number | tag tag-value]
         #
         # (partial implemented)
    for (split " ", $rl) {

        if ($p == 0) {
            ($_ eq 'ip') && do { $p++; next; };
            die "unexpected token while parsing 'ip' in $rl\n";
        }
        if ($p == 1) {
            ($_ eq 'route') && do { $p++; next; };
            die "unexpected token while parsing 'route' in $rl\n";
        }
        if ($p == 2) {
            defined($rh->{BASE} = quad2int($_)) && do { $p++; next; };
            die "illegal tupel $_ in $rl\n";
        }
        if ($p == 3) {
            defined($rh->{MASK} = quad2int($_)) && do { $p++; next; };
            die "illegal tupel $_ in $rl\n";
        }
        if ($p == 4) {
            defined($rh->{NEXTHOP} = quad2int($_)) && do { $p++; next; };

            # maybe NexthopInterFace is specified
            unless (exists $rh->{NIF}) {
                $rh->{NIF} = $_;
                $p++;
                next;
            }

            # die "(4) illegal tupel $_ in $rl\n";
        }
        if ($p == 5 or $p == 6) {

            # tag tag-value doesnt work yet
            if ($_ =~ /(\d+)/) {
                if (exists $rh->{MISC} and $rh->{MISC} eq 'track') {
                    $rh->{TRACK_NUMBER} = $1;
                }
                else {
                    $rh->{METRIC} = $1;
                }
                $p++;
                next;
            }
            elsif ($_ eq 'permanent') {
                $rh->{MISC} = $_;
                $p++;
                next;
            }
            elsif ($_ eq 'track') {
                $rh->{MISC} = $_;
                $p++;
                next;
            }

            die "(5) illegal tupel $_ in $rl\n";
        }
        die "unexpected token $_ in $rl\n";
    }

    # to do: check for correct mask
    return 1;
}

sub parse_acl_line ( $$$ ) {
    my ($self, $al, $ah) = @_;
    $self->acl_entry($ah, \$al);
}

##################################################################
#
#       acl syntax derived from cisco ios12.2 documentation
#       pix is using subset of this with inverted masks
#
###    	acl-entry: 	[dynamic] action prot_spec [precedence] [tos] [log] [timerange][fragments]
#
#                  or   remark
#
sub acl_entry($$$) {
    my ($self, $ah, $al) = @_;
    my $result = (
             $self->dynamic($ah, $al)
          && $self->action($ah, $al)
          && $self->prot_spec($ah, $al)
          &&

          # precedence
          # tos
          $self->log_packet($ah, $al)

          # timerange
          # fragments
    ) || $self->remark($ah, $al);
    if ($self->{PRINT}) {
        $$al =~ s/^ +//;
    }
    return $result;
}

###     dynamic:	'dynamic' /\w+/ [timeout]
#
#                        ->{DYNAMIC}->{NAME} (name of dynamic access-list)
sub dynamic($$$) {
    my ($self, $ah, $al) = @_;
    if ($self->{PRINT} and exists $ah->{DYNAMIC}) {
        $$al = join ' ', $$al, 'dynamic', $ah->{DYNAMIC}->{NAME};
    }
    elsif ($$al =~ /\G\s*[Dd]ynamic\s+(\w+)$ts/cgxo) {
        $ah->{DYNAMIC} = { NAME => $1 };
    }
    else {
        return 1;
    }
    $self->timeout($ah->{DYNAMIC}, $al);
    return 1;
}
###     timeout:	'timeout' /\d+/
#
#                       ->{TIMEOUT} (timeout in minutes)
sub timeout($$$) {
    my ($self, $ah, $al) = @_;
    if ($self->{PRINT} and exists $ah->{TIMEOUT}) {
        $$al = join ' ', $$al, 'timeout', $ah->{TIMEOUT};
    }
    elsif ($$al =~ /\G\s*timeout\s+(\d+)$ts/cgxo) {
        $ah->{TIMEOUT} = $1;
    }
}
###   	prot_spec: 	p_ip | p_tcp | p_icmp | p_igmp | p_udp | p_other
#
#                       ->{PROTO}
sub prot_spec($$$) {
    my ($self, $ah, $al) = @_;
    unless ($self->{PRINT}) {
        $ah->{PROTO} = {};
    }
    unless (
           $self->p_tcp($ah->{PROTO}, $al)
        || $self->p_udp($ah->{PROTO}, $al)
        || $self->p_icmp($ah->{PROTO}, $al)
        || $self->p_ip($ah->{PROTO}, $al)
        ||    # faster when ip _not_ at beginning!
              #  $self->p_igmp($ah->{PROTO},$al) ||
        $self->p_other($ah->{PROTO}, $al)
      )
    {
        $self->parse_error($al, "no protocol block found");
    }
    return 1;
}
### (-)	precedence:	'precedence' /\w+/
#
#                       ->{PRECEDENCE} (name or number)
### (-)	tos:		'tos' /\\w+/
#
#                       ->{TOS} (name or number)
###	log:		'log'|'log-input'
#
#                       ->{LOG}
sub log_packet($$$) {
    my ($self, $ah, $al) = @_;
    if ($self->{PRINT}) {
        if ($ah->{LOG}) {
            $$al = join ' ', $$al, $ah->{LOG};
        }
    }
    elsif ($$al =~ /\G\s*(log-input|log)$ts/cgxo) {
        $ah->{LOG} = $1;
    }
    return 1;
}
### (-)	timerange:	'time-range' /\w+/
#
#                       ->{TIME_RANGE} (name of the time-range)
###	p_ip:		'ip' adr adr
#
#                       ->{TYPE}
sub p_ip($$$) {
    my ($self, $ah, $al) = @_;
    if ($self->{PRINT}) {
        if ($ah->{'TYPE'} eq 'ip') {
            $$al = join ' ', $$al, 'ip';
        }
        else {
            return 0;
        }
    }
    elsif ($$al =~ /\G\s*ip$ts/cgxo) {

        # if 'ip' not found return 0
        $ah->{SRC}    = {};
        $ah->{DST}    = {};
        $ah->{'TYPE'} = 'ip';
    }
    else {
        return 0;
    }
    $self->adr($ah->{SRC}, $al);
    $self->adr($ah->{DST}, $al);
    return 1;
}
###	p_tcp:		( 'tcp' | '6' ) adr [spec] adr [spec] [established]
#
#                       ->{TYPE}
sub p_tcp($$$) {
    my ($self, $ah, $al) = @_;
    if ($self->{PRINT}) {
        if ($ah->{TYPE} eq 'tcp' or $ah->{TYPE} eq 6) {
            $$al = join ' ', $$al, $ah->{TYPE};
        }
        else {
            return 0;
        }
    }
    elsif ($$al =~ /\G\s*(tcp|6)$ts/cgxo) {

        # if tcp not found return 0
        $ah->{SRC}  = {};
        $ah->{DST}  = {};
        $ah->{TYPE} = 'tcp';
    }
    else {
        return 0;
    }
    $self->adr($ah->{SRC}, $al);
    $self->{PORTMODE} = \%PORT_Trans_TCP;
    $self->spec($ah->{SRC}, $al);
    $self->adr($ah->{DST}, $al);
    $self->spec($ah->{DST}, $al);
    $self->{PORTMODE} = {};
    $self->established($ah->{DST}, $al);
    return 1;
}
###  established:       'established'
#
#                       ->{ESTA}
sub established($$$) {

    my ($self, $ah, $al) = @_;
    if ($self->{PRINT} and exists $ah->{ESTA}) {
        $$al = join ' ', $$al, $ah->{ESTA};
    }
    elsif ($$al =~ /\G\s*established$ts/cgxo) {
        $ah->{ESTA} = 'established';
    }
}
###	p_udp:		( 'udp' | '17' ) adr [spec] adr [spec]
#
#                       ->{TYPE}
sub p_udp($$$) {
    my ($self, $ah, $al) = @_;
    if ($self->{PRINT}) {
        if ($ah->{TYPE} eq 'udp' or $ah->{TYPE} eq 17) {
            $$al = join ' ', $$al, $ah->{TYPE};
        }
        else {
            return 0;
        }
    }
    elsif ($$al =~ /\G\s*(udp|17)$ts/cgxo) {

        # if udp not found return 0
        $ah->{SRC}  = {};
        $ah->{DST}  = {};
        $ah->{TYPE} = 'udp';
    }
    else {
        return 0;
    }
    $self->adr($ah->{SRC}, $al);
    $self->{PORTMODE} = \%PORT_Trans_UDP;
    $self->spec($ah->{SRC}, $al);
    $self->adr($ah->{DST}, $al);
    $self->spec($ah->{DST}, $al);
    $self->{PORTMODE} = {};
    return 1;
}
###	p_icmp:		( 'icmp' | '1' ) adr adr [icmpmessage]
#
#
sub p_icmp($$$) {
    my ($self, $ah, $al) = @_;
    if ($self->{PRINT}) {
        if ($ah->{TYPE} eq 'icmp' or $ah->{TYPE} eq 1) {
            $$al = join ' ', $$al, $ah->{TYPE};
        }
        else {
            return 0;
        }
    }
    elsif ($$al =~ /\G\s*(icmp|1)$ts/cgxo) {

        # if icmp not found return 0
        $ah->{SRC}  = {};
        $ah->{DST}  = {};
        $ah->{SPEC} = {};
        $ah->{TYPE} = 'icmp';
    }
    else {
        return 0;
    }
    $self->adr($ah->{SRC}, $al);
    $self->adr($ah->{DST}, $al);
    $self->icmpmessage($ah->{SPEC}, $al);
    return 1;
}
###     p_other:        (/\d+/ | <protocol-name>) adr adr
#
#                       ->{TYPE}
sub p_other($$$) {
    my ($self, $ah, $al) = @_;
    if ($self->{PRINT}) {
        my $prot = $ah->{TYPE};
        (exists $Re_IP_Trans{$prot}) and $prot = $Re_IP_Trans{$prot};
        $$al = join ' ', $$al, $prot;
    }
    elsif ($$al =~ /\G\s*($tc+)$ts/cgxo) {
        my $tmp = $1;
        $ah->{SRC} = {};
        $ah->{DST} = {};
        if (exists $IP_Trans{$tmp}) {
            $ah->{TYPE} = $IP_Trans{$tmp};
        }
        elsif ($tmp =~ /\d+/ && 0 <= $tmp && $tmp < 256) {
            $ah->{TYPE} = $tmp;
        }
        else {
            $self->parse_error($al, "unknown ip protocol $1");
        }
    }
    else {
        return 0;
    }
    $self->adr($ah->{SRC}, $al);
    $self->adr($ah->{DST}, $al);
    return 1;
}

#######################################################
# --- printing ---
#######################################################
#
# ios only !
#
sub ip_inspect_line_to_string($$) {
    my ($self, $i) = @_;
    my $r = join ' ', "ip inspect name", $i->{NAME}, $i->{SPEC};
    if ($i->{SPEC} eq 'rpc') {
        $r = join ' ', $r, $i->{PROG}, $i->{NUM};
    }
    return $r;
}

sub route_line_to_string ($$) {
    my ($self, $o) = @_;
    my $r;
    $r = join ' ', "ip route", int2quad $o->{BASE}, int2quad $o->{MASK};
    (exists $o->{NIF})      and do { $r = join ' ', $r, $o->{NIF} };
    (defined $o->{NEXTHOP}) and do { $r = join ' ', $r, int2quad $o->{NEXTHOP} };
    (defined $o->{METRIC})  and do { $r = join ' ', $r, $o->{METRIC} };
    (defined $o->{MISC})    and do { $r = join ' ', $r, $o->{MISC} };
    (defined $o->{TRACK_NUMBER}) and do { $r = join ' ', $r, $o->{TRACK_NUMBER} };
    return $r;
}

sub acl_line_to_string ($$) {
    my ($self, $a) = @_;
    my $s = '';
    $self->{PRINT} = 'yes';
    $self->acl_entry($a, \$s);
    $self->{PRINT} = undef;
    return $s;
}

sub print_icmpmessage ($$$) {
    my ($self, $ah, $al) = @_;

    # we prefer textual output of icmp message due to
    # problems in the ios ace parser:
    #
    # in ios holds:   icmp 8 0 != icmp echo
    # because of this echo is coded as type 8 code -1
    #
    if (exists $ah->{TYPE}) {
        if (exists $ah->{CODE}) {

# ToDo
#	    if(exists $ICMP_Re_Trans{$ah->{TYPE}}->{$ah->{CODE}}){
#		$$al =join ' ',$$al,$ICMP_Re_Trans{$ah->{TYPE}}->{$ah->{CODE}};
#	    }
#	    else
            {
                $$al = join ' ', $$al, $ah->{TYPE};
                $ah->{CODE} != -1 and $$al = join ' ', $$al, $ah->{CODE};
            }
        }
        else {
            $$al = join ' ', $$al, $ah->{TYPE};
        }
    }
}

############################################################################
# from drc2_ios.pm
############################################################################


##############################################################
# issue command
##############################################################
sub cmd_check_error($$){
    my ($self, $out) = @_;

    if($$out =~ /^\s*%\s*/m){
	#### hack start ###
	if($$out =~/Delete failed. NV generation of acl in progress/){
	    ### probably slow acl proccessing
	    my @pre = split(/\n/,$$out);
	    for my $line (@pre){
		warnpr $line,"\n";
	    }
	    return 1;
	}
	### hack end ###
	my @pre = split(/\n/,$$out);
	errpr_info "+++ ",$pre[0],"\n";
	for(my $i = 0 ; $i < @pre ; $i++ ){
	    if($pre[$i] =~ /%/){
		if($pre[$i] =~ /'\^'/){
		    errpr_info "+++ ",$pre[$i-2],"\n"; 
		    errpr_info "+++ ",$pre[$i-1],"\n";
		}
		errpr_info "+++ ",$pre[$i],"\n";
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
sub checkinterfaces($$){
    my ($self, $devconf, $spocconf) = @_;
    mypr " === check for unknown or missconfigured interfaces at device ===\n";
    my $ports_in_vlan_1 = 0;
    my $check_vlan1 = 1;
    for my $intf  ( sort keys %{$devconf->{IF}}){
	next if($devconf->{IF}->{$intf}->{SHUTDOWN} == 1);
	next if($intf eq 'Null0');
	next if(exists $devconf->{IF}->{$intf}->{SWITCHPORT} and 
		exists $devconf->{IF}->{$intf}->{SWITCHPORT}->{MODE} and
		$devconf->{IF}->{$intf}->{SWITCHPORT}->{MODE} eq "trunk");
	if(exists $spocconf->{IF}->{$intf}){
	    if(exists $devconf->{IF}->{$intf}->{ADDRESS}){
		if(exists $devconf->{IF}->{$intf}->{ADDRESS}->{BASE}){
		    mypr "$intf ip: ".int2quad($devconf->{IF}->{$intf}->{ADDRESS}->{BASE})."\n";
		}
		elsif(exists $devconf->{IF}->{$intf}->{ADDRESS}->{DYNAMIC}){
		    mypr "$intf ip: $devconf->{IF}->{$intf}->{ADDRESS}->{DYNAMIC}\n"; 
		}
	    }
	    else{
		warnpr "$intf: no address found at netspoc configured interface\n";
	    }
	    next;
	}
	#
	# interface name *not* known by netspoc!
	#
	if(exists $devconf->{IF}->{$intf}->{ADDRESS}){
	    if(exists $devconf->{IF}->{$intf}->{ADDRESS}->{BASE}){
		warnpr "unknown interface $intf with ip: ".
		    int2quad($devconf->{IF}->{$intf}->{ADDRESS}->{BASE})." detected!\n";
	    }
	    elsif(exists $devconf->{IF}->{$intf}->{ADDRESS}->{DYNAMIC}){
		warnpr "unknown interface $intf with ip: $devconf->{IF}->{$intf}->{ADDRESS}->{DYNAMIC}\n"; 
	    }
	    next;
	}
	# check known harmless interfaces
	if($intf =~ /\ABRI\d+/      or
	   $intf =~ /\ALoopback\d+/ or
	   $intf =~ /\AVlan\d+/ or
	   $intf =~ /\AATM\d+/){
	    mypr "$intf without ip detected - OK\n";
	    next;
	}
	
	
	# the interface has to be bound to a vlan!
	if(!exists $devconf->{IF}->{$intf}->{SWITCHPORT}){
	    #Ethernet without vlan def located in vlan1 as default!
	    push @{$devconf->{IF}->{$intf}->{SWITCHPORT}->{ACCESS_VLAN}},1;
	    mypr "$intf assigned to vlan1 for further checking\n";
	}
	my $switchportconf = $devconf->{IF}->{$intf}->{SWITCHPORT};
	# Some ios routers have switchport modules with slightly differnet config:
	#
	# no 'nonegotiate' command
	# no 'switchport mode' entry in access mode  for WIC Switch-Modules
	#	
	if($self->{HARDWARE} =~ /831|836|1721|1712|1812|2801|2811/){ 
	    # vlan1 checking only necessary for *real* switches due to produktion
	    # vonventions in dataport silan
	    $check_vlan1 = 0;
	}
	else{
	    if(!exists $switchportconf->{MODE}){
		errpr "missing switchport mode config at interface $intf\n";
	    }
	    elsif($switchportconf->{MODE} ne "access" and
		  $switchportconf->{MODE} ne "trunk"){
		errpr "$intf wrong switchport mode: $switchportconf->{MODE}\n";
		errpr " only \'access\' and \'trunk\' allowed\n";
		}
	    else{
		mypr "$intf switchport mode: $switchportconf->{MODE}\n";
	    }
	    if(! $switchportconf->{NONEGOTIATE}){
		errpr "missing \'switchport nonegotiate\' at interface $intf\n";
	    }
	}
	# ok now check if switchport config is well shaped
	#
	# TODO: check trunks
	#
	if($switchportconf->{MODE} and 
	   $switchportconf->{MODE} eq "access" or 
	   $switchportconf->{ACCESS_VLAN}){
	    if(!exists $switchportconf->{ACCESS_VLAN}){
		$ports_in_vlan_1++;
	    }
	    elsif(scalar @{$switchportconf->{ACCESS_VLAN}} > 1){
		errpr "$intf: member of more than 1 vlan (".
		    scalar @{$switchportconf->{ACCESS_VLAN}}
		.") - forbidden!\n";
	    }
	    for my $vlan (@{$switchportconf->{ACCESS_VLAN}}){
		if($vlan eq 99){
		    errpr "active interface $intf at vlan 99 - forbidden!\n";
		}
		if($vlan eq 1){
		    $ports_in_vlan_1++;
		}
	    }
	}
    } 
    if($ports_in_vlan_1 > 1 and $check_vlan1){
	for my $intf  (sort keys %{$devconf->{IF}}){
	    if($intf =~ /vlan1\Z/i){
		errpr "Admin Vlan(1) has $ports_in_vlan_1 switchports - only 1 allowed\n";
	    }
	}
    }
    mypr " === done ===\n";
}

sub check_firewall ( $$ ) {
    my ($self, $conf) = @_;
    for my $interface (keys %{$conf->{IF}}){
	if(exists $conf->{IF}->{$interface}->{INSPECT}){
	    errpr "CBAC detected at $interface for non-Firewall-Router\n";
	}
    }
    
}

#######################################################
# telnet login, check name and set convenient options
#######################################################
sub prepare(){
    my ($self) = @_;
    $self->{PROMPT} = qr/.*[\%\>\$\#]\s?$/;
    $self->{ENAPROMPT} = qr/.*#\s?$/;
    $self->{ENA_MODE} = 0;
    $self->login_enable() or exit -1;
    mypr "logged in\n";
    $self->{ENA_MODE} = 1;
    my @output = $self->shcmd('') or exit -1;
    $output[1] =~ m/^\x0d?(\S+)\#\s?$/;
    my $name = $1;
    unless($self->{CHECKHOST} eq 'no'){
	$self->checkidentity($name) or exit -1;
    }
    else{
	mypr "hostname checking disabled!\n";
    }
    $self->{ENAPROMPT} = qr/^[\w-]+(?:\([\w-]+\))?#\s?$/; # speed up reading of long configs especially nvram
    $self->cmd('term len 0') or exit -1;
    my @tmp = $self->shcmd('sh ver');
    $tmp[0] =~ /Software .* Version +(\d+\.\d+[\w\d\(\)]+)/i or die "fatal error: could not identify IOS Version from $tmp[0]\n";
    $self->{VERSION} = $1;
    $tmp[0] =~ /(cisco\s+\S+) .*memory/i or die "could not identify Hardware Info $tmp[0]\n";
    $self->{HARDWARE} = $1;
    # max. term width is 511 for pix 512 for ios
    $self->cmd('term width 512')or exit -1;
    unless($self->{COMPARE}){
	$self->cmd('conf t')or exit -1;
	$self->cmd('no logging console') or exit -1;
	mypr "console logging is now disabled!\n";
	$self->cmd('ip subnet-zero') or exit -1; # needed for default route to work as expected
	mypr "ip subnet-zero is now enabled!\n";
	$self->cmd('ip classless') or exit -1;	# needed for default route to work as expected
	mypr "ip classless is now enabled!\n";
	$self->cmd('end') or exit -1;


    }

    mypr "-----------------------------------------------------------\n";
    mypr " DINFO: $self->{HARDWARE} $self->{VERSION}\n";
    mypr "-----------------------------------------------------------\n";
}

##########################################
#
# BEGIN unified shru and Netspoc parsing !!!
#
##########################################
my %spotags = ( START => '^\s*!*\s*\[ BEGIN router:(.*) \]',
		MODEL => '^\s*!*\s*\[ Model = (.*) \]',
		STOP  => '^\s*!*\s*\[ END router:(.*) \]',
		COMMENT => '^\s*!',
		IGNORE  => [q(^\s*$),
			      '^\[ ACL \]',
			      '^\[ Routing \]',
			      '^\[ Static \]',
			      '^\[ Crypto \]',
			      ]
			    );
	
sub eat_shit ( $$ ){
    my ($self, $l) = @_;
    if($l =~/$spotags{START}/o or
       $l =~/$spotags{MODEL}/o or
       $l =~/$spotags{STOP}/o
       ){
	return 0;
    }
    if($l =~/$spotags{COMMENT}/o){
	return 1;
    }
    for my $i (@{$spotags{IGNORE}}){
	if($l =~ /$i/){
	    return 1;
	}
    }
    return 0;
}
sub parse_crypto_isakmp_policy( $$$ ) {
 my ($self,$p,$sfile) = @_;
    while(defined(my $line = shift @$sfile)){
	if($line  =~ /^\s*authentication (\S+)/){
	    $p->{AUTHENTICATION} = $1;
	}
	elsif($line  =~ /^\s*(encr|encryption) (\S+)/){
	    $p->{ENCRYPTION} = $2;
	}
	elsif($line  =~ /^\s*hash (\S+)/){
	    $p->{HASH} = $1;
	}
	elsif($line  =~ /^\s*group (\d+)/){
	    $p->{GROUP} = $1;
	}
	elsif($line  =~ /^\s*lifetime (\d+)/){
	    $p->{LIFETIME} = $1;
	}
	else{
	    unshift @$sfile,$line;
	    last;
	}
    }
}
sub parse_crypto_ipsec_client_ezvpn ( $$$ ) {
    my ($self,$p,$sfile) = @_;
    while(defined(my $line = shift @$sfile)){
	if($line  =~ /^\s*acl (\S+)/){
	    $p->{MATCH_ACL}->{NAME} = $1;
	}
	#elsif($line  =~ /^\s*set ip access-group (\S+) (in|out)/){
	#    if($2 eq 'in'){
	#	$p->{ACCESS_GROUP_IN}->{NAME} = $1;
	#    }
	#    else{
	#	$p->{ACCESS_GROUP_OUT}->{NAME} = $1;
	#    }
	#}
	elsif($line  =~ /^\s*peer (\S+)/){
	    my $ip = quad2int($1);
	    $ip or die "Could not parse peer address: $line\n";
	    $p->{PEER}->{$1} = $ip;
	}
	elsif($line  =~ /^\s*connect (\S+)/o){
	    $p->{CONNECT} = $1;  
	}
	elsif($line  =~ /^\s*mode (\S+)/){
	    $p->{MODE} = $1;
	}
	elsif($line  =~ /^\s*virtual-interface (\d)/){
	    $p->{V_INTERFACE} = "Virtual-Template$1";
	}
	elsif($line  =~ /^\s*(username|xauth)(.*)/){
	    	mypr " Ignoring ezvpn parameter: $1$2\n";
	}
	else{
	    unshift @$sfile,$line;
	    last;
	}
    }
} 
sub parse_crypto_map_ipsec_isakmp( $$ ) {
    my ($self,$p,$sfile) = @_;
    while(defined(my $line = shift @$sfile)){
	if($line  =~ /^\s*match address (\S+)/){
	    $p->{MATCH_ADDRESS}->{NAME} = $1;
	}
	elsif($line  =~ /^\s*set ip access-group (\S+) (in|out)/){
	    if($2 eq 'in'){
		$p->{ACCESS_GROUP_IN}->{NAME} = $1;
	    }
	    else{
		$p->{ACCESS_GROUP_OUT}->{NAME} = $1;
	    }
	}
	elsif($line  =~ /^\s*set peer (\S+)/){
	    my $ip = quad2int($1);
	    $ip or die "Could not parse peer address: $line\n";
	    $p->{PEER}->{$1} = $ip;
	}
	elsif($line  =~ /^\s*set security-association lifetime (seconds|kilobytes) (\d+)/o){
	    $p->{SECURITY_ASSOCIATION_LIFETIME}->{UNIT} = $1;  
	    $p->{SECURITY_ASSOCIATION_LIFETIME}->{VAL} = $2;
	}
	elsif($line  =~ /^\s*set transform-set (\S+)/){
	    $p->{TRANSFORM_SET}->{NAME} = $1;
	}
	elsif($line  =~ /^\s*set pfs (\S+)/){
	    $p->{PFS} = $1;
	}
	else{
	    unshift @$sfile,$line;
	    last;
	}
    }
}
sub parse_crypto ( $$$ ) {
    my ($self,$p,$sfile) = @_;
    my $length = scalar @$sfile;
    while(defined(my $line = shift @$sfile)){
	$self->eat_shit($line) and next;
	#if($line =~ /^\s*crypto isakmp identity (\S+)/o){
	#    my $identity = $1;
	#    if($identity =~ /\Aaddress|hostname\Z/o){
	#	$p->{CRYPTO}->{ISAKMP}->{IDENTITY} = $identity;
	#    }
	#    else{
	#	mypr "unknown crypto isakmp identity: \'$identity\'\n";
	#	return 0;
	#    }
	#}
	#els
	if($line =~ /^\s*crypto isakmp policy (\S+)/o){
	    my $priority = $1;
	    $p->{CRYPTO}->{ISAKMP}->{POLICY}->{$priority} = {};
	    my $policy = $p->{CRYPTO}->{ISAKMP}->{POLICY}->{$priority};
	    $policy->{PRIORITY} = $priority;
	    $self->parse_crypto_isakmp_policy($policy,$sfile);
	}
	elsif($line =~ /^\s*crypto ipsec transform-set (\S+) (\S+) (\S+)( (\S+))?/o){
	    $p->{CRYPTO}->{IPSEC}->{TRANSFORM_SET}->{$1} = {};
	    my $tr = $p->{CRYPTO}->{IPSEC}->{TRANSFORM_SET}->{$1};
	    $tr->{NAME} = $1;
	    $tr->{T1} = $2;
	    $tr->{T2} = $3;
	    $5 and $tr->{T3} = $5;
	}
	elsif($line =~ /^\s*crypto ipsec client ezvpn (\S+)/o){
	    $p->{CRYPTO}->{IPSEC}->{CLIENT_EZVPN}->{$1} = {};
	    my $ez = $p->{CRYPTO}->{IPSEC}->{CLIENT_EZVPN}->{$1};
	    $ez->{NAME} = $1;
	    $ez->{ATTR} = {};
	    $self->parse_crypto_ipsec_client_ezvpn($ez->{ATTR},$sfile);
	}
	#elsif($line =~ /^\s*crypto ipsec security-association lifetime (seconds|kilobytes) (\d+)/o){
	#   $p->{CRYPTO}->{IPSEC}->{SECURITY_ASSOCIATION_LIFETIME}->{$1} = $2;
	#}
	elsif($line =~ /^\s*crypto map (\S+) (\d+) (ipsec-isakmp)/o){
	    my ($name,$sequ,$type) = ($1,$2,$3);
	    exists $p->{CRYPTO}->{MAP}->{$name}->{INSTANCES}->{$sequ} or
		$p->{CRYPTO}->{MAP}->{$name}->{INSTANCES}->{$sequ} = {};
	    my $map = $p->{CRYPTO}->{MAP}->{$name}->{INSTANCES}->{$sequ};
	    $map->{NAME} = $name;
	    $map->{SEQU} = $sequ;
	    $map->{TYPE} = $type;
	    $map->{ATTR} = {};
	    $self->parse_crypto_map_ipsec_isakmp($map->{ATTR},$sfile);
	}
	else{
	    unshift @$sfile,$line;
	    last;
	}
    }
    if(scalar @$sfile < $length){
	return 1;
    }
    else{
	# nothing found
	return 0;
    }
}
# checking, binding  and info printing of parsed crypto config
sub crypto_checking( $ ){
    my ($p) = @_;
    mypr meself(2)."*** begin ***\n";
    my $crypto_map_found = 0;
    my $ezvpn_client_found = 0;
    for my $intf (keys %{$p->{IF}}){
	if(exists $p->{IF}->{$intf}->{CRYPTO_MAP}){
	    $crypto_map_found = 1;
	    my $imap = $p->{IF}->{$intf}->{CRYPTO_MAP};
	    if(exists $p->{CRYPTO}->{MAP}->{$imap}){
		# bind interface to crypto map
		push @{$p->{CRYPTO}->{MAP}->{$imap}->{BOUND_TO_IF}}, $intf;
		mypr " crypto map \'$imap\' bound to interface \'$intf\'\n";
	    }
	    else{
		errpr "No definition for crypto map $imap at interface $intf  found\n";
		return 0;
	    }
	}
	elsif(exists $p->{IF}->{$intf}->{EZVPN}){
	    $ezvpn_client_found = 1;
	    my $ezvpn = $p->{IF}->{$intf}->{EZVPN}->{NAME};
	    if(exists $p->{CRYPTO}->{IPSEC}->{CLIENT_EZVPN}->{$ezvpn}){
		# bind interface to ezvpn
		push @{$p->{CRYPTO}->{IPSEC}->{CLIENT_EZVPN}->{$ezvpn}->{BOUND_TO_IF}}, $intf;
		mypr " crypto ipsec client \'$ezvpn\' bound to interface \'$intf\'\n";
	    }
	    else{
		errpr "No definition for ezvpn client $ezvpn at interface $intf  found\n";
		return 0;
	    } 
	}
    }
    if ($crypto_map_found and $ezvpn_client_found){
	errpr "ezvpn and crypto map at interfaces found - only one of them allowed\n";
	return 0;
    }
    if($crypto_map_found){
	for my $cm_name (keys %{$p->{CRYPTO}->{MAP}}){
	    unless( $p->{CRYPTO}->{MAP}->{$cm_name}->{BOUND_TO_IF} ){
		warnpr "Unattached crypto map \'$cm_name\' found\n";
		next;
	    } 
	    my $cm = $p->{CRYPTO}->{MAP}->{$cm_name};
	    mypr " found crypto map \'$cm_name\' (instances:".scalar(keys %{$cm->{INSTANCES}}).")\n";
	    for my $sequ (keys %{$cm->{INSTANCES}}){
		my $entry = $cm->{INSTANCES}->{$sequ}->{ATTR};
		mypr "  seq: $sequ\n";
		if(exists $entry->{MATCH_ADDRESS}){
		    mypr "   match-address: $entry->{MATCH_ADDRESS}->{NAME}\n";
		    if(exists $p->{ACCESS}->{$entry->{MATCH_ADDRESS}->{NAME}}){
			# bind match address to crypto map
			$entry->{MATCH_ADDRESS}->{ACL} = 
			    $p->{ACCESS}->{$entry->{MATCH_ADDRESS}->{NAME}};
		    }
		    else{
			errpr "Crypto: ACL $entry->{MATCH_ADDRESS}->{NAME} does not exist!\n";
			return 0;
		    }
		}
		else{
		    errpr "Crypto: no match-address entry found\n";
		    return 0;
		}
		if(exists $entry->{ACCESS_GROUP_IN}){
		    mypr "   access-group:  $entry->{ACCESS_GROUP_IN}->{NAME}\n";
		    if(exists $p->{ACCESS}->{$entry->{ACCESS_GROUP_IN}->{NAME}}){
			# bind access group to crypto map
			$entry->{ACCESS_GROUP_IN}->{ACL} = 
			    $p->{ACCESS}->{$entry->{ACCESS_GROUP_IN}->{NAME}};
		    }
		    else{
			errpr "Crypto: ACL $entry->{ACCESS_GROUP_IN}->{NAME} does not exist!\n"; 
			return 0;
		    }
		}
		if(exists $entry->{ACCESS_GROUP_OUT}){
		    warnpr "Crypto: outgoing filter-acl \'$entry->{ACCESS_GROUP_OUT}->{NAME}\' found\n";
		}
		exists $entry->{PEER} or errpr "Crypto: no peer found\n";
		if(exists $entry->{TRANSFORM_SET}){ 
		    if(exists $p->{CRYPTO}->{IPSEC}->{TRANSFORM_SET}->{$entry->{TRANSFORM_SET}->{NAME}}){
			# bind transform set to crypto map
			$entry->{TRANSFORM_SET}->{BIND} = 
			    $p->{CRYPTO}->{IPSEC}->{TRANSFORM_SET}->{$entry->{TRANSFORM_SET}->{NAME}}; 
			mypr "   transform set: $entry->{TRANSFORM_SET}->{NAME}\n";
		    }
		    else{
			errpr "Crypto: transform set $entry->{TRANSFORM_SET}->{NAME} does not exist!\n";
			return 0;
		    }
		}
	    }
	}
    }
    elsif($ezvpn_client_found){
	my $ezvpn = $p->{CRYPTO}->{IPSEC}->{CLIENT_EZVPN};
	for my $ez_name (keys %{$ezvpn}){
	    unless( $ezvpn->{$ez_name}->{BOUND_TO_IF} ){
		warnpr "Unattached crypto ipsec ezvpn client \'$ez_name\' found\n";
		next;
	    }
	    mypr " found crypto ipsec client ezvpn \'$ez_name\'\n";
	    my $ez_attr = $ezvpn->{$ez_name}->{ATTR};
	    # checking for traffic match acl
	    if(exists $ez_attr->{MATCH_ACL}){
		mypr "  match-acl: $ez_attr->{MATCH_ACL}->{NAME}\n";
		if(exists $p->{ACCESS}->{$ez_attr->{MATCH_ACL}->{NAME}}){
		    # bind match address to crypto map
		    $ez_attr->{MATCH_ACL}->{ACL} = 
			$p->{ACCESS}->{$ez_attr->{MATCH_ACL}->{NAME}};
		}
		else{
		    errpr "Crypto: ACL $ez_attr->{MATCH_ACL}->{NAME} does not exist!\n";
		    return 0;
		}
	    }
	    else{
		errpr "Crypto: no match-acl entry found\n";
		return 0;
	    }
	    # checking for virtual interface
	    if ($ez_attr->{V_INTERFACE}){
		my $intf = $ez_attr->{V_INTERFACE};
		if (exists $p->{IF}->{$intf}){
		    mypr "  client terminates at \'$intf\'\n";
		    }
		else{
		    errpr "Crypto: virtual-interface $intf not found\n";
		    return 0;
		}
	    }
	    else{
		errpr "Crypto: virtual-interface missing for ez_name\n";
		return 0;
	    }
	    # misc
	    exists $ez_attr->{PEER} or errpr "Crypto: no peer found\n";
	}
    }
    mypr meself(2)."*** end ***\n";
    return 1;
}
##########################################
#
# END unified shru and Netspoc parsing !!!
#
##########################################

##########################################
#
# BEGIN Netspoc parsing !!!
#
##########################################
# ios parse access-list lines
sub parse_acl ( $$$$ ) {
    my ($self, $p,$name,$sfile) = @_;
    my $d_counter = 0;
    while(defined(my $line = shift @$sfile)){
	$self->eat_shit($line) and next;
	my %acl;	    
	if($line  =~ /^\s*(permit|deny)/){
	    $self->parse_acl_line($line,\%acl);
	    my $aclstrg = $self->acl_line_to_string(\%acl);
	    unless(exists $p->{ACCESS_HASH}->{$name}->{$aclstrg}){
		# *new* acl_entry
		push @{$p->{ACCESS}->{$name}},\%acl;
		$p->{ACCESS_HASH}->{$name}->{$aclstrg} = 1;
	    }
	    else{
		$d_counter++;
	    }
	}
	else{
	    unshift @$sfile,$line;
	    last;
	}
    }
    ($d_counter) and mypr "double acl entries in spocfile skipped: $d_counter\n";
    return 1; 
}
# ios actually: parse access_group entry and crypto
sub parse_interface_section ( $$$$ ) {
    my ($self, $p,$name,$sfile) = @_;
    while(defined(my $line = shift @$sfile)){
	$self->eat_shit($line) and next;
	if($line  =~ /^\s*(ip\s+)?access[ -]group (\S+)/){
	    my $aclname = $2;
	    if(exists $p->{ACCESS}->{$aclname}){
		for my $entry (keys %{$p->{IF}}){
		    if(exists $p->{IF}->{$entry}->{ACCESS} and 
		       $p->{IF}->{$entry}->{ACCESS} eq $aclname){
			errpr "access-group: access-list already assigned: $line\n";
			return 0;
		    }
		}
		$p->{IF}->{$name}->{ACCESS} = $aclname;
	    }
	    else{
		mypr "access-list not found: $aclname\n";
		return 0;
	    }
	}
	elsif($line  =~ /^\s*crypto map (\S+)/){
	    $p->{IF}->{$name}->{CRYPTO_MAP} = $1;
	}
	elsif($line  =~ /^\s*crypto ipsec client ezvpn (\S+)( (\S+))?/){
	    $p->{IF}->{$name}->{EZVPN}->{NAME} = $1;
	    if($2){
		$p->{IF}->{$name}->{EZVPN}->{LOCATION} = $2;
	    }
	    else{
		$p->{IF}->{$name}->{EZVPN}->{LOCATION} = "outside";
	    }
	}
	else{
	    unshift @$sfile,$line;
	    last;
	}
    }
    return 1;
}
# ios parse 1st lvl from spoc config payload
sub parse_L1 ( $$$ ){
    my ($self, $p,$sfile) = @_;
    while(defined(my $line = shift @$sfile)){
	$self->eat_shit($line) and next;
	if($line =~ /^\s*ip route/o){
	    my %r_entry;
	    $self->parse_route_line($line,\%r_entry);
	    push @{$p->{ROUTING}},\%r_entry;
	    next;
	}
	if($line =~ /^\s*ip access-list extended (\S+)/o){
	    if(exists $p->{ACCESS}->{$1}){
		errpr "access-list redefinition: $line\n";
		return 0;
	    }
	    unless($self->parse_acl ($p,$1,$sfile)){
		mypr "could not parse acl\n";
		return 0;
	    }
	    next;
	}
	if($line =~ /^\s*interface (\S+)/o){
	    unless ($self->parse_interface_section($p,$1,$sfile)){
		mypr "could not parse interface section\n";
		return 0;
	    }
	    next;
	}
	# unified crypto parsing
	if($line =~ /^\s*crypto/o){
	    unshift @$sfile,$line;
	    unless($self->parse_crypto($p,$sfile)){
		die "fatal error in netspoc file - could not parse: $line\n";
	    }
	    next;
	}
	unshift @$sfile,$line;
	last;
    }
    return 1; 
}
# parse START - payload - STOP from config payload
sub parse_spocfile ( $$ ){
    my ($self, $p, $sfile) = @_;
    mypr "parse spocfile\n";
    $p->{DEVICE} = '';
    while(defined(my $line = shift @$sfile)){
	$self->eat_shit($line) and next;
	if($line =~ /$spotags{START}/o){
	    $p->{DEVICE} = $1;
	    next;
	}
	if($line =~ /$spotags{MODEL}/o){
	    $p->{MODEL} = $1;
	    $self->parse_L1($p,$sfile);
	    last;
	}
	my $ttt = unpack("H*", "$line");
	errpr "unexpected line (hex): $ttt\n";
	return 0;
    }
    if(!$p->{DEVICE}){
	errpr "START tag not found or no device name specified in spocfile\n"; 
	return 0;
    }
    if(@$sfile == 0){
	errpr "unexpected end of spocfile\n"; 
	return 0;
    }
    my $line = shift @$sfile;
    if($line !~ /$spotags{STOP}/o or $p->{DEVICE} ne $1){
	mypr "no matching STOP tag found for $p->{DEVICE} \n";
	mypr "instead found line: \n";
	mypr $line;
	errpr "giving up\n";
	return 0;
    }
    mypr "... done parsing spocfile\n";
    # check wether every interface in spocfile has an access-group
    for my $intf_name (keys %{$p->{IF}}){
	exists $p->{IF}->{$intf_name}->{ACCESS} or 
	    errpr "no access-group for interface \'$intf_name\' found\n";
    }
    if($p->{DEVICE} ne $self->{NAME}){
	if($self->{CHECK_DEVICE_IN_SPOCFILE} eq "yes"){
	    errpr "wrong device name in spocfile - expected: $self->{NAME} found: $p->{DEVICE}\n";
	    return 0;
	}
	else{
	    warnpr "wrong device name in spocfile - expected: $self->{NAME} found: $p->{DEVICE}\n";
	    $p->{DEVICE} = $self->{NAME};
	    
	}
    }
    # do plausibility checks and binding for crypto conf
    unless(crypto_checking($p)){
	errpr "fatal error in spocfile\n"; exit -1;
    }
    return 1;
}
##########################################
#
# END Netspoc parsing !!!
#
##########################################

############################################################
#
# BEGIN shru parsing
#
############################################################
#
# TODO: secure parsing -> only accept expected lines!	
#
sub parse_acl_shru ( $$$$ ) {
    my ($self,$p,$name,$sfile) = @_;
    #
    # we must only parse the non-dynamic part of the acl. 
    #
    my $d_counter = 0;
    my $e_counter = 0;
    my $r_counter = 0;

    # init acl !
    @{$p->{ACCESS}->{$name}} = ();
    while(defined(my $line = shift @$sfile)){
	next if $line =~ /^\s*>/;
	my %pacl;
	if($self->parse_acl_line($line,\%pacl)){
	    push @{$p->{ACCESS}->{$name}},\%pacl;
	    if(exists $pacl{REMARK}){
		$r_counter++;
	    }
	    else{
		$e_counter++;
	    }
	}
	else{
	    unshift @$sfile,$line;
	    last; 
	};
    }
    if(exists $p->{RUNNING}){
	mypr " found normal  entries at $name: $e_counter\n";
	mypr " found remark  entries at $name: $r_counter\n";
    }
    return 1; 
}
sub parse_if_sec_shru ( $$$$ ) {
    my ($self, $p,$name,$sfile) = @_;
    $p->{IF}->{$name}->{SHUTDOWN} = 0; # default for interfaces is "no shutdown"
    while(defined(my $line = shift @$sfile)){
	($line =~ /^\s*!|^ *$/o) and return 1;
	if($line  =~ /^\s*ip access-group (\S+) in/){
	    $p->{IF}->{$name}->{ACCESS} = $1;
	}
	if($line  =~ /^\s*ip access-group (\S+) out/){
	    $p->{IF}->{$name}->{ACCESS_OUT} = $1;
	}
	if($line  =~ /^\s*ip inspect (\S+) in/){
	    $p->{IF}->{$name}->{INSPECT} = $1;
	}
	if($line  =~ /^\s*shutdown/){
	    $p->{IF}->{$name}->{SHUTDOWN} = 1;
	}
	if($line  =~ /^\s*crypto map (\S+)/){
	    $p->{IF}->{$name}->{CRYPTO_MAP} = $1;
	}
	if($line  =~ /^\s*crypto ipsec client ezvpn (\S+)( (\S+))?/){
	    $p->{IF}->{$name}->{EZVPN}->{NAME} = $1;
	    if($2){
		$p->{IF}->{$name}->{EZVPN}->{LOCATION} = $2;
	    }
	    else{
		$p->{IF}->{$name}->{EZVPN}->{LOCATION} = "outside";
	    }
	}
	if($line  =~ /^\s*switchport mode (\S+)/){
	    $p->{IF}->{$name}->{SWITCHPORT}->{MODE} = $1;
	}
	if($line  =~ /^\s*switchport access vlan (\d+)/){
	    push @{$p->{IF}->{$name}->{SWITCHPORT}->{ACCESS_VLAN}}, $1;
	}
	if($line  =~ /^\s*switchport nonegotiate/){
	    $p->{IF}->{$name}->{SWITCHPORT}->{NONEGOTIATE} = 1;
	}
	if($line  =~ /^\s* ip address (\d+\.\d+\.\d+\.\d+)/){
	    my $addr = quad2int($1) or die "Could not parse address of interface $name\n";
	    $p->{IF}->{$name}->{ADDRESS}->{BASE} = $addr;
	}
	if($line  =~ /^\s* ip address negotiated/){
	    $p->{IF}->{$name}->{ADDRESS}->{DYNAMIC} = 'negotiated';   
	}
	if($line  =~ /^\s* ip unnumbered/){
	    $p->{IF}->{$name}->{ADDRESS}->{DYNAMIC} = 'unnumbered';   
	}
    }
    return 1; 
}
sub parse_shru ( $$$$ ){
    my ($self, $p,$sfile) = @_;
    while(defined(my $line = shift @$sfile)){
	if($line =~ /^\s*ip route /o){
	    my %r_entry;
	    $self->parse_route_line($line,\%r_entry);
	    push @{$p->{ROUTING}},\%r_entry;
	    next;
	}
	if($line =~ /^\s*ip access-list extended (\S+)/o){
	    unless($self->parse_acl_shru ($p,$1,$sfile)){
		mypr "could not parse acl\n";
		return 0;
	    }
	    next;
	}
	if($line =~ /^\s*access-list (\d+)\s+(.*)\Z/o){
	    my $name = $1;
	    unless($2 =~ /\s*remark/){
		# don't parse remarks!
		if(100 <= $name && $name < 200){
		    # extended access-list! -> only for option -A !!
		    my $acl = {};
		    $self->parse_acl_line($2,$acl);
		    push @{$p->{ACCESS}->{$1}},$acl;
		}
		if(0 < $name && $name < 100){
		    # simple access-list! -> only for option -A !!
		    # 
		    # currently this workz only if address is A.B.C.D
		    my $to_parse;
		    my $acl = {};
		    my $simple = $2;
		    $simple =~ /(permit|deny) (.*) (log)\Z/;
		    my $mode = $1;
		    my $address = $2;
		    my $log = $3?$3:"";
		    if($address =~ /\S+ \S+/ or $address =~ /any/){
			$to_parse = "$mode ip $address any $log";
		    }
		    else{
			$to_parse = "$mode ip host $address any $log";
		    }
		    $self->parse_acl_line($to_parse,$acl);
		    push @{$p->{ACCESS}->{$name}},$acl;
		}
	    }
	    next;
	}
	if($line =~ /^\s*interface (\S+)/o){
	    unless(exists $p->{IF}->{$1}){
		# do not touch interface if allready known! This can only 
		# happen if we are parsing the epilog.
		$p->{IF}->{$1} = {}; 
	    }
	    $self->parse_if_sec_shru($p,$1,$sfile);
	    next;
	}
	# this must be behind interface parsing!!
	# (otherwise ip inspect in interface section would be parsed)
	if($line =~ /^\s*ip inspect /o){
	    my %insp_entry;
	    $self->parse_ip_inspect_line($line,\%insp_entry);
	    push @{$p->{INSPECT}},\%insp_entry;
	    next;
	}
	# unified crypto parsing
	if($line =~ /^\s*crypto/o){
	    unshift @$sfile,$line;
	    unless($self->parse_crypto($p,$sfile)){
		# nothing read by parse_crypto - we have to re-shift!!!
		my $l = 	shift @$sfile;
		$l =~ /^\s*(crypto.*)/o;
		mypr " Ignoring Crypto line: $1\n";
	    }
	    next;
	}
	# check for OSPF
	if($line =~ /^\s*router ospf /o){
	    $p->{OSPF} = 1;
	    next;
	}
    }
    return 1; 
}

sub get_config_from_device( $ ) {
    my ($self) = @_;

    my @out = $self->shcmd('sh run') or exit -1;
    my @conf = split /(?=\n)/, $out[0];
    mypr "got config from device\n";
    return (\@conf);
}

sub parse_device ( $$$ ) {
    my ($self, $p, $conf) = @_;

    mypr "parse device config\n";
    unless($self->parse_shru($p,$conf)){
	errpr "could not parse router config\n";
	return 0;
    }
    mypr "... done parsing device config\n";
    # do plausibility checks and binding for crypto conf
    unless($self->crypto_checking($p)){
	errpr "fatal error in device config\n"; exit -1;
    }
    return 1;
}
############################################################
#
# END shru parsing
#
############################################################

###########################################
#
# BEGIN RAW processing
#
###########################################
sub process_rawdata( $$$ ){
    my ($self, $pspoc, $epilog) = @_;
    my $epilogacl;
    my $spocacl;
    ### helper ###
    my $sec_time = time(); # for status info timestamps
    my $check = sub{
	my ($intf,$epi) = @_;
	unless(exists $epi->{IF}->{$intf}->{ACCESS}){
	    mypr " - no acl in raw data -\n";
	    return 0; 
	}

	# there is an epilog acl for this interface
	my $ep_name = $epi->{IF}->{$intf}->{ACCESS};

## It is sufficient to check for spoc-interface below.
#
#	unless(exists $conf->{IF}->{$intf}){
#	    errpr "rawdata: interface not found on device: $intf\n";
#	    exit -1;
#	}

	# the interface exists on the device
	my $sp_name;
	exists $pspoc->{IF}->{$intf} 
	  or die "rawdata: $intf not found in spocfile\n";
	unless(exists $pspoc->{IF}->{$intf}->{ACCESS}){
	    warnpr "rawdata: no spocacl for interface: $intf\n";
	    return 0;
	}

	# there is a corresponding acl in the spocfile
	$sp_name = $pspoc->{IF}->{$intf}->{ACCESS};
	unless(exists $epi->{ACCESS}->{$ep_name}){
	    errpr 
	      "rawdata: no matching raw acl found for name $ep_name in interface definition\n";
	    exit -1;
	}
	$epilogacl = $epi->{ACCESS}->{$ep_name};
	$spocacl = $pspoc->{ACCESS}->{$sp_name};
	return 1;
    };
    if(scalar @{$epilog}){
 	my $epilog_conf = {};

 	# *** PARSE RAWDATA ***
	$self->parse_shru($epilog_conf, $epilog);
 	mypr "--- raw processing\n";
 	for my $intf (keys %{$epilog_conf->{IF}}){
 	    mypr " interface: $intf\n";
 	    &$check($intf,$epilog_conf) or next;

 	    # _prepend_
 	    my @remove = ();
 	    for(my $i = 0; $i < scalar @$spocacl;$i++){
 		for my $epi (@$epilogacl){
 		    if($self->acl_line_a_eq_b($epi,$spocacl->[$i])){
 			warnpr "RAW: double ACE \'".
 			    $self->acl_line_to_string($spocacl->[$i]).
 			    "\' scheduled for remove from spocacl.\n";
 			push @remove,$i;
 		    }
 		}
 	    }
 	    for my $r (reverse sort @remove){
 		splice @$spocacl,$r,1;
 	    }
 	    for(my $i = scalar @{$epilogacl} - 1;$i >= 0;$i--){
 		unshift @{$spocacl},$$epilogacl[$i];
 	    }
	    mypr "   entries prepended: ".scalar @{$epilogacl}."\n";

# Attribute STD_ACCESS isn't used anywere.
#	    $cnob->{IF}->{$intf}->{STD_ACCESS} = $epilogacl;
#	    $cnob->{MIGRATE_STATUS}->{"STD ACL TRANS:: $intf"} = 
#		scalar @{$cnob->{IF}->{$intf}->{STD_ACCESS}}; 
#	     $active_std_interfaces = $active_std_interfaces." $intf";
 	}
#	$cnob->{MIGRATE_STATUS}->{"STD INTERFACES"} = $active_std_interfaces;
 	### ROUTE PROCESSING STD ###
	if(defined $pspoc->{ROUTING}){
	    my $newroutes = ();
	    SPOC: for(my $i = 0; $i < scalar @{$pspoc->{ROUTING}};$i++){
		my $se = $pspoc->{ROUTING}->[$i];
		for my $re (@{$epilog_conf->{ROUTING}}){
		    if($self->route_line_a_eq_b($se,$re)){
			warnpr "RAW: double RE \'".
 			    $self->route_line_to_string($re).
				"\' scheduled for remove from spocconf.\n";
			next SPOC;
		    }
		    elsif($re->{BASE} eq $se->{BASE} 
		      and $re->{MASK} eq $se->{MASK})
		    {
			warnpr 
			    "RAW: inconsistent NEXT HOP in routing entries:\n";
			warnpr "     spoc: "
			    . $self->route_line_to_string($se)
			    . " (scheduled for remove)\n";
			warnpr "     raw:  "
			    . $self->route_line_to_string($re) . "\n";
			next SPOC;
		    }
		}
		push @{$newroutes}, $se;
	    }
	    $pspoc->{ROUTING} = $newroutes;
	}
	for my $re (@{$epilog_conf->{ROUTING}}){
	    push @{$pspoc->{ROUTING}},$re;
	}
 	mypr " attached routing entries: ".scalar @{$epilog_conf->{ROUTING}}."\n"; 

# Attribute STD_ROUTING isn't used anywere.
#	$cnob->{STD_ROUTING} = $epilog_conf->{ROUTING};

    }
    else{
 	mypr "--- raw processing: nothing to do\n";
    }
    mypr "--- raw processing: done\n";
    return 1;
}
###########################################
#
# END RAW processing
#
###########################################

#######################################################
# *** ios transfer ***
#######################################################

# *** small helpers (ios) ***

sub write_mem( $$$ ){
    my ($self, $retries,$seconds) = @_;
    mypr "writing config to nvram\n";
    my @output;
    my $written = "NO";
    my $tries = 0;
    while($written ne "YES"){
	@output= $self->shcmd('write memory') or exit -1;
	$tries++;
	if($output[0] =~ /Building configuration/){
	    mypr "seems ok\n";
	    $written = "YES";
	}
	elsif($output[0] =~ /startup-config file open failed/i){
	    if($tries > $retries){
		errpr "startup-config file open failed $tries times - giving up\n";
	    }
	    else{
		warnpr "startup-config file open failed $tries times - sleeping ".
		    "$seconds seconds then trying again\n";
		sleep $seconds; 
	    }
	}
	else{
	    errpr "Unexpected result for write memory. Check *.tel file\n";
	}
    }
}

sub compare_ram_with_nvram( $ ){
    my ($self) = @_;
    # *** FETCH CONFIGS ***
    mypr "fetch running config from device again ";
    my @out = $self->shcmd('show run brief') or exit -1; # do not show content of certificates
    # some devices have no 'brief' option
    if($out[0] =~ /^\s*%\s+invalid/im){
	@out = $self->shcmd('show run') or exit -1;
    }
    my @conf = split /\n/,$out[0];
    mypr "... done\n";
    mypr "fetch startup config from device again ";
    @out = $self->shcmd('show start') or exit -1;
    my @start = split /\n/,$out[0];
    mypr "... done\n";
    # *** COMPARE ***
    my $compare_run = "NO";
    my $startup_index = 0;
    my @startup_certs = ();
    my @running_certs = ();
    for( my $i = 0;$i<scalar @start;$i++){
	if ($start[$i] =~ /version/i){
	    $startup_index = $i;
	    last;
	}
    }
    for my $line (@conf){
	if ($line =~ /version/i){
	    $compare_run = "YES";
	}
	next if ($compare_run ne "YES");
	# ignore patterns in running config
	if($line =~ /\A\s*!/ or
	   $line =~ /ntp clock-period/ or
	   $line =~ /\A(\s+[A-F0-9]{8})+/ or # match certificate contents 
	   $line =~ /\A\s*quit\s*\Z/ or # match certificate contents 
	   $line =~ /^\s*certificate/ or
	   $line =~ /no scheduler allocate/ or 
	   $line =~ /boot system flash:/ # at some devices this is not included by 'sh run brief'
	   ){
	    if($line =~ /certificate/){
		# mask out nvram file info for certificates
		$line =~ s/\snvram:\S*//;
		# collect cert IDs in running
		push @running_certs,$line;
	    }
	    next;
	}
	# ignore patterns in startup config
	while($start[$startup_index] =~ /\A\s*!/ or
	      $start[$startup_index] =~ /ntp clock-period/ or
	      $start[$startup_index] =~ /\A(\s+[A-F0-9]{8})+/ or # match certificate contents 
	      $start[$startup_index] =~ /\A\s*quit\s*\Z/ or # match certificate contents 
	      $start[$startup_index] =~ /^\s*certificate/ or
	      $start[$startup_index] =~ /no scheduler allocate/ or 
	      $start[$startup_index] =~ /boot system flash:/
	      ){ 
	    if($start[$startup_index] =~ /certificate/){
		# mask out nvram file info for certificates
		$start[$startup_index] =~ s/\snvram:\S*//;
		# collect cert IDs in startup
		push @startup_certs,$start[$startup_index];
	    }
	    $startup_index++;
	}
	if($line ne $start[$startup_index]){
	    warnpr "Diff found   RUN: $line\n";
	    warnpr "Diff found START: $start[$startup_index]\n";
	    return 0;
	}
	$startup_index++;
    }
    # compare certificate lines
    my @sc = sort @startup_certs;
    my @rc = sort @running_certs;
    if(scalar @sc != scalar @rc){
	warnpr "Diff found for certificate IDs\n";
	warnpr "startup ".scalar @sc." ID(s) found\n";
	warnpr "running ".scalar @rc." ID(s) found\n";
	return 0;
    }
    for(my $i = 0;$i<scalar @sc;$i++){
	if($sc[$i] ne $rc[$i]){
	    warnpr "START: $startup_certs[$i]\n"; 
	    warnpr "RUN:   $running_certs[$i]\n";
	    return 0;
	}
    }
    #check if any residual non-space lines in startup config
    while (scalar @start > $startup_index){
	$startup_index++;
	# ignore patterns in startup config
	my $t = scalar @start;
	#mypr "$t $startup_index\n";
	if($start[$startup_index] !~ /\A\s*!/){
	    warnpr "Residual pattern in startup-config found: $start[$startup_index]\n"; 
	    return 0;
	}
    }
    return 1;
}
sub schedule_reload ( $$ ){
    my ($self, $minutes) = @_;
    mypr "schedule reload in $minutes minutes\n";
    my $psave = $self->{ENAPROMPT};
    $self->{ENAPROMPT} = qr/\[yes\/no\]:|\[confirm\]/;
    my @out = $self->shcmd("reload in $minutes") or exit -1;
    #$tel->buffer_empty;
    $self->{ENAPROMPT} = qr/\[confirm\]/;
    if ($out[0] =~ /ave/){
	# someone has fiddled with the router ;)
	$self->cmd('n') or exit -1;
    }
    $self->{ENAPROMPT} = $psave;
    $self->cmd('') or exit -1;
    $self->{RELOAD_SCHEDULED} = 1;
    mypr "reload scheduled\n";
}
sub cancel_reload ( $ ){
    my ($self) = @_;
    if(exists  $self->{RELOAD_SCHEDULED} and
       $self->{RELOAD_SCHEDULED} == 1){
	mypr "cancel reload ";
	# workaround: wait longer
	my $con = $self->{CONSOLE};
	my $tt = $con->{TIMEOUT};
	$con->{TIMEOUT} = 2*$tt;
	mypr "(timeout temporary set from $tt sec to $con->{TIMEOUT} sec)\n";
	$self->cmd('reload cancel') or exit -1;
	$con->{TIMEOUT} = $tt;
	# we have to wait for the 
	
	# *** 
	# *** --- SHUTDOWN ABORTED ---
	# ***
	
	# lines, hopefully
	unless ($con->con_wait("--- SHUTDOWN ABORTED ---",$con->{TIMEOUT})){
	    warnpr "*** --- SHUTDOWN ABORTED --- $con->{RESULT}->{ERROR}\n";
	}
	unless ($con->con_wait(qr/\*\*\*/,$con->{TIMEOUT})){
	    warnpr "***  $con->{RESULT}->{ERROR}\n";
	}
	# really no reload scheduled?
	my @out = $self->shcmd('sh reload');
	unless($out[0] =~ /No reload is scheduled/){
	    warnpr "could not cancel reload\n";
	}
	else{
	    $self->{RELOAD_SCHEDULED} = 0;
	}
    }
}
##################################
###   ios master helpers
##################################
sub verbose_acl_equal( $$$$$$$ ){
    # calling rule: a should be spoc (new) acl
    #               b should be conf (old) acl
    my ($self, $a_acl,$b_acl,$a_name,$b_name,$context,$verbose) = @_;
    my $diff = 0;
    mypr "compare ACLs $a_name $b_name for $context\n";
    ### textual compare
    if(scalar @{$a_acl} == scalar @{$b_acl}){
	mypr "length equal: ",scalar @{$a_acl},"\n";
	mypr "compare line by line: ";
	for(my $i = 0;$i<scalar @{$a_acl};$i++){
	    #mypr " ",$i+1;
	    if($self->acl_line_a_eq_b($$a_acl[$i],$$b_acl[$i])){
		next;
	    }
	    else{
		# acls differ
		mypr " diff at ",$i+1;
		$diff = 1;
		last;
	    }
	}
	mypr "\n";
    }
    else{
	$diff = 1;
	mypr "lenght differ: C ".scalar @{$b_acl}." S ".scalar @{$a_acl}."\n";
    }
    ### textual compare finished
    if(!$diff){
	mypr "acl's textual identical!\n";
    }
    else{
	my $newinold;
	my $oldinnew;
	mypr "acl's differ textualy!\n";
	mypr "begin semantic compare:\n";
	if($verbose eq 4){
	    $newinold = $self->acl_array_compare_a_in_b($a_acl,$b_acl,$verbose); 
	    $oldinnew = $self->acl_array_compare_a_in_b($b_acl,$a_acl,$verbose);
	}
	else{
	    mypr "#### BEGIN NEW in OLD - $context\n";
	    mypr "#### $a_name in $b_name\n";
	    $newinold = $self->acl_array_compare_a_in_b($a_acl,$b_acl,$verbose); 
	    mypr "#### END   NEW in OLD - $context\n";   
	    mypr "#### BEGIN OLD in NEW - $context\n";
	    mypr "#### $b_name in $a_name\n";
	    $oldinnew = $self->acl_array_compare_a_in_b($b_acl,$a_acl,$verbose);
	    mypr "#### END   OLD in NEW - $context\n";   
	}
	if ($newinold and $oldinnew ){
	    $diff = 0;
	    mypr "#### ACLs equal #### \n";
	    }
	else{
	    mypr "acl's differ semanticaly!\n"; 
	}
    }
    # return 1 iff equal: 
    return !$diff;
}
sub compare_interface_acls ( $$$$ ){
    #
    # check for existance of (spoc)interface on device
    # and check for textual identical acls 
    #    
    my ($self,$pspoc,$conf,$mode) = @_;
    
    mypr "===== compare (incoming) acls =====\n";
    for my $if (keys %{$pspoc->{IF}}){
	$pspoc->{IF}->{$if}->{TRANSFER} = '';
	unless(exists $pspoc->{IF}->{$if}->{ACCESS}){
	    warnpr "no spoc-acl for interface $if\n";
	    next;
	}
	# there *is* an access-list
	unless(exists $conf->{IF}->{$if}){
	    errpr "interface not found on device: $if\n";
	    next;
	}
	##############################
	# FORCE TRANSFER MODUS
	##############################
	if($mode eq 'FORCE'){
	    $pspoc->{IF}->{$if}->{TRANSFER} = 'YES';
	    warnpr "Interface $if: transfer of ACL forced!\n";
	    next;
	}
	##############################
	my $sa_name = $pspoc->{IF}->{$if}->{ACCESS};
	my $ca_name;
	if(exists $conf->{IF}->{$if}->{ACCESS}){
	    $ca_name = $conf->{IF}->{$if}->{ACCESS};
	    if(exists $conf->{ACCESS}->{$ca_name}){
		mypr "at interface $if - spoc: $sa_name <-> actual: $ca_name\n";
	    }
	    else{
		$pspoc->{IF}->{$if}->{TRANSFER} = 'YES';
		warnpr "acl $ca_name does not exist on device!\n";
		next;
	    }
	}
	else{
	    $pspoc->{IF}->{$if}->{TRANSFER} = 'YES';
	    warnpr "no incoming acls found at interface $if\n";
	    next;
	}
	if($self->verbose_acl_equal($pspoc->{ACCESS}->{$sa_name},
			    $conf->{ACCESS}->{$ca_name},
			    $sa_name,
			    $ca_name,
			    "interface $if",
			    $mode)
	   ){
	    $pspoc->{IF}->{$if}->{TRANSFER} = "NO";
	}
	else{
	    $pspoc->{IF}->{$if}->{TRANSFER} = 'YES'; 
	}
    }
    mypr "===== done ====\n";
}
sub process_routing ( $$$ ){
    my ($self,$conf,$pspoc) = @_;
    if($pspoc->{ROUTING} and scalar@{$pspoc->{ROUTING}}){
	my $counter;
	if(!$conf->{ROUTING} or $conf->{ROUTING} and !scalar(@{$conf->{ROUTING}})){
	    if(!$conf->{OSPF}){
		errpr "ERROR: no routing entries found on device\n";
		return 0;
	    }
	    else{
		mypr "no routing entries found on device - but OSPF found...\n";
		# generate emty routing config for device:
		@{$conf->{ROUTING}} = ();
	    }
	}
	mypr "==== compare routing information ====\n\n";
	mypr " routing entries on device:    ",scalar @{$conf->{ROUTING}},"\n";
	mypr " routing entries from netspoc: ",scalar @{$pspoc->{ROUTING}},"\n";
	for my $c (@{$conf->{ROUTING}}){ # from device
	    $counter++;
	    unless($self->{COMPARE}){
		mypr " $counter";
	    }
	    for my $s (@{$pspoc->{ROUTING}}){ # from netspoc
		($s) or next;
		if($self->route_line_a_eq_b($c,$s)){
		    $c->{DELETE} = $s->{DELETE} = 1;
		    last;
		}
	    }
	} 
	mypr "\n";
	unless($self->{COMPARE}){
	    #
	    # *** SCHEDULE RELOAD ***
	    #
	    # TODO: check if 10 minutes are OK
	    #
	    $self->schedule_reload(10);
	    # transfer to device
	    $self->cmd('configure terminal') or exit -1;
	    mypr "transfer routing entries to device:\n";
	    $counter = 0;
	    for my $r (@{$pspoc->{ROUTING}}){
		($r->{DELETE}) and next; 
		$counter++;
		$self->cmd($self->route_line_to_string($r)) or exit -1;
		mypr " $counter";
	    }  
	    mypr " $counter";
	    mypr "\n";
	    ($counter) and $self->{CHANGE}->{ROUTE} = 1;
	    mypr "deleting non matching routing entries from device\n";
	    $counter = 0;
	    for my $r (@{$conf->{ROUTING}}){
		($r->{DELETE}) and next; 
		$counter++;
		my $tr = join ' ',"no",$self->route_line_to_string($r);
		$self->cmd($tr) or exit -1;
		mypr " $counter";
	    }  
	    mypr " $counter";
	    mypr "\n";
	    $self->cmd('end') or exit -1;
	    ($counter) and $self->{CHANGE}->{ROUTE} = 1;
	    $self->cancel_reload();
	}
	else{
	    # show compare results
	    mypr "non matching routing entries on device:\n";
	    $counter = 0;
	    for my $r (@{$conf->{ROUTING}}){
		($r->{DELETE}) and next; 
		$counter++;
		mypr $self->route_line_to_string($r),"\n";
	    }  
	    mypr "total: ",$counter,"\n";
	    ($counter) and $self->{CHANGE}->{ROUTE} = 1;
	    mypr "additional routing entries from spoc:\n";
	    $counter = 0;
	    for my $r (@{$pspoc->{ROUTING}}){
		($r->{DELETE}) and next; 
		$counter++;
		mypr $self->route_line_to_string($r),"\n";
	    }  
	    mypr "total: ",$counter,"\n";
	    ($counter) and $self->{CHANGE}->{ROUTE} = 1;
	}
	mypr "==== done ====\n";
    }
    else{
	mypr "no routing entries specified - leaving routes untouched\n"; 
    }
    return 1;
}
sub append_acl_entries( $$$ ){
    my ($self,$name,$entries) = @_;
    $self->cmd('configure terminal') or exit -1;
    #mypr "ip access-list extended $name\n";
    $self->cmd("ip access-list extended $name") or exit -1;
    my $counter = 0;
    for my $c (@$entries){
	my $acl = $self->acl_line_to_string($c);
	$self->cmd($acl) or exit -1;
	$counter++;
	mypr " $counter";
    }
    mypr "\n";
    $self->cmd('end') or exit -1;
}
sub remove_acl_entries( $$$ ){
    my ($self,$name,$entries) = @_;
    #
    # remove ace's in reverse order!!!
    #
    $self->cmd('configure terminal') or exit -1;
    #mypr "ip access-list extended $name\n";
    $self->cmd("ip access-list extended $name") or exit -1;
    my $counter = 0;
    for my $c (reverse @$entries){
	my $acl = "no ".$self->acl_line_to_string($c);
	# *** HACK *** to handle NV ram slowdown
	my @output = $self->shcmd($acl);
	$self->cmd_check_error(\${@output}[0]) or exit -1;
	if($output[0] =~ /Delete failed. NV generation of acl in progress/){
	    mypr "sleep 1 second and try again.\n";
	    sleep 1;
	    $self->cmd($acl) or exit -1;
	}
	# *** HACK END ***
	#$self->cmd($acl) or exit -1;
	$counter++;
	mypr " $counter";
    }
    mypr "\n";
    $self->cmd('end') or exit -1;
}

#
# *** access-lists processing *** 
#
sub process_interface_acls ( $$$ ){
    my ($self,$conf,$pspoc) = @_;
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
    for my $if (keys %{$pspoc->{IF}}){
	(exists($pspoc->{IF}->{$if}->{ACCESS}) and $pspoc->{IF}->{$if}->{TRANSFER} eq "YES") or next;
	my $confacl=(exists $conf->{IF}->{$if}->{ACCESS})?$conf->{IF}->{$if}->{ACCESS}:'';
	# check acl-names
	my $aclindex;
	if($confacl =~ /\S+-DRC-([01])/){
	    # active acls matches name convention
	    $aclindex = (not $1) * 1;
	}
	else{
	    if($confacl){
		warnpr "unexpected acl-name $confacl at interface $if\n";
	    }
	    else{
		warnpr "no acl found at interface $if\n";
	    }
	    $aclindex = 0;
	}
	# generate *new* access-list entries
	my $spocacl = $pspoc->{IF}->{$if}->{ACCESS};
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
	$self->cmd('configure terminal') or exit -1;
	#mypr "no ip access-list extended $aclname\n";
	$self->cmd("no ip access-list extended $aclname") or exit -1;
	$self->cmd('end') or exit -1;
	$self->cancel_reload();
	# hopefully this is not critical!
	$self->append_acl_entries($aclname,$pspoc->{ACCESS}->{$spocacl});
	#
	# *** SCHEDULE RELOAD ***
	#
	$self->schedule_reload(5);
	#
	# assign new acl to interfaces
	#
	mypr "assign new acl:\n";
	$self->cmd('configure terminal') or exit -1;
	mypr " interface $if\n";
	$self->cmd("interface $if") or exit -1;
	mypr " ip access-group $aclname in\n";
	$self->cmd("ip access-group $aclname in") or exit -1;
	$self->cmd('end') or exit -1;
	#
	# delete old ACL (if present)
	#
	$self->cmd('configure terminal') or exit -1;
	if($confacl && exists $conf->{ACCESS}->{$confacl}){
	    mypr "no ip access-list extended $confacl\n";
	    $self->cmd("no ip access-list extended $confacl") or exit -1;
	}
	$self->cmd('end') or exit -1;
	$self->cancel_reload();
	mypr "---\n";
    }
    mypr "======================================================\n";
    mypr "done\n";
    mypr "======================================================\n";
}
sub generic_interface_acl_processing ( $$$ ){
    my ($self, $conf,$pspoc) = @_;

    # check if anything to do
    unless(exists $pspoc->{IF}){
	warnpr "no interfaces specified - leaving access-lists untouched\n"; 
	return 1;
    }
    # check for outgoing ACLS
    for my $if (keys %{$conf->{IF}}){
	if(exists $conf->{IF}->{$if}->{ACCESS_OUT} and $conf->{IF}->{$if}->{SHUTDOWN} == 0){
	    warnpr "interface $if: outgoing acl $conf->{IF}->{$if}->{ACCESS_OUT} detected\n";
	}
    }
    # check which spocacls really have to be transfered
    if($self->{COMPARE}){
	$self->compare_interface_acls($pspoc,$conf,$self->{CMPVAL}) or return 0;
	for my $if (keys %{$pspoc->{IF}}){
	    if($pspoc->{IF}->{$if}->{TRANSFER} eq 'YES'){
		$self->{CHANGE}->{ACL}   = 1;
		last;
	    }
	}
	return 1;
    }
    else{
	if($self->{FORCE_TRANSFER}){
	    $self->{CHANGE}->{ACL} = 1;
	    $self->compare_interface_acls($pspoc,$conf,'FORCE') or return 0;
	}
	else{
	    $self->compare_interface_acls($pspoc,$conf,4) or return 0;
	}
    }
    # transfer
    $self->process_interface_acls($conf,$pspoc) or return 0;
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
sub crypto_struct_equal( $$$$$ ){
    my ($self, $a,$b,$context,$changes,$ident) = @_;
    $ident = " $ident";
    #print "-$a--$b-\n";
    if(!ref $a){
	if(!ref $b){
	    ($a eq $b) and return 1;
	}
	else{
	    my $type = ref $b; 
	    errpr "could not compare scalar $a with type $type\n";
	}
	mypr "${ident}diff $a <=> $b\n";
	return 0;
    }
    elsif (ref $a eq 'SCALAR'){
	if (ref $b eq 'SCALAR'){
	    $self->crypto_struct_equal($$a,$$b,$context,$changes,$ident) and return 1;
	}
	else{
	    my $type = ref $b; 
	    errpr "could not compare scalar ref $a with type $type\n";
	}
	mypr "${ident}diff $a <=> $b\n";
	return 0;
    }
    elsif (ref $a eq 'ARRAY'){
	if (ref $b eq 'ARRAY'){
	    # arrays are equal iff have same elements in same order
	    if(scalar @$a eq scalar @$b){ 
		my $equal = 1;
		my $upper_context = $context;
		for(my $i = 0;$i < scalar @$a; $i++){
		    if($upper_context eq "INSTANCES"){
			# this MUSTbe the sequence number from DEVICE!!!!
			$context = @$b[$i]->{SEQU};
		    }
		    unless($self->crypto_struct_equal(@$a[$i],@$b[$i],$context,$changes,$ident)){
			mypr "${ident}diff array element $i\n";
			$equal = 0;
		    }		    
		}
		return $equal;
	    }
	    else{
		mypr "${ident}diff array lenght\n";
	    }
	}
	else{
	    my $type = ref $b; 
	    errpr "could not compare array with type $type\n";
	}
	return 0;
    }
    elsif (ref $a eq 'HASH'){
	if (ref $b eq 'HASH'){
	    my $equal = 1;
	    for my $entry (keys %$a){
		if($entry eq "ACCESS_GROUP_IN"){
		    # special handling forthis entry because it 
		    # is subject of change by netspoc
		    if(exists  $b->{$entry}){
			my $verbose = $self->{COMPARE}?$self->{CMPVAL}:4;
			unless($self->verbose_acl_equal($a->{$entry}->{ACL},
						 $b->{$entry}->{ACL},
						 $a->{$entry}->{NAME},
						 $b->{$entry}->{NAME},
						 $entry,
						 $verbose)
			       ){
			    # $context holds sequence number of map
			    $changes->{$entry}->{$context}->{SPOC} = $a->{$entry}->{NAME}; 
			    $changes->{$entry}->{$context}->{CONF} = $b->{$entry}->{NAME};
			    # differences in the contens of these ACLs handled elsewhere!!!
			    # $equal = 0;
			}
		    }
		    else{
			warnpr "no crypto filter ACL found\n";
			$changes->{$entry}->{$context}->{SPOC} = $a->{$entry}->{NAME};
			$changes->{$entry}->{$context}->{CONF} = '';
		    }
		}
		elsif(exists $b->{$entry}){
		    if($entry eq "MATCH_ADDRESS" or $entry eq "MATCH_ACL"){
			#parser already checked that match address present!
			my $verbose = $self->{COMPARE}?$self->{CMPVAL}:4;
			unless($self->verbose_acl_equal($a->{$entry}->{ACL},
						 $b->{$entry}->{ACL},
						 $a->{$entry}->{NAME},
						 $b->{$entry}->{NAME},
						 $entry,
						 $verbose)
			       ){
			    $equal = 0;
			}
		    }
		    elsif($entry eq "INSTANCES"){
			# the sequence numbers need not to match
			# so transform them to sorted arrays and check contents
			mypr "${ident}transforming crypto map instances\n";
			mypr ${ident}.join ' ',(sort keys %{$a->{$entry}}),"\n";
			mypr ${ident}.join ' ',(sort keys %{$b->{$entry}}),"\n";
			mypr "${ident}to arrays!\n";
			my @a_inst = map $a->{$entry}->{$_}, sort keys %{$a->{$entry}};
			my @b_inst = map $b->{$entry}->{$_}, sort keys %{$b->{$entry}};
			$context = $entry;
			unless($self->crypto_struct_equal(\@a_inst,\@b_inst,$context,$changes,$ident)){
			    mypr "${ident}diff hash element $entry\n";
			    $equal = 0;
			}
		    }
		    elsif($entry eq "NAME" or
			  $entry eq "SEQU" or
			  $entry eq "BOUND_TO_IF"){
			# do not check this !
		    }
		    else{
			unless($self->crypto_struct_equal($a->{$entry},$b->{$entry},$context,$changes,$ident)){
			    mypr "${ident}diff hash element $entry\n";
			    $equal = 0;
			} 
		    }
		}
		else{
		    mypr "${ident}missing hash-key $entry in device config\n";
		    $equal = 0;
		}
	    }
	    for my $entry (keys %$b){
		unless(exists  $a->{$entry}){
		    mypr "${ident}missing hash-key $entry in netspoc config\n"; 
		    $equal = 0;
		}
	    }
	    return $equal;
	}
	else{
	    my $type = ref $b; 
	    errpr "could not compare hash with type $type\n";
	}
	return 0;
    }
    else{
	errpr meself(2)."unsupported type".ref($a)."\n";
	
    }
    return 0;
}
sub crypto_processing( $$$ ){
    my ($self,$conf,$spoc) = @_;
    my $context = {};
    my $changes = {};
    mypr "====                         ====\n";
    mypr "==== begin crypto processing ====\n";
    mypr "====                         ====\n";
    # only proceed if netspoc crypto config present!!!
    if(exists $spoc->{CRYPTO}){
	mypr " +++ spocfile contains crypto definitions!\n";
    }
    else{
	mypr " +++ no crypto definitions in spocfile - skipping\n";
	return 1;
    }
    if(exists $spoc->{CRYPTO}->{ISAKMP}){
	##################################
	#       standard IPSEC
	##################################
	mypr " --- begin compare crypto isakmp ---\n";
	if(exists $conf->{CRYPTO}->{ISAKMP}){
	    if($self->crypto_struct_equal($spoc->{CRYPTO}->{ISAKMP},
				   $conf->{CRYPTO}->{ISAKMP},
				   $context,$changes,'')){ 
		mypr "    no diffs found\n";
	    }
	    else{
		warnpr "severe diffs in crypto isakmp detected!\n";
	    }
	}
	else{
	    errpr "missing isakmp config at device\n";
	}
	mypr " --- end compare crypto isakmp ---\n";
	my %surplus_acls = ();
	#compare crypto config which is bound to inerfaces
	for my $intf (keys %{$spoc->{IF}}){
	    #my $changed = 0;
	    my $trans_crypto = {}; #takes the new crypto config! 
	    $context = {};
	    $changes = {};
	    mypr " --- interface $intf ---\n";
	    if($spoc->{IF}->{$intf}->{CRYPTO_MAP}){
		mypr " crypto map in spocfile found\n";

	    }
	    else{
		mypr " no crypto map in spocfile found\n";
		if($conf->{IF}->{$intf}->{CRYPTO_MAP}){
		    warnpr " crypto map at device found\n";
		    #$self->{CHANGE}->{CRYPTO}   = 1;
		} 
		next;
	    }
	    my $spoc_map_name = $spoc->{IF}->{$intf}->{CRYPTO_MAP};
	    # ok. There should be an crypto map on this interface
	    my $conf_map_name = (exists $conf->{IF}->{$intf}->{CRYPTO_MAP})?$conf->{IF}->{$intf}->{CRYPTO_MAP}:'';
	    unless($conf_map_name){
		errpr "no crypto map at device - leaving crypto untouched\n";
		#$changed = 1; 
		#$self->{CHANGE}->{CRYPTO}   = 1;
		next;
	    }
	    mypr " --- begin compare crypto maps---\n";
	    mypr " $spoc_map_name <-> $conf_map_name\n";
	    unless($self->crypto_struct_equal($spoc->{CRYPTO}->{MAP}->{$spoc_map_name},
				       $conf->{CRYPTO}->{MAP}->{$conf_map_name},
				       $context,$changes,'')){
		errpr "severe diffs in crypto map detected - leaving crypto untouched\n";
		next;
	    }
	    mypr " --- end compare crypto maps---\n";
	    if(exists $changes->{ACCESS_GROUP_IN}){
		mypr " --- processing results ---\n";
		$self->{CHANGE}->{CRYPTO}   = 1;
		for my $sequ (keys %{$changes->{ACCESS_GROUP_IN}}){
		    mypr "Interface \'$intf\': Crypto map: \'$conf_map_name\' instance $sequ *** filter ACL changed ***\n";
		    my $conf_acl_name = $changes->{ACCESS_GROUP_IN}->{$sequ}->{CONF};
		    my $spoc_acl_name = $changes->{ACCESS_GROUP_IN}->{$sequ}->{SPOC};
		    mypr " incoming device  ACL \'$conf_acl_name\' differs from\n";
		    mypr " incoming netspoc ACL \'$spoc_acl_name\'\n";
		    unless($self->{COMPARE}){
			# process crypto filter acls
			my $aclindex;
			if($conf_acl_name =~ /\S+-DRC-([01])/){
			    # active acls matches name convention
			    $aclindex = (not $1) * 1;
			}
			else{
			    if($conf_acl_name){
				warnpr "unexpected filter-acl-name $conf_acl_name at $conf_map_name $sequ\n";
			    }
			    else{
				warnpr "no filter-acl found at $conf_map_name $sequ\n";
			    }
			    $aclindex = 0;
			}
			my $new_acl_name = "$spoc_acl_name-DRC-$aclindex";
			#
			# *** SCHEDULE RELOAD ***
			#
			# TODO: check if 10 minutes are OK
			#
			$self->schedule_reload(10);
			#
			# begin transfer
			#
			mypr "create *new* acl $new_acl_name on device\n";
			#
			# maybe there is an old acl with $aclname:
			# first remove old entries because acl should be empty - otherwise
			# new entries are only appended - bad
			#
			$self->cmd('configure terminal') or exit -1;
			#mypr "no ip access-list extended $aclname\n";
			$self->cmd("no ip access-list extended $new_acl_name") or exit -1;
			$self->cmd('end') or exit -1;
			$self->append_acl_entries($new_acl_name,$spoc->{ACCESS}->{$spoc_acl_name});
			#
			# assign new acl to interfaces
			#
			mypr "assign new acl:\n";
			$self->cmd('configure terminal') or exit -1;
			mypr " crypto map $conf_map_name $sequ\n";
			$self->cmd("crypto map $conf_map_name $sequ") or exit -1;
			mypr " set ip access-group $new_acl_name in\n";
			$self->cmd("set ip access-group $new_acl_name in") or exit -1;
			$self->cmd('end') or exit -1;
			$self->cancel_reload();
			mypr "---\n";
			#new acl established - old one should be removed:
			$surplus_acls{$conf_acl_name} = 1;
		    }
		}
		mypr " --- done processing results ---\n";
	    } 
	}
	# remove surplus ACLs if still present
	unless($self->{COMPARE}){
	    mypr " --- begin remove surplus acls ---\n";
	    #
	    # *** SCHEDULE RELOAD ***
	    #
	    # TODO: check if 3 minutes are OK
	    #
	    $self->schedule_reload(3);
	    for my $acl (keys %surplus_acls){
		$self->cmd('configure terminal') or exit -1;
		if($acl and exists $conf->{ACCESS}->{$acl}){
		    mypr "no ip access-list extended $acl\n";
		    $self->cmd("no ip access-list extended $acl") or exit -1;
		}
		$self->cmd('end') or exit -1;
	    }
	    $self->cancel_reload();
	    mypr " --- done remove surplus acls ---\n";
	}
    }
    elsif(exists $spoc->{CRYPTO}->{IPSEC}->{CLIENT_EZVPN}){
	##################################################
	# in ezvpn mode we grant that the tunnel is terminatet at some
	# virtual interface. this interface holds an ACL
	# the ACL is checked by standard ACL code
	##################################################
	mypr " --- begin compare crypto ezvpn ---\n";
	if(exists $conf->{CRYPTO}->{IPSEC}->{CLIENT_EZVPN}){
	    if($self->crypto_struct_equal($spoc->{CRYPTO}->{IPSEC},
				   $conf->{CRYPTO}->{IPSEC},
				   $context,$changes,'')){ 
		mypr "    no diffs found\n";
	    }
	    else{
		warnpr "severe diffs in crypto ipsec detected!\n";
	    }
	}
	else{
	    errpr "missing ezvpn config at device\n";
	}
	mypr " --- end compare crypto ezvpn ---\n";
    }

    mypr "====                       ====\n";
    mypr "==== end crypto processing ====\n";
    mypr "====                       ====\n";
    return 1;
}
###############################
#
# END crypto processing
#
###############################

sub transfer(){
    my ($self, $conf, $pspoc) = @_;

    # *** BEGIN TRANSFER ***
    $self->generic_interface_acl_processing($conf,$pspoc) or return 0;
    $self->crypto_processing($conf,$pspoc) or return 0;
    $self->process_routing($conf,$pspoc) or return 0;
    #
    # *** CLEANUP
    #
    if($self->{COMPARE}){
	if(not $self->{CHANGE}) {
	    mypr "no changes in running config -" .
		" check if startup is uptodate:\n";
	    if($self->compare_ram_with_nvram()){
		mypr "comp: Startup is uptodate\n";
	    }
	    else{
		mypr "Startup not uptodate ***\n";
		warnpr "Write memory recommended!\n";
		$self->{CHANGE}->{STARTUP_CONFIG} = 1;
	    }
	}
    }
    else {
	$self->cancel_reload();
	if($self->{CHANGE}){
	    # check config size
	    mypr "re-read config\n";
	    $self->cmd('show running') or 
		errpr "possible Problem with config size: config NOT written!\n";
	    # save config
	    mypr "ok\n";
	    $self->write_mem(5,3); # 5 retries, 3 seconds intervall
	}
	else{
	    mypr "no changes to save - check if startup is uptodate:\n";
	    #
	    # Handle past problems with write mem compare 
	    # running  with startup config
	    #
	    if($self->compare_ram_with_nvram()){
		mypr "Startup is uptodate\n";
	    }
	    else{
		warnpr "Startup is *NOT* uptodate - trying to fix:\n";
		$self->write_mem(5,3);
	    }
	}
    }
    return 1;
}

# Packages must return a true value;
1;

