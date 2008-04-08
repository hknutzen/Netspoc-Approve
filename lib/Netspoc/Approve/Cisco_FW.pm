
package Netspoc::Approve::Device::Cisco::Firewall;

#       - ios acl parser
#
#       - pix config       parser
#
#       - semi xml parser
#
#       ---------------------------------------------------------------
#
#       (the corresponding data-struktures are shown below the productions together
#        with their possible values)
#
#       (-) means: not (fully) implemented yet
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

sub version_drc2_Firewall() {
    return $id;
}

# Following lists are subject of permanent adaption from pix and ios devices.
# Not all numbers have names on cisco devices
# and they use non-iana names :(

our %ICMP_Trans = (
    'echo-reply'                  => { type => 0,  code => -1 },
    'unreachable'                 => { type => 3,  code => -1 },
    'net-unreachable'             => { type => 3,  code => 0 },
    'host-unreachable'            => { type => 3,  code => 1 },
    'protocol-unreachable'        => { type => 3,  code => 2 },
    'port-unreachable'            => { type => 3,  code => 3 },
    'packet-too-big'              => { type => 3,  code => 4 },
    'source-route-failed'         => { type => 3,  code => 5 },
    'network-unknown'             => { type => 3,  code => 6 },
    'host-unknown'                => { type => 3,  code => 7 },
    'host-isolated'               => { type => 3,  code => 8 },
    'dod-net-prohibited'          => { type => 3,  code => 9 },
    'dod-host-prohibited'         => { type => 3,  code => 10 },
    'net-tos-unreachable'         => { type => 3,  code => 11 },
    'host-tos-unreachable'        => { type => 3,  code => 12 },
    'administratively-prohibited' => { type => 3,  code => 13 },
    'host-precedence-unreachable' => { type => 3,  code => 14 },
    'precedence-unreachable'      => { type => 3,  code => 15 },
    'source-quench'               => { type => 4,  code => -1 },
    'redirect'                    => { type => 5,  code => -1 },
    'net-redirect'                => { type => 5,  code => 0 },
    'host-redirect'               => { type => 5,  code => 1 },
    'net-tos-redirect'            => { type => 5,  code => 2 },
    'host-tos-redirect'           => { type => 5,  code => 3 },
    'alternate-address'           => { type => 6,  code => -1 },
    'echo'                        => { type => 8,  code => -1 },
    'router-advertisement'        => { type => 9,  code => -1 },
    'router-solicitation'         => { type => 10, code => -1 },
    'time-exceeded'               => { type => 11, code => -1 },
    'ttl-exceeded'                => { type => 11, code => 0 },
    'reassembly-timeout'          => { type => 11, code => 1 },
    'parameter-problem'           => { type => 12, code => -1 },
    'general-parameter-problem'   => { type => 12, code => 0 },
    'option-missing'              => { type => 12, code => 1 },
    'no-room-for-option'          => { type => 12, code => 2 },
    'timestamp-request'           => { type => 13, code => -1 },
    'timestamp-reply'             => { type => 14, code => -1 },
    'information-request'         => { type => 15, code => -1 },
    'information-reply'           => { type => 16, code => -1 },
    'mask-request'                => { type => 17, code => -1 },
    'mask-reply'                  => { type => 18, code => -1 },
    'traceroute'                  => { type => 30, code => -1 },
    'conversion-error'            => { type => 31, code => -1 },
    'mobile-redirect'             => { type => 32, code => -1 }
);

our %IP_Trans = (
    'eigrp'  => 88,
    'gre'    => 47,
    'icmp'   => 1,
    'igmp'   => 2,
    'igrp'   => 9,
    'ipinip' => 4,
    'nos'    => 94,    # strange name
    'ospf'   => 89,
    'pim'    => 103,
    'tcp'    => 6,
    'udp'    => 17,
    'ah'     => 51,
    'ahp'    => 51,
    'esp'    => 50
);

our %PORT_Trans_TCP = (
    'bgp'               => 179,
    'chargen'           => 19,
    'citrix-ica'        => 1494,
    'cmd'               => 514,
    'daytime'           => 13,
    'discard'           => 9,
    'domain'            => 53,
    'echo'              => 7,
    'exec'              => 512,
    'finger'            => 79,
    'ftp'               => 21,
    'ftp-data'          => 20,
    'gopher'            => 70,
    'hostname'          => 101,
    'https'             => 443,
    'irc'               => 194,
    'ident'             => 113,
    'klogin'            => 543,
    'kshell'            => 544,
    'ldap'              => 389,
    'ldaps'             => 636,
    'lpd'               => 515,
    'login'             => 513,
    'lotusnotes'        => 1352,
    'netbios-ssn'       => 139,
    'nntp'              => 119,
    'pcanywhere-data'   => 5631,
    'pcanywhere-status' => 5632,
    'pim-auto-rp'       => 496,
    'pop2'              => 109,
    'pop3'              => 110,
    'smtp'              => 25,
    'sqlnet'            => 1521,
    'ssh'               => 22,
    'sunrpc'            => 111,
    'tacacs'            => 49,
    'tacacs-ds'         => 65,
    'talk'              => 517,
    'telnet'            => 23,
    'time'              => 37,
    'uucp'              => 540,
    'whois'             => 63,
    'www'               => 80
);

our %PORT_Trans_UDP = (
    'biff'          => 512,
    'bootpc'        => 68,
    'bootps'        => 67,
    'discard'       => 9,
    'dns'           => 53,
    'domain'        => 53,
    'dnsix'         => 90,
    'echo'          => 7,
    'isakmp'        => 500,
    'mobile-ip'     => 434,    # maybe this is 435 ?
    'nameserver'    => 42,
    'netbios-dgm'   => 138,
    'netbios-ns'    => 137,
    'netbios-ss'    => 139,
    'non500-isakmp' => 4500,
    'ntp'           => 123,
    'pim-auto-rp'   => 496,
    'radius'        => 1645,
    'radius-acct'   => 1646,
    'rip'           => 520,
    'ripng'         => 521,
    'snmp'          => 161,
    'snmptrap'      => 162,
    'sunrpc'        => 111,
    'syslog'        => 514,
    'tacacs'        => 49,
    'tacacs-ds'     => 65,
    'talk'          => 517,
    'tftp'          => 69,
    'time'          => 37,
    'who'           => 513,
    'www'           => 80,
    'xdmcp'         => 177
);

my %Re_IP_Trans       = reverse %IP_Trans;
my %PORT_Re_Trans_TCP = reverse %PORT_Trans_TCP;
my %PORT_Re_Trans_UDP = reverse %PORT_Trans_UDP;

my %PORT_Trans_TCP_UDP = (%PORT_Trans_TCP, %PORT_Trans_UDP);
my %PORT_Re_Trans_TCP_UDP = reverse %PORT_Trans_TCP_UDP;

my %ICMP_Re_Trans = ();

for my $message (keys %ICMP_Trans) {
    $ICMP_Re_Trans{ $ICMP_Trans{$message}->{type} }
      ->{ $ICMP_Trans{$message}->{code} } = $message;
}

sub dev_cor ($$) {
    my ($self, $addr) = @_;
    return $addr;
}

sub parse_error($$$) {
    my ($self, $line, $message) = @_;

    my ($package, $file, $ln, $sub) = caller 1;

    if ($self->{PRINT}) {
        die
          "parse error (PRINTING) \n in \'$sub\' - $message - yet printed: \'$$line\'\n";
    }

    if (not $self->{PRINT}) {
	$$line =~
	    m/(.{0,25})\G(.{0,25})/s;
	die
	    "parse error (PARSING)  \n in \'$sub\' - $message - \n\'$1<< HERE >>$2\'\n";
    }
}
############################################################
# --- parsing ---
############################################################

# eol
my $eol = qr/\s*(\n|\r|\Z)/;

# token (cluster) separator  {};, are currently *not* in use
#                            - is needed for pix global command
my $ts = qr/(?=[\s{};,-]|\Z|\n)/;

# token (word) charakter class
my $tc = qr/[\w\:-]/;

############################################################
############################################################

sub parse_dummy_lines ( $$$ ) {
    my ($self, $ah, $al) = @_;
    if ($$al =~ /\G(.*\n)/cgxo) {

        #print "DUMMY $1";
        return 1;
    }
    else {
        return 0;
    }
}
#############################################
#
#  [no] global [(<ext_if_name>)] <nat_id>
#              {<global_ip>[-<global_ip>] [netmask <global_mask>]} | interface
#
#  global pix_global()
#
#  only generate arry
#
sub parse_global_lines( $$$ ) {
    my ($self, $ah, $al) = @_;
    if ($self->{PRINT}) {
        for my $entry (@$ah) {
            $self->pix_global($entry, $al);
            $$al = "${$al}\n";
        }
    }
    else {
        my $foundone = 0;
        while ($$al =~ /\G\s*global$ts/cgxo) {
            my $entryhash = {};
            push @{$ah}, $entryhash;
            $self->pix_global($entryhash, $al);
            $$al =~ /\G$eol/cgxo
              or $self->parse_error($al, "end of string or newline expected");
            $foundone = 1;
        }
        return $foundone;
    }
}

### pix_global: (<ext_if_name>) <nat_id> pix_pool()|interface_keyword()
#
# ->{EXT_IF_NAME} ->{NAT_ID}
#
sub pix_global( $$$ ) {
    my ($self, $ah, $al) = @_;
    if ($self->{PRINT}) {
        $$al = "${$al}global ($ah->{EXT_IF_NAME}) $ah->{NAT_ID}";
    }
    elsif ($$al =~ /\G\s*\(($tc+)\)\s+(\d+)$ts/cgxo) {
        $ah->{EXT_IF_NAME} = $1;
        $ah->{NAT_ID}      = $2;
    }
    else {
        $self->parse_error($al, "interface name and nat ID expected");
    }
    $self->pix_pool($ah, $al)
      || $self->interface_keyword($ah, $al)
      || $self->parse_error($al, "address specs expected");
}
### pix_pool: <global_ip>[-<global_ip>] [netmask <global_mask>]
#
# ->{BEGIN} ->{END}
#
sub pix_pool( $$$ ) {
    my ($self, $ah, $al) = @_;
    if ($self->{PRINT}) {

        # we can not use ip_spec here because there
        # is no space between adresses
        if ($ah->{BEGIN}->{BASE}) {
            $$al = "$$al " . int2quad($ah->{BEGIN}->{BASE});
            if ($ah->{END}->{BASE}) {
                $$al = "$$al-" . int2quad($ah->{END}->{BASE});
            }
            $self->netmask($ah, $al);
            return 1;
        }
        else {
            return 0;
        }
    }
    else {
        $ah->{BEGIN} = {};
        $ah->{END}   = {};
        $self->ip_spec($ah->{BEGIN}, $al) or return 0;
        if ($$al =~ /\G-/cgxo) {
            $self->ip_spec($ah->{END}, $al)
              or $self->parse_error($al, "address range end expected");
        }
        $self->netmask($ah, $al);
        return 1;
    }
}
#############################################
#
# [no] nat [(<real_ifc>)] <nat-id>
#                {<real_ip> [<mask>]} | {access-list <acl_name>}
#                [dns] [norandomseq] [outside] [<max_conn> [<emb_limit>]]
#
#  nat pix_nat()
#
#  only generate array
#
sub parse_nat_lines( $$$ ) {
    my ($self, $ah, $al) = @_;
    if ($self->{PRINT}) {
        for my $entry (@$ah) {
            $self->pix_nat($entry, $al);
            $$al = "${$al}\n";
        }
    }
    else {
        my $foundone = 0;
        while ($$al =~ /\G\s*nat$ts/cgxo) {
            my $entryhash = {};
            push @{$ah}, $entryhash;
            pix_nat($self, $entryhash, $al);
            $$al =~ /\G$eol/cgxo
              or $self->parse_error($al, "end of string or newline expected");
            $foundone = 1;
        }
        return $foundone;
    }
}
### pix_nat:  [(<real_ifc>)] <nat-id> { net() | access_list_spec() }
#
#pix_nat_traffic() pix_nat_options()
#
#  ->{NAT_ID} ->{IF_NAME}
#
sub pix_nat( $$$ ) {
    my ($self, $ah, $al) = @_;
    if ($self->{PRINT}) {
        $$al = "${$al}nat ($ah->{IF_NAME}) $ah->{NAT_ID}";
    }
    elsif ($$al =~ /\G\s*\(($tc+)\)\s+(\d+)$ts/cgxo) {
        $ah->{IF_NAME} = $1;
        $ah->{NAT_ID}  = $2;
    }
    else {
        $self->parse_error($al, "interface name and nat ID expected");
    }

    ($self->net_p($ah, $al) || $self->access_list_spec($ah, $al))
      or $self->parse_error($al, "incomplete nat line");

    # $self->dns($ah,$al) &&         => flaw in documentation? disable till clear!
    # $self->norandomseq($ah,$al) && => flaw in documentation? order of items switched...
    $self->outside_keyword($ah, $al);
    $self->max_conns($ah, $al);
    $self->norandomseq($ah, $al);
    return 1;
}
###      outside_keyword:     'outside'
#
#        ->{OUTSIDE}
#
sub outside_keyword($$$) {
    my ($self, $ah, $al) = @_;
    if ($self->{PRINT} and $ah->{OUTSIDE}) {
        $$al = join ' ', $$al, $ah->{OUTSIDE};
    }
    elsif ($$al =~ /\G\s*(outside)$ts/cgxo) {
        $ah->{OUTSIDE} = $1;
    }
    else {
        return 0;
    }
    return 1;
}
#############################################
#
# ip address <if_name> <ip-address> <netmask>
#
# ->{ADDRESS}->{<if_name>}->{BASE}
# ->{ADDRESS}->{<if_name>}->{MASK}
#
sub parse_ip_address( $$$ ) {
    my ($self, $ah, $al) = @_;
    if ($self->{PRINT}) {
        for my $if_name (sort keys %$ah) {
            my $entry = $ah->{ADDRESS}->{$if_name};
            $$al =
                "${$al}ip address $if_name "
              . int2quad($entry->{BASE}) . " "
              . int2quad($entry->{MASK}) . "\n";
        }
    }
    elsif ($$al =~ /\G\s*ip\s+address$ts/cgxo) {
        my $name;
        if ($$al =~ /\G\s*(\S+)$ts/cgxo) {
            $name = $1;
        }
        else {
            $self->parse_error($al, "interface name missing");
        }
        if ($$al =~ /\G\s*([.\d]+)$ts/cgxo) {
            defined($ah->{ADDRESS}->{$name}->{BASE} = quad2int($1))
              or $self->parse_error($al, "base no ipv4 address");
        }
        else {
            $self->parse_error($al, "base missing");
        }
        if ($$al =~ /\G\s*([.\d]+)$ts/cgxo) {
            defined($ah->{ADDRESS}->{$name}->{MASK} = quad2int($1))
              or $self->parse_error($al, "mask no ipv4 address");
        }
        else {
            $self->parse_error($al, "mask missing");
        }
        $$al =~ /\G$eol/cgxo
          or $self->parse_error($al, "end of string or newline expected");
    }
    else {
        return 0;
    }
    return 1;
}

#############################################
#
# up to pix os 6.3
#
# interface <hardware_id> [<hardware_speed> [shutdown]]
#
# ->{<hardware_id>}->{SHUTDOWN}
# ->{<hardware_id>}->{HW_SPEED}
#
sub parse_old_interface( $$$ ) {
    my ($self, $ah, $al) = @_;
    if ($self->{PRINT}) {
        for my $hw_id (sort keys %$ah) {
            my $entry = $ah->{$hw_id};
            $$al = "${$al}interface $hw_id";
            $entry->{HW_SPEED} and $$al = "$$al $entry->{HW_SPEED}";
            $entry->{SHUTDOWN} and $$al = "$$al shutdown";
            $$al = "${$al}\n";
        }
    }
    elsif ($$al =~ /\G\s*interface$ts/cgxo) {
        my $hw_id;
        if ($$al =~ /\G\s*(\S+)$ts/cgxo) {
            $hw_id = $1;
        }
        else {
            $self->parse_error($al, "hardware_id missing");
        }
        if ($$al =~ /\G\s*($tc+)$ts/cgxo) {
            $ah->{$hw_id}->{HW_SPEED} = $1;
        }
        if ($$al =~ /\G\s*shutdown$ts/cgxo) {
            $ah->{$hw_id}->{SHUTDOWN} = 1;
        }
        else {
            $ah->{$hw_id}->{SHUTDOWN} = 0;
        }
        $$al =~ /\G$eol/cgxo
          or $self->parse_error($al, "end of string or newline expected");
    }
    else {
        return 0;
    }
    return 1;
}

#
#  pix os 7.x and FWSM
#
# interface <hardware_id> [<hardware_speed> [shutdown]]
#
# ->{<hardware_id>}->{<pix7_shutdown>SHUTDOWN}
# ->{<hardware_id>}->{HW_SPEED}
# ->{<hardware_id>}->{IF_NAME}
# ->{<hardware_id>}->{SECURITY}
#
sub parse_interface( $$$ ) {
    my ($self, $ah, $al) = @_;
    if ($self->{PRINT}) {
        for my $hw_id (sort keys %$ah) {
            my $entry = $ah->{$hw_id};
            $$al = "${$al}interface $hw_id\n";
            $self->shutdown($entry, $al);
            $self->hw_speed($entry, $al);
            $self->duplex($entry, $al);
            $self->if_name($entry, $al);
            $self->security($entry, $al);
            $self->ip_address($entry, $al);
            $$al = "${$al}!\n";
        }
    }
    elsif ($$al =~ /\G\s*interface$ts/cgxo) {
        my $hw_id;
        if ($$al =~ /\G\s*(\S+)$ts/cgxo) {
            $hw_id = $1;
        }
        else {
            $self->parse_error($al, "hardware_id missing");
        }
        $ah->{$hw_id} = {};
        while ($self->shutdown($ah->{$hw_id}, $al)
            || $self->hw_speed($ah->{$hw_id}, $al)
            || $self->duplex($ah->{$hw_id}, $al)
            || $self->if_name($ah->{$hw_id}, $al)
            || $self->security($ah->{$hw_id}, $al)
            || $self->ip_address($ah->{$hw_id}, $al)
	    || $self->skip_management($ah->{$hw_id}, $al)
	    || $self->skip_description($ah->{$hw_id}, $al))
        {
            $$al =~ /\G$eol/cgxo
              or $self->parse_error($al, "end of string or newline expected");

            #my $p = pos($$al);
            #$$al =~ /\G(\n*|.*)$ts/cgxo;
            #print "--> $p $1 <--\n";
            #print ".";
            #pos($$al) = $p;
        }

        # "!" at end of interface section
        ($$al =~ /\G\s*!$ts/cgxo)
          or $self->parse_error($al, "unknown entry in interface section");

        #
        # postprocess defaults
        #
        if (!exists $ah->{$hw_id}->{SHUTDOWN}) {
            $ah->{$hw_id}->{SHUTDOWN} = 0;
        }
        if (!exists $ah->{$hw_id}->{HW_SPEED}) {
            $ah->{$hw_id}->{HW_SPEED} = 'auto';
        }
        if (!exists $ah->{$hw_id}->{DUPLEX}) {
            $ah->{$hw_id}->{DUPLEX} = 'auto';
        }
    }
    else {
        return 0;
    }
    return 1;
}

sub shutdown( $$$ ) {
    my ($self, $ah, $al) = @_;
    if ($self->{PRINT}) {
        if ($ah->{SHUTDOWN}) {
            $$al = "${$al} shutdown\n";
        }

        # no shutdown is default, so do not print anything
    }
    else {
        if ($$al =~ /\G\s*shutdown$ts/cgxo) {
            $ah->{SHUTDOWN} = 1;
        }
        else {
            return 0;
        }
    }
    return 1;
}

sub hw_speed( $$$ ) {
    my ($self, $ah, $al) = @_;
    if ($self->{PRINT}) {
        if ($ah->{HW_SPEED} and $ah->{HW_SPEED} ne 'auto') {
            $$al = "${$al} speed $ah->{HW_SPEED}\n";
        }

        # speed auto is default, so do not print anything
    }
    else {
        if ($$al =~ /\G\s*speed$ts/cgxo) {
            if ($$al =~ /\G\s*(\d+)$ts/cgxo) {
                $ah->{HW_SPEED} = $1;
            }
            else {
                $self->parse_error($al,
                    "missing speed value in interface speed section");
            }
        }
        else {
            return 0;
        }
    }
    return 1;
}

sub duplex( $$$ ) {
    my ($self, $ah, $al) = @_;
    if ($self->{PRINT}) {
        if ($ah->{DUPLEX} and $ah->{DUPLEX} ne 'auto') {
            $$al = "${$al} duplex $ah->{DUPLEX}\n";
        }

        # duplex auto is default, so do not print anything
    }
    else {
        if ($$al =~ /\G\s*duplex$ts/cgxo) {
            if ($$al =~ /\G\s*($tc+)$ts/cgxo) {
                $ah->{DUPLEX} = $1;
            }
            else {
                $self->parse_error($al,
                    "missing duplex value in interface duplex section");
            }
        }
        else {
            return 0;
        }
    }
    return 1;
}

sub if_name( $$$ ) {
    my ($self, $ah, $al) = @_;
    if ($self->{PRINT}) {
        if (defined $ah->{IF_NAME}) {
            $$al = "${$al} nameif $ah->{IF_NAME}\n";
        }
        else {
            $$al = "${$al} no nameif\n";
        }
    }
    else {
        if ($$al =~ /\G\s*(no)?(\s*)?nameif$ts/cgxo) {
            if (defined $1) {

                # nothing to do
            }
            elsif ($$al =~ /\G\s*(\S+)$ts/cgxo) {
                $ah->{IF_NAME} = $1;
            }
            else {
                $self->parse_error($al,
                    "missing interface name in nameif section");
            }
        }
        else {
            return 0;
        }
    }
    return 1;
}

sub security( $$$ ) {
    my ($self, $ah, $al) = @_;
    if ($self->{PRINT}) {
        if (defined $ah->{SECURITY}) {
            $$al = "${$al} security-level $ah->{SECURITY}\n";
        }
        else {
            $$al = "${$al} no security-level\n";
        }
    }
    else {
        if ($$al =~ /\G\s*(no)?(\s*)?security-level$ts/cgxo) {
            if (defined $1) {

                # nothing to do
            }
            elsif ($$al =~ /\G\s*(\d+)$ts/cgxo) {
                $ah->{SECURITY} = $1;
            }
            else {
                $self->parse_error($al,
                    "malformed security-level in interface section");
            }
        }
        else {
            return 0;
        }
    }
    return 1;
}

# ip address 10.1.13.191 255.255.255.0 [standby 10.1.13.192]
sub ip_address( $$$ ) {
    my ($self, $ah, $al) = @_;
    if ($self->{PRINT}) {
        if (defined $ah->{ADDRESS}) {
            my $entry = $ah->{ADDRESS};
            $$al =
                "${$al}ip address "
              . int2quad($entry->{BASE}) . " "
              . int2quad($entry->{MASK}) . "\n";
        }
    }
    elsif ($$al =~ /\G\s*(no)?(\s*)?ip\s+address$ts/cgxo) {
        if (defined $1) {

            # nothing to do
        }
        else {
            if ($$al =~ /\G\s*([.\d]+)$ts/cgxo) {
                defined($ah->{ADDRESS}->{BASE} = quad2int($1))
                  or $self->parse_error($al, "base no ipv4 address");
            }
            else {
                $self->parse_error($al, "base missing");
            }
            if ($$al =~ /\G\s*([.\d]+)$ts/cgxo) {
                defined($ah->{ADDRESS}->{MASK} = quad2int($1))
                  or $self->parse_error($al, "mask no ipv4 address");
            }
            else {
                $self->parse_error($al, "mask missing");
            }
	    if ($$al =~ /\G\s*standby\s+([.\d]+)$ts/cgxo) {
                if(defined( $ah->{ADDRESS}->{STANDBY} = quad2int($1))) {
		    my $err_msg = "unable to determine standby IP-address";
		    $self->parse_error($al, $err_msg);
		}
            }

#	$$al =~ /\G$eol/cgxo or $self->parse_error($al,"end of string or newline expected");
        }
    }
    else {
        return 0;
    }
    return 1;
}

sub skip_management( $$$ ) {
    my ($self, $ah, $al) = @_;

    if ($$al =~ /\G\s*management\-only\s*([\w\s]+)$ts/cgxo) {
	mypr "Skipping entry 'management-only'\n";
    }
}

sub skip_description( $$$ ) {
    my ($self, $ah, $al) = @_;

    if ($$al =~ /\G\s*description\s+([\w\s]+)$ts/cgxo) {
	mypr "Skipping description: $1\n";
    }
}

#############################################
#
# nameif {<hardware_id>|<vlan_id>} <if_name> <security_level>
#
# ->{<hardware_id>}->{IF_NAME}
# ->{<hardware_id>}->{SECURITY}
#
sub parse_nameif( $$$ ) {
    my ($self, $ah, $al) = @_;
    if ($self->{PRINT}) {
        for my $hw_id (sort keys %$ah) {
            my $entry = $ah->{$hw_id};
            $$al = "${$al}nameif $hw_id $entry->{IF_NAME} $entry->{SECURITY}\n";
        }
    }
    elsif ($$al =~ /\G\s*nameif$ts/cgxo) {
        my $hw_id;
        if ($$al =~ /\G\s*(\S+)$ts/cgxo) {
            $hw_id = $1;
        }
        else {
            $self->parse_error($al, "hardware_id missing");
        }
        if ($$al =~ /\G\s*($tc+)\s+($tc+)$ts/cgxo) {
            $ah->{$hw_id}->{IF_NAME}  = $1;
            $ah->{$hw_id}->{SECURITY} = $2;
        }
        else {
            $self->parse_error($al, "interface name or security level missing");
        }
        $$al =~ /\G$eol/cgxo
          or $self->parse_error($al, "end of string or newline expected");
    }
    else {
        return 0;
    }
    return 1;
}
#############################################
#
# access-group <access_list_name> in interface <if_name>
#
# ->{<access_list_name>}->{IF_NAME}
#
sub parse_access_group( $$$ ) {
    my ($self, $ah, $al) = @_;
    if ($self->{PRINT}) {
        for my $acl_name (sort keys %$ah) {
            my $entry = $ah->{$acl_name};
            $$al =
              "${$al}access-group $acl_name in interface $entry->{IF_NAME}\n";
        }
    }
    elsif ($$al =~ /\G\s*access-group$ts/cgxo) {
        my $acl_name;
        if ($$al =~ /\G\s*($tc+)$ts/cgxo) {
            $acl_name = $1;
        }
        else {
            $self->parse_error($al, "acl name missing");
        }
        if ($$al =~ /\G\s*in(\s+interface)?\s+($tc+)$ts/cgxo) {
            $ah->{$acl_name}->{IF_NAME} = $2;
        }
        else {
            $self->parse_error($al, "interface name missing");
        }
        $$al =~ /\G$eol/cgxo
          or $self->parse_error($al, "end of string or newline expected");
    }
    else {
        return 0;
    }
    return 1;
}
#############################################
#
# generate array with pix routing entrys
#
# route  syntax from pix OS 6.3 documentation:
#
# [no] route if_name ip_address netmask gateway_ip [metric]
#
# route pix_route
#
# ->[]
#
sub parse_route_lines( $$$ ) {
    my ($self, $ah, $al) = @_;
    if ($self->{PRINT}) {
        for my $entry (@{$ah}) {
            $self->pix_route($entry, $al);
            $$al = "$$al\n";
        }
    }
    else {
        my $foundone = 0;
        while ($$al =~ /\G\s*route$ts/cgxo) {
            $foundone = 1;
            my $entryhash = {};
            push @{$ah}, $entryhash;
            $self->pix_route($entryhash, $al);
            $$al =~ /\G$eol/cgxo
              or $self->parse_error($al, "end of string or newline expected");
        }
        return $foundone;
    }
}
##############################################################
#
# route  syntax from pix OS 6.3 documentation:
#
#  ip_address netmask gateway_ip [metric]
#
# ->{IF} ->{BASE} ->{MASK} ->{NEXTHOP} [->{METRIC}]
#
sub pix_route( $$$) {
    my ($self, $ah, $al) = @_;
    if ($self->{PRINT}) {
        $$al =
            "${$al}route $ah->{IF} "
          . int2quad($ah->{BASE}) . " "
          . int2quad($ah->{MASK}) . " "
          . int2quad($ah->{NEXTHOP});
        exists $ah->{METRIC} and $$al = "${$al} $ah->{METRIC}";
    }
    else {
        if ($$al =~ /\G\s*($tc+)$ts/cgxo) {
            $ah->{IF} = $1;
        }
        else {
            $self->parse_error($al, "interface name expected");
        }
        if ($$al =~ /\G\s*([.\d]+)$ts/cgxo) {
            defined($ah->{BASE} = quad2int($1))
              or $self->parse_error($al, "base no ipv4 address");
        }
        else {
            $self->parse_error($al, "base missing");
        }
        if ($$al =~ /\G\s*([.\d]+)$ts/cgxo) {
            defined($ah->{MASK} = quad2int($1))
              or $self->parse_error($al, "mask no ipv4 address");
        }
        else {
            $self->parse_error($al, "mask missing");
        }
        if ($$al =~ /\G\s*([.\d]+)$ts/cgxo) {
            defined($ah->{NEXTHOP} = quad2int($1))
              or $self->parse_error($al, "nexthop no ipv4 address");
        }
        else {
            $self->parse_error($al, "nexthop missing");
        }
        if ($$al =~ /\G\s*(\d+)$ts/cgxo) {
            $ah->{METRIC} = $1;
        }
    }
}

#
#

sub parse_crypto( $$$ ) {
    my ($self, $ah, $al) = @_;
    my $foundone = 0;
    while ($$al =~ /\G\s*crypto$ts/cgxo) {
        (        $self->pix_crypto_map($ah, $al)
              || $self->pix_crypto_ca($ah, $al)
              || $self->pix_crypto_dynamic_map($ah, $al)
              || $self->pix_crypto_ipsec($ah, $al)
              || $self->pix_crypto_isakmp($ah, $al)
              || $self->pix_crypto_sa($ah, $al))
          or $self->parse_error($al, "unknown subcommand");
        $foundone = 1;
    }
    return $foundone;
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

sub pix_crypto_map( $$$ ) {
    my ($self, $ah, $al) = @_;
    if ($self->{PRINT}) {
        parse_error $self, $al, "printing not implemented for crypto maps yet";
    }
    if ($$al =~ /\G\s*map\s+($tc+)$ts/cgxo) {
        my $map_name = $1;

        #print $map_name."\n";
        # hack #
        if ($$al =~ /\G\s*(\d+)\s+match\s+address\s+($tc+)$ts/cgxo) {
            my $seq_num  = $1;
            my $acl_name = $2;

            #print "crypto map $map_name $seq_num $acl_name\n";
            $ah->{MAP}->{$map_name}->{SEQ_NUM}->{$seq_num}->{MATCH_ADDRESS} =
              $acl_name;
        }
        elsif ($$al =~ /\G(.*)$eol/cgxo) {
        }

    }
    return 1;
}

sub pix_crypto_ca( $$$ ) {
    my ($self, $ah, $al) = @_;
    if ($$al =~ /\G\s*ca.*$eol/cgxo) {
    }
    return 1;
}

sub pix_crypto_dynamic_map( $$$ ) {
    my ($self, $ah, $al) = @_;
    if ($$al =~ /\G\s*dynamic-map.*$eol/cgxo) {
    }
    return 1;
}

sub pix_crypto_ipsec( $$$ ) {
    my ($self, $ah, $al) = @_;
    if ($$al =~ /\G\s*ipsec.*$eol/cgxo) {
    }
    return 1;
}

sub pix_crypto_isakmp( $$$ ) {
    my ($self, $ah, $al) = @_;
    if ($$al =~ /\G\s*isakmp.*$eol/cgxo) {
    }
    return 1;
}

sub pix_crypto_sa( $$$ ) {
    my ($self, $ah, $al) = @_;
    if ($$al =~ /\G\s*sa.*$eol/cgxo) {
    }
    return 1;
}

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
# *** only subcommands yet implemented ***
#
###     object_group: object-group {icmp-type|network|protocol|service} <grp_id>
#
#   ->{<grp-id>}
#
sub parse_object_group($$$) {
    my ($self, $ah, $al) = @_;
    if ($self->{PRINT}) {
        for my $og_name (sort keys %$ah) {
            my $entry = $ah->{$og_name};
            $$al = "${$al}object-group $entry->{TYPE} $og_name\n";

            # no check for valid entrys here - it is done when parsing
            $self->og_description($entry, $al);

            #
            # TO DO: implementing the following functions
            #
            #   og_icmp_object
            #   og_protocol_object
            #   og_port_object
            #
            $self->og_network_object($entry, $al);
            $self->og_group_object($entry, $al);
        }
    }
    else {
        my $foundone = 0;
        while ($$al =~
            /\G\s*object-group\s+(icmp-type|network|protocol|service)\s+(\S+)$ts/cgxo
          )
        {
            $ah->{$2} = {};
            my $entry   = $ah->{$2};
            my $og_type = $1;
            if (exists $entry->{TYPE} and $entry->{TYPE} ne $og_type) {
                $self->parse_error($al,
                    "An object-group with the same id ($2) but different type ($entry->{TYPE}) exists"
                );
            }
            $$al =~ /\G$eol/cgxo
              or $self->parse_error($al, "end of string or newline expected");
            $entry->{TYPE} = $og_type;
            if ($og_type eq "icmp-type") {
                $self->parse_error($al, "icmp-type not implemented yet");
            }
            elsif ($og_type eq "network") {
                while ($self->og_description($entry, $al)
                    || $self->og_network_object($entry, $al)
                    || $self->og_group_object($entry, $al))
                {
                    $$al =~ /\G$eol/cgxo
                      or $self->parse_error($al,
                        "end of string or newline expected");
                }
            }
            elsif ($og_type eq "protocol") {
                $self->parse_error($al, "protocol not implemented yet");
            }
            elsif ($og_type eq "service") {
                $self->parse_error($al, "service not implemented yet");
            }
            else {
                $self->parse_error($al, "internal error");
            }
            $foundone = 1;
        }
        if ($self->{PRINT}) {
            $$al =~ s/^ +//;
        }
        return $foundone;
    }
}
###  og_description: description description_text
#
#    ->{DESCRIPTION}
#
sub og_description($$$) {
    my ($self, $ah, $al) = @_;
    if ($self->{PRINT} and $ah->{DESCRIPTION}) {
        $$al = "${$al} description $ah->{DESCRIPTION}\n";
    }
    elsif ($$al =~ /\G\s*description$ts/cgxo) {

        if ($$al =~ /\G\s*(\S+.*)$ts/cgxo) {
            $ah->{DESCRIPTION} = $1;
        }
        else {
            $self->parse_error($al, "non empty description expected");
        }
    }
    else {
        return 0;
    }
    return 1;
}
###  og_network_object: network-object address
#
#    ->{NETWORK_OBJECT}[]
#
sub og_network_object($$$) {
    my ($self, $ah, $al) = @_;
    if ($self->{PRINT}) {
        for my $entry (@{ $ah->{NETWORK_OBJECT} }) {
            $$al = join ' ', $$al, 'network-object', int2quad($entry->{BASE}),
              int2quad(dev_cor($self->{MODE}, $entry->{MASK}));
            $$al = "$$al\n";
        }
    }
    else {
        my $foundone = 0;
        while ($$al =~ /\G\s*network-object$ts/cgxo) {
            my $entryhash = {};
            push @{ $ah->{NETWORK_OBJECT} }, $entryhash;
            ($self->net($entryhash, $al) || host($self, $entryhash, $al))
              or $self->parse_error($al, "network-object missing");
            $foundone = 1;
        }
        return $foundone;
    }
}
### og_group_object: group-object grp_id
#
#
#    ->{GROUP_OBJECT}
#
sub og_group_object($$$) {
    my ($self, $ah, $al) = @_;
    if ($self->{PRINT}) {
        for my $entry (@{ $ah->{GROUP_OBJECT} }) {
            $$al = join ' ', $$al, 'group-object', $entry->{NAME};
            $$al = "$$al\n";
        }
    }
    else {
        my $foundone = 0;
        while ($$al =~ /\G\s*group-object$ts/cgxo) {
            if ($$al =~ /\G\s*(\S+)$ts/cgxo) {
                push @{ $ah->{GROUP_OBJECT} }, { NAME => $1 };
            }
            else {
                $self->parse_error($al, "non empty group id expected");
            }
            $foundone = 1;
        }
        return $foundone;
    }
}
#############################################
#
# generate array of statics
#
sub parse_static_lines($$$) {
    my ($self, $ah, $al) = @_;
    if ($self->{PRINT}) {
        for my $entry (@{$ah}) {
            $self->static_line($entry, $al);
            $$al = "$$al\n";
        }
    }
    else {
        my $foundone = 0;
        my $done;
        until ($done) {
            my $entryhash = {};
            if ($self->static_line($entryhash, $al)) {
                $foundone = 1;
                push @{$ah}, $entryhash;
                $$al =~ /\G$eol/cgxo
                  or
                  $self->parse_error($al, "end of string or newline expected");
            }
            else {
                $done = 1;
            }
        }
        return $foundone;
    }
}
#############################################
#
# static syntax from pix OS 6.3 documentation:
#
# [no] static [(local_ifc,global_ifc)] {global_ip | interface} {local_ip [netmask mask] | access-list acl_name} [dns] [norandomseq] [max_conns [emb_limit]]
# [no] static [(local_ifc,global_ifc)] {tcp | udp} {global_ip | interface} global_port {local_ip local_port [netmask mask] | access-list acl_name} [dns] [norandomseq] [max_conns [emb_limit]]
#
###     static_line:  local_global  translation [dns] [norandomseq] [max_conns]
#
#                                               ^^^^^ disabled due to documentation flaw!!!
#                                                     -> instead parse dns in trans_nat and trans_pat
#
#                                               => another flaw: order of last two item weired
sub static_line($$$) {
    my ($self, $ah, $al) = @_;
    my $result = (
             $self->local_global($ah, $al)
          && $self->translation($ah, $al)
          &&

          # $self->dns($ah,$al) &&         => flaw in documentation? disable till clear!
          # $self->norandomseq($ah,$al) && => flaw in documentation? order of items switched...
          $self->max_conns($ah, $al)
    ) && $self->norandomseq($ah, $al);
    if ($self->{PRINT}) {
        $$al =~ s/^ +//;
    }
    return $result;
}
###     local_global: static (local_ifc,global_ifc)
#
#       ->{LOCAL_IF} ->{GLOBAL_IF}    (names of interfaces)
#
#       =>  the local - global interface spec is *not* optional in this parser!
#
sub local_global($$$) {
    my ($self, $ah, $al) = @_;
    if ($self->{PRINT}) {
        $$al = "${$al}static ($ah->{LOCAL_IF},$ah->{GLOBAL_IF})";
    }
    elsif ($$al =~ /\G\s*static$ts/cgxo) {
        if ($$al =~ /\G\s*\(($tc+),($tc+)\)$ts/cgxo) {
            $ah->{LOCAL_IF}  = $1;
            $ah->{GLOBAL_IF} = $2;
        }
        else {
            $self->parse_error($al, "(local_if,global_if) expected");
        }
    }
    else {
        return 0;
    }
    return 1;
}
###     translation:    static_nat
#
#                or:    (tcp|udp) static_pat
#
#         ->{TRANS}->{TYPE} (tcp|udp|ip)
#
sub translation($$$) {
    my ($self, $ah, $al) = @_;
    if ($self->{PRINT}) {
        $ah->{TRANS}->{TYPE} or return 0;
    }
    else {
        if ($$al =~ /\G\s*(tcp|udp)$ts/cgxo) {
            $ah->{TRANS}->{TYPE} = $1;
        }
        else {
            $ah->{TRANS}->{TYPE} = 'ip';
        }
    }
    if ($ah->{TRANS}->{TYPE} eq 'ip') {
        $self->static_nat($ah->{TRANS}, $al)
          or $self->parse_error($al, "nat expected");
    }
    else {
        $self->static_pat($ah->{TRANS}, $al)
          or $self->parse_error($al, "pat expected");
    }
    ###
    ### TO DO: maybe we want to check the netmask in the future ...
    ###
    return 1;
}
###      static_nat:    {ip_spec | 'interface'} {ip_spec [dns] [netmask] | access_list_spec [dns]}
#
#                                                        ^^^^^ <- bug in docu ??? ->        ^^^^^
#        ->{LOCAL} ->{GLOBAL}
#
sub static_nat($$$) {
    my ($self, $ah, $al) = @_;
    unless ($self->{PRINT}) {
        $ah->{GLOBAL} = {};
        $ah->{LOCAL}  = {};
    }
    return ( $self->ip_spec($ah->{GLOBAL}, $al)
          || $self->interface_keyword($ah->{GLOBAL}, $al))
      && ( $self->ip_spec($ah->{LOCAL}, $al)
        && $self->dns($ah->{LOCAL}, $al)
        && $self->netmask($ah->{LOCAL}, $al)
        || $self->access_list_spec($ah->{LOCAL}, $al)
        && $self->dns($ah->{LOCAL}, $al));
}
###   static_pat: {ip_spec | 'interface'} port_spec {ip_spec port_spec [dns] [netmask] | access_list_spec [dns]}
#
#                                                                      ^^^^^ <- bug in docu ??? ->        ^^^^^
#        ->{LOCAL} ->{GLOBAL}
#
sub static_pat($$$) {
    my ($self, $ah, $al) = @_;
    if ($self->{PRINT}) {
        $$al = join ' ', $$al, $ah->{TYPE};
    }
    else {
        $ah->{GLOBAL} = {};
        $ah->{LOCAL}  = {};
    }
    ($ah->{TYPE} eq 'tcp') and $self->{PORTMODE} = \%PORT_Trans_TCP;
    ($ah->{TYPE} eq 'udp') and $self->{PORTMODE} = \%PORT_Trans_UDP;
    my $result = (
        (
                 $self->ip_spec($ah->{GLOBAL}, $al)
              || $self->interface_keyword($ah->{GLOBAL}, $al)
        )
          && $self->port_spec($ah->{GLOBAL}, $al)
      )
      && ( $self->ip_spec($ah->{LOCAL}, $al)
        && $self->port_spec($ah->{LOCAL}, $al)
        && $self->dns($ah->{LOCAL}, $al)
        && $self->netmask($ah->{LOCAL}, $al)
        || $self->access_list_spec($ah->{LOCAL}, $al)
        && $self->dns($ah->{LOCAL}, $al));
    $self->{PORTMODE} = {};
    return $result;
}
###      interface_keyword:     'interface'
#
#        ->{INTERFACE}
#
sub interface_keyword($$$) {
    my ($self, $ah, $al) = @_;
    if ($self->{PRINT} and $ah->{INTERFACE}) {
        $$al = join ' ', $$al, $ah->{INTERFACE};
    }
    elsif ($$al =~ /\G\s*(interface)$ts/cgxo) {
        $ah->{INTERFACE} = $1;
    }
    else {
        return 0;
    }
    return 1;
}
###      ip_spec:     <ip-adress>
#
#        ->{BASE}
#
sub ip_spec($$$) {
    my ($self, $ah, $al) = @_;
    if ($self->{PRINT} and exists $ah->{BASE}) {
        $$al = join ' ', $$al, int2quad($ah->{BASE});
    }
    elsif ($$al =~ /\G\s*([.\d]+)$ts/cgxo) {
        defined($ah->{BASE} = quad2int($1))
          or $self->parse_error($al, "no ipv4 address");
    }
    else {
        return 0;
    }
    return 1;
}
###      netmask:   netmask <mask>
#
#        ->{NETMASK}
#
sub netmask($$$) {
    my ($self, $ah, $al) = @_;
    if ($self->{PRINT} and $ah->{NETMASK}) {
        $$al = join ' ', $$al, 'netmask', int2quad($ah->{NETMASK});
    }
    elsif ($$al =~ /\G\s*netmask\s+([.\d]+)$ts/cgxo) {
        defined($ah->{NETMASK} = quad2int($1))
          or $self->parse_error($al, "no ipv4 address");
    }
    else {
        return 0;
    }
    return 1;
}
###      port_spec:  <port>  (udp or tcp according to $self->{PORTMODE} or number
#
#        ->{PORT}
#
sub port_spec($$$) {
    my ($self, $ah, $al) = @_;
    if ($self->{PRINT}) {
        $$al = join ' ', $$al, $ah->{PORT};
    }
    elsif ($$al =~ /\G\s*($tc+)$ts/cgxo) {
        my $port = $1;
        if (exists $self->{PORTMODE}{$port}) {
            $port = $self->{PORTMODE}{$port};
        }
        unless ($port =~ /\d+/ && $port <= 0xffff) {
            $self->parse_error($al, "unknown port specifier $port");
        }
        $ah->{PORT} = $port;
    }
    else {
        return 0;
    }
    return 1;
}
###      access_list_spec:  access-list <acl_name>
#
#        ->{ACCESS_LIST}->{NAME}
#
sub access_list_spec($$$) {
    my ($self, $ah, $al) = @_;
    if ($self->{PRINT}) {
        $$al = join ' ', $$al, 'access-list', $ah->{ACCESS_LIST}->{NAME};
    }
    elsif ($$al =~ /\G\s*access-list\s+($tc+)$ts/cgxo) {
        $ah->{ACCESS_LIST}->{NAME} = $1;
    }
    else {
        return 0;
    }
    return 1;
}
###      dns:   'dns'
#
#          ->{DNS}
#
sub dns($$$) {
    my ($self, $ah, $al) = @_;
    if ($self->{PRINT} and $ah->{DNS}) {
        $$al = join ' ', $$al, $ah->{DNS};
    }
    elsif ($$al =~ /\G\s*(dns)$ts/cgxo) {
        $ah->{DNS} = $1;
    }
    return 1;
}
###      norandomseq: 'norandomseq'
#
#        ->{NORANDOMSEQ}
#
sub norandomseq($$$) {
    my ($self, $ah, $al) = @_;
    if ($self->{PRINT} and $ah->{NORANDOMSEQ}) {
        $$al = join ' ', $$al, $ah->{NORANDOMSEQ};
    }
    elsif ($$al =~ /\G\s*(norandomseq)$ts/cgxo) {
        $ah->{NORANDOMSEQ} = $1;
    }
    return 1;
}

###     max_cons:       [max_conns [emb_limit]]
#
#       ->{MAX_CONS}
#
sub max_conns($$$) {
    my ($self, $ah, $al) = @_;
    if ($self->{PRINT} and exists $ah->{MAX_CONS}) {
        $$al = join ' ', $$al, $ah->{MAX_CONS};
    }
    elsif ($$al =~ /\G\s*(\d+)$ts/cgxo) {
        $ah->{MAX_CONS} = $1;
    }
    else {
        $ah->{MAX_CONS} = 0;
    }
    $self->emb_limit($ah, $al);
    return 1;
}

###     emb_limit:
#
#       ->{EMB_LIMIT}
#
sub emb_limit($$$) {
    my ($self, $ah, $al) = @_;
    if ($self->{PRINT} and exists $ah->{EMB_LIMIT}) {
        $$al = join ' ', $$al, $ah->{EMB_LIMIT};
    }
    elsif ($$al =~ /\G\s*(\d+)$ts/cgxo) {
        $ah->{EMB_LIMIT} = $1;
    }
    else {
        $ah->{EMB_LIMIT} = 0;
    }
    return 1;
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

##################################################################
#
#       acl syntax derived from cisco pix 6.3 documentation (above)
#
#       changed handling of ip protocol field: only 3 kinds of entrys:
#
#               'ip','object-group' and "ip protocol coded as integer"
#
### pix_show_access_list_line: { access-list id [line line-num] pix_acl_entry } *
#
# fill arry and ignore(!) object-group lines
#
sub pix_show_access_list_line($$$) {
    my ($self, $ah, $al) = @_;
    if ($$al =~ /\G\s*description$ts/cgxo) {
    }
}
### pix_write_term_acl: { access-list id pix_acl_entry } *
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
sub parse_write_term_acl($$$) {
    my ($self, $ah, $al) = @_;
    my $foundone = 0;
    if ($self->{PRINT}) {
        for my $acl_name (sort keys %$ah) {
            for my $entry (@{ $ah->{$acl_name}->{RAW_ARRAY} }) {
                $$al = "${$al}access-list $acl_name";
                $self->pix_acl_entry($entry, $al);
                $$al = "$$al\n";
            }
        }
    }
    else {
        while ($$al =~ /\G\s*access-list$ts/cgxo) {
            if ($$al =~ /\G\s*(\S+)(\s+extended)?$ts/cgxo) {
                my $entryhash = {};
                my $id        = $1;
                push @{ $ah->{$id}->{RAW_ARRAY} }, $entryhash;
                if ($self->pix_acl_entry($entryhash, $al)) {
                    $$al =~ /\G$eol/cgxo
                      or $self->parse_error($al,
                        "end of string or newline expected");
                    $foundone = 1;
                }
                elsif ($id eq 'compiled') {

                    # this is to ignore "access-list compiled" keyword !!!
                    # remove surplus hash entry
                    $$al =~ /\G$eol/cgxo
                      or $self->parse_error($al,
                        "end of string or newline expected");
                    delete $ah->{$id};
                }
                elsif ($id eq 'deny-flow-max') {

                    # this is to ignore "access-list deny-flow-max n" keyword !!!
                    # remove surplus hash entry
                    $$al =~ /\G\s+\d+$eol/cgxo
                      or $self->parse_error($al,
                        "end of string or newline expected");
                    delete $ah->{$id};
                }
                elsif ($id eq 'alert-interval') {

                    # this is to ignore "access-list alert-interval sec" keyword !!!
                    # remove surplus hash entry
                    $$al =~ /\G\s+\d+$eol/cgxo
                      or $self->parse_error($al,
                        "end of string or newline expected");
                    delete $ah->{$id};
                }
                else {
                    $self->parse_error($al, "incomplete access-list entry");
                }
            }
            else {
                $self->parse_error($al, "access-list id expected");
            }
        }
    }
    if ($self->{PRINT}) {
        $$al =~ s/^ +//;
    }
    return $foundone;
}
###    	pix_acl_entry:  action {pixacl_og_spec | pixacl_ip_prot_spec}
#                        pixacl_adr_srv_spec pixacl_adr_srv_spec
#                         [pixacl_log_packet] [pixacl_interval]
#
#                  or   remark
#
sub pix_acl_entry($$$) {
    my ($self, $ah, $al) = @_;
    if ($self->{PRINT}) {
    }
    else {
        $ah->{PROTO}->{SRC}  = {};
        $ah->{PROTO}->{DST}  = {};
        $ah->{PROTO}->{SPEC} = {};
    }
    my $result;
    if (
        $self->action($ah, $al)
        && (   $self->pixacl_ip_prot_spec($ah->{PROTO}, $al)
            || $self->pixacl_og_spec($ah->{PROTO}, $al, 'protocol'))
      )
    {

        # 2 general cases group or type
        # 3 sub cases: icmp tcp/udp "any other protocol"
        if (defined $ah->{PROTO}->{TYPE}) {

            #
            # icmp
            #
            if ($ah->{PROTO}->{TYPE} eq 1) {    # "icmp"
                $result = (
                    $self->adr_opt($ah->{PROTO}->{SRC}, $al)
                      || $self->pixacl_og_spec(
                        $ah->{PROTO}->{SRC}, $al, 'network'
                      )
                  )
                  && ($self->adr_opt($ah->{PROTO}->{DST}, $al)
                    || $self->pixacl_og_spec($ah->{PROTO}->{DST}, $al,
                        'network'))
                  && $self->icmpmessage($ah->{PROTO}->{SPEC}, $al)
                  && $self->pixacl_log_packet($ah, $al);
            }

            #
            # udp/tcp
            #
            elsif ($ah->{PROTO}->{TYPE} eq 17 or $ah->{PROTO}->{TYPE} eq 6) {
                $result = $self->pixacl_adr_srv_spec($ah->{PROTO}->{SRC}, $al)
                  && $self->pixacl_adr_srv_spec($ah->{PROTO}->{DST}, $al)
                  && $self->pixacl_log_packet($ah, $al);
            }

            #
            # any other protocol
            #
            else {
                $result = (
                    $self->adr_opt($ah->{PROTO}->{SRC}, $al)
                      || $self->pixacl_og_spec(
                        $ah->{PROTO}->{SRC}, $al, 'network'
                      )
                  )
                  && ($self->adr_opt($ah->{PROTO}->{DST}, $al)
                    || $self->pixacl_og_spec($ah->{PROTO}->{DST}, $al,
                        'network'))
                  && $self->pixacl_log_packet($ah, $al);
            }
        }
        elsif ($ah->{PROTO}->{OBJECT_GROUP}) {

            # the only thing we know about this line is: 
	    # ICMP should *not* be used
            $result = $self->pixacl_adr_srv_spec($ah->{PROTO}->{SRC}, $al)
              && $self->pixacl_adr_srv_spec($ah->{PROTO}->{DST}, $al)
              && $self->pixacl_log_packet($ah, $al);
        }
    }
    else {
        $result = $self->remark($ah, $al) || $self->compiled_keyword($ah, $al);
    }
    if ($self->{PRINT}) {
        $$al =~ s/^ +//;
    }
    return $result;
}
###      compiled_keyword:     'compiled'
#
#        ->{OUTSIDE}
#
sub compiled_keyword($$$) {
    my ($self, $ah, $al) = @_;
    if ($self->{PRINT} and $ah->{COMPILED}) {
        $$al = join ' ', $$al, $ah->{COMPILED};
    }
    elsif ($$al =~ /\G\s*(compiled)$ts/cgxo) {
        $ah->{COMPILED} = $1;
    }
    else {
        return 0;
    }
    return 1;
}
###     pixacl_og_spec: object-group obj_grp_id
#
#       ->{OBJECT_GROUP}
#
sub pixacl_og_spec( $$$$ ) {
    my ($self, $ah, $al, $type) = @_;
    if ($self->{PRINT}) {
        if ($ah->{OBJECT_GROUP}) {
            $$al = join ' ', $$al, 'object-group', $ah->{OBJECT_GROUP};
            return 1;
        }
        return 0;
    }
    if ($$al =~ /\G\s*object-group$ts/cgxo) {
        my $id;
        if ($$al =~ /\G\s*(\S+)$ts/cgxo) {
            $id = $1;
	    $ah->{OBJECT_GROUP} = $id;
	    return 1;
        }
        else {
            $self->parse_error($al, "object-group id expected");
        }
    }
    return 0;
}
###     pixacl_ip_prot_spec: ip_protocol
#
#       ->{TYPE}
#
sub pixacl_ip_prot_spec( $$$ ) {
    my ($self, $ah, $al) = @_;
    if ($self->{PRINT}) {
        if (defined $ah->{TYPE}) {
            my $prot = $ah->{TYPE};
            (exists $Re_IP_Trans{$prot}) and $prot = $Re_IP_Trans{$prot};
            $$al = join ' ', $$al, $prot;
            return 1;
        }
        return 0;
    }
    my $retry = pos($$al);
    if ($$al =~ /\G\s*(\S+)$ts/cgxo) {
        my $tmp = $1;
        if (exists $IP_Trans{$tmp}) {
            $ah->{TYPE} = $IP_Trans{$tmp};
        }
        elsif ($tmp eq 'ip') {
            $ah->{TYPE} = 'ip';
        }
        elsif ($tmp =~ /\d+/ && 0 <= $tmp && $tmp < 256) {
            $ah->{TYPE} = $tmp;
        }
        else {
            pos($$al) = $retry;
            return 0;
        }
        return 1;
    }
    return 0;
}
### pixacl_adr_srv_spec:  {adr_opt | pixacl_og_spec} [ pixacl_og_spec | spec]
#
#  ->{SRV}
#
sub pixacl_adr_srv_spec( $$$ ) {
    my ($self, $ah, $al) = @_;
    unless ($self->{PRINT}) {
        $ah->{SRV} = {};
    }
    $self->{PORTMODE} = \%PORT_Trans_TCP_UDP;
    if ($self->adr_opt($ah, $al) || $self->pixacl_og_spec($ah, $al, 'network'))
    {
        $self->single_spec($ah->{SRV}, $al)
          || $self->range_spec($ah->{SRV}, $al)
          || $self->pixacl_og_spec($ah->{SRV}, $al, 'service');
        return 1;
    }
    else {
        return 0;
    }
}
###  pixacl_log_packet:   log [[disable | default]| [<level>] [interval <seconds>]
#
#   ->{LOG}->{MODE}
#   ->{LOG}->{LEVEL}
#   ->{LOG}->{INTERVAL}
#
sub pixacl_log_packet( $$$ ) {
    my ($self, $ah, $al) = @_;
    if ($self->{PRINT}) {
        if ($ah->{LOG}) {
            $$al = join ' ', $$al, 'log';
            if ($ah->{LOG}->{MODE}) {
                $$al = join ' ', $$al, $ah->{LOG}->{MODE};
            }
            else {
                $ah->{LOG}->{LEVEL}
                  and $$al = join ' ', $$al, $ah->{LOG}->{LEVEL};
                $ah->{LOG}->{INTERVAL}
                  and $$al = join ' ', $$al, 'interval', $ah->{LOG}->{INTERVAL};
            }
        }
    }
    elsif ($$al =~ /\G\s*log$ts/cgxo) {
        $ah->{LOG}->{SET} = 1;
        if ($$al =~ /\G\s*(disable|default)$ts/cgxo) {
            $ah->{LOG}->{MODE} = $1;
        }
        else {
            if ($$al =~ /\G\s*([0-7])$ts/cgxo) {
                $ah->{LOG}->{LEVEL} = $1;
            }
            if ($$al =~ /\G\s*(interval)$ts/cgxo) {
                if ($$al =~ /\G\s*(\d+)$ts/cgxo) {
                    $ah->{LOG}->{INTERVAL} = $1;
                }
                else {
                    $self->parse_error($al, "\'seconds\' expected");
                }
            }
        }
    }
    return 1;
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
###     remark:          'remark' <up to 100 chars of remark>
#
#                       ->{REMARK}
sub remark($$$) {
    my ($self, $ah, $al) = @_;
    if ($self->{PRINT} and exists $ah->{REMARK}) {
        $$al = join ' ', $$al, 'remark', $ah->{REMARK};
        return 1;
    }
    elsif ($$al =~ /\G\s*remark\s(.*)(?=\Z|\n)/cgxo)
    {    #read remark till end of string|line
        $ah->{REMARK} = $1;
        return 1;
    }
    return 0;
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
###   	action:		'permit' | 'deny'
#
#                       ->{MODE}
sub action($$$) {
    my ($self, $ah, $al) = @_;
    if ($self->{PRINT}) {
        if ($ah->{MODE}) {
            $$al = join ' ', $$al, $ah->{MODE};
            return 1;
        }
        else {
            return 0;
        }
    }
    elsif ($$al =~ /\G\s*(permit|deny)$ts/cgxo) {
        $ah->{MODE} = $1;
        return 1;
    }
    else {
        return 0;
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

sub print_icmpmessage ($$$) {
    my ($self, $ah, $al) = @_;
    (exists $ah->{TYPE}) and $$al = join ' ', $$al, $ah->{TYPE};

    # no code for pixfirewall
}

###	icmpmessage:	<message-name> | (/d+/ [/d+])
#
#                      ->{TYPE} / ->{CODE} (if defined)
sub icmpmessage($$$) {
    my ($self, $ah, $al) = @_;
    if ($self->{PRINT}) {
        $self->print_icmpmessage($ah, $al);
    }
    else {
        my $parse_start = pos($$al);
        if ($$al =~ /\G\s*($tc+)$ts/cgxo) {
            my $match = $1;
            if (exists $ICMP_Trans{$match}) {
                $ah->{TYPE} = $ICMP_Trans{$match}->{type};
                $ah->{CODE} = $ICMP_Trans{$match}->{code};
            }
            elsif ($match =~ /\d+/) {
                $ah->{TYPE} = $match;
                if ($$al =~ /\G\s*(\d+)$ts/cgxo) {
                    $ah->{CODE} = $1;
                }
                else {
                    $ah->{CODE} = -1;
                }
            }
            else {

                # maybe it is something else?
                pos($$al) = $parse_start;
            }
        }
    }
    return 1;
}
### (-)	p_igmp:		( 'igmp' | '2' ) adr adr [igmptype | igmpmessage]

### (-)	igmptype:	/\d+/

### (-) igmpmessage:    /\w+/

###     spec:           single_spec | range_spec
#
#                       ->{SRV}->{SPEC}
sub spec($$$) {
    my ($self, $ah, $al) = @_;
    unless ($self->{PRINT}) {
        $ah->{SRV} = {};
    }
    $self->single_spec($ah->{SRV}, $al)
      or $self->range_spec($ah->{SRV}, $al);
}
###	single_spec:	( 'lt' | 'gt' | 'eq' | 'neq' ) port
#
#                       ->{SPEC} ->{PORT_L} / {PORT_H}
sub single_spec($$$) {
    my ($self, $ah, $al) = @_;
    if ($self->{PRINT} and $ah->{SPEC}) {
        my $port;
        if ($ah->{SPEC} =~ /lt|eq|neq/) {
            $port = $ah->{PORT_H};
        }
        elsif ($ah->{SPEC} =~ /gt/) {
            $port = $ah->{PORT_L};
        }
        else {
            return 0;
        }
        $$al = join ' ', $$al, $ah->{SPEC};
        (exists $self->{PORTMODE}{$port}) and $port = $self->{PORTMODE}{$port};
        $$al = join ' ', $$al, $port;
        return 1;
    }
    if ($$al =~ /\G\s*(eq|gt|lt|neq)\s+($tc+)$ts/cgxo) {
        my $spec = $1;
        my $port = $2;
        if (exists $self->{PORTMODE}{$port}) {
            $port = $self->{PORTMODE}{$port};
        }
        unless ($port =~ /\d+/ && $port <= 0xffff) {
            $self->parse_error($al, "unknown port specifier $port");
        }

        # set port ranges depending on SPEC
        if ($spec eq 'eq') {
            $ah->{PORT_L} = $port;
            $ah->{PORT_H} = $port;
        }
        elsif ($spec eq 'gt') {
            if ($port < 0xffff) {
                $ah->{PORT_L} = $port + 1;
                $ah->{PORT_H} = 0xffff;
                $spec         = 'range';
            }
            else {
                $self->parse_error($al, "invalid port-number $port for 'gt'");
            }
        }
        elsif ($spec eq 'lt') {
            if (0 < $port) {
                $ah->{PORT_L} = 0;
                $ah->{PORT_H} = $port - 1;
                $spec         = 'range';
            }
            else {
                $self->parse_error($al, "invalid port-number $port for 'lt'");
            }
        }
        elsif ($spec eq 'neq') {
            $self->parse_error($al, "port specifier 'neq' not implemented yet");
            $ah->{PORT_L} = $port;
            $ah->{PORT_H} = $port;
        }
        $ah->{SPEC} = $spec;
        return 1;
    }
    else {
        return 0;
    }
}
###     range_spec:     'range' port port
#
#                       ->{SPEC} ->{PORT_L} / {PORT_H}
sub range_spec($$$) {
    my ($self, $ah, $al) = @_;
    if ($self->{PRINT} and $ah->{SPEC} and $ah->{SPEC} eq 'range') {
        my $port_l = $ah->{PORT_L};
        my $port_h = $ah->{PORT_H};
        (exists $self->{PORTMODE}{$port_l})
          and $port_l = $self->{PORTMODE}{$port_l};
        (exists $self->{PORTMODE}{$port_h})
          and $port_h = $self->{PORTMODE}{$port_h};
        $$al = join ' ', $$al, 'range', $port_l, $port_h;
        return 1;
    }
    if ($$al =~ /\G\s*range\s+($tc+)\s+($tc+)$ts/cgxo) {
        my $port_l = $1;
        my $port_h = $2;
        if (exists $self->{PORTMODE}{$port_l}) {
            $port_l = $self->{PORTMODE}{$port_l};
        }
        if (exists $self->{PORTMODE}{$port_h}) {
            $port_h = $self->{PORTMODE}{$port_h};
        }
        unless ($port_l =~ /\d+/
            && $port_l <= 0xffff
            && $port_h =~ /\d+/
            && $port_h <= 0xffff
            && $port_l <= $port_h)
        {
            $self->parse_error($al,
                "unknown or invalid port specifiers $port_l $port_h");
        }
        $ah->{PORT_L} = $port_l;
        $ah->{PORT_H} = $port_h;
        $ah->{SPEC}   = 'range';
        return 1;
    }
    return 0;
}
###	adr:		'any' | host | net
#
#                       if 'any': ->{BASE} = 0 / ->{MASK} = 0
sub adr($$$) {
    my ($self, $ah, $al) = @_;
    if ($self->{PRINT}) {

        # addresses are *allways* 'base' and 'mask'!
        (defined $ah->{BASE} and defined $ah->{MASK})
          and $$al = join ' ', $$al, int2quad($ah->{BASE}),
          int2quad(dev_cor($self->{MODE}, $ah->{MASK}));
        return 1;
    }
    if ($$al =~ /\G\s*any$ts/cgxo) {
        $ah->{BASE} = 0;
        $ah->{MASK} = 0;
        return 1;
    }
    unless ($self->host($ah, $al)
        || $self->net($ah, $al))
    {
        $self->parse_error($al, "no address found");
    }
    return 1;
}
### same as adr but with return code 0 possible
#
sub adr_opt($$$) {
    my ($self, $ah, $al) = @_;
    if ($self->{PRINT}) {

        # addresses are *allways* 'base' and 'mask'!
        if (defined $ah->{BASE} and defined $ah->{MASK}) {
            $$al = join ' ', $$al, int2quad($ah->{BASE}),
              int2quad(dev_cor($self->{MODE}, $ah->{MASK}));
            return 1;
        }
        else {
            return 0;
        }
    }
    if ($$al =~ /\G\s*any$ts/cgxo) {
        $ah->{BASE} = 0;
        $ah->{MASK} = 0;
        return 1;
    }
    return $self->net($ah, $al) || $self->host($ah, $al);
}
###	host:		'host' quad
#
#                       ->{BASE} / ->{MASK} = 0xffffffff;
sub host($$$) {
    my ($self, $ah, $al) = @_;
    if ($$al =~ /\G\s*host\s+([.\d]+)$ts/cgxo) {
        defined($ah->{BASE} = quad2int($1))
          or $self->parse_error($al, "no ipv4 address");
        $ah->{MASK} = 0xffffffff;
        return 1;
    }
    else {
        return 0;
    }
}
###	net:		quad quad
#
#                       ->{BASE} / ->{MASK}
#
# mask checking is only:
#		                    1011/1101 forbidden
#		                    1011/1011 allowed    !!!
# because this is not routing
#
sub net($$$) {
    my ($self, $ah, $al) = @_;
    if ($$al =~ /\G\s*([.\d]+)\s+([.\d]+)$ts/cgxo) {
        defined($ah->{BASE} = quad2int($1))
          or $self->parse_error($al, "no ipv4 address");
        defined($ah->{MASK} = quad2int($2))
          or $self->parse_error($al, "no ipv4 address");
        $ah->{MASK} = dev_cor($self->{MODE}, $ah->{MASK});
        $ah->{MASK} & $ah->{BASE} ^ $ah->{BASE}
          and $self->parse_error($al, "illegal mask");
        return 1;
    }
    else {
        return 0;
    }
}
###	net_p:	same as net() but with print
#
sub net_p($$$) {
    my ($self, $ah, $al) = @_;
    if ($self->{PRINT}) {

        # addresses are *allways* 'base' and 'mask'!
        if (defined $ah->{BASE} and defined $ah->{MASK}) {
            $$al = join ' ', $$al, int2quad($ah->{BASE}),
              int2quad(dev_cor($self->{MODE}, $ah->{MASK}));
            return 1;
        }
        else {
            return 0;
        }
    }
    if ($$al =~ /\G\s*([.\d]+)\s+([.\d]+)$ts/cgxo) {
        defined($ah->{BASE} = quad2int($1))
          or $self->parse_error($al, "no ipv4 address");
        defined($ah->{MASK} = quad2int($2))
          or $self->parse_error($al, "no ipv4 address");
        $ah->{MASK} = dev_cor($self->{MODE}, $ah->{MASK});
        $ah->{MASK} & $ah->{BASE} ^ $ah->{BASE}
          and $self->parse_error($al, "illegal mask");
        return 1;
    }
    else {
        return 0;
    }
}

#######################################################
# --- printing ---
#######################################################
sub static_line_to_string($$) {
    my ($self, $s) = @_;
    my $r = '';
    $self->{PRINT} = 'yes';
    $self->static_line($s, \$r, 1);
    $self->{PRINT} = undef;
    return $r;
}

sub pix_global_line_to_string($$) {
    my ($self, $s) = @_;
    my $r = '';
    $self->{PRINT} = 'yes';
    $self->pix_global($s, \$r);
    $self->{PRINT} = undef;
    return $r;
}

sub pix_nat_line_to_string($$) {
    my ($self, $s) = @_;
    my $r = '';
    $self->{PRINT} = 'yes';
    $self->pix_nat($s, \$r);
    $self->{PRINT} = undef;
    return $r;
}

sub route_line_to_string ($$) {
    my ($self, $o) = @_;
    my $r = '';
    $self->{PRINT} = 'yes';
    $self->pix_route($o, \$r);
    $self->{PRINT} = undef;
    return $r;
}

sub acl_line_to_string ($$) {
    my ($self, $a) = @_;
    my $s = '';
    $self->{PRINT} = 'yes';
    $self->pix_acl_entry($a, \$s);
    $self->{PRINT} = undef;
    return $s;
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
    my $ga = $a->{TRANS}->{GLOBAL};
    my $gb = $b->{TRANS}->{GLOBAL};
    unless (exists $ga->{'INTERFACE'} xor exists $gb->{'INTERFACE'}) {
        exists $ga->{'INTERFACE'}
          and do { $ga->{'INTERFACE'} eq $gb->{'INTERFACE'} and return 3 }
    }

    # local
    my $la = $a->{TRANS}->{LOCAL};
    my $lb = $b->{TRANS}->{LOCAL};
    unless ($la->{ACCESS_LIST} xor $lb->{ACCESS_LIST}) {
        $la->{ACCESS_LIST} and do {
            $la->{ACCESS_LIST}->{NAME} eq $lb->{ACCESS_LIST}->{NAME}
              or return 3;
        };
    }

    # masks
    (exists $la->{NETMASK} and exists $lb->{NETMASK})
      or return 3;    # pix uses some kind of mask detection
                      # so we force hand crafted masks here ;)
    my $amask = exists $la->{NETMASK} ? $la->{NETMASK} : 0xffffffff;
    my $bmask = exists $lb->{NETMASK} ? $lb->{NETMASK} : 0xffffffff;

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
    $a->{LOCAL_IF}           eq $b->{LOCAL_IF}
      && $a->{GLOBAL_IF}     eq $b->{GLOBAL_IF}
      && $a->{TRANS}->{TYPE} eq $b->{TRANS}->{TYPE}
      or return 0;
    my @keylist;

    # global spec
    my $ga = $a->{TRANS}->{GLOBAL};
    my $gb = $b->{TRANS}->{GLOBAL};
    if ($a->{TRANS}->{TYPE} eq 'ip') {
        @keylist = ('BASE', 'INTERFACE');
    }
    else {
        @keylist = ('BASE', 'INTERFACE', 'PORT');
    }
    for my $key (@keylist) {
        (exists $ga->{$key} xor exists $gb->{$key}) and return 0;
        exists $ga->{$key} and do { $ga->{$key} eq $gb->{$key} or return 0 }
    }

    # local spec
    my $la = $a->{TRANS}->{LOCAL};
    my $lb = $b->{TRANS}->{LOCAL};
    if ($a->{TRANS}->{TYPE} eq 'ip') {
        @keylist = ('BASE', 'NETMASK', 'DNS');
    }
    else {
        @keylist = ('BASE', 'PORT', 'NETMASK', 'DNS');
    }
    for my $key (@keylist) {
        (exists $la->{$key} xor exists $lb->{$key}) and return 0;
        exists $la->{$key} and do { $la->{$key} eq $lb->{$key} or return 0 }
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

sub pix_nat_line_a_eq_b( $$$ ) {
    my ($self, $a, $b) = @_;
    $a->{NAT_ID} eq $b->{NAT_ID} && $a->{IF_NAME} eq $b->{IF_NAME}
      or return 0;
    my @keylist = (
        'BASE',        'MASK',     'ACCESS_LIST', 'OUTSIDE',
        'NORANDOMSEQ', 'MAX_CONS', 'EMB_LIMIT'
    );
    for my $key (@keylist) {
        (exists $a->{$key} xor exists $b->{$key}) and return 0;
        exists $a->{$key} and do { $a->{$key} eq $b->{$key} or return 0 }
    }
    return 1;
}

sub pix_global_line_a_eq_b( $$$ ) {
    my ($self, $a, $b) = @_;
    $a->{NAT_ID} eq $b->{NAT_ID} && $a->{EXT_IF_NAME} eq $b->{EXT_IF_NAME}
      or return 0;
    my @keylist = ('BEGIN', 'END');
    for my $key (@keylist) {
        (exists $a->{$key}->{BASE} xor exists $b->{$key}->{BASE}) and return 0;
        exists $a->{$key}->{BASE}
          and do { $a->{$key}->{BASE} eq $b->{$key}->{BASE} or return 0 }
    }
    @keylist = ('INTERFACE', 'NETMASK');
    for my $key (@keylist) {
        (exists $a->{$key} xor exists $b->{$key}) and return 0;
        exists $a->{$key} and do { $a->{$key} eq $b->{$key} or return 0 }
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

sub issue_cmd( $$$ ) {
    my ($self, $cmd, $prompt) = @_;
    my @output;

    my $con = $self->{CONSOLE};
    $con->{PROMPT} = $prompt;
    $con->con_cmd("$cmd\n") or $con->con_error();
    @output = ($con->{RESULT}->{BEFORE}, $con->{RESULT}->{MATCH});
    return (\@output);

}

sub cmd( $$ ) {
    my ($self, $cmd) = @_;
    my $prompt = $self->{ENA_MODE} ? $self->{ENAPROMPT} : $self->{PROMPT};
    my $out = $self->issue_cmd($cmd, $prompt) or return 0;

    # check for  errors
    # argument is ref to prematch from issue_cmd
    return $self->cmd_check_error(\${$out}[0]);
}

sub shcmd( $$ ) {
    my ($self, $cmd) = @_;
    my $prompt = $self->{ENA_MODE} ? $self->{ENAPROMPT} : $self->{PROMPT};
    my $out = $self->issue_cmd($cmd, $prompt) or die "...giving up\n";
    return @$out;
}

sub login_enabel( $ ) {
    my ($self) = @_;
    my $ip = $self->{IP};
    my $user;
    my $pass;
    my $con = $self->{CONSOLE};

    if ($self->{PASS} =~ /:/ or $self->{LOCAL_USER}) {
        if ($self->{LOCAL_USER}) {
            $pass = $self->{PASS};
            $user = $self->{LOCAL_USER} or die "no user found\n";
        }
        else {
            ($user, $pass) = split(/:/, $self->{PASS});
        }
        mypr "Username found\n";
        mypr "checking for SSH access at port 22\n";
        my $server = IO::Socket::INET->new(
            'PeerAddr' => $ip,
            'PeerPort' => 22
        );
        if ($server) {
            $server->close();
            mypr "port 22 open - trying SSH for login\n";
            $con->{EXPECT}->spawn("ssh", ("-l", "$user", "$ip"))
              or die "Cannot spawn ssh: $!\n";
            my $prm = qr/password:|\(yes\/no\)\?/i;
            my $tmt = $self->{telnet_timeout};
            $con->con_wait("$prm", $tmt) or $con->con_error();
            if ($con->{RESULT}->{MATCH} =~ qr/\(yes\/no\)\?/i) {
                $con->con_dump();
                $con->{PROMPT}  = qr/password:/i;
                $con->{TIMEOUT} = $self->{telnet_timeout};
                $con->con_cmd("yes\n") or $con->con_error();
                mypr "\n";
                warnpr
                  "RSA key for $self->{IP} permanently added to the list of known hosts\n";
                $con->con_dump();
            }
            $con->{PROMPT}  = $self->{PROMPT};
            $con->{TIMEOUT} = $self->{telnet_timeout};
            $con->con_cmd("$pass\n") or $con->con_error();
            $con->con_dump();
            $self->{PRE_LOGIN_LINES} = $con->{RESULT}->{BEFORE};
        }
        else {
            mypr "port 22 closed -  trying telnet for login\n";
            $con->{EXPECT}->spawn("telnet", ($ip))
              or die "Cannot spawn telnet: $!\n";
            my $tmt = $self->{telnet_timeout};
            my $prm = "Username:";
            $con->con_wait("$prm", $tmt) or $con->con_error();
            $con->con_dump();
            $self->{PRE_LOGIN_LINES} = $con->{RESULT}->{BEFORE};
            $con->con_issue_cmd("$user\n", "[Pp]assword:", $tmt)
              or $con->con_error();
            $con->con_dump();
            $con->{PROMPT}  = $self->{PROMPT};
            $con->{TIMEOUT} = $tmt;
            $con->con_cmd("$pass\n") or $con->con_error();
            $con->con_dump();
        }
    }
    else {
        mypr "using simple TELNET for login\n";
        $pass = $self->{PASS};
        $con->{EXPECT}->spawn("telnet", ($ip))
          or die "Cannot spawn telnet: $!\n";
        my $prm = "PIX passwd:|Password:";
        my $tmt = $self->{telnet_timeout};
        $con->con_wait("$prm", $tmt) or $con->con_error();
        $con->con_dump();
        $self->{PRE_LOGIN_LINES} = $con->{RESULT}->{BEFORE};
        $con->{PROMPT}           = $self->{PROMPT};
        $con->{TIMEOUT}          = $self->{telnet_timeout};
        $con->con_cmd("$pass\n") or $con->con_error();
        $con->con_dump();
    }
    my $psave = $self->{PROMPT};
    $self->{PROMPT} = qr/Password:/;
    $self->cmd('enable') or return 0;
    $self->{PROMPT} = $psave;
    $self->cmd($self->{PASS}) or return 0;
    return 1;
}

#
#    *** some checking ***
#
sub checkidentity($$) {
    my ($self, $name) = @_;
    if ($name ne $self->{NAME}) {
	errpr "wrong device name: $name expected: $self->{NAME}\n";
	return 0;
    }
    return 1;
}

sub checkinterfaces($$$) {
    my ($self, $devconf, $spocconf) = @_;
    mypr " === check for unknown or missconfigured interfaces at device ===\n";
    for my $intf (sort keys %{ $devconf->{IF} }) {
        next if ($devconf->{IF}->{$intf}->{SHUTDOWN} == 1);
        unless (exists $spocconf->{IF}->{$intf}) {
            warnpr "unknown interface detected: $intf\n";
        }
    }
    mypr " === done ===\n";
}

sub checkbanner($) {
    my ($self) = @_;
    if ($self->{VERSION} < 6.3) {
        mypr "banner checking disabled for $self->{TYPE} $self->{VERSION}\n";
    }
    elsif ( $self->{CHECKBANNER}
        and $self->{PRE_LOGIN_LINES} !~ /$self->{CHECKBANNER}/)
    {
        if ($self->{APPROVE}) {
            errpr "Missing banner at NetSPoC managed device.\n";
        }
        else {
            warnpr "Missing banner at NetSPoC managed device.\n";
        }
    }
}
#######################################################
# telnet login, check name and set convenient options
#######################################################
sub prepare($) {
    my ($self) = @_;
    $self->{PROMPT}    = qr/\n.*[\%\>\$\#]\s?$/;
    $self->{ENAPROMPT} = qr/\n.*#\s?$/;
    $self->{ENA_MODE}  = 0;
    $self->login_enabel() or exit -1;
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
	$self->{HARDWARE} = 'unknown';
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
#######################################################
#   parsing - helper
#######################################################
my %spotags = (
    START   => '^\s*!*\s*\[ BEGIN router:(.*) \]',
    MODEL   => '^\s*!*\s*\[ Model = (.*) \]',
    STOP    => '^\s*!*\s*\[ END router:(.*) \]',
    COMMENT => '^\s*!',
    IGNORE  => [ q(^\s*$), '^\[ ACL \]', '^\[ Routing \]', '^\[ Static \]', ]
);

sub eat_shit ( $$ ) {
    my ($self, $l) = @_;
    if (   $l =~ /$spotags{START}/o
        or $l =~ /$spotags{MODEL}/o
        or $l =~ /$spotags{STOP}/o)
    {
        return 0;
    }
    if ($l =~ /$spotags{COMMENT}/o) {
        return 1;
    }
    for my $i (@{ $spotags{IGNORE} }) {
        if ($l =~ /$i/) {
            return 1;
        }
    }
    return 0;
}

# parse START - payload - STOP from config payload
sub parse_spocfile ( $$$ ) {
    my ($self, $p, $sfile) = @_;
    $p->{DEVICE} = '';
    while (defined(my $line = shift @$sfile)) {
        $self->eat_shit($line) and next;
        if ($line =~ /$spotags{START}/o) {
            $p->{DEVICE} = $1;
            next;
        }
        if ($line =~ /$spotags{MODEL}/o) {
            $p->{MODEL} = $1;
            $self->pix_parse($p, $sfile);
            last;
        }
        errpr "unexpected line: $line\n";
        return 0;
    }
    if (!$p->{DEVICE}) {
        errpr "START tag not found or no device name specified in spocfile\n";
        return 0;
    }
    if (@$sfile == 0) {
        errpr "unexpected end of spocfile\n";
        return 0;
    }

    # unified pixparser eats up all, so do not check for STOP Tag
    if ($p->{DEVICE} ne $self->{NAME}) {
        if ($self->{CHECK_DEVICE_IN_SPOCFILE} eq "yes") {
            errpr
              "wrong device name in spocfile - expected: $self->{NAME} found: $p->{DEVICE}\n";
            return 0;
        }
        elsif ($self->{CHECK_DEVICE_IN_SPOCFILE} eq "no") {
            mypr "compare $self->{NAME} and $p->{DEVICE}\n";
        }
        else {
            warnpr
              "wrong device name in spocfile - expected: $self->{NAME} found: $p->{DEVICE}\n";
            $p->{DEVICE} = $self->{NAME};

        }
    }
    return 1;
}

sub get_parsed_config_from_device( $$ ) {
    my ($self, $conf_hash) = @_;

    # *** FETCH CONFIG ***
    my @out;
    @out = $self->shcmd('wr t') or exit -1;
    my @conf = split /(?=\n)/, $out[0];
    mypr "got config from device\n";

    # *** PARSE CONFIG ***
    unless ($self->pix_parse($conf_hash, \@conf)) {
        errpr "could not parse pix config\n";
        return 0;
    }
    return 1;
}

sub get_config_from_device( $ ) {
    my ($self)      = @_;
    my ($conf_hash) = @_;

    # *** FETCH CONFIG ***
    my @out;
    @out = $self->shcmd('wr t') or exit -1;
    my @conf = split /(?=\n)/, $out[0];
    mypr "got config from device\n";
    return (\@conf);
}
##############################################################
# rawdata processing
##############################################################
sub process_rawdata( $$$ ) {
    my ($self, $pspoc, $epilog) = @_;
    my $epilogacl;
    my $spocacl;
    ### helper ###
    my $sec_time = time();    # for status info timestamps
    my $check    = sub {
        my ($intf, $epi) = @_;
        unless (exists $epi->{IF}->{$intf}->{ACCESS}) {
            mypr " - no acl in raw data -\n";
            return 0;
        }

        # there is an epilog acl for this interface
        my $ep_name = $epi->{IF}->{$intf}->{ACCESS};

## It is sufficient to check for spoc-interface below.
#
#        unless (exists $conf->{IF}->{$intf}) {
#            errpr "rawdata: interface not found on device: $intf\n";
#            exit -1;
#        }

        # the interface exists on the device
        my $sp_name;
        exists $pspoc->{IF}->{$intf}
          or die "rawdata: $intf not found in spocfile\n";
        unless (exists $pspoc->{IF}->{$intf}->{ACCESS}) {
            warnpr "rawdata: no spocacl for interface: $intf\n";
            return 0;
        }

        # there is a corresponding acl in the spocfile
        $sp_name = $pspoc->{IF}->{$intf}->{ACCESS};
        unless (exists $epi->{ACCESS}->{$ep_name}) {
            errpr "rawdata: no matching raw acl found for name $ep_name" 
		. " in interface definition\n";
            exit -1;
        }
        $epilogacl = $epi->{ACCESS}->{$ep_name};
        $spocacl   = $pspoc->{ACCESS}->{$sp_name};
        return 1;
    };
    if (scalar @{$epilog}) {
        my $epilog_conf = {};

        # *** PARSE RAWDATA ***
        mypr " *** PARSE RAWDATA ***\n";
        $self->pix_parse($epilog_conf, $epilog);
        mypr "--- raw processing\n";
        for my $intf (keys %{ $epilog_conf->{IF} }) {
            mypr " interface: $intf\n";
            &$check($intf, $epilog_conf) or next;

            # _prepend_
            my @remove = ();
            for (my $i = 0 ; $i < scalar @$spocacl ; $i++) {
                for my $epi (@$epilogacl) {
                    if ($self->acl_line_a_eq_b($epi, $spocacl->[$i])) {
                        warnpr "RAW: double ACE \'"
                          . $self->acl_line_to_string($spocacl->[$i])
                          . "\' scheduled for remove from spocacl.\n";
                        push @remove, $i;
                    }
                }
            }
            for my $r (reverse sort @remove) {
                splice @$spocacl, $r, 1;
            }
            for (my $i = scalar @{$epilogacl} - 1 ; $i >= 0 ; $i--) {
                unshift @{$spocacl}, $$epilogacl[$i];
            }
            mypr "   entries prepended: " . scalar @{$epilogacl} . "\n";

# Attribute STD_ACCESS isn't used anywere.
#            $cnob->{IF}->{$intf}->{STD_ACCESS} = $epilogacl;
#            $cnob->{MIGRATE_STATUS}->{"STD ACL TRANS:: $intf"} =
#              scalar @{ $cnob->{IF}->{$intf}->{STD_ACCESS} };
#            $active_std_interfaces = $active_std_interfaces . " $intf";
        }

#        $cnob->{MIGRATE_STATUS}->{"STD INTERFACES"} = $active_std_interfaces;
        ### ROUTE PROCESSING STD ###
        if (defined $pspoc->{ROUTING}) {
            my $newroutes = ();
          SPOC: for (my $i = 0 ; $i < scalar @{ $pspoc->{ROUTING} } ; $i++) {
                my $se = $pspoc->{ROUTING}->[$i];
                for my $re (@{ $epilog_conf->{ROUTING} }) {
                    if ($self->route_line_a_eq_b($se, $re)) {
                        warnpr "RAW: double RE \'"
                          . $self->route_line_to_string($re)
                          . "\' scheduled for remove from spocconf.\n";
                        next SPOC;
                    }
                    elsif ( $re->{BASE} eq $se->{BASE}
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
        for my $re (@{ $epilog_conf->{ROUTING} }) {
            push @{ $pspoc->{ROUTING} }, $re;
        }
        mypr " attached routing entries: " . scalar @{ $epilog_conf->{ROUTING} } . "\n";

# Attribute STD_ROUTING isn't used anywere.
#        $cnob->{STD_ROUTING} = $epilog_conf->{ROUTING};

        ### STATIC PROCESSING ###
        my @std_static = ();
        if ($epilog_conf->{STATIC}) {
            my @remove = ();
            for my $s (@{ $epilog_conf->{STATIC} }) {
                my $covered = 0;
                for (my $i = 0 ; $i < scalar @{ $pspoc->{STATIC} } ; $i++) {
                    my $spoc  = $pspoc->{STATIC}[$i];
                    my $match = 0;
                    if ($self->static_line_a_eq_b($spoc, $s)) {
                        warnpr "RAW: static coverd by: \'",
                          $self->static_line_to_string($s),
                          "\' - RAW static discarded!\n";
                        $covered = 1;
                    }
                    elsif ($match =
                        $self->static_global_local_match_a_b($spoc, $s))
                    {
                        unless ($match == 3) {
                            mypr "RAW: spoc static \'",
                              $self->static_line_to_string($spoc),
                              " replaced by \'",
                              $self->static_line_to_string($s), "\'\n";
                            push @remove, $i;
                        }
                        else {
                            warnpr "RAW: weired match RAW: \'",
                              $self->static_line_to_string($s), "\'\n";
                            warnpr "RAW: weired match SPOC: \'",
                              $self->static_line_to_string($spoc), "\'\n";
                            warnpr "RAW: static discarded!\n";
                            $covered = 1;
                        }
                    }
                }
                $covered or push @std_static, $s;
            }
            for my $r (reverse sort @remove) {
                splice @{ $pspoc->{STATIC} }, $r, 1;
            }
            @{ $pspoc->{STATIC} } = (@{ $pspoc->{STATIC} }, @std_static),
              mypr " attached static entries: " . scalar @std_static . "\n";
        }
        ### GLOBAL PROCESSING ###
        my @std_global = ();
        if ($epilog_conf->{GLOBAL}) {
            for my $s (@{ $epilog_conf->{GLOBAL} }) {
                my $covered = 0;
                for (my $i = 0 ; $i < scalar @{ $pspoc->{GLOBAL} } ; $i++) {
                    my $spoc  = $pspoc->{GLOBAL}[$i];
                    my $match = 0;
                    if ($self->pix_global_line_a_eq_b($spoc, $s)) {
                        warnpr "raw global coverd by: \'",
                          $self->pix_global_line_to_string($s), "\'\n";
                        $covered = 1;
                    }
                }
                $covered or push @std_global, $s;
            }
            @{ $pspoc->{GLOBAL} } = (@{ $pspoc->{GLOBAL} }, @std_global),
              mypr " attached global entries: " . scalar @std_global . "\n";
        }
        ### NAT PROCESSING ###
        my @std_nat = ();
        if ($epilog_conf->{NAT}) {
            for my $s (@{ $epilog_conf->{NAT} }) {
                my $covered = 0;
                for (my $i = 0 ; $i < scalar @{ $pspoc->{NAT} } ; $i++) {
                    my $spoc  = $pspoc->{NAT}[$i];
                    my $match = 0;
                    if ($self->pix_nat_line_a_eq_b($spoc, $s)) {
                        warnpr "raw nat coverd by: \'",
                          $self->pix_nat_line_to_string($s), "\'\n";
                        $covered = 1;
                    }
                }
                $covered or push @std_nat, $s;
            }
            @{ $pspoc->{NAT} } = (@{ $pspoc->{NAT} }, @std_nat),
              mypr " attached nat entries: " . scalar @std_nat . "\n";
        }

    }
    else {
        mypr "--- raw processing: nothing to do\n";
    }
    mypr "--- raw processing: done\n";
    return 1;
}

#-------------- helper end

sub copy_structure {
    my $src = shift;

    #print "-$src-\n";
    if (ref $src eq 'SCALAR') {
        my $dst = $$src;
        return \$dst;
    }
    elsif (ref $src eq 'ARRAY') {
        my @dst = @$src;
        for my $entry (@dst) {
            (ref $entry) and $entry = copy_structure($entry);
        }
        return \@dst;
    }
    elsif (ref $src eq 'HASH') {
        my %dst = %$src;
        for my $entry (keys %dst) {
            (ref($dst{$entry})) and $dst{$entry} = copy_structure($dst{$entry});
        }
        return \%dst;
    }
    else {
        errpr meself(2) . "unsupported type" . ref($src) . "\n";
    }
}

#
# supports only object-group type 'network' !!
#
sub pix_expand_acl_entry($$$$) {
    my ($self, $ace, $parsed, $acl_name) = @_;

    my $groups = $parsed->{OBJECT_GROUP};
    my $replace;

    for my $adr ('SRC', 'DST') {
        if ($ace->{PROTO}->{$adr}->{OBJECT_GROUP}) {
            my $obj_id = $ace->{PROTO}->{$adr}->{OBJECT_GROUP};

            #check
            unless ($groups->{$obj_id}) {
                errpr meself(1), "no group name \'$obj_id\' found\n";
            }
            unless ($groups->{$obj_id}->{TYPE} eq 'network') {
                errpr meself(1),
                  "unsupported object type \'$groups->{$obj_id}->{TYPE}\'\n";
            }
            for my $network (@{ $groups->{$obj_id}->{NETWORK_OBJECT} }) {
                push @{ $replace->{$adr} }, $network;
            }

            # remeber that group $obj_id is referenced by ACL $acl
            $groups->{$obj_id}->{ACL_REFERENCES}->{$acl_name} = 1;
            $parsed->{ACCESS_LIST}->{$acl_name}->{GROUP_REFERENCES}->{$obj_id} =
              1;

        }
        else {
            push @{ $replace->{$adr} }, $ace->{PROTO}->{$adr};
        }
    }
    my @expanded;
    for my $src (@{ $replace->{SRC} }) {
        for my $dst (@{ $replace->{DST} }) {
            my $copy = copy_structure($ace);
            $copy->{PROTO}->{SRC}->{MASK} = $src->{MASK};
            $copy->{PROTO}->{SRC}->{BASE} = $src->{BASE};
            $copy->{PROTO}->{DST}->{MASK} = $dst->{MASK};
            $copy->{PROTO}->{DST}->{BASE} = $dst->{BASE};
            $copy->{EXPANDED_FROM}        = $ace;
            push @expanded, $copy;
        }
    }
    return \@expanded;
}

sub pix_parse ( $$$ ) {

    my ($self, $p, $conf) = @_;

    # standard conf arg is an arry :(
    my $conf_as_string = join '', @{$conf};

    # *** parse ***
    $self->write_term_config($p, \$conf_as_string);

    #
    # *** postprocess ***
    #
    # expand aces
    my $acl_counter   = 0;
    my $d_acl_counter = 0;
    my $c_acl_counter = 0;
    for my $acl_name (sort keys %{ $p->{ACCESS_LIST} }) {
        my %temp;
        for my $entry (@{ $p->{ACCESS_LIST}->{$acl_name}->{RAW_ARRAY} }) {
            next
              unless $entry->{MODE};   # filter out 'remark', 'compiled', etc...
            my $e_acl = $self->pix_expand_acl_entry($entry, $p, $acl_name);

#	    push @{$p->{ACCESS}->{$acl_name}},@$e_acl;
#	    $acl_counter += scalar @$e_acl;
            for my $e_entry (@$e_acl) {
                my $aclstrg = $self->acl_line_to_string($e_entry);
                unless (exists $temp{$aclstrg}) {
                    push @{ $p->{ACCESS}->{$acl_name} }, $e_entry;
                    $temp{$aclstrg} = 1;
                    $acl_counter++;
                }
                else {
                    $d_acl_counter++;
                }
            }
        }
    }

    # access-group
    for my $acl_name (sort keys %{ $p->{ACCESS_GROUP} }) {
        my $entry = $p->{ACCESS_GROUP}->{$acl_name};
        $p->{IF}->{ $entry->{IF_NAME} }->{ACCESS} = $acl_name;
        if (exists $p->{ACCESS_LIST}->{$acl_name}) {
            push @{ $p->{ACCESS_LIST}->{$acl_name}->{INTERFACE_REFERENCES} },
              $entry->{IF_NAME};
        }
    }

    # interface and nameif
    if ($self->{VERSION} >= 7.0) {

        # bind ip address to IF_NAME
        for my $hw_id (sort keys %{ $p->{HWIF} }) {
            my $entry = $p->{HWIF}->{$hw_id};
            if (defined $entry->{IF_NAME}) {
                $p->{IF}->{ $entry->{IF_NAME} }->{SHUTDOWN} =
                  $entry->{SHUTDOWN};
                if (!$entry->{SHUTDOWN}) {
                    $p->{IF}->{ $entry->{IF_NAME} }->{ADDRESS}->{BASE} =
                      $entry->{ADDRESS}->{BASE};
                    $p->{IF}->{ $entry->{IF_NAME} }->{ADDRESS}->{MASK} =
                      $entry->{ADDRESS}->{MASK};
                }
            }
        }
    }
    else {
        for my $hw_id (sort keys %{ $p->{HWIF} }) {
            my $entry = $p->{HWIF}->{$hw_id};
            $p->{IF}->{ $entry->{IF_NAME} }->{SHUTDOWN} = $entry->{SHUTDOWN};
            if (!$entry->{SHUTDOWN}) {
                $p->{IF}->{ $entry->{IF_NAME} }->{ADDRESS}->{BASE} =
                  $p->{IP}->{ADDRESS}->{ $entry->{IF_NAME} }->{BASE};
                $p->{IF}->{ $entry->{IF_NAME} }->{ADDRESS}->{MASK} =
                  $p->{IP}->{ADDRESS}->{ $entry->{IF_NAME} }->{MASK};
            }
        }
    }
    for my $if (sort keys %{ $p->{IF} }) {
        if ($p->{IF}->{$if}->{SHUTDOWN}) {
            mypr meself(2) . "Interface $if: shutdown\n";
        }
        else {
            if (exists $p->{IF}->{$if}->{ADDRESS}) {
                my $adr = $p->{IF}->{$if}->{ADDRESS};
                if (defined $adr->{BASE} and defined $adr->{MASK}) {
                    mypr meself(2)
                      . "Interface $if: IP: "
                      . int2quad($adr->{BASE}) . "/"
                      . int2quad($adr->{MASK}) . "\n";
                }
                else {
                    warnpr
                      "undifined address for non-shutdown interface \'$if\'\n";
                }
            }
        }
    }

    # crypto maps
    for my $map_name (keys %{ $p->{CRYPTO}->{MAP} }) {
        for my $seq_num (keys %{ $p->{CRYPTO}->{MAP}->{$map_name}->{SEQ_NUM} })
        {
            if ($p->{CRYPTO}->{MAP}->{$map_name}->{SEQ_NUM}->{$seq_num}
                ->{MATCH_ADDRESS})
            {
                my $acl_name =
                  $p->{CRYPTO}->{MAP}->{$map_name}->{SEQ_NUM}->{$seq_num}
                  ->{MATCH_ADDRESS};
                if (exists $p->{ACCESS_LIST}->{$acl_name}) {
                    push
                      @{ $p->{ACCESS_LIST}->{$acl_name}->{CRYPTO_REFERENCES} },
                      { MAP => $map_name, SEQ_NUM => $seq_num };
                }
                else {
                    warnpr
                      "crypto map match address acl $acl_name does not exist\n";
                }
            }
        }
    }
    mypr meself(2)
      . ": CRYPTO MAPS found: "
      . scalar(keys %{ $p->{CRYPTO}->{MAP} }) . "\n";

    #
    # ****** TO DO: more consistence checking
    #
    mypr meself(2)
      . ": OBJECT GROUPS found: "
      . scalar(keys %{ $p->{OBJECT_GROUP} }) . "\n";
    mypr meself(2)
      . ": ACCESS LISTS found: "
      . scalar(keys %{ $p->{ACCESS} }) . "\n";
    for my $acl_name (sort keys %{ $p->{ACCESS_LIST} }) {
        if ($p->{ACCESS_LIST}->{$acl_name}->{CRYPTO_REFERENCES}) {
            $c_acl_counter++;
        }
        elsif ($p->{ACCESS_LIST}->{$acl_name}->{INTERFACE_REFERENCES}) {
            mypr meself(2)
              . ": $acl_name "
              . scalar @{ $p->{ACCESS}->{$acl_name} } . "\n";
        }
        else {
            $p->{ACCESS_LIST}->{$acl_name}->{NO_REFERENCES} = 1;
            mypr meself(2)
              . ": $acl_name "
              . scalar @{ $p->{ACCESS}->{$acl_name} }
              . " *** SPARE ***\n";
        }
    }
    ($c_acl_counter)
      and mypr "--> found $c_acl_counter acls referenced by crypto maps\n";
    mypr meself(2) . ": GLOBALS found: " . scalar @{ $p->{GLOBAL} } . "\n";
    mypr meself(2) . ": NATS    found: " . scalar @{ $p->{NAT} } . "\n";
    mypr meself(2) . ": STATICS found: " . scalar @{ $p->{STATIC} } . "\n";
    mypr meself(2) . ": ROUTES  found: " . scalar @{ $p->{ROUTING} } . "\n";

    # double entries in fetched pix config are impossible, so this could
    # only happen when parsing the epilog
    ($d_acl_counter)
      and mypr "double acl entries skipped: $d_acl_counter\n";
    return 1;
}

sub pix_transfer_lines( $$$$$ ) {
    my ($self, $printstring, $compare, $spoc_lines, $device_lines) = @_;
    my $counter;
    my $change = 0;
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
            my $tr = join ' ', "no", $self->$printstring($d);
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
            $self->cmd($self->$printstring($s)) or exit -1;
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
            mypr $self->$printstring($d) . "\n";
        }
        mypr "total: " . $counter, "\n";
        ($counter) and $change = 1;
        mypr "additional entries from spoc:\n";
        $counter = 0;
        for my $s (@{$spoc_lines}) {
            ($s->{DELETE}) and next;
            $counter++;
            mypr $self->$printstring($s), "\n";
        }
        mypr "total: ", $counter, "\n";
        ($counter) and $change = 1;
    }
    return $change;
}

sub pix_acls_textual_identical($$$) {
    my ($self, $confacl, $spocacl) = @_;
    mypr "check for textual identity\n";
    if (scalar @{$spocacl} == scalar @{$confacl}) {
        mypr " acls have equal lenght: ", scalar @{$spocacl}, "\n";
        mypr " compare line by line: ";
        for (my $i = 0 ; $i < scalar @{$spocacl} ; $i++) {

            #mypr " $i";
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
        return 1;
    }
    else {
        mypr "lenght of acls differ: at device ", scalar @{$confacl},
          " from netspoc ", scalar @{$spocacl}, "\n";
        return 0;
    }
}

sub pix_acls_semantical_indentical($$$$) {
    my ($self, $confacl, $spocacl, $if) = @_;
    unless ($self->{COMPARE}) {
        mypr "  do semantic compare - at interface $if:\n";
        if (
            $self->acl_array_compare_a_in_b($spocacl, $confacl, 4)    # 4 silent
            && $self->acl_array_compare_a_in_b($confacl, $spocacl, 4)
          )
        {
            mypr "   -> interface $if: acls identical\n";
            return 1;
        }
        else {
            mypr "   -> interface $if: acls differ\n";
            return 0;
        }
    }
    else {

        # show compare results
        mypr "#### BEGIN NEW in OLD - interface $if\n";
        my $newinold =
          $self->acl_array_compare_a_in_b($spocacl, $confacl, $self->{CMPVAL});
        mypr "#### END   NEW in OLD - interface $if\n";
        mypr "#### BEGIN OLD in NEW - interface $if\n";
        my $oldinnew =
          $self->acl_array_compare_a_in_b($confacl, $spocacl, $self->{CMPVAL});
        mypr "#### END   OLD in NEW - interface $if\n";
        if ($newinold && $oldinnew) {
            mypr "#### ACLs equal for interface $if\n";
            return 1;
        }
        else {
            mypr "#### ACLs differ - at interface $if ####\n";
            return 0;
        }
        mypr "#### --------------------------------\n";
    }
}

sub pixtrans () {
    my ($self, $conf, $pspoc) = @_;

    # *** BEGIN TRANSFER ***
    unless ($self->{COMPARE}) {
        $self->cmd('configure terminal') or exit -1;
    }

    #
    # *** routing ***
    #
    if ($pspoc->{ROUTING} and scalar @{ $pspoc->{ROUTING} }) {

        #mypr "found:\n";
        my $counter;
        if (exists $conf->{ROUTING} && !scalar(@{ $conf->{ROUTING} })) {
            errpr "ERROR: no routing entries found on device\n";
            return 0;
        }

        # sort netspoc-generated routing entries (long masks first)
        my @route_sort =
          sort { $b->{MASK} <=> $a->{MASK} } @{ $pspoc->{ROUTING} };
        $pspoc->{ROUTING} = \@route_sort;
        mypr "==== compare routing information ====\n\n";
        mypr " routing entries on device:    ", scalar @{ $conf->{ROUTING} },
          "\n";
        mypr " routing entries from netspoc: ", scalar @{ $pspoc->{ROUTING} },
          "\n";
        for my $c (@{ $conf->{ROUTING} }) {    # from device
            $counter++;

            #unless($self->{COMPARE}){
            #	mypr " $counter";
            #   }
            for my $s (@{ $pspoc->{ROUTING} }) {    # from netspoc
                                                    #($s) or next;
                if ($self->route_line_a_eq_b($c, $s)) {
                    $c->{DELETE} = $s->{DELETE} = 1;
                    last;

                    # double entries in spocfile are *not* deleted :(
                }
            }
        }
        mypr "\n";
        unless ($self->{COMPARE}) {
            mypr "transfer routing entries to device:\n";
            $counter = 0;
            for my $r (@{ $pspoc->{ROUTING} }) {
                ($r->{DELETE}) and next;
                $counter++;

                # pix did not allow 2 entries for same destination
                for my $c (@{ $conf->{ROUTING} }) {
                    ($c->{DELETE}) and next;
                    if ($self->route_line_destination_a_eq_b($r, $c)) {
                        my $tr = join ' ', "no",
                          $self->route_line_to_string($c);
                        $self->cmd($tr) or exit -1;
                        $c->{DELETE} = 1;    # could not deleted 2 times
                    }
                }
                $self->cmd($self->route_line_to_string($r)) or exit -1;
                mypr " $counter";
            }
            $counter and $self->{ROUTE_CHANGE} = '*** routing changed ***';
            mypr " $counter";
            mypr "\n";
            mypr "deleting non matching routing entries from device:\n";
            $counter = 0;
            for my $r (@{ $conf->{ROUTING} }) {
                ($r->{DELETE}) and next;
                $counter++;
                my $tr = join ' ', "no", $self->route_line_to_string($r);
                $self->cmd($tr) or exit -1;
                mypr " $counter";
            }
            $counter and $self->{ROUTE_CHANGE} = '*** routing changed ***';
            mypr " $counter";
            mypr "\n";
        }
        else {

            # show compare results
            mypr "additional routing entries from spoc:\n";
            $counter = 0;
            for my $r (@{ $pspoc->{ROUTING} }) {
                ($r->{DELETE}) and next;
                $counter++;
                mypr $self->route_line_to_string($r), "\n";
            }
            mypr "total: $counter\n";
            ($counter) and $self->{ROUTE_CHANGE} = '*** routing changed ***';
            mypr "non matching routing entries on device:\n";
            $counter = 0;
            for my $r (@{ $conf->{ROUTING} }) {
                ($r->{DELETE}) and next;
                $counter++;
                mypr $self->route_line_to_string($r), "\n";
            }
            mypr "total: $counter\n";
            ($counter) and $self->{ROUTE_CHANGE} = '*** routing changed ***';
        }
        mypr "==== done ====\n";
    }
    else {
        mypr "no routing entries specified - leaving routes untouched\n";
    }

    #
    # *** access-lists ***
    #
    my $get_acl_names_and_objects = sub {
        my ($intf)  = @_;
        my $sa_name = $pspoc->{IF}->{$intf}->{ACCESS};
        my $spocacl = $pspoc->{ACCESS}->{$sa_name};
        my $ca_name =
          (exists $conf->{IF}->{$intf}->{ACCESS})
          ? $conf->{IF}->{$intf}->{ACCESS}
          : '';
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
        while (exists $objects->{"$new_id_prefix$new_id_index"}) {
            $new_id_index++;
        }
        return "$new_id_prefix$new_id_index";
    };
    my $pix_mark_for_transfer;
    $pix_mark_for_transfer = sub {
        my ($acl_name) = @_;
        ($pspoc->{ACCESS_LIST}->{$acl_name}->{TRANSFER}) and return;
        $pspoc->{ACCESS_LIST}->{$acl_name}->{TRANSFER} = 1;
        mypr "marked acl $acl_name for transfer\n";
        for my $gid (
            keys %{ $pspoc->{ACCESS_LIST}->{$acl_name}->{GROUP_REFERENCES} })
        {
            unless ($pspoc->{OBJECT_GROUP}->{$gid}->{TRANSFER}) {
                $pspoc->{OBJECT_GROUP}->{$gid}->{TRANSFER} = 1;
                print "marked group $gid for transfer\n";
            }
            for my $name (
                keys %{ $pspoc->{OBJECT_GROUP}->{$gid}->{ACL_REFERENCES} })
            {
                &$pix_mark_for_transfer($name);
            }
        }
    };
    my $pix_mark_for_remove;
    $pix_mark_for_remove = sub {

        # non recursive!
        my ($acl_name) = @_;
        ($conf->{ACCESS_LIST}->{$acl_name}->{REMOVE})
          and errpr "unexpected REMOVE mark\n";
        $conf->{ACCESS_LIST}->{$acl_name}->{REMOVE} = 1;
        mypr "marked acl $acl_name for remove\n";
        for my $gid (
            keys %{ $conf->{ACCESS_LIST}->{$acl_name}->{GROUP_REFERENCES} })
        {
            next if ($conf->{OBJECT_GROUP}->{$gid}->{REMOVE});
            my $remove_group = "OK";
            for my $name (
                keys %{ $conf->{OBJECT_GROUP}->{$gid}->{ACL_REFERENCES} })
            {

                # only remove group from pix if all ACLs that reference
                # this group are renewed by netspoc!
                unless ($pspoc->{ACCESS_LIST}->{$name}->{TRANSFER}) {
                    $remove_group = "NO";
                    last;
                }
            }
            if ($remove_group eq "OK") {
                $conf->{OBJECT_GROUP}->{$gid}->{REMOVE} = 1;
                mypr "marked group $gid for remove\n";

            }
        }
    };
    unless (exists $pspoc->{IF}) {
        warnpr " no interfaces specified - leaving access-lists untouched\n";
    }
    else {
        mypr "processing access-lists\n";

        mypr keys %{ $pspoc->{IF} };
        mypr "+++\n";

        for my $intf (keys %{ $pspoc->{IF} }) {
            unless (exists $conf->{IF}->{$intf}) {
                errpr
                  "netspoc configured interface \'$intf\' not found on device\n";

                #errpr "skiping\n";
                #next;
                return 0;
            }
        }

        # detect diffs
        if ($self->{COMPARE}) {
            for my $intf (keys %{ $pspoc->{IF} }) {
                mypr "interface $intf\n";
                my ($confacl, $spocacl, $confacl_name, $spocacl_name) =
                  &$get_acl_names_and_objects($intf);

                if ($confacl_name && $confacl) {
                    unless (
                        $self->pix_acls_textual_identical($confacl, $spocacl)
                        or $self->pix_acls_semantical_indentical(
                            $confacl, $spocacl, $intf
                        )
                      )
                    {
                        $self->{ACL_CHANGE} = '*** acls    changed ***';
                    }
                }
                else {

                    $self->{ACL_CHANGE} = '*** new acls!       ***';
                    mypr "#### OOPS:  $spocacl_name at interface $intf:\n";
                    mypr "#### OOPS:  no corresponding acl on device\n";
                }
                mypr "-------------------------------------------------\n";
            }
        }
        else {

            # mark objects to transfer
            for my $intf (keys %{ $pspoc->{IF} }) {
                mypr "interface $intf\n";
                my ($confacl, $spocacl, $confacl_name, $spocacl_name) =
                  &$get_acl_names_and_objects($intf);
                if ($pspoc->{ACCESS_LIST}->{$spocacl_name}->{TRANSFER}) {
                    mypr " ...already marked for transfer\n";
                    next;
                }
                if (!$confacl) {
                    warnpr "interface $intf no acl on device - new acl has ",
                      scalar @{ $pspoc->{ACCESS}->{$spocacl_name} },
                      " entries\n";
                    $self->{ACL_CHANGE} = 1;
                    &$pix_mark_for_transfer($spocacl_name);
                }
                elsif (
                    !$self->pix_acls_textual_identical($confacl, $spocacl)
                    && !$self->pix_acls_semantical_indentical(
                        $confacl, $spocacl, $intf
                    )
                  )
                {

                    # either there is no acl on $intf or the acl differs
                    # mark groups and interfaces recursive for transfer of spocacls
                    $self->{ACL_CHANGE} = 1;
                    &$pix_mark_for_transfer($spocacl_name);
                }
                elsif ($self->{FORCE_TRANSFER}) {
                    warnpr "Interface $intf: transfer of ACL forced!\n";
                    $self->{ACL_CHANGE} = 1;
                    &$pix_mark_for_transfer($spocacl_name);
                }
                mypr "-------------------------------------------------\n";
            }

            # mark objects to remove
            for my $intf (keys %{ $pspoc->{IF} }) {

                #next if($conf->{IF}->{$intf}->{REMOVE}); # allready marked
                my ($confacl, $spocacl, $confacl_name, $spocacl_name) =
                  &$get_acl_names_and_objects($intf);
                next
                  unless ($pspoc->{ACCESS_LIST}->{$spocacl_name}->{TRANSFER});
                next unless ($confacl);    # no ACL on device - nothing to mark
                &$pix_mark_for_remove($confacl_name);
            }

            # generate names for transfer
            for my $obj_id (keys %{ $pspoc->{OBJECT_GROUP} }) {
                next unless ($pspoc->{OBJECT_GROUP}->{$obj_id}->{TRANSFER});
                $pspoc->{OBJECT_GROUP}->{$obj_id}->{TRANSFER_ID} =
                  &$generate_names_for_transfer($obj_id, $conf->{OBJECT_GROUP});
            }
            for my $obj_id (keys %{ $pspoc->{ACCESS_LIST} }) {
                next unless ($pspoc->{ACCESS_LIST}->{$obj_id}->{TRANSFER});
                $pspoc->{ACCESS_LIST}->{$obj_id}->{TRANSFER_ID} =
                  &$generate_names_for_transfer($obj_id, $conf->{ACCESS_LIST});
            }

            # transfer groups
            mypr "transfer object-groups to device\n";
            for my $obj_id (keys %{ $pspoc->{OBJECT_GROUP} }) {
                next unless ($pspoc->{OBJECT_GROUP}->{$obj_id}->{TRANSFER});
                mypr
                  "object-group $pspoc->{OBJECT_GROUP}->{$obj_id}->{TRANSFER_ID}\n";
                my $copy = copy_structure($pspoc->{OBJECT_GROUP}->{$obj_id});

                # build transfer object group
                my $group_obj = (
                    {
                        $pspoc->{OBJECT_GROUP}->{$obj_id}->{TRANSFER_ID} =>
                          $copy
                    }
                );

                # generate commands
                my $string = '';
                $self->{PRINT} = 'yes';
                $self->parse_object_group($group_obj, \$string, 1);
                $self->{PRINT} = undef;

                # build cmd array
                my @cmd_array = split '\n', $string;
                push @cmd_array, 'exit';
                my %DDH;    # detect double hash
                for (@cmd_array) {
                    if ($DDH{$_}) {
                        mypr "discard double entry $_ in group $obj_id\n";
                    }
                    else {
                        $DDH{$_} = 1;
                        $self->cmd($_) or exit -1;
                    }
                }
            }

            # transfer ACLs
            mypr "transfer access-lists to device\n";
            for my $obj_id (keys %{ $pspoc->{ACCESS_LIST} }) {
                next unless ($pspoc->{ACCESS_LIST}->{$obj_id}->{TRANSFER});
                my $transfer_id =
                  $pspoc->{ACCESS_LIST}->{$obj_id}->{TRANSFER_ID};
                mypr "access-list $transfer_id\n";
                my $counter = 0;
                my $tr;
                for my $ace (@{ $pspoc->{ACCESS}->{$obj_id} }) {
                    if ($ace->{EXPANDED_FROM}) {
                        next if ($ace->{EXPANDED_FROM}->{COLLAPSED});
                        $ace->{EXPANDED_FROM}->{COLLAPSED} =
                          1;    # only one entry has to be transferred
                        my $new_ace = copy_structure($ace->{EXPANDED_FROM});
                        my $gid;
                        if ($new_ace->{PROTO}->{SRC}->{OBJECT_GROUP}) {
                            $gid = $new_ace->{PROTO}->{SRC}->{OBJECT_GROUP};
                            $new_ace->{PROTO}->{SRC}->{OBJECT_GROUP} =
                              $pspoc->{OBJECT_GROUP}->{$gid}->{TRANSFER_ID};
                        }
                        if ($new_ace->{PROTO}->{DST}->{OBJECT_GROUP}) {
                            $gid = $new_ace->{PROTO}->{DST}->{OBJECT_GROUP};
                            $new_ace->{PROTO}->{DST}->{OBJECT_GROUP} =
                              $pspoc->{OBJECT_GROUP}->{$gid}->{TRANSFER_ID};
                        }
                        $tr = join ' ', "access-list", $transfer_id,
                          $self->acl_line_to_string($new_ace);
                    }
                    else {
                        $tr = join ' ', "access-list", $transfer_id,
                          $self->acl_line_to_string($ace);
                    }
                    $self->cmd($tr) or exit -1;

                    #mypr "$tr\n";
                    $counter++;
                    mypr " $counter";
                }
                mypr "\n";

                # assign list to interface
                my $intf = $pspoc->{ACCESS_GROUP}->{$obj_id}->{IF_NAME};
                mypr "access-group $transfer_id in interface $intf\n";
                $self->cmd("access-group $transfer_id in interface $intf")
                  or exit -1;
            }

            # remove ACLs (first, because otherwise group remove would not work)
            mypr "remove spare acls from device\n";
            for my $acl_name (keys %{ $conf->{ACCESS_LIST} }) {
                if (   $conf->{ACCESS_LIST}->{$acl_name}->{REMOVE}
                    or $conf->{ACCESS_LIST}->{$acl_name}->{NO_REFERENCES})
                {
                    if ($self->{VERSION} >= 7.0) {
                        mypr " clear configure access-list $acl_name\n";
                        $self->cmd("clear configure access-list $acl_name")
                          or exit -1;
                    }
                    else {
                        mypr " no access-list $acl_name\n";
                        $self->cmd("no access-list $acl_name") or exit -1;
                    }
                }
            }

            # remove groups
            mypr "remove spare object-groups from device\n";
            for my $gid (keys %{ $conf->{OBJECT_GROUP} }) {
                my $type = $conf->{OBJECT_GROUP}->{$gid}->{TYPE};
                if (!$conf->{OBJECT_GROUP}->{$gid}->{ACL_REFERENCES}
                    or $conf->{OBJECT_GROUP}->{$gid}->{REMOVE})
                {
                    mypr " no object-group $type $gid\n";
                    $self->cmd("no object-group $type $gid") or exit -1;
                }
            }

        }
    }

    #
    # *** static nat ***
    #
    mypr " === processing statics ===\n";
    $self->pix_transfer_lines(
        'static_line_to_string', 'static_line_a_eq_b',
        $pspoc->{STATIC},        $conf->{STATIC}
    ) and $self->{STAT_CHANGE} = '*** statics changed ***';

    #
    # *** global pools ***
    #
    mypr " === processing global pools ===\n";
    $self->pix_transfer_lines('pix_global_line_to_string',
        'pix_global_line_a_eq_b', $pspoc->{GLOBAL}, $conf->{GLOBAL})
      and $self->{GLOB_CHANGE} = '*** globals changed ***';

    #
    # *** (dynamic) nat ***
    #
    mypr " === processing nat ===\n";
    $self->pix_transfer_lines('pix_nat_line_to_string', 'pix_nat_line_a_eq_b',
        $pspoc->{NAT}, $conf->{NAT})
      and $self->{NAT_CHANGE} = '*** nat changed ***';

    unless ($self->{COMPARE}) {
        if (   $self->{ROUTE_CHANGE}
            or $self->{ACL_CHANGE}
            or $self->{STAT_CHANGE}
            or $self->{GLOB_CHANGE}
            or $self->{NAT_CHANGE})
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

##################################################################
#    methods
##################################################################

sub check_device( $ ) {
    my ($self) = @_;
    my $retries = $self->{OPTS}->{p} || 3;
    return $self->checkping($self->{IP}, $retries);
}

sub check_crypto( $ ) {
    my ($self) = @_;
    mypr "Sorry - Check Crypto Config not supported for devices of "
      . "type \'$self->{JOBTYPE}\'\n";
}

sub remote_execute( $ ) {
    my ($self) = @_;
    $self->adaption();

    # to prevent configured by console messages
    # in compare mode prepare() does not change router config
    $self->{COMPARE} = 1;
    $self->con_setup(
        "START: execute user command at > " . scalar localtime() . " < ($id)");
    $self->prepare();
    $self->{OPTS}->{E} =~ s/\\n/\n/g;
    for my $line (split /[;]/, $self->{OPTS}->{E}) {
        my @output = $self->shcmd($line) or exit -1;
        mypr @output, "\n";
    }
    mypr "\n";
    $self->con_shutdown("STOP");
}

sub approve( $$ ) {
    my ($self, $spoc_path) = @_;
    $self->adaption();

    # remember approve mode
    $self->{APPROVE}       = 1;
    $self->{COMPARE}       = undef;
    $self->{ROUTE_CHANGE}  = $self->{ACL_CHANGE} = $self->{STAT_CHANGE} =
      $self->{GLOB_CHANGE} = $self->{NAT_CHANGE} = 0;

    # set up console
    $self->con_setup("START: $self->{OPTS}->{P} (telnet) at > "
          . scalar localtime()
          . " < ($id)");

    # prepare device for configuration
    $self->prepare();

    # check if Netspoc message in device banner
    $self->checkbanner();

    # fetch device configuration
    my $device_lines = $self->get_config_from_device();

    #
    # now do the main thing
    #
    my ($device_conf, $spoc_conf) =
      $self->prepare_devicemode($device_lines, $spoc_path)
      or errpr "devicemode prepare failed\n";
    if ($self->pixtrans($device_conf, $spoc_conf)) {
        mypr "approve done\n";
    }
    else {
        errpr "approve failed\n";
    }
    $self->con_shutdown("STOP: $self->{OPTS}->{P} (telnet) at > "
          . scalar localtime()
          . " < ($id)");
}

sub compare( $$ ) {
    my ($self, $spoc_path) = @_;
    $self->adaption();

    # save compare mode
    $self->{COMPARE}      = 1;
    $self->{CMPVAL}       = $self->{OPTS}->{C};
    $self->{ROUTE_CHANGE} = 'routing unchanged';
    $self->{ACL_CHANGE}   = 'acls unchanged';
    $self->{STAT_CHANGE}  = 'statics unchanged';
    $self->{GLOB_CHANGE}  = 'globals unchanged';
    $self->{NAT_CHANGE}   = 'nat unchanged';

    # set up console
    $self->con_setup("START: $self->{OPTS}->{P} (telnet) at > "
          . scalar localtime()
          . " < ($id)");

    # prepare device for configuration
    $self->prepare();

    # check if Netspoc message in device banner
    $self->checkbanner();

    # fetch device configuration
    my $device_lines = $self->get_config_from_device();

    #
    # now do the main thing
    #
    my ($device_conf, $spoc_conf) =
      $self->prepare_devicemode($device_lines, $spoc_path)
      or errpr "devicemode prepare failed\n";
    if ($self->pixtrans($device_conf, $spoc_conf)) {
        mypr "compare done\n";
    }
    else {
        errpr "compare failed\n";
    }

    $self->con_shutdown("STOP: $self->{OPTS}->{P} (telnet) at > "
          . scalar localtime()
          . " < ($id)");
    mypr "comp: $self->{OPTS}->{P} ", scalar localtime, " ($id)\n";
    mypr "comp: $self->{OPTS}->{P} $self->{NAME} $self->{ROUTE_CHANGE}\n";
    mypr "comp: $self->{OPTS}->{P} $self->{NAME} $self->{ACL_CHANGE}\n";
    mypr "comp: $self->{OPTS}->{P} $self->{NAME} $self->{STAT_CHANGE}\n";
    mypr "comp: $self->{OPTS}->{P} $self->{NAME} $self->{GLOB_CHANGE}\n";
    mypr "comp: $self->{OPTS}->{P} $self->{NAME} $self->{NAT_CHANGE}\n";

    if (   $self->{ROUTE_CHANGE} ne 'routing unchanged'
        or $self->{ACL_CHANGE}  ne 'acls unchanged'
        or $self->{STAT_CHANGE} ne 'statics unchanged'
        or $self->{GLOB_CHANGE} ne 'globals unchanged'
        or $self->{NAT_CHANGE}  ne 'nat unchanged')
    {
        return 1;
    }
    else {

        # no changes to report
        return 0;
    }
}

sub compare_files( $$$) {
    my ($self, $path1, $path2) = @_;
    &adaption($self);

    # save compare mode
    $self->{COMPARE} = 1;

    # default compare is silent(4) mode
    $self->{CMPVAL} = $self->{OPTS}->{C} || 4;

    $self->{ROUTE_CHANGE} = 'routing unchanged';
    $self->{ACL_CHANGE}   = 'acls unchanged';
    $self->{STAT_CHANGE}  = 'statics unchanged';
    $self->{GLOB_CHANGE}  = 'globals unchanged';
    $self->{NAT_CHANGE}   = 'nat unchanged';
    $self->{VERSION}      = "unknown";

    my ($conf1, $conf2) = $self->prepare_filemode($path1, $path2)
      or errpr "filemode prepare failed\n";

    if ($self->pixtrans($conf1, $conf2)) {
        mypr "compare done\n";
    }
    else {
        errpr "compare failed\n";
    }
    mypr "comp: ", scalar localtime, " ($id)\n";
    mypr "comp: $self->{NAME} $self->{ROUTE_CHANGE}\n";
    mypr "comp: $self->{NAME} $self->{ACL_CHANGE}\n";
    mypr "comp: $self->{NAME} $self->{STAT_CHANGE}\n";
    mypr "comp: $self->{NAME} $self->{GLOB_CHANGE}\n";
    mypr "comp: $self->{NAME} $self->{NAT_CHANGE}\n";

    if (   $self->{ROUTE_CHANGE} ne 'routing unchanged'
        or $self->{ACL_CHANGE}  ne 'acls unchanged'
        or $self->{STAT_CHANGE} ne 'statics unchanged'
        or $self->{GLOB_CHANGE} ne 'globals unchanged'
        or $self->{NAT_CHANGE}  ne 'nat unchanged')
    {
        return 1;
    }
    else {

        # no changes to report
        return 0;
    }
}

# Packages must return a true value;
1;

