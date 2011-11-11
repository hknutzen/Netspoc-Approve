
package Netspoc::Approve::Helper;

#
# Author: Arne Spetzler
#
# Description:
# module with misc helpers
#
# $Id$

require Exporter;
use strict;
use warnings;
use Expect;

our @ISA    = qw(Exporter);
our @EXPORT = qw( mypr errpr check_erro errpr_mode errpr_info
  warnpr check_warn internal_err debug quad2int int2quad is_ip
  %ICMP_Trans %IP_Trans %PORT_Trans_TCP %PORT_Trans_UDP  
);

############################################################
# --- parsing ---
############################################################

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
    'h323'              => 1720,	# from PIX 6.3 docu
    'hostname'          => 101,
    'https'             => 443,
    'ident'             => 113,
    'imap4'             => 143,		# from PIX 6.3 docu
    'irc'               => 194,
    'kerberos'          => 750,		# from PIX 6.3 docu
    'klogin'            => 543,
    'kshell'            => 544,
    'ldap'              => 389,
    'ldaps'             => 636,
    'lpd'               => 515,
    'login'             => 513,
    'lotusnotes'        => 1352,
    'nfs'               => 2049,
    'netbios-ssn'       => 139,
    'nntp'              => 119,
    'pcanywhere-data'   => 5631,
    'pim-auto-rp'       => 496,
    'pop2'              => 109,
    'pop3'              => 110,
    'pptp'              => 1723,	# from PIX 6.3 docu
    'smtp'              => 25,
    'sqlnet'            => 1521,
    'rsh'		=> 514,		# ASA 8.0, duplicate of 'cmd'
    'ssh'               => 22,
    'sunrpc'            => 111,
    'tacacs'            => 49,
    'tacacs-ds'         => 65,
    'talk'              => 517,
    'telnet'            => 23,
    'time'              => 37,
    'uucp'              => 540,
    'whois'             => 43,		# PIX 6.3 docu, IOS 12.4(15)T1
    'www'               => 80
);

our %PORT_Trans_UDP = (
    'biff'          => 512,
    'bootpc'        => 68,
    'bootps'        => 67,
    'discard'       => 9,
    'dns'           => 53,
    'domain'        => 53,
    'dnsix'         => 90,	# PIX 6.3 docu: 195 
    'echo'          => 7,
    'isakmp'        => 500,
    'kerberos'      => 750,	# from PIX 6.3 docu
    'mobile-ip'     => 434,    # maybe this is 435 ?
    'nameserver'    => 42,
    'netbios-dgm'   => 138,
    'netbios-ns'    => 137,
    'netbios-ss'    => 139,	# PIX 6.3 docu: netbios-ssn
    'nfs'           => 2049,
    'non500-isakmp' => 4500,
    'ntp'           => 123,
    'pcanywhere-status' => 5632,
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

my $warn     = "NO";      # sorry its global...
my $erro     = "NO";      # same applies to this :(
my $err_mode = "";

sub mypr {
    print STDOUT @_;
}

sub errpr {
    $erro = "YES";
    print STDERR "ERROR>>> ", @_;
#    unless ($err_mode eq "COMPARE") {
#        print STDERR "ERROR>>> --- approve aborted ---\n";
        exit -1;
#    }
}

sub errpr_mode( $ ) {
    $err_mode = shift;
    $err_mode eq "COMPARE" or die "COMPARE expected\n";
}

sub check_erro() {
    return $erro;
}

sub errpr_info {
    print STDERR "ERROR>>> ", @_;
}

sub warnpr {
    $warn = "YES";
    print STDOUT "WARNING>>> ", @_;
}

sub check_warn() {
    return $warn;
}

sub internal_err( @ ) {
    my ($package, $file, $line, $sub) = caller 1;
    errpr "Internal error in $sub:\n ", @_, "\n";
}

sub debug ( @ ) {
    print STDERR @_, "\n";
}

sub quad2int ($) {
    ($_[0] =~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/) or return undef;
    ($1 < 256 && $2 < 256 && $3 < 256 && $4 < 256) or return undef;
    return $1 << 24 | $2 << 16 | $3 << 8 | $4;
}

sub int2quad ($) {
    return join('.', unpack('C4', pack("N", $_[0])));
}

sub is_ip {
    my ( $obj ) = @_;
    return $obj =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
}


1;
