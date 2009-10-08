
package Netspoc::Approve::Helper;

#
# Author: Arne Spetzler
#
# Description:
# module with misc helpers to drc2
#

'$Id$ ' =~ / (.+),v (.+?) /;
my $id = "$1 $2";

sub version_drc2_helper() {
    return $id;
}

require Exporter;
use strict;
use warnings;
use Fcntl;
use Expect;
use File::Basename;

our @ISA    = qw(Exporter);
our @EXPORT = qw( mypr errpr check_erro errpr_mode errpr_info
  warnpr check_warn meself quad2int int2quad writestatus
  formatstatus getstatus getfullstatus updatestatus
  open_status 
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
    'whois'             => 63,		# PIX 6.3 docu: 43
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

my %statfields = (
    DEVICENAME  => 0,
    APP_MESSAGE => 1,
    APP_STATUS  => 3,     # same as for DEV_STATUS and ***UNFINISHED APPROVE***
    APP_POLICY  => 2,
    APP_TIME    => 4,     # seconds since 1970 Cleartext
    APP_USER    => 5,
    DEV_MESSAGE => 6,
    DEV_STATUS  => 8,     # ***WARNINGS***, ***ERRORS***  or OK
    DEV_POLICY  => 7,
    DEV_TIME    => 9,     # seconds since 1970 Cleartext
    DEV_USER    => 10,
    COMP_COMP   => 11,
    COMP_RESULT => 12,    # DIFF or UPTODATE
    COMP_POLICY => 13,
    COMP_CTIME  => 14,    # seconds since 1970 Cleartext
    COMP_TIME   => 15,    # seconds since 1970
    COMP_DTIME  => 16,    # DEV_TIME in seconds
    FC_FC       => 17,
    FC_LAST_OK  => 18,    #last policy which seems to be identical to DEV_POLICY
    FC_STATE    => 19,    # result of last file compare: DIFF or OK
    FC_CTIME    => 20,    # seconds since 1970 Cleartext
    FC_TIME     => 21,    # seconds since 1970 (last change in state)
    MAX         => 21
);

my $warn     = "NO";      # sorry its global...
my $erro     = "NO";      # same applies to this :(
my $err_mode = "";

sub meself( $ ) {
    my $l    = $_[0];
    my $subs = "";
    for (my $i = 1 ; $i <= $l ; $i++) {
        my ($package, $file, $ln, $sub) = caller $i;
        $sub and $subs = $sub . " " . $subs;
    }
    return $subs;
}

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

sub writestatus ( $ ) {
    my $stat = shift;

    # disable output buffering for status messages
    # due to better reliability
    my $oldselect   = select STATUS;
    my $oldbuffmode = $|;
    unless ($oldbuffmode == 1) {
        $| = 1;
    }
    seek STATUS, 0, 0;
    print join ';', @$stat;
    truncate STATUS, tell STATUS or die "could not truncate statfile\n";
    $| = $oldbuffmode;
    select $oldselect;
}

sub formatstatus ( $ ) {
    my $stat = shift;
    for (my $i = 0 ; $i <= $statfields{MAX} ; $i++) {
        unless (exists $stat->[$i]
            and $stat->[$i] =~ /\S/
            and $stat->[$i] ne 'undef')
        {
            if ($i == $statfields{APP_MESSAGE}) {
                $stat->[ $statfields{APP_MESSAGE} ] = 'LAST_APPROVE';
            }
            elsif ($i == $statfields{DEV_MESSAGE}) {
                $stat->[ $statfields{DEV_MESSAGE} ] = 'LAST_SUCCESS';
            }
            elsif ($i == $statfields{DEV_POLICY}) {
                $stat->[ $statfields{DEV_POLICY} ] = 'p0';
            }
            elsif ($i == $statfields{COMP_COMP}) {
                $stat->[ $statfields{COMP_COMP} ] = 'COMPARE';
            }
            elsif ($i == $statfields{COMP_POLICY}) {
                $stat->[ $statfields{COMP_POLICY} ] = 'p0';
            }
            elsif ($i == $statfields{COMP_TIME}) {
                $stat->[ $statfields{COMP_TIME} ] = 0;
            }
            elsif ($i == $statfields{COMP_DTIME}) {
                $stat->[ $statfields{COMP_DTIME} ] = 0;
            }
            elsif ($i == $statfields{FC_FC}) {
                $stat->[ $statfields{FC_FC} ] = 'FILE_COMPARE';
            }
            elsif ($i == $statfields{FC_LAST_OK}) {
                $stat->[ $statfields{FC_LAST_OK} ] = 0;
            }
            elsif ($i == $statfields{FC_TIME}) {
                $stat->[ $statfields{FC_TIME} ] = 0;
            }
            else {
                $stat->[$i] = 'undef';
            }
        }
    }
    $stat->[ $statfields{MAX} + 1 ] = "\n";
    writestatus($stat);
}

sub getstatus ( $ ) {
    my $position = shift;
    seek STATUS, 0, 0;
    my @stat = split ';', <STATUS>;

    # @stat may be  empty
    if ($#stat < $statfields{MAX} + 1) {
        formatstatus(\@stat);
    }
    (exists $statfields{$position})
      || die "unknown status field $position\n";

    return $stat[ $statfields{$position} ];
}

sub getfullstatus () {
    my $fst = {};
    for my $pos (keys %statfields) {
        $fst->{$pos} = getstatus($pos);
    }
    return $fst;
}

sub updatestatus ( $$ ) {
    my ($position, $value) = @_;

    # disable output buffering for status messages
    # due to better reliability
    seek STATUS, 0, 0;
    my @stat = split ';', <STATUS>;

    # @stat may be  empty
    if ($#stat < $statfields{MAX} + 1) {
        formatstatus(\@stat);
    }
    (exists $statfields{$position})
      || die "unknown status field $position\n";

    @stat[ $statfields{$position} ] = $value;

    writestatus(\@stat);
}

sub open_status( $ ) {
    my $job        = shift;
    my $devicename = $job->{NAME};
    my $statuspath = $job->{GLOBAL_CONFIG}->{STATUSPATH};

    # open status file for update and checking
    unless (-f "$statuspath$devicename") {
        (sysopen(STATUS, "$statuspath$devicename", O_RDWR | O_CREAT))
          or die "could not open/create file: $statuspath$devicename\n$!\n";
        defined chmod 0644, "$statuspath$devicename"
          or die " couldn't chmod lockfile $statuspath$devicename\n$!\n";
    }
    else {
        (sysopen(STATUS, "$statuspath$devicename", O_RDWR))
          or die "could not open file: $statuspath$devicename\n$!\n";
    }
}

sub quad2int ($) {
    ($_[0] =~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/) or return undef;
    ($1 < 256 && $2 < 256 && $3 < 256 && $4 < 256) or return undef;
    return $1 << 24 | $2 << 16 | $3 << 8 | $4;
}

sub int2quad ($) {
    return join('.', unpack('C4', pack("N", $_[0])));
}


1;
