
=head1 DESCRIPTION

Base class for the different varieties of Cisco devices.

=head1 COPYRIGHT AND DISCLAIMER

https://github.com/hknutzen/Netspoc-Approve
(c) 2018 by Heinz Knutzen <heinz.knutzen@gmail.com>
(c) 2009 by Daniel Brunkhorst <daniel.brunkhorst@web.de>
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

package Netspoc::Approve::Cisco;

use base "Netspoc::Approve::Device";
use strict;
use warnings;
use Algorithm::Diff;
use Netspoc::Approve::Helper;
use Netspoc::Approve::Parse_Cisco;
use Regexp::IPv6 qw($IPv6_re);

our $VERSION = '2.3'; # VERSION: inserted by DZP::OurPkgVersion

############################################################
# Translate names to port numbers, icmp type/code numbers
############################################################

my %ICMP_Names = (
    'administratively-prohibited' => { type => 3,  code => 13 },
    'alternate-address'           => { type => 6,  code => -1 },
    'conversion-error'            => { type => 31, code => -1 },
    'dod-host-prohibited'         => { type => 3,  code => 10 },
    'dod-net-prohibited'          => { type => 3,  code => 9 },
    'echo'                        => { type => 8,  code => -1 },
    'echo-reply'                  => { type => 0,  code => -1 },
    'general-parameter-problem'   => { type => 12, code => 0 },
    'host-isolated'               => { type => 3,  code => 8 },
    'host-precedence-unreachable' => { type => 3,  code => 14 },
    'host-redirect'               => { type => 5,  code => 1 },
    'host-tos-redirect'           => { type => 5,  code => 3 },
    'host-tos-unreachable'        => { type => 3,  code => 12 },
    'host-unknown'                => { type => 3,  code => 7 },
    'host-unreachable'            => { type => 3,  code => 1 },
    'information-reply'           => { type => 16, code => -1 },
    'information-request'         => { type => 15, code => -1 },
    'mask-reply'                  => { type => 18, code => -1 },
    'mask-request'                => { type => 17, code => -1 },
    'mobile-redirect'             => { type => 32, code => -1 },
    'net-redirect'                => { type => 5,  code => 0 },
    'net-tos-redirect'            => { type => 5,  code => 2 },
    'net-tos-unreachable'         => { type => 3,  code => 11 },
    'net-unreachable'             => { type => 3,  code => 0 },
    'network-unknown'             => { type => 3,  code => 6 },
    'no-room-for-option'          => { type => 12, code => 2 },
    'option-missing'              => { type => 12, code => 1 },
    'packet-too-big'              => { type => 3,  code => 4 },
    'parameter-problem'           => { type => 12, code => -1 },
    'port-unreachable'            => { type => 3,  code => 3 },
    'precedence-unreachable'      => { type => 3,  code => 15 },
    'protocol-unreachable'        => { type => 3,  code => 2 },
    'reassembly-timeout'          => { type => 11, code => 1 },
    'redirect'                    => { type => 5,  code => -1 },
    'router-advertisement'        => { type => 9,  code => -1 },
    'router-solicitation'         => { type => 10, code => -1 },
    'source-quench'               => { type => 4,  code => -1 },
    'source-route-failed'         => { type => 3,  code => 5 },
    'time-exceeded'               => { type => 11, code => -1 },
    'timestamp-reply'             => { type => 14, code => -1 },
    'timestamp-request'           => { type => 13, code => -1 },
    'traceroute'                  => { type => 30, code => -1 },
    'ttl-exceeded'                => { type => 11, code => 0 },
    'unreachable'                 => { type => 3,  code => -1 },
);

my %ICMP6_Names = (
    'echo'                   => { type => 128,  code => 0 },
    'echo-reply'             => { type => 129,  code => 0 },
    'membership-query'       => { type => 130,  code => 0 },
    'membership-reduction'   => { type => 132,  code => 0 },
    'membership-report'      => { type => 131,  code => 0 },
    'neighbor-advertisement' => { type => 136,  code => 0 },
    'neighbor-redirect'      => { type => 137,  code => 0 },
    'neighbor-solicitation'  => { type => 135,  code => 0 },
    'packet-too-big'         => { type => 2,    code => 0 },
    'parameter-problem'      => { type => 4,    code => -1 },
    'router-advertisement'   => { type => 134,  code => 0 },
    'router-renumbering'     => { type => 138,  code => -1 },
    'router-solicitation'    => { type => 133,  code => 0 },
    'time-exceeded'          => { type => 3,    code => -1 },
);

# Leave names unchanged for standard protocols icmp, tcp, udp.
my %IP_Names = (
    'ah'     => 51,
    'ahp'    => 51,
    'eigrp'  => 88,
    'esp'    => 50,
    'gre'    => 47,
#    'icmp'   => 1,
#    'icmp6'  => 58,
    'igmp'   => 2,
    'igrp'   => 9,
    'ipinip' => 4,
    'nos'    => 94,
    'ospf'   => 89,
    'pcp'    => 108,    # NX-OS 6.x
    'pim'    => 103,
#    'tcp'    => 6,
#    'udp'    => 17,
);

my %PORT_Names_TCP = (
    'bgp'               => 179,
    'chargen'           => 19,
    'citrix-ica'        => 1494,
    'cmd'               => 514,
    'connectedapps-plain' => 15001,
    'connectedapps-tls' => 15002,
    'ctiqbe'            => 2748,
    'daytime'           => 13,
    'discard'           => 9,
    'domain'            => 53,
    'drip'              => 3949,        # NX-OS 6.x
    'echo'              => 7,
    'exec'              => 512,
    'finger'            => 79,
    'ftp'               => 21,
    'ftp-data'          => 20,
    'gopher'            => 70,
    'h323'              => 1720,
    'hostname'          => 101,
    'https'             => 443,
    'ident'             => 113,
    'imap4'             => 143,
    'irc'               => 194,
    'kerberos'          => 750,
    'klogin'            => 543,
    'kshell'            => 544,
    'ldap'              => 389,
    'ldaps'             => 636,
    'login'             => 513,
    'lotusnotes'        => 1352,
    'lpd'               => 515,
    'msrpc'             => 135,
    'netbios-ssn'       => 139,
    'nfs'               => 2049,
    'nntp'              => 119,
    'pcanywhere-data'   => 5631,
    'pim-auto-rp'       => 496,
    'pop2'              => 109,
    'pop3'              => 110,
    'pptp'              => 1723,
    'rsh'               => 514,         # ASA 8.0, duplicate of 'cmd'
    'rtsp'              => 554,
    'sip'               => 5060,
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
    'whois'             => 43,
    'www'               => 80
);

sub tcp_name2num {
    my ($self, $name) = @_;
    return $PORT_Names_TCP{$name};
}

my %PORT_Names_UDP = (
    'biff'          => 512,
    'bootpc'        => 68,
    'bootps'        => 67,
    'discard'       => 9,
    'dns'           => 53,
    'dnsix'         => 90,
    'domain'        => 53,
    'echo'          => 7,
    'isakmp'        => 500,
    'kerberos'      => 750,
    'mobile-ip'     => 434,
    'nameserver'    => 42,
    'netbios-dgm'   => 138,
    'netbios-ns'    => 137,
    'netbios-ss'    => 139,
    'nfs'           => 2049,
    'non500-isakmp' => 4500,
    'ntp'           => 123,
    'pcanywhere-status' => 5632,
    'pim-auto-rp'   => 496,
    'radius'        => 1645,
    'radius-acct'   => 1646,
    'rip'           => 520,
    'ripng'         => 521,
    'ripv6'         => 521,
    'sip'           => 5060,
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

sub udp_name2num {
    my ($self, $name) = @_;
    return $PORT_Names_UDP{$name};
}

#########################################################################
# Purpose    : Parse config lines according to the directions given for
#              device commands by $parse_info. Checks correct intendation
#              and handles unknown commands. Store known commands within
#              an array. Every command is represented as hash, with
#              subcommands being a hash entry of the associated top level
#              command hash.
# Parameters : $lines - Array containing one entry for every config file line.
#              $parse_info - hash containing device specific parsing directions.
#              $strict - flag, is set if parsed lines are from raw file.
#                Induces abort on unknown command instead of ignoring them.
# Returns    : $config array, containing one hash for every toplevel command
#              from $lines.
# Comment    :
# - arg: an array of tokens split by whitespace
#      first element, the command name, consists of multiple tokens,
#      if prefix tokens are used.
# - subcmd: sub-commands related to current command
#
# $config->[{args => [$cmd, @args], subcmd => [{args => [$cmd @args]}, ...]},
#           {args => [$cmd, @args], subcmd => [...]}
#        ..]
sub analyze_conf_lines {
    my ($self, $lines, $parse_info, $strict) = @_;
    $self->add_prefix_info($parse_info);
    my @stack;
    my $level = 0;
    my $config = [];
    my $counter = 0;
    my $in_banner = 0;
    my $end_banner_regex;
    my $first_subcmd = 0;

    for my $line (@$lines) {

        $counter++;

        # Subsequent line of multiline command. $end_banner_regex and
        # $in_banner were set in a preceding iteration.
        if(my $cmd = $in_banner) {
            if($line =~ $end_banner_regex) {
                $in_banner = 0;
            }
            else {
                push(@{ $cmd->{lines} }, $line);
            }
            next;
        }

        # Ignore comment lines.
        next if $line =~ /^ *!/;

        # Ignore empty lines.
        next if $line =~ /^\s*$/;

        # Check proper indentation level: Get number of leading spaces.
        my ($indent, $rest) = $line =~ /^( *)(.*)$/;
        my $sub_level = length($indent);

        # Level is set accordingly to expected command in previous iteration.
        if($sub_level == $level) {

            # Got expected command or sub-command.
        }

        # Indentation higher than expected. NX-OS and some older IOS
        # versions use sub commands, which have a higher indentation
        # level than 1. This is only applicable for the first sub
        # command.
        elsif($sub_level > $level) {

            if($first_subcmd) {

                # For unknown commands allow first command(s) to be
                # indented deeper and following commands to be indented
                # only by one.
                if (not $parse_info or not keys %$parse_info) {
                    push @stack, [ $config, $parse_info, $level, $strict ];
                    $config = undef;
                    $parse_info = undef;
                }
                $level = $sub_level;
            }
            else {
                chomp $line;
                abort("Expected indentation '$level' but got '$sub_level'" .
                      " at line $counter:",
                      ">>$line<<");
            }
        }

        # Line is from a new command with higher level: get appropriate
        # command-level info from stack.
        else {
            while($sub_level < $level && @stack) {
                ($config, $parse_info, $level, $strict) = @{ pop @stack };
            }

            # All sub commands need to use the same indentation level.
            if ($sub_level != $level) {
                if ( ( ($level+1) == $sub_level ) && $rest eq 'quit' ) {
                    # Skip certificate data.
                }
                else {
                    chomp $line;
                    abort("Expected indentation '$level' but got '$sub_level'" .
                          " at line $counter:",
                          ">>$line<<");
                }
            }
        }

        # Process $rest (non indent part of line).
        $first_subcmd = 0;
        my @args = split(' ', $rest);
        my $orig = join(' ', @args);
        my ($cmd, $lookup);

        # Look for command line (@args) within command dictionary of specific
        # device in $parse_info->{_prefix}. Lookup is performed wordwise.
        # Found command prefixes are stored twice: Unaltered as $cmd, and
        # as $lookup with arguments replaced by '_skip' and 'any'.
        #  Trailing '_skip's are omitted.
        if(my $prefix_info = $parse_info->{_prefix}) {
            my $skip = 0;
            my @a = @args;
            my @c = ();
            my @l = ();
            my @skipped;
            while(@a > $skip) {
                my $prefix = $a[$skip];
                my $next;
                if ($next = $prefix_info->{$prefix}) {
                    splice(@a, $skip, 1);
                    push @c, $prefix;
                    push @l, @skipped, $prefix;
                    @skipped = ();
                }
                elsif ($next = $prefix_info->{_any}) {
                    splice(@a, $skip, 1);
                    push @c, $prefix;
                    push @l, @skipped, '_any';
                    @skipped = ();
                }
                elsif ($next = $prefix_info->{_skip}) {
                    $skip++;
                    push @skipped, '_skip';
                }
                else {

                    # Take longest match, found so far.
                    last;
                }
                last if not keys %$next;
                $prefix_info = $next;
            }
            @args = @a;
            $cmd = join(' ', @c);
            $lookup = join(' ', @l);
        }
        if (!$lookup) {
            $cmd = $lookup = shift @args;
        }

        if (my $cmd_info = ($parse_info->{$lookup} || $parse_info->{_any})) {

            # Remember current line number, set parse position.
            # Remember a version of the unparsed line without duplicate
            # whitespace.
            my $new_cmd = { line => $counter,
                            pos => 0,
                            orig => $orig,
                            args => [ $cmd, @args ],
                            cmd_info => $cmd_info,
                        };
            push(@$config, $new_cmd);
            if (my $subcmd = $cmd_info->{subcmd}) {

                # Prepare to parse subcommand within next iteration.
                push @stack, [ $config, $parse_info, $level, $strict ];
                $level++;
                $parse_info = $subcmd;
                $config = [];
                $strict ||= $cmd_info->{strict};
                $new_cmd->{subcmd} = $config;
                $first_subcmd = 1;
            }
            elsif ($end_banner_regex = $cmd_info->{banner}) {
                $new_cmd->{lines} = [];
                $in_banner = $new_cmd;
            }

        }

        # Ignore unknown command. Prepare to ignore subcommands as well.
        else {
            push @stack, [ $config, $parse_info, $level, $strict ];
            $config = undef;
            $parse_info = undef;
            $level++;
            $first_subcmd = 1;
            if ($strict) {
                abort("Unexpected command in line $counter:\n>>$orig<<");
            }
        }
    }

    # Fetch toplevel command $config from stack (final line can be
    # from subcommand).
    while($level--) {
        ($config, $parse_info, $level, $strict) = @{ pop @stack };
    }
    return $config;
}

#########################################################################
# Purpose    : Parse network address string and store information as hash
# Parameters : $arg - Hash representation of a command as generated by
#              analyze_conf_lines, with $arg->{pos} pointing to $arg->{args}
#              in such a way that next token to be read is a network address.
# Returns    : A hash with BASE and MASK keys and values.
sub parse_address {
    my ($self, $arg) = @_;
    my ($ip, $mask);
    my $token = get_token($arg);

    if ($token eq 'any'){
        $ip = $mask = pack('N', 0);
    }
    elsif ($token eq 'host') {
        $ip   = get_ip($arg);
        if (is_ipv6($ip)) {
            $mask = NetAddr::IP::Util::ipv6_aton(
                'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff');
        }
        else {
            $mask = pack('N', 0xffffffff);
        }
    }
    elsif ($token =~ /(:?$IPv6_re|::)/) {
#        my ($i, $prefix) = split(/\//, $token);
        unread($arg);
        ($ip, $mask) = get_ip_prefix($arg);
    }
    else {
        $ip   = quad2bitstr($token);
        $mask = $self->adjust_mask(get_ip($arg));
    }
    return ({ BASE => $ip, MASK => $mask });
}

sub adjust_mask {
    my ($self, $mask) = @_;
    return $mask;
}

sub parse_port {
    my ($self, $arg, $proto) = @_;
    my $port = get_token($arg);

    # Port is numeric.
    return $port if $port =~ /^\d+$/;

    # Convert named port to numeric port.
    if ($proto eq 'tcp') {
        $port = $self->tcp_name2num($port);
    }
    elsif ($proto eq 'udp') {
        $port = $self->udp_name2num($port);
    }

    # For tcp-udp and object-group check for intersection of port names.
    else {
        my $tcp = $self->tcp_name2num($port);
        my $udp = $self->udp_name2num($port);
        if ($tcp && $udp && $tcp == $udp) {
            $port = $tcp;
        }
        else {
            $port = undef;
        }
    }
    defined $port or err_at_line($arg, 'Expected port number or port name');
    return $port;
}

# ( 'lt' | 'gt' | 'eq' | 'neq' ) port
# 'range' port port
sub parse_port_spec {
    my ($self, $arg, $proto) = @_;
    my ($low, $high);
    my $spec = check_regex('eq|gt|lt|neq|range', $arg)
      or return { LOW => 0, HIGH => 0xffff };
    my $port = $self->parse_port($arg, $proto);
    if ($spec eq 'eq') {
        $low = $high = $port;
        $spec = 'range';
    }
    elsif ($spec eq 'gt') {
        $low  = $port + 1;
        $high = 0xffff;
        $spec = 'range';
    }
    elsif ($spec eq 'lt') {
        $low  = 0;
        $high = $port - 1;
        $spec = 'range';
    }
    elsif ($spec eq 'neq') {
        abort("port specifier 'neq' not implemented");
    }
    elsif ($spec eq 'range') {
        $low = $port;
        $high = $self->parse_port($arg, $proto);
    }
    return ({ LOW => $low, HIGH => $high });
}

my $icmp_regex = join('|', '\d+', keys %ICMP_Names);
my $icmp6_regex = join('|', '\d+', keys %ICMP6_Names);

# <message-name> | (/d+/ [/d+])
# ->{TYPE} / ->{CODE} (if defined)
sub parse_icmp_spec {
    my ($self, $arg, $version) = @_;
    my $regex = $version eq 'icmp'? $icmp_regex : $icmp6_regex;
    my $token = check_regex($regex, $arg);
    return({}) if not defined $token;
    my ($type, $code);
    my $names = $version eq 'icmp'? \%ICMP_Names : \%ICMP6_Names;
    if (my $spec = $names->{$token}) {
        ($type, $code) = @{$spec}{ 'type', 'code' };
    }
    else {
        $type = $token;
        $code = check_regex('\d+', $arg) || -1;
    }
    return ({ TYPE => $type, CODE => $code });
}

sub normalize_proto {
    my ($self, $arg, $proto) = @_;
    $proto = $IP_Names{$proto} || $proto;
    $proto =~ /^(?:\d+|icmp|tcp|udp|icmp6)$/
        or err_at_line($arg, "Expected numeric proto '$proto'");
    $proto =~ /^(1|6|17|58)$/
        and err_at_line($arg, "Don't use numeric proto for",
                               " icmp|tcp|udp|icmp6: '$proto'");
    return($proto);
}

##############################################################################
# Purpose    : Adds acls from raw data config hash to corresponding ipv4/ipv6
#              config hash or acls from (combined) ipv6 config hash to
#              (combined) ipv4 config hash. Unless $mode equals 'prepend',
#              new acls are added at the beginning of acl array.
# Parameters : $spoc - ipv4 netspoc config in $result - hash format.
#              $add_conf - raw or ipv6 config in $result - hash format.
#              $mode - 'append', 'prepend', 'ipv6', indicates operational mode.
sub merge_acls {
    my ($self, $spoc, $add_conf, $mode) = @_;
    my $raw_only = keys %$spoc? 0 : 1;
    my %raw_acl_seen;

    # Iterate over interfaces in config to add.
    for my $intf_name ( keys %{ $add_conf->{IF} } ) {
        my $add_intf = delete($add_conf->{IF}->{$intf_name});
        my $spoc_intf = $spoc->{IF}->{$intf_name};

        # Create interface entry in main config hash, if it doesnt exist.
        if ( ! $spoc_intf ) {
            $mode ne 'dual_stack' and not $raw_only and
            warn_info("Interface $intf_name referenced in raw doesn't",
                      " exist in Netspoc");
            $spoc_intf = $spoc->{IF}->{$intf_name} = { name => $intf_name };
        }

        # Merge acls for possibly existing access-group of this interface.
        for my $direction ( qw( IN OUT ) ) {
            my $access_group = "ACCESS_GROUP_$direction";
            if (my $add_name = $add_intf->{$access_group}) {
                my $add_acl = delete($add_conf->{ACCESS_LIST}->{$add_name});
                if (not $add_acl) {
                    if ($raw_acl_seen{$add_name}) {
                        abort("ACL '$add_name' must not be referenced" .
                              " multiple times in raw");
                    }
                    else {
                        abort("Referencing unknown ACL '$add_name' in raw");
                    }
                }
                $raw_acl_seen{$add_name} = 1;

                # Access group exists already for this interface in
                # netspoc config, add additional acl entries.
                if(my $spoc_name = $spoc_intf->{$access_group}) {

                    my $msg;
                    my $spoc_entries =
                        $spoc->{ACCESS_LIST}->{$spoc_name}->{LIST} ||= [];
                    my $add_entries = $add_acl->{LIST};

                    # Append mode adds entries behind last permit line.
                    if ($mode eq 'append') {
                        $msg = 'Appending';

                        # Find last permit line within netspoc entries.
                        my $index = @$spoc_entries;
                        while ($index > 0) {
                            if ($spoc_entries->[$index-1]->{MODE} eq 'deny') {
                                $index--;
                            }
                            else {
                                last;
                            }
                        }
                        splice(@$spoc_entries, $index, 0, @$add_entries);
                    }
                    else {
                        $msg = 'Prepending';
                        unshift(@$spoc_entries, @$add_entries);
                    }

                    my $count = @$add_entries;
                    info("$msg $count entries to $direction ACL of $intf_name");
                }
                else {
                    # Access group does not exist for current
                    # interface in netspoc. Abort if it exists for
                    # another interface. This can only happen with
                    # access groups defined in raw files. Generate new
                    # acl and access group entries otherwise.
                    $spoc->{ACCESS_LIST}->{$add_name} and
                        abort("Name clash for '$add_name' of ACCESS_LIST from "
                              . ($mode eq 'dual_stack'? "ipv6" : "raw"));
                    $spoc->{ACCESS_LIST}->{$add_name} = $add_acl;
                    $spoc_intf->{$access_group} = $add_name;
                }
            }
        }
    }
    # Check for unbound ACL in raw.
    # Must not trigger autovivification.
    if (my $acls = $add_conf->{ACCESS_LIST}) {
        if (my @names = sort keys %$acls) {
            abort("Found unbound ACCESS_LIST in raw: " . join(', ', @names));
        }
    }
}

sub enter_conf_mode {
    my($self) = @_;
    $self->cmd('configure terminal');
    $self->{CONF_MODE} = 1;
}

sub leave_conf_mode {
    my($self) = @_;
    $self->cmd('end');
    $self->{CONF_MODE} = 0;
}

sub check_conf_mode {
    my($self) = @_;
    $self->{CONF_MODE};
}

sub write_mem {
    my($self) = @_;
    $self->cmd('copy running-config startup-config');
}

sub route_add {
    my($self, $entry) = @_;
    return($entry->{orig});
}

sub route_del {
    my($self, $entry) = @_;
    return("no $entry->{orig}");
}

sub get_identity {
    my ($self) = @_;
    my $name = ($self->get_cmd_output('show hostname'))->[0];

    # Ignore domain-name
    $name =~ s/[.].*//;
    return $name;
}

sub login_enable {
    my ($self) = @_;
    my $std_prompt = qr/[\>\#]/;

    # If running as privileged user, try to get user and password
    # for login. Otherwise get current user or user from option
    # '-u' and no password.
    my ($user, $pass) = $self->get_aaa_password();

    my ($con, $ip) = $self->connect_ssh($user);
    my $prompt = qr/password:|\(yes\/no\)\?/i;
    my $result = $con->con_short_wait($prompt);
    if ($result->{MATCH} =~ m/\(yes\/no\)\?/i) {
        $prompt = qr/password:/i;
        $result = $con->con_issue_cmd('yes', $prompt);
        info("SSH key for $ip permanently added to known hosts");
    }
    $self->{PRE_LOGIN_LINES} = $result->{BEFORE};
    $prompt = qr/$prompt|$std_prompt/i;
    $pass ||= $self->get_user_password($user);
    $result = $con->con_issue_cmd($pass, $prompt);
    $self->{PRE_LOGIN_LINES} .= $result->{BEFORE};

    if ($result->{MATCH} eq '>') {

        # Enter enable mode.
        my $prompt = qr/password:|\#/i;
        $result = $con->con_issue_cmd('enable', $prompt);
        if ($result->{MATCH} ne '#') {

            # Enable password required.
            # Use login password as enable password.
            $result = $con->con_issue_cmd($pass, $prompt);
        }
        if ($result->{MATCH} ne '#') {
            abort("Authentication for enable mode failed");
        }
    }
    elsif ($result->{MATCH} ne '#') {
        abort("Authentication failed");
    }

    # Force new prompt by issuing empty command.
    # Set prompt again because of performance impact of standard prompt.
    $self->{ENAPROMPT} = qr/\r\n.*\#[ ]?$/;
    $result = $self->issue_cmd('');
    $result->{MATCH} =~ m/^(\r\n\s?\S+)\#[ ]?$/;
    my $prefix = $1;
    $self->{ENAPROMPT} = qr/$prefix\S*\#[ ]?/;
}

sub check_device_IP {
    my ($self, $name, $conf_intf, $spoc_intf) = @_;
    my $get_addr = sub {
        my ($intf) = @_;
        my $primary = $intf->{ADDRESS};
        if (not $primary) {
            if ($intf->{UNNUMBERED}) {
                return 'unnumbered';
            }
            else {
                return 'missing';
            }
        }
        if (my $dyn = $primary->{DYNAMIC}) {
            return $dyn;
        }
        my $secondary = $intf->{SECONDARY} || [];
        my @result;
        for my $addr ($primary, @$secondary) {

            # ip address 10.1.1.0 255.255.255.0 --> 10.1.1.0 255.255.255.0
            my $ip = $addr->{orig};
            $ip =~ s/^.*address //;
            $ip =~ s/ secondary$//;
            push @result, $ip;
        }
        return join ',', sort @result;
    };
    my $conf_addr = $get_addr->($conf_intf);
    my $spoc_addr = $get_addr->($spoc_intf);
    return if $spoc_addr eq $conf_addr;
    return if $spoc_addr eq 'negotiated';
    warn_info("Different address defined for interface $name:" .
              " Conf: $conf_addr, Netspoc: $spoc_addr");
}

# All active interfaces on device must be known by Netspoc.
sub check_device_interfaces {
    my ($self, $conf, $spoc) = @_;

    my @errors;
    for my $name (sort keys %{ $conf->{IF} }) {
        my $conf_intf = $conf->{IF}->{$name};
        next if $conf_intf->{SHUTDOWN};
        $conf_intf->{ADDRESS} or $conf_intf->{UNNUMBERED} or next;
        if (my $spoc_intf = $spoc->{IF}->{$name}) {

            # Compare statefulness.
            my $conf_inspect = $conf_intf->{INSPECT} ? 'enabled' : 'disabled';
            my $spoc_inspect = $spoc_intf->{INSPECT} ? 'enabled' : 'disabled';
            $conf_inspect eq $spoc_inspect or
                push(@errors,
                     "Different 'ip inspect' defined for interface $name:" .
                     " Conf: $conf_inspect, Netspoc: $spoc_inspect");
        }
        else {
            warn_info("Interface '$name' on device is not known by Netspoc");
        }
    }
    @errors and abort(@errors);
}

##############################################################################
# Purpose    : (for ASA devices: check whether interfaces from netspoc config
#               are known on device (no mpls/vrf for ASA))
sub check_spoc_interfaces {
    my ($self, $conf, $spoc, $has_mpls) = @_;

    my @errors;
    for my $name (sort keys %{ $spoc->{IF} }) {
        my $spoc_intf = $spoc->{IF}->{$name};
        if (my $conf_intf = $conf->{IF}->{$name}) {

            # Compare mapping to VRF.
            my $spoc_vrf = $spoc_intf->{VRF} || '-';
            my $conf_vrf = $conf_intf->{VRF} || '-';
            $conf_vrf eq $spoc_vrf or
                push(@errors,
                     "Different VRFs defined for interface $name:" .
                     " Conf: $conf_vrf, Netspoc: $spoc_vrf");
            $self->check_device_IP($name, $conf_intf, $spoc_intf);
        }
        else {

            # Ignore unnumbered pseudo mpls interface
            if ($has_mpls && $name =~ /^mpls/ && $spoc_intf->{UNNUMBERED}) {
                delete $spoc->{IF}->{$name};
                next;
            }

            push(@errors, "Interface '$name' from Netspoc not known on device");
        }
    }
    @errors and abort(@errors);
}

##############################################################################
# Purpose    : Check interfaces to be known in both device and netspoc config.
#              Ensure interfaces have same state within both configs.
# Parameters : $conf - device configuration in structure hash format.
#              $spoc - netspoc configuration in structure hash format.
#              $has_mpls - ? - never used with ASA
sub checkinterfaces {
    my ($self, $conf, $spoc, $has_mpls) = @_;

    # Only check device interfaces, if Netspoc config has some
    # access-lists or crypto config. Otherwise the device is probably
    # of type "managed=routing_only", and Netspoc won't change any
    # interface config.
    if (grep { /^(?:ACCESS_LIST|CRYPTO)/ } keys %$spoc) {
        $self->check_device_interfaces($conf, $spoc);
    }

    $self->check_spoc_interfaces($conf, $spoc, $has_mpls);
}

my %object2key_sub = (
    network => sub { my ($e) = @_; "$e->{BASE}/$e->{MASK}"; },
    tcp     => sub { my ($e) = @_; "$e->{LOW}/$e->{HIGH}"; },
    udp     => sub { my ($e) = @_; "$e->{LOW}/$e->{HIGH}"; },
    'tcp-udp' => sub { my ($e) = @_; "$e->{LOW}/$e->{HIGH}"; },
    service => sub {
        my ($e) = @_;
        my $r = $e->{TYPE};
        if ($e->{TYPE} eq 'icmp') {
            my $s = $e->{SPEC};
            for my $where (qw(TYPE CODE)) {
                my $v = $s->{$where} // '-';
                $r .= $v;
            }
        }
        elsif ($e->{TYPE} =~ /^(?:tcp|udp)/) {
            my $port = $e->{PORT};
            $r .= "$port->{LOW}:$port->{HIGH}";
        }
        $r;
    },
    protocol => sub { my ($e) = @_; $e->{TYPE} },
);

sub sort_object_group {
    my ($group) = @_;
    my $aref = $group->{OBJECT};
    my $type = $group->{TYPE};
    my $sub = $object2key_sub{$type};
    return [ map { $_->[0] }
             sort { $a->[1] cmp $b->[1] }
             map { [ $_, $sub->($_) ] }
             @$aref ];
}

# Return value: Bool
# 1: group-name is modified in ACL
# 0: group-name remains unmodified.
sub equalize_obj_group {
    my($self, $conf_group, $spoc_group) = @_;

    # Current group from netspoc is already available on device.
    # No need to transfer the group.
    # But access-list must be changed in this situation:
    # conf     spoc
    # g1-drc0  g1
    # g2-drc0  g1
    if(my $other_conf_group_name = $spoc_group->{name_on_dev}) {
        # Change has already been marked.
        if($conf_group->{name} ne $other_conf_group_name) {
            info(" ACL changes because $conf_group->{name} changes to",
                 " $other_conf_group_name (netspoc $spoc_group->{name})");
            return 1;
        }
        else {
            return 0;
        }
    }

    # Current group on device has already been marked as needed.
    # conf     spoc
    # g1-drc0  g1
    # g1-drc0  g2
    # Don't change group on device twice.
    if(my $other_spoc_group = $conf_group->{needed}) {
        $spoc_group->{transfer} = 1;
        $self->mark_as_changed('OBJECT_GROUP');
        info(" ACL changes because $conf_group->{name} is split",
             " into $spoc_group->{name} and $other_spoc_group->{name}");
        return 1;
    }

    if ($spoc_group->{transfer} && $spoc_group->{fixed}) {
        info(" ACL changes because $spoc_group->{name} has fixed transfer status");
        return 1;
    }

    if ($conf_group->{TYPE} ne $spoc_group->{TYPE}) {
        $spoc_group->{transfer} = 1;
        $self->mark_as_changed('OBJECT_GROUP');
        info(" ACL changes because $conf_group->{name} and",
             " $spoc_group->{name} have different type");
        return 1;
    }

    # Sort entries before finding diffs.
    # Order doesn't matter and
    # order is disturbed later by incremental update.
    my $conf_networks = sort_object_group($conf_group);
    my $spoc_networks = sort_object_group($spoc_group);
    my $type = $conf_group->{TYPE};
    my $address2key = $object2key_sub{$type};
    my $diff = Algorithm::Diff->new( $conf_networks, $spoc_networks,
                                     { keyGen => $address2key } );

    # Check, if identical or how many changes needed.
    my $change_lines = 0;
    while($diff->Next()) {
        if($diff->Diff()) {
            $change_lines += $diff->Items(1);
            $change_lines += $diff->Items(2);
        }
    }

    # Take group from device.
    if(not $change_lines) {
        $spoc_group->{name_on_dev} = $conf_group->{name};
        $conf_group->{needed} = $spoc_group;
        $self->mark_as_unchanged('OBJECT_GROUP');
        if($spoc_group->{transfer}) {
            info(" Canceled transfer of $spoc_group->{name},",
                 " because $conf_group->{name} was found on device");
            undef $spoc_group->{transfer};
        }
        info(" equal: $conf_group->{name} $spoc_group->{name}");
        return 0;
    }

    # Take group from netspoc.
    elsif($change_lines >= @$spoc_networks) {
        $spoc_group->{transfer} = 1;
        $self->mark_as_changed('OBJECT_GROUP');
        info(" ACL changes because $spoc_group->{name} is transferred");
        return 1;
    }

    # Change group on device.
    $spoc_group->{name_on_dev} = $conf_group->{name};
    $conf_group->{needed} = $spoc_group;
    $diff->Reset();
    while($diff->Next()) {
        next if($diff->Same());
        push(@{$spoc_group->{del_entries}}, $diff->Items(1));
        push(@{$spoc_group->{add_entries}}, $diff->Items(2));
    }
    $self->mark_as_changed('OBJECT_GROUP');
    info(" $conf_group->{name} is changed to values of $spoc_group->{name}");
    if($spoc_group->{transfer}) {
        info(" Canceled transfer of $spoc_group->{name},",
             " because $conf_group->{name} now has its values");
        undef $spoc_group->{transfer};
    }
    return 0;
}

sub check_object_group {
    my ($attr, $abstract) = @_;
    if (ref($attr) && (my $group = $attr->{GROUP})) {
        if ($abstract) {
            return('object-group');
        }
        else {
            my $name = $group->{name_on_dev}
                || ($group->{transfer} && $group->{new_name})

                # Take original name for group from device.
                || $group->{name};
            return("object-group $name");
        }
    }
    else {
        return;
    }
}

sub mark_object_group_from_acl {
    my ($self, $acl) = @_;
    for my $entry (@{ $acl->{LIST} }) {
        $self->mark_object_group_from_acl_entry($entry);
    }
}

sub mark_object_group_from_acl_entry {
    my ($self, $acl_entry) = @_;
    return if $acl_entry->{REMARK};
    for my $where (qw(TYPE SRC DST SRC_PORT DST_PORT)) {
        my $what = $acl_entry->{$where};
        if(my $group = ref($what) && $what->{GROUP}) {
            if(not $group->{name_on_dev}) {
                $group->{transfer} = 1;
                $self->mark_as_changed('OBJECT_GROUP');
            }
        }
    }
}

# Build textual representation from ACL entry for use with Algorithm::Diff.
# $abstract = 1: Ignore name of object-group.
# $ignore_log = 1: Ignore logging keywords
sub acl_entry2key0 {
    my ($e, $abstract, $ignore_log) = @_;

    if (my $string = $e->{REMARK}) {
        return "remark $string";
    }
    if ($e->{UNKNOWN}) {
        abort("Can't compare ACL with unknown attribute:\n $e->{orig}");
    }

    my @r;
    push(@r, $e->{MODE});
    for my $where (qw(SRC DST)) {
        my $what = $e->{$where};

        push(@r, $what->{ANY46}
             ? 'any'
             : check_object_group($what, $abstract)
             || "$what->{BASE}/$what->{MASK}");
    }

    push(@r, check_object_group($e->{TYPE}) || $e->{TYPE});
    if ($e->{TYPE} eq 'icmp') {
        my $s = $e->{SPEC};
        for my $where (qw(TYPE CODE)) {
            my $v = $s->{$where} // '-';
            push(@r, $v);
        }
    }
    elsif ($e->{TYPE} eq 'tcp' or $e->{TYPE} eq 'udp') {
        for my $where (qw(SRC_PORT DST_PORT)) {
            my $port = $e->{$where};
            push(@r, check_object_group($port) || "$port->{LOW}:$port->{HIGH}");
        }
        push(@r, 'established') if $e->{ESTA};
    }
    if(my $log = $e->{LOG} && ! $ignore_log) {
        push(@r, $log);
        push(@r, $e->{LOG_MODE}) if $e->{LOG_MODE};
        push(@r, $e->{LOG_LEVEL}) if $e->{LOG_LEVEL};
        push(@r, "interval $e->{LOG_INTERVAL}") if $e->{LOG_INTERVAL};
    }
    return join(' ', @r);
}

sub acl_entry_abstract2key {
    my ($e) = @_;
    acl_entry2key0($e, 1, 0);
}

sub acl_entry2key {
    my ($e) = @_;
    acl_entry2key0($e, 0, 0);
}

# Two ACL lines which differ only in 'log' attribute,
# can't both be present on a device.
# Hence we must remove one line before we can add the other one.
sub acl_entry_no_log2key {
    my ($e) = @_;
    acl_entry2key0($e, 0, 1);
}

# Set {fixed} attribute at object-group from netspoc, if
# - acl entry references object-group,
# - group is assumed to be transferred to device,
# - there are to be deleted entries,
# - there is a matching to be deleted entry.
# The name of a fixed object-group isn't changed later,
# even if a matching object-group is found, when other ACLs are compared.
# This is only a workaround.
# We should analyze all ACLs with object-groups in a first pass
# and operate with immutable group names in second pass.
sub fix_transfer_groups {
    my ($self, $entry, $dupl, $abstract) = @_;
    return if ! keys %$dupl;
    return if $entry->{REMARK};
    my @need_fix;
    for my $where (qw(SRC DST)) {
        my $what = $entry->{$where};
        if (ref($what) && (my $group = $what->{GROUP})) {
            if ($group->{transfer}) {
                push(@need_fix, $group);
            }
        }
    }
    return if ! @need_fix;

    if (! keys %$abstract) {
        %$abstract = map { acl_entry_abstract2key($_) => $_ } values %$dupl;
    }
    my $key = acl_entry_abstract2key($entry);
    return if not $abstract->{$key};
    for my $group (@need_fix) {
        $group->{fixed} = 1;
    }
}

# Return value:
# 1: ACL is unchanged
# 0: ACL needs to be changed
sub equalize_acl_groups {
    my($self, $conf_acl, $spoc_acl) = @_;
    my $conf_entries = $conf_acl->{LIST};
    my $spoc_entries = $spoc_acl->{LIST};
    my $acl_modified;
    my $diff = Algorithm::Diff->new( $conf_entries, $spoc_entries,
                                     { keyGen => \&acl_entry_abstract2key } );
    while($diff->Next()) {

        # ACL lines are equal, but object-group may change.
        if($diff->Same()) {
            my $conf_min = $diff->Min(1);
            my $count = $diff->Max(1) - $conf_min;
            my $spoc_min = $diff->Min(2);
            for my $i (0 .. $count) {
                my $conf_entry = $conf_entries->[$conf_min+$i];
                next if $conf_entry->{REMARK};
                my $spoc_entry = $spoc_entries->[$spoc_min+$i];
                for my $where (qw(TYPE SRC DST SRC_PORT DST_PORT)) {
                    my $what = $conf_entry->{$where};
                    if(my $conf_group = ref($what) && $what->{GROUP}) {
                        $what = $spoc_entry->{$where};
                        my $spoc_group = ref($what) && $what->{GROUP};
                        if($self->equalize_obj_group($conf_group, $spoc_group))
                        {
                            $acl_modified = 1;
                        }
                        else {
                            $self->mark_as_unchanged('OBJECT_GROUP');
                        }
                    }
                }
            }
        }

        # ACL lines differ.
        else {
            $acl_modified = 1;

            # Mark object-groups referenced by acl lines from spoc
            # but not on device.
            for my $spoc_entry ($diff->Items(2)) {
                $self->mark_object_group_from_acl_entry($spoc_entry);
            }
        }
    }
    return !$acl_modified;
}

sub subst_ace_name_og {
    my ($self, $ace, $name) = @_;
    my $cmd = $ace->{orig};

    # Only applicable for model ASA.
    $cmd =~ s/^access-list \S+/access-list $name/;

    for my $where ( qw( TYPE SRC DST SRC_PORT DST_PORT ) ) {
        my $what = $ace->{$where};
        if (my $group = ref($what) && $what->{GROUP}) {
            my $gid = $group->{name};
            my $new_gid = $group->{name_on_dev} ||
                ($group->{transfer} && $group->{new_name}) or
                abort("Expected group $gid already on device");

            # Add marker '!' in front of inserted names.
            # This prevents accidental renaming of an already renamed group.
            # This situation can occur if identical names are used
            # for different groups in device and in netspoc configuration.
            $cmd =~ s/group $gid(?!\S)/group !$new_gid/;
        }
    }

    # Remove marker '!' of substitution above.
    $cmd =~ s/!//g;
    $cmd;
}

sub check_max_acl_entries {
    my ($self, $acl) = @_;
    my $entries = $acl->{LIST};
    my (undef, $incr) = $self->ACL_line_discipline();
    if ($incr > 1 && @$entries >= $incr) {
        abort("Can't handle ACL $acl->{name} with $incr or more entries");
    }
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
# to minimize the time frame, where traffic is rejected.
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
# 1: ACL has not changed
# 0: ACL needs to be changed
sub equalize_acl_entries {
    my($self, $conf_acl, $spoc_acl) = @_;
    my $conf_entries = $conf_acl->{LIST};
    my $spoc_entries = $spoc_acl->{LIST};
    my $acl_name = $conf_acl->{name};

    my $diff = Algorithm::Diff->new( $conf_entries, $spoc_entries,
                                     { keyGen =>
                                           \&acl_entry2key } );

    # Hash for finding duplicates when comparing old and new entries.
    my %dupl;

    # Used in fix_transfer_groups
    my %abstract;

    # ACL lines which are moved upwards.
    # Mapping from spoc entry to conf entry.
    my %move_up;

    # ACL lines which are moved downwards.
    # Mapping from conf entry to spoc entry.
    my %move_down;

    # Entry needs not to be deleted because it was moved earlier.
    my %moved;

    # Collect entries
    # - to be added on device (includes move_up)
    # - to be deleted on device (includes move_down).
    my (@add, @delete);

    # Device line numbers of ACL entries, $entry => <nr>.
    my %device_line;

    # Conf line or spoc line at which position a spoc line will be added.
    my %add_before;

    # Relative line numbers for added lines relative to next conf line.
    # For IOS: -9999, -9998, -9997, ...
    # For ASA: 0, 0, 0, ...
    my %spoc_line_offset;

    my ($line_start, $line_incr, $add_offset, $add_incr) =
        $self->ACL_line_discipline();

    # Add line numbers to ACL entries read from device.
    for (my $i = 0; $i < @$conf_entries; $i++) {
        $device_line{$conf_entries->[$i]} = $line_start + $i * $line_incr;
    }
    $device_line{LAST} = $line_start + @$conf_entries * $line_incr;

    # 1. Process to be deleted entries.
    while($diff->Next()) {
        if ($diff->Diff() & 1) {
            for my $conf_entry ($diff->Items(1)) {
#               debug "R: $conf_entry->{orig}";
                if (!$conf_entry->{REMARK}) {
                    my $key = acl_entry_no_log2key($conf_entry);
                    $dupl{$key} and
                        internal_err "Duplicate ACL entry on device";
                    $dupl{$key} = $conf_entry;
                }
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
            my $prev_entry;
            my $offset = $add_offset;
            for my $spoc_entry ($diff->Items(2)) {
#               debug "A: $spoc_entry->{orig}";

                # Remember conf line where to add new line.
                $add_before{$spoc_entry} = $next_conf_entry;

                # Overwrite relation from previous entry to current entry,
                # if line numbers are shifted automatically.
                # ASA only.
                $add_before{$prev_entry} = $spoc_entry
                    if !$add_incr && $prev_entry;

                $prev_entry = $spoc_entry;

                $spoc_line_offset{$spoc_entry} = $offset;
                $offset += $add_incr;
#               debug " next: ",
#               $next_conf_entry eq 'LAST' ? 'LAST' : $next_conf_entry->{orig};

                # Find lines already present on device
                my $key = acl_entry_no_log2key($spoc_entry);
                if (!$spoc_entry->{REMARK} && (my $conf_entry = $dupl{$key})) {
#                   debug "D: $conf_entry->{orig}";

                    # Abort move operation, if this ACL line permits
                    # current access from Netspoc to this device.
                    if ($self->is_device_access($conf_entry)) {
                        info("Can't modify $acl_name.");
                        info("Some entry must be moved and is assumed",
                             " to allow device access:");
                        info(" $conf_entry->{orig}");

                        # New ACL is created (because modify_cmds is undef).
                        return 0;
                    }

                    # Move upwards, to lower line number.
                    if ($device_line{$next_conf_entry} <
                        $device_line{$conf_entry})
                    {
                        $move_up{$spoc_entry} = $conf_entry;
                        $moved{$conf_entry} = 1;
                        push @add, $spoc_entry;
                    }

                    # Move downwards, to higher line number.
                    #
                    # Attention:
                    # Delete operations occur in reversed order, hence the
                    # associated new entry must be added in front of
                    # some other new entry, if this has already been
                    # added before.
                    # This is handled in sub $entry2line below.
                    else {
                        $move_down{$conf_entry} = $spoc_entry;
                    }
                }

                # Add.
                else {

                    # If $spoc_entry references a group
                    # which is scheduled to be transferred to device
                    # then don't change name of group later.
                    # Otherwise we accidentally could get duplicate
                    # ACL entries because we don't recognize the
                    # original entry as duplicate.  The name would be
                    # changed if the same group is referenced from
                    # another ACL and a matching group is found on
                    # device when comparing the other ACL later.
                    $self->fix_transfer_groups($spoc_entry, \%dupl, \%abstract);

                    push @add, $spoc_entry;
                }
            }
        }
    }

    return 1 if not (@add || @delete);

    $self->check_max_acl_entries($conf_acl);
    $self->check_max_acl_entries($spoc_acl);

    # Collect commands to change ACL in place.
    my @vcmds;

    # Finds line number of next entry on device
    # for IOS: %add_before gives next entry already on device
    # for ASA: gives next spoc entry already inserted in front of device entry
    my $entry2line = sub {
        my ($entry) = @_;
#        debug "Search line for $entry->{orig}";
        my $line;
        while(my $next_entry = $add_before{$entry}) {
            if($line = $device_line{$next_entry}) {
#                debug "$line from $next_entry->{orig}" if ref($next_entry);
                last;
            }
            $entry = $next_entry;
        }
        return($line + $spoc_line_offset{$entry});
    };

    # 1. Add lines from netspoc and move lines upwards.
    for my $spoc_entry (@add) {
        my $vcmd1;
        if (my $conf_entry = $move_up{$spoc_entry}) {
            my $line = $device_line{$conf_entry};
            $vcmd1 = { ace => $conf_entry,  name => $acl_name,
                       delete => 1, line => $line};
            $self->change_acl_numbers(\%device_line, $line+1, -1);
        }
        my $vcmd2 = { ace => $spoc_entry, name => $acl_name };
        my $line = $entry2line->($spoc_entry);
        $vcmd2->{line} = $line;
        $self->change_acl_numbers(\%device_line, $line, +1);
        $device_line{$spoc_entry} = $line;
        push(@vcmds, $vcmd1 ? [ $vcmd1, $vcmd2] : $vcmd2);
    }

    # 2. Delete lines on device and move lines downwards.
    # Work from bottom to top. Otherwise
    # - we could lock out ourselves (on IOS only) or
    # - permit too much traffic for some time range.
    for my $conf_entry (reverse @delete) {
        next if $moved{$conf_entry};
        my $line = $device_line{$conf_entry};
        my $vcmd1 = { ace => $conf_entry, name => $acl_name,
                      delete => 1, line => $line};
        $self->change_acl_numbers(\%device_line, $line+1, -1);
        my $vcmd2;
        if (my $spoc_entry = $move_down{$conf_entry}) {
            $vcmd2 = { ace => $spoc_entry, name => $acl_name };
            my $line2 = $entry2line->($spoc_entry);
            $vcmd2->{line} = $line2;
            $self->change_acl_numbers(\%device_line, $line2, +1);
            $device_line{$spoc_entry} = $line2;
        }
        push(@vcmds, $vcmd2 ? [ $vcmd1, $vcmd2] : $vcmd1);
    }

    # ACL will be modified incrementally.
    $spoc_acl->{modify_cmds} = \@vcmds;
    return 0;
}

# Return value:
# 1: ACL is unchanged
# 0: ACL has changed
#   $spoc_acl->{modify_cmds} is set: change ACL incrementally
#   otherwise: ACL can't be updated; a new ACL needs to be defined and assigned.
sub equalize_acl {
    my($self, $conf_acl, $spoc_acl) = @_;
    return($self->equalize_acl_groups($conf_acl, $spoc_acl) ||
           $self->equalize_acl_entries($conf_acl, $spoc_acl));
}

# Packages must return a true value;
1;
