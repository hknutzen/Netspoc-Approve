
=head1 DESCRIPTION

Remote configure Linux iptables and routing

=head1 COPYRIGHT AND DISCLAIMER

https://github.com/hknutzen/Netspoc-Approve
(c) 2017 by Heinz Knutzen <heinz.knutzen@gmail.com>

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

package Netspoc::Approve::Linux;

use strict;
use warnings;
use File::Basename;
use File::Temp qw/ tempfile /;
use base "Netspoc::Approve::Device";
use Netspoc::Approve::Helper;
use Netspoc::Approve::Parse_Cisco;

our $VERSION = '2.016'; # VERSION: inserted by DZP::OurPkgVersion

my $config = {
    user => 'root',
    device_routing_file => '/etc/network/routing',
    device_iptables_file => '/etc/network/packet-filter',
    # Avoid /tmp/, because it may have attribute 'noexec'.
    tmp_routing => '/etc/network/routing.new',
    tmp_iptables => '/etc/network/packet-filter.new',
    store_flash_cmd => '/usr/sbin/backup',
};

sub get_parse_info {
    my ($self) = @_;
    my $result =
    {

# The output of netspoc contains lines like this:
# ip route add 10.2.9.0/24 via 10.1.13.39
# Function 'parse_config' uses the data below to parse the output of netspoc.
#
# The routing information of a device is retrieved with "ip route show".
# The output looks like this:
# 10.2.9.0/24 via 10.1.13.39 dev eth0
# The prefix "ip route add" is added before the string is parsed.
        'ip route add' => {
            store => 'ROUTING',
            multi => 1,
            parse => ['seq',
                      { parse => qr/unicast|local|broadcast|multicast|throw|unreachable|prohibit|blackhole|nat/,
                        store => 'TYPE', default => 'unicast' },
                      { parse => \&get_ip_prefix,
                        store_multi => ['BASE', 'MASK'] },
                      ['cond1',
                       { parse => qr/via/ },
                       { parse => \&get_ip, store => 'NEXTHOP' } ],
                      ['cond1',
                       { parse => qr/dev/ },
                       { parse => \&get_token, store => 'NIF' } ],
                      ['cond1',
                       { parse => qr/tos/ },
                       { parse => \&get_token, store => 'TOS' } ],
                      ['cond1',
                       { parse => qr/table/ },
                       { parse => \&get_token, store => 'TABLE' } ],
                      ['cond1',
                       { parse => qr/proto/ },
                       { parse => \&get_token, store => 'PROTO' } ],
                      ['cond1',
                       { parse => qr/scope/ },
                       { parse => \&get_token, store => 'SCOPE' } ],
                      ['cond1',
                       { parse => qr/metric/ },
                       { parse => \&get_token, store => 'METRIC' } ],
                      ['cond1',
                       { parse => qr/mpath/ },
                       { parse => \&get_token, store => 'MPATH' } ],
                      ['cond1',
                       { parse => qr/weight/ },
                       { parse => \&get_ip, store => 'WEIGHT' } ],
                      {parse => qr/onlink|pervasive/, store => 'NHFLAGS' },
                      {parse => qr/equalize/, store => 'FLAGS' },
                      ['cond1',
                       { parse => qr/mtu/ },
                       { parse => \&get_ip, store => 'MTU' } ],
                      ['cond1',
                       { parse => qr/src/ },
                       { parse => \&get_ip, store => 'SRC' } ]]},

        # # Comment
        # *filter
        # :INPUT ACCEPT [68024:74200042]
        # :FORWARD ACCEPT [0:0]
        # :OUTPUT ACCEPT [54724:5982979]
        # -A INPUT -s 10.1.2.3 -j ACCEPT
        # COMMIT
        # # Comment
        '*' => {
            store => 'IPTABLES',
            named => 1,
            subcmd => {
                ':' => {
                    store => 'POLICY',
                    named => 1,
                    parse => 'parse_policy',
                },
                '-A' => {
                    multi => 1,
                    store => 'RULES',
                    named => 1,
                    parse => 'parse_rule',
                },
                'COMMIT' => {},

                # Only used in code from netspoc.
                'EOF' => {},
            },
        },
    };
    $result;
};

# Read lines from linux device.
# Build an array where each command line is described by a hash
# - arg: an array of tokens
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
    my $config = [];
    my $counter = 0;

    for my $line (@$lines) {
        $counter++;

        # Ignore comment lines.
        next if $line =~ /^\s*#/;

        # Ignore empty lines.
        next if $line =~ /^\s*$/;

        my @args = split(' ', $line);

        # Remember a version of unparsed line without duplicate whitespace.
        my $orig = join(' ', @args);

        # Substitute "*name" by "*" "name" and ":name" by ":" "name".
        if($args[0] =~ /^([*:])(.*)$/) {
            splice(@args, 0, 1, $1, $2);
        }
        my $cmd = shift(@args);
        if(my $prefix_info = $parse_info->{_prefix}) {
            my $prefix = $cmd;
            while($prefix_info = $prefix_info->{$prefix} and
                  keys %$prefix_info)
            {
                $prefix = shift(@args);
                $cmd .= ' ' . $prefix;
            }
        }

        # Remember current line number, set parse position.
        # Remember the original line.
        my $new_cmd = { line => $counter,
                        pos  => 0,
                        orig => $orig,
                        args => [ $cmd, @args ], };

        # Unknown command terminates current subcommand level.
        while(not $parse_info->{$cmd} and @stack) {
            ($config, $parse_info) = @{ pop @stack };
        }

        # Store only known commands.
        if(my $cmd_info = $parse_info->{$cmd}) {
            $new_cmd->{cmd_info} = $cmd_info;
            push(@$config, $new_cmd);
            if(my $subcmd = $parse_info->{$cmd}->{subcmd}) {
                push @stack, [ $config, $parse_info ];
                $config = [];
                $new_cmd->{subcmd} = $config;
                $parse_info = $subcmd;
            }
        }

        # Terminate on unknown command.
        else {
            err_at_line($new_cmd, "Unknown command");
        }
    }
    while(@stack) {
        ($config, $parse_info) = @{ pop @stack };
    }
    return($config);
}

# Called by parse_config

# :INPUT ACCEPT [68024:74200042]
# :e0_in - [0:0]
sub parse_policy {
    my($self, $arg) = @_;
    my $policy = get_token($arg);

    # Ignore optional counters.
    check_token($arg);

    # Ignore value of user defined chain.
    return($policy eq '-') ? undef : $policy;
}

# -A INPUT -s 10.1.2.3 -p tcp ! --syn -j ACCEPT
sub parse_rule {
    my($self, $arg) = @_;

    # Store rule as hash.
    # Allow zero, one or more arguments after key.
    # '!' can occur before or after the key,
    # but only after key, if at least one argument.
    my $rule = {};
    my $negate_next_cmd = '';
    while(my $key = check_token($arg)) {
        my $negate = $negate_next_cmd;
        $negate_next_cmd = '';
        if($key eq '!') {
            $negate ||= $key;
            $key = get_token($arg);
        }
        my @args;
        my $negate_arg = check_regex(qr/!/, $arg) || '';
        while(defined (my $value = check_regex(qr/[^!-].*/, $arg))) {
            push @args, $value;
        }
        if(not @args) {
            $negate_next_cmd = $negate_arg;
        }
        else {
            $negate ||= $negate_arg;
        }
        my $v = $negate . join(' ', @args);

        # Hard code special case:
        # ! --tcp-flags FIN,SYN,RST,ACK SYN ==> ! --syn
        if($key eq '--tcp-flags' and $v = '!FIN,SYN,RST,ACK SYN') {
            $key = '--syn';
            $v = '!';
        }
        $rule->{$key} = $v;
    }
    $negate_next_cmd and err_at_line($arg, "Unexpected trailing '!'");
    return $rule;
}

# Convert parse tree into a simpler format.
# Pre:
# IPTABLES->{$table}->{RULES|POLICY}->{$chain}
# Post:
# IPTABLES->{$table}->{$chain}->{RULES|POLICY}
sub postprocess_iptables {
    my ($self, $p) = @_;

    my $tables = $p->{IPTABLES};

    # Convert to simpler format.
    for my $table (values %$tables) {
        my $new;
        my $policies = $table->{POLICY};
        my $chains = $table->{RULES};
        for my $name (keys %$chains) {
            my $entry = { name => $name, RULES => $chains->{$name}};
            $entry->{POLICY} = $policies->{$name} if $policies->{$name};
            $new->{$name} = $entry;
        };
        for my $name (keys %$policies) {
            next if $new->{$name};
            $new->{$name} = { name => $name,
                              RULES => [],
                              POLICY => $policies->{$name} };
        }
        $table = $new;
    }
}

my %normalize = (

    '-s' => sub {
        my($v) = @_;
        $v =~ s(/32$)();
        return $v;
    },

    # Lowercase protocol names.
    # Use numbers for some protocol names.
    '-p' => sub {
        my($v) = @_;
        $v = lc $v;
        $v =~ s/^vrrp$/112/;
        $v =~ s/^ipv6-icmp$/58/;
        return $v;
    },

    '--dport' => sub {
        my($v) = @_;
        $v =~ s/^0:/:/;
        $v =~ s/:65535$/:/;
        return $v;
    },

    # RELATED,ESTABLISHED -> ESTABLISHED,RELATED
    '--state' => sub {
        my($v) = @_;
        $v = join(',', sort(split(/,/, $v)));
        return $v;
    },
    '--set-mark' => sub {
        my($v) = @_;

        # Ignore default mask.
        $v =~ s(/0xffffffff$)()i;

        # Convert from hex to decimal.
        $v =~ s/^0x[0-9a-f]+/hex($v)/ie;

        return $v;
    },
    '--log-level' => sub {
        my($v) = @_;
        $v =~ s/^debug$/7/;
        return $v;
    },
);
$normalize{'-d'} = $normalize{'-s'};

# Normalize values of iptables rules.
sub normalize {
    my($p) = @_;
    my $tables = $p->{IPTABLES};
    for my $table (values %$tables) {
        for my $chain (values %$table) {
            for my $rule (@{ $chain->{RULES} }) {

                # Ignore match option for standard protocols.
                if(my $v = $rule->{'-m'}) {
                    my $proto = $rule->{'-p'} || '';
                    if(lc($v) eq lc($proto)) {
                        delete $rule->{'-m'};
                    }
                }

                # --set-xmark is equivalent to --set-mark
                # for default mask /0xffffffff
                if(my $v = $rule->{'--set-xmark'}) {
                    if($v !~ m'/' || $v =~ m'/0xffffffff$'i) {
                        delete $rule->{'--set-xmark'};
                        $rule->{'--set-mark'} = $v;
                    }
                }

                for my $key (keys %$rule) {
                    next if $key !~ /^-/;
                    my $v = $rule->{$key};
                    my $fun = $normalize{$key} or next;
                    $v = $fun->($v);
                    $rule->{$key} = $v;
                }
            }
        }
    }
}

##############################################################################
# Purpose    : Adds acls from another config hash to the netspoc ipv4 config
#              hash. Unless $mode equals 'prepend', new acls are added at
#              the beginning of acl array.
# Parameters : $spoc - ipv4 netspoc config in $result - hash format.
#              $add_conf - raw or ipv6 config in $result - hash format.
#              $mode - 'append', 'prepend', 'ipv6', indicates operational mode.
sub get_merge_worker {
    my ($self) = @_;
    my $merge_iptables = sub {
        my ($self, $spoc_conf, $add_conf, $mode) = @_;
        my $spoc_tables = $spoc_conf->{IPTABLES};
        my $add_tables = $add_conf->{IPTABLES};
        for my $table_name (keys %$add_tables) {
            my $spoc_chains = $spoc_tables->{$table_name};
            my $add_chains = $add_tables->{$table_name};
            if(not $spoc_chains) {
                info("Adding all chains of table '$table_name'");
                $spoc_tables->{$table_name} = $add_chains;
                next;
            }
            for my $add_chain (values %$add_chains) {
                my $chain_name = $add_chain->{name};
                my $spoc_chain = $spoc_chains->{$chain_name};
                if(not $spoc_chain) {
                    info("Adding chain '$chain_name' of table '$table_name'");
                    $spoc_chains->{$chain_name} = $add_chain;
                    next;
                }
                if(not $spoc_chain->{POLICY}) {
                    abort("Must not redefine chain '$chain_name' from rawdata");
                }

                # Prepend/append.
                my $msg;
                my $spoc_entries = $spoc_chain->{RULES} ||= [];
                my $add_entries = $add_chain->{RULES};
                if ($mode eq 'append') {
                    $msg = 'Appending';

                    # Find last non deny line.
                    my $index = @$spoc_entries;
                    while ($index > 0) {
                        if ($spoc_entries->[$index-1]->{-j} =~ /^drop/i) {
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
                info("$msg to chain '$chain_name' of table '$table_name'");
            }
        }
    };
    return { IPTABLES => $merge_iptables };
}

sub postprocess_routes {
    my ($self, $config) = @_;
    return if ! $config->{ROUTING};

    # Ignore entries with 'scope link'.
    # Ignore entries with 'proto xxx' except 'proto static'.
    # Ignore attribute 'dev', if 'via' is provided.
    my @routes;
    for my $entry (@{ delete $config->{ROUTING} }) {
        next if $entry->{SCOPE} && $entry->{SCOPE} eq 'link';
        next if $entry->{PROTO} && $entry->{PROTO} ne 'static';
        if($entry->{NEXTHOP}) {
            delete $entry->{NIF};
        }
        push(@routes, $entry);
    }
    $config->{ROUTING_VRF}->{''} = \@routes;
}

sub postprocess_config {
    my ($self, $config) = @_;
    $self->postprocess_routes($config);
    $self->postprocess_iptables($config);
    normalize($config);
}

sub value_differ {
    my ($conf, $spoc) = @_;
    if (my $type = ref $conf || ref $spoc) {
        if ($type eq 'HASH') {
            return hash_differ($conf, $spoc);
        }
        else {
            return array_differ($conf, $spoc);
        }
    }
    else {
        $conf ||= '';
        $spoc ||= '';
        if ($conf eq $spoc) {
            return;
        }
        else {
            return "[$conf<->$spoc]";
        }
    }
}

sub hash_differ {
    my ($conf, $spoc) = @_;
    my $c_extra = join(',', grep { not exists $spoc->{$_} } sort keys %$conf);
    my $s_extra = join(',', grep { not exists $conf->{$_} } sort keys %$spoc);
    if ($c_extra || $s_extra) {
        return "[keys: $c_extra<->$s_extra]";
    }
    for my $key (sort keys %$conf) {
        next if $key =~ /(?:name|line|orig)/;
        if (my $diff = value_differ($conf->{$key}, $spoc->{$key})) {
            return "$key:$diff";
        }
    }
    return;
}

sub array_differ {
    my ($conf, $spoc) = @_;
    if(@$conf != @$spoc) {
        my $c_size = @$conf;
        my $s_size = @$spoc;
        return "[size: $c_size<->$s_size]";
    }
    for (my $i = 0; $i < @$conf; $i++) {
        if (my $diff = value_differ($conf->[$i], $spoc->[$i])) {
            return "$i:$diff";
        }
    }
    return;
}

# Compare iptables config recursively.
sub compare_iptables {
    my ($self, $conf, $spoc) = @_;
    $self->{CHANGE}->{ACL} = 0;
    my $diff = value_differ($conf->{IPTABLES}, $spoc->{IPTABLES}) or return;
    $self->{CHANGE}->{ACL} = 1;
    my $msg = "iptables differs at $diff";

    # Show complete config if anything changed.
    if ($self->{COMPARE}) {

        # Print info to STDOUT for simpler testing,
        # because info messages are suppressed during testing.
        print("$msg\n");
        my $lines = $self->get_iptables_config($spoc);
        $self->cmd($_) for @$lines;
    }
    else {
        info($msg);
    }
}

sub status_ok {
    my($self) = @_;
    my $status = $self->get_cmd_output('echo $?');
    return(@$status == 1 and $status->[0] eq '0');
}

sub cmd_ok {
    my ($self, $cmd) = @_;

    # Ignore Output; only check echo and exit status.
    $self->get_cmd_output($cmd);
    return($self->status_ok);
}

my %valid_cmd_output = (
    $config->{store_flash_cmd} => q#tar: Removing leading `/' from member names#,
);

sub cmd_check_error {
    my ($self, $cmd, $lines) = @_;
    if(@$lines) {
        my $valid = $valid_cmd_output{$cmd};
        if(not(@$lines == 1 and $valid and $lines->[0] eq $valid)) {
            chomp $cmd;
            abort("Unexpected output of '$cmd'", @$lines);
        }
    }
    if(not $self->status_ok) {
        abort("$cmd failed (exit status)");
    }
}

# NoOp.
sub enter_conf_mode {
    my($self) = @_;
}

# NoOp.
sub leave_conf_mode {
    my($self) = @_;
}

# Entry from netspoc is complete  command.
sub route_add {
    my($self, $entry) = @_;
    return($entry->{orig});
}

sub route_del {
    my($self, $entry) = @_;
    my $orig = $entry->{orig};
    $orig =~ s/^ip route add//;
    return("ip route del$orig");
}

sub do_scp {
    my ($self, $mode, $src, $dst) = @_;
    return if $ENV{SIMULATE_ROUTER};
    my $ip = $self->{IP};
    my $user = $config->{user};
    my @args =
               ($mode eq 'put')
             ? ($src, "$user\@$ip:$dst")
             : ($mode eq 'get')
             ? ("$user\@$ip:$src", $dst)
             :  abort("undefined mode $mode for secure copy");
    unshift @args, 'scp', '-q';
    info(join(' ', 'Executing:', @args));
    system(@args) == 0
        or abort("system(". join(' ', @args) .") failed: $?");
}

sub write_startup_routing {
    my ($self, $spoc, $file) = @_;
    local $\ = "\n";

    # Create and open temporary file.
    # File is automatically removed when the program exits.
    my ($fh, $tmpname) = tempfile(UNLINK => 1) or abort("Can't create tempfile: $!");
    print $fh '#!/bin/sh';
    print $fh '# Generated by NetSPoC';
    for my $entry (@{ $spoc->{ROUTING_VRF}->{''} }) {
        my $cmd = $self->route_add($entry);
        chomp $cmd;
        print $fh $cmd;
    }
    close $fh or abort("Can't close $tmpname: $!");
    $self->do_scp('put', $tmpname, $file);
}

sub find_iptables_restore_cmd {
    my ($self) = @_;
    if ( $self->{COMPARE} ) {
        return "/sbin/iptables-restore";
    }
    my $path = ($self->get_cmd_output('which iptables-restore'))->[0] or
        abort("Can't find path of 'iptables-restore'");
    return $path;
}

sub get_iptables_config {
    my ($self, $spoc) = @_;
    my $path = $self->find_iptables_restore_cmd();
    my @result;
    push @result, "#!$path";
    push @result, '# Generated by NetSPoC';
    my $iptables = $spoc->{IPTABLES};
    for my $tname (sort keys %$iptables) {
        my $chains = $iptables->{$tname};
        push @result, "*$tname";
        for my $cname (sort keys %$chains) {
            my $chain = $chains->{$cname};
            my $policy = $chain->{POLICY} || '-';
            push @result, ":$cname $policy";
        }
        for my $cname (sort keys %$chains) {
            my $chain = $chains->{$cname};
            for my $rule (@{$chain->{RULES}}) {
                my $line = $rule->{orig};
                chomp $line;
                push @result, $line;
            }
        }
        push @result, 'COMMIT';
    }
    return \@result;
}

sub write_startup_iptables {
    my ($self, $spoc, $file) = @_;
    my $lines = $self->get_iptables_config($spoc);
    my ($fh, $tmpname) = tempfile(UNLINK => 1) or
        abort("Can't create tempfile: $!");
    local $\ = "\n";
    print $fh $_ for @$lines;
    close $fh or abort("Can't close $tmpname: $!");
    $self->do_scp('put', $tmpname, $file);
}

sub transfer {
    my ($self, $conf, $spoc_conf) = @_;

    # Change running configuration of device.
    $self->process_routing($conf, $spoc_conf);

    # This only compares.
    $self->compare_iptables($conf, $spoc_conf);

    return if $self->{COMPARE};

    # Copy startup routing config to temporary file on device.
    if ($self->{CHANGE}->{ROUTING}) {
        my $tmp_routing = $config->{tmp_routing};
        $self->write_startup_routing($spoc_conf, $tmp_routing);
    }

    # Copy startup iptables config to temporary file on device.
    # Change iptables configuration of device.
    if ($self->{CHANGE}->{ACL}) {
        my $tmp_iptables = $config->{tmp_iptables};
        $self->write_startup_iptables($spoc_conf, $tmp_iptables);
        $self->cmd("chmod a+x $tmp_iptables");
        info("Changing iptables running config");
        $self->cmd($tmp_iptables);
    }
}

sub write_mem {
    my ($self) = @_;

    # Change routing startup configuration of device.
    my $tmp_routing = $config->{tmp_routing};
    my $startup_routing = $config->{device_routing_file};
    if ($self->{CHANGE}->{ROUTING}) {

        # Running config has already been changed differentially.
        info("Writing routing startup config");
        $self->cmd("mv -f $tmp_routing $startup_routing");
    }

    # Change iptables startup configuration of device.
    my $tmp_iptables = $config->{tmp_iptables};
    my $startup_iptables = $config->{device_iptables_file};
    if ($self->{CHANGE}->{ACL}) {
        info("Writing iptables startup config");
        $self->cmd("mv -f $tmp_iptables $startup_iptables");
    }

    # Write configuration to flash if platform has this cmd.
    if((my $cmd = $config->{store_flash_cmd}) &&
       $self->cmd_ok('ls /etc/router-version'))
    {
        info("Saving config to flash");
        $self->cmd($cmd);
    }
}

sub get_config_from_device {
    my ($self) = @_;

    my $route_lines = $self->get_cmd_output('ip route show');
    my $iptables_lines = $self->get_cmd_output('iptables-save');
    return [ map({ "ip route add $_" } @$route_lines), @$iptables_lines ];
}

sub get_identity {
    my ($self) = @_;
    return ($self->get_cmd_output('hostname -s'))->[0];
}

sub parse_version {
    my ($self) = @_;
    $self->{VERSION} = ($self->get_cmd_output('uname -r'))->[0];
    $self->{HARDWARE} = ($self->get_cmd_output('uname -m'))->[0];
}

sub set_terminal {
    my ($self) = @_;
}

sub search_banner {
    my ($self, $string) = @_;
    return $self->get_cmd_output("grep '$string' /etc/issue");
}

sub login_enable {
    my ($self) = @_;
    my $std_prompt = qr/\r\n\S*\s?[\%\>\$\#]\s?(?:\e\S*)?$/;
    my ($con, $ip) = $self->connect_ssh($config->{user});
    my $prompt = qr/$std_prompt|password:|\(yes\/no\)\?/i;
    my $result = $con->con_short_wait($prompt);
    if ($result->{MATCH} =~ qr/\(yes\/no\)\?/i) {
        $prompt = qr/$std_prompt|password:/i;
        $result = $con->con_issue_cmd('yes', $prompt);
        info("SSH key for $ip permanently added to known hosts");
    }

    # Password prompt comes only if no ssh keys are in use.
    if($result->{MATCH} =~ qr/password:/i) {
        my $pass = $self->get_user_password('device');
        $prompt = qr/$std_prompt|password:/i;
        $result = $con->con_issue_cmd($pass, $prompt);
        if ($result->{MATCH} !~ $std_prompt) {
            abort("Authentication failed");
        }
    }
    $self->{ENAPROMPT} = $std_prompt;

    # Force prompt to simple, known value.
    # Don't use '#', because it is used as comment character
    # in output of iptables-save.
    # This is a workaround for bug #100342 in Expect.pm.
    my $new_prompt = 'router#';
    $self->device_cmd("PS1=$new_prompt");
    $self->{ENAPROMPT} = qr/\r\n \Q$new_prompt\E $/x;
}

# Packages must return a true value;
1;
