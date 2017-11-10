
=head1 DESCRIPTION

Base class for all supported devices

=head1 COPYRIGHT AND DISCLAIMER

https://github.com/hknutzen/Netspoc-Approve
(c) 2017 by Heinz Knutzen <heinz.knutzen@gmail.com>
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

package Netspoc::Approve::Device;

use strict;
use warnings;
use Fcntl qw/:flock/;    # import LOCK_* constants
use File::Basename;
use Netspoc::Approve::Helper;
use Netspoc::Approve::Console;
use Netspoc::Approve::Parse_Cisco;

# VERSION: inserted by DZP::OurPkgVersion

############################################################
# --- constructor ---
############################################################
sub new {
    my $class = shift;
    my $self  = {@_};
    return bless($self, $class);
}

###########################################################################
#   methods
###########################################################################

sub match {
    my ($pattern, $name) = @_;

    # Escape other regex meta characters.
    $pattern =~ s/([^*?]+)/\Q$1\E/g;

    # Substitute * and ? by real regexes
    $pattern =~ s/\*/.*/g;
    $pattern =~ s/\?/./g;

    return $name =~ /^$pattern$/;
}

# Format of aaa_credentials file
# - multiple lines
# - three fields, separated by whitespace: pattern username password
# - If current device name matches pattern, then return username and password.
# - Pattern may contain shell wildcard characters
#   * matches zero or more characters
#   ? matches one character
# - First matching line is taken.
sub get_aaa_password {
    my ($self) = @_;
    my $name = $self->{NAME};
    my $system_user = $self->{CONFIG}->{systemuser};
    $system_user and $self->{USER} eq $system_user or return $self->{USER};

    my $aaa_credential = $self->{CONFIG}->{aaa_credentials}
       or abort("Must configure AAA_CREDENTIALS together with SYSTEMUSER");
    open(my $file, '<', $aaa_credential)
       or abort("Can't open $aaa_credential: $!");
    my @lines = <$file>;
    close($file);

    # Strip leading and trailing whitespace and comments.
    for (@lines) {
        s/^\s*//;
        s/\s*$//;
        s/^[#].*//;
    }

    # Ignore empty lines.
    @lines = grep { $_ ne '' } @lines;

    for my $line (@lines) {
        my $count = (my ($pattern, $user, $pass) = split(' ', $line));
        if ($count != 3) {
            abort("Expected 3 fields in lines of $aaa_credential");
        }

        if (match($pattern, $name)) {
            info("User $user extracted from aaa credentials");
            return($user, $pass);
        }
    }
    abort("No matching AAA credential found");
}

sub get_user_password {
    my ($self, $user) = @_;
    my $pass;

    # Write directly to tty, because STDOUT may be redirected.
    open(my $tty, '>:unix', '/dev/tty') or abort("Can't open /dev/tty: $!");
    print $tty "Running in non privileged mode and no "
	. "password found in database.\n";
    print $tty "Password for $user?";
    system('stty', '-echo');
    $pass = <STDIN>;
    system('stty', 'echo');
    print $tty "  ...thank you :)\n";
    close $tty;
    chomp $pass;
    return ($pass);
}

# Read type and IP addresses from header of spoc file.
# ! [ Model = IOS ]
# ! [ IP = 10.1.13.80,10.1.14.77 ]
sub get_spoc_data {
    my ($self, $spocfile) = @_;
    my $type;
    my @ip;
    open(my $file, '<', $spocfile) or abort("Can't open $spocfile: $!");
    while (my $line = <$file>) {
        if ($line =~ /\[ Model = (\S+) ]/) {
            $type = $1;
        }
        if ($line =~ /\[ IP = (\S+) ]/) {
            @ip = split(/,/, $1);
	    last;
        }
    }
    close $file;
    return($type, @ip);
}

sub load_spocfile {
    my ($self, $path) = @_;
    my @result;

    open(my $file, '<', $path) or abort("Can't open spocfile $path: $!");
    @result = <$file>;
    close($file);

    my $count = @result;
    info("Read config file $path with $count lines");
    return \@result;
}

sub load_raw {
    my ($self, $path) = @_;
    my $raw = "$path.raw";
    my @prepend;
    if (-f $raw) {
        open(my $file, '<', $raw) or abort("Can't open $raw: $!");
        @prepend = <$file>;
        close $file;
    }

    # Find [APPEND] line.
    my $index;
    for (my $i = 0; $i < @prepend; $i++) {
        if ($prepend[$i] =~ /^\[APPEND\]\s*$/) {
            $index = $i;
            last;
        }
    }

    # Split at [APPEND] line.
    my @append;
    if (defined $index) {
        @append = splice(@prepend, $index);
        shift @append;
    }
    my $msg;

    if (my $count = @prepend) {
        $msg .= "$count prepend";
    }
    if (my $count = @append) {
        $msg and $msg .= " and ";
        $msg .= "$count append";
    }
    if ($msg) {
        info("Read rawdata file $raw with $msg lines");
    }
    return \@prepend, \@append;
}

sub load_spoc {
    my ($self, $path) = @_;
    my $lines     = $self->load_spocfile($path);
    my $conf      = $self->parse_config($lines);
    my ($prepend, $append) = $self->load_raw($path);
    my $raw_prepend  = $self->parse_config($prepend, 'strict');
    my $raw_append   = $self->parse_config($append, 'strict');
    $self->merge_rawdata($conf, $raw_prepend, $raw_append);
    return($conf);
}

sub load_device {
    my ($self) = @_;
    $self->con_set_logtype('config');
    my $device_lines = $self->get_config_from_device();
    info("Parsing device config");
    my $conf  = $self->parse_config($device_lines);
    return($conf);
}

# A command line consists of two parts: command and argument.
# A command is either a single word or a multi word command.
# A multi word command is put together from some words at fixed positions
# of the word list.
# Examples:
# - ip access-group NAME in
#   coded as "ip access-group _skip in", takes first two words and 4th word.
# - tunnel-group NAME type TYPE
#   coded as "tunnel-group _skip type"
# - isakmp ikev1-user-authentication|keepalive
#   coded as "isakmp _any", takes two words, but second is unspecified.
#   such a wildcard command may be referenced by "_cmd".
# This function identifies
# - all words, which are prefix of some command.
# Known commands are read from the hash keys of $parse_info.
sub add_prefix_info {
    my ($self, $parse_info) = @_;
    my $result = {};
    for my $key (keys %$parse_info) {
	my @split = split(' ', $key);
        my $hash = $result;
        while(@split) {
            my $word = shift(@split);
            $hash->{$word} ||= {};
            $hash = $hash->{$word};
        }
	if(my $subcmd = $parse_info->{$key}->{subcmd}) {
	    $self->add_prefix_info($subcmd);
	}
    }
    $parse_info->{_prefix} = $result if keys %$result;
}

sub parse_seq {
    my($self, $arg, $info, $result) = @_;
    my $type = $info->[0];
    my $success;
    for my $part (@{$info}[1..(@$info-1)]) {
	my $ref = ref $part;
	my $part_success;
	if(not $ref) {

	    # A method call which fills $result.
	    # Return value: true if success.
	    $part_success = $self->$part($arg, $result);
	}
	elsif($ref eq 'HASH') {
	    if(my $msg = $part->{error}) {
		err_at_line($arg, $msg);
	    }
	    my $parser = $part->{parse};
	    my $params = $part->{params};
	    my @evaled = map( { /^\$(.*)/ ? $result->{$1} : $_ }
			      $params ? @$params : ());
	    if(my $keys = $part->{store_multi}) {
		my @values;
                @values = parse_line($self, $arg, $parser, @evaled)
		    if $parser;
		for(my $i = 0; $i < @values; $i++) {
		    $result->{$keys->[$i]} = $values[$i];
		}
		$part_success = @values;
	    }
	    else {
		my $value;
		$value = parse_line($self, $arg, $parser, @evaled)
		    if $parser;
		if(not defined $value) {
		    $value = $part->{default};
		}
		if(defined $value) {
		    if(my $key = $part->{store}) {
			$result->{$key} = $value;
		    }
		    $part_success = 1;
		}
	    }
	}
	elsif($ref eq 'CODE') {
	    $part_success = $part->($arg, $result);
	}
	elsif($ref eq 'ARRAY') {
	    $part_success = parse_seq($self, $arg, $part, $result);
	}
	$success ||= $part_success;
	if($type eq 'seq') {

	    # All args must match
	}
	elsif($type eq 'or') {
	    last if $success;
	}
	elsif($type eq 'cond1') {

	    # Stop if first arg doesn't match.
	    last if not $success;
	}
	else {
            # uncoverable statement
	    internal_err "Expected 'seq|cond1|or' but got $type";
	}
    }
    return $success;
}

sub parse_line {
    my($self, $arg, $info, @params) = @_;
    my $ref = ref $info;
    if(not $ref) {

	# A method name.
	return($self->$info($arg, @params));
    }
    elsif($ref eq 'Regexp') {
	return(check_regex($info, $arg));
    }
    elsif($ref eq 'CODE') {
	return($info->($arg, @params));
    }
    elsif($ref eq 'ARRAY') {
	my $result = {};
	parse_seq($self, $arg, $info, $result);
	not keys %$result and $result = undef;
	return($result);
    }
    else {
        # uncoverable statement
	internal_err "Unexpected parse attribute: $info";
    }
}

# $config are prepared config lines.
# $parse_info describes grammar.
sub parse_config1 {
    my($self, $config, $parse_info) = @_;
    my $result = {};
    for my $arg (@$config) {
        my $cmd_info = $arg->{cmd_info};
	if(my $msg = $cmd_info->{error}) {
	    err_at_line($arg, $msg);
	}
	my $cmd;
        if (!$cmd_info->{leave_cmd_as_arg}) {
            $cmd = get_token($arg);
        }
	my $named = $cmd_info->{named};
	my $name;
	if($named and $named ne 'from_parser') {
	    $name = get_token($arg);
	}
	my $parser = $cmd_info->{parse};
        my @params = map({ $_ eq '_cmd' ? $cmd : $_ }
                         $cmd_info->{params} ? @{ $cmd_info->{params} } : ());
	my $value;
	$value = parse_line($self, $arg, $parser, @params) if $parser;
	get_eol($arg);
	if(my $subcmds = $arg->{subcmd}) {
	    my $parse_info = $cmd_info->{subcmd} or
		err_at_line($arg, 'Unexpected subcommand');
	    my $value2 = parse_config1($self, $subcmds, $parse_info);
	    if(keys %$value2) {
		if(defined $value) {
		    $value = { %$value, %$value2 };
		}
		else {
		    $value = $value2;
		}
	    }
	}
	if(not defined $value) {
	    $value = $cmd_info->{default};
	}
	if(not defined $value) {
	    next;
	}
	if($named and $named eq 'from_parser') {
	    $name = $value->{name} or err_at_line($arg, 'Missing name');
	}
	if(ref($value) eq 'HASH') {
	    $named and $value->{name} = $name;
	    $value->{orig} = $arg->{orig};
	    $value->{line} = $arg->{line};
	}
	my $store = $cmd_info->{store};
	my @extra_keys = ref $store ? @$store : $store;
	my $key;
	if($named) {
	    $key = $name;
	}
	else {
	    $key = pop @extra_keys;
	    $key = $cmd if $key eq '_cmd';
	}
	my $dest = $result;
	for my $x (@extra_keys) {
	    $x = $cmd if $x eq '_cmd';
	    $dest->{$x} ||= {};
	    $dest = $dest->{$x};
	}
	if($cmd_info->{multi}) {
	    push(@{ $dest->{$key} }, $value);
	}
	else {
	    if(my $old = $dest->{$key}) {
		if($cmd_info->{merge}) {
		    for my $key (keys %$value) {
			next if $key =~ /(?:name|line|orig)/;
			if(defined $old->{$key}) {
                            $old->{$key} eq $value->{$key} or
                                err_at_line($arg,
                                            "Duplicate '$key' while merging");
			}
                        else {
                            $old->{$key} = $value->{$key};
                        }
		    }
		}
		else {
		    err_at_line($arg,
				'Multiple occurences of command not allowed');
		}
	    }
	    else {
		$dest->{$key} = $value;
	    }
	}
    }
    return($result);
}

sub parse_config {
    my ($self, $lines, $strict) = @_;

    my $parse_info = $self->get_parse_info();
    my $config = $self->analyze_conf_lines($lines, $parse_info, $strict);
    my $result = $self->parse_config1($config, $parse_info);
    $self->postprocess_config($result);
    return $result;
}

sub merge_rawdata {
    my ($self, $spoc_conf, $raw_prepend, $raw_append) = @_;
    $self->merge_acls($spoc_conf, $raw_prepend);
    $self->merge_acls($spoc_conf, $raw_append, 'append');
    if (my @keys = grep { my $v = $raw_append->{$_};
                          ref $v eq 'HASH' && keys %$v || ref $v eq 'ARRAY' }
        keys %$raw_append)
    {
        my $keys = join(',', @keys);
        abort("Must only use ACLs in [APPEND] part, but found $keys");
    }

    for my $key (%$raw_prepend) {
	my $raw_v = $raw_prepend->{$key};

        if ($key eq 'ROUTING_VRF') {
	    my $spoc_v = $spoc_conf->{$key} ||= {};
	    for my $vrf (sort keys %$raw_v) {
		my $raw_routes = $raw_v->{$vrf};
                my $spoc_routes = $spoc_v->{$vrf} ||= [];
                unshift(@$spoc_routes, @$raw_routes);
                my $count = @$raw_routes;
                my $for = $vrf ? " for VRF $vrf" : $vrf;
                info("Prepended $count routes${for} from raw") if $count;
            }
	}

	# Hash of named entries: USERNAME, ...
	else {
	    my $spoc_v = $spoc_conf->{$key} ||= {};
	    my $count = 0;
	    for my $name (sort keys %$raw_v) {
		my $entry = $raw_v->{$name};
		if($spoc_v->{$name}) {
		    abort("Name clash for '$name' of $key from raw");
		}
		$spoc_v->{$name} = $entry;
		$count++;
	    }
	    info("Added $count entries of $key from raw") if $count;
	}
    }
}

sub route_line_a_eq_b {
    my ($self, $a, $b) = @_;
    ($a->{BASE} == $b->{BASE} && $a->{MASK} == $b->{MASK})
      or return 0;
    for my $key (qw(VRF IF NIF NEXTHOP METRIC TRACK TAG PERMANENT)) {
        if (defined($a->{$key}) || defined($b->{$key})) {
            (        defined($a->{$key})
                  && defined($b->{$key})
                  && $a->{$key} eq $b->{$key})
              or return 0;
        }
    }
    return 1;
}

sub route_line_destination_a_eq_b {
    my ($self, $a, $b) = @_;
    return($a->{BASE} == $b->{BASE} && $a->{MASK} == $b->{MASK});
}

# Unique union of all elements.
# Preserves original order.
sub unique {
    my %seen;
    return grep { !$seen{$_}++ } @_;
}

# Default: No op
sub vrf_route_mode {
    my ($self, $vrf) = @_;
}

# Process routing separately for each VRF.
# VRF is empty string for default VRF.
sub process_routing {
    my ($self, $conf, $spoc_conf) = @_;

    my $spoc_vrf = $spoc_conf->{ROUTING_VRF};
    my $conf_vrf = $conf->{ROUTING_VRF};

    my @vrfs = unique(keys %$spoc_vrf, keys %$conf_vrf);
    for my $vrf (sort @vrfs) {
        my $spoc_routing = $spoc_vrf->{$vrf};
        my $conf_routing = $conf_vrf->{$vrf} ||= [];
        if (not $spoc_routing) {
            my $for = $vrf ? " for VRF $vrf" : '';
            info("No routing specified$for - leaving routes untouched");
            next;
        }

        $self->{CHANGE}->{ROUTING} = 0;
        for my $c (@$conf_routing) {
            for my $s (@$spoc_routing) {
                if ($self->route_line_a_eq_b($c, $s)) {
                    $c->{DELETE} = $s->{DELETE} = 1;
                    last;
                }
            }
        }

        my @cmds;

        # Add routes with long mask first.
        # If we switch the default route, this ensures, that we have the
        # new routes available before deleting the old default route.
        for my $r (sort {$b->{MASK} <=> $a->{MASK}} @{ $spoc_routing })
        {
            next if $r->{DELETE};
            $self->{CHANGE}->{ROUTING} = 1;
            my $cmd = $self->route_add($r, $vrf);

            # ASA doesn't allow two routes to identical
            # destination. Remove and add routes in one transaction.
            for my $c (@$conf_routing) {
                next if $c->{DELETE};
                if($self->route_line_destination_a_eq_b($r, $c)){
                    $cmd = [ $self->route_del($c, $vrf), $cmd ];
                    $c->{DELETE} = 1; # Must not delete again.
                    last;
                }
            }
            push(@cmds, $cmd);
        }
        for my $r (@$conf_routing) {
            next if $r->{DELETE};
            $self->{CHANGE}->{ROUTING} = 1;
            push(@cmds, $self->route_del($r, $vrf));
        }
        if(@cmds) {
            info("Changing routing entries on device");
            $self->schedule_reload(5);
            $self->enter_conf_mode;
            $self->vrf_route_mode($vrf);
            for my $cmd (@cmds) {
                if (ref $cmd eq 'ARRAY') {
                    $self->two_cmd(@$cmd);
                }
                else {
                    $self->cmd($cmd);
                }
            }
            $self->leave_conf_mode;
            $self->cancel_reload();
        }
    }
}

sub issue_cmd {
    my ($self, $cmd) = @_;
    my $con = $self->{CONSOLE};
    $con->con_issue_cmd($cmd, $self->{ENAPROMPT});
    return $con->{RESULT};
}

# Send command to device or
# print to STDOUT if in compare mode.
sub cmd {
    my ($self, $cmd) = @_;

    if ( $self->{COMPARE} ) {
	print("> $cmd\n");
    }
    else {
	$self->device_cmd($cmd);
    }
}

# Send command to device, regardless of compare mode.
sub device_cmd {
    my ($self, $cmd) = @_;
    my $lines = $self->get_cmd_output($cmd);
    $self->cmd_abort_on_error($cmd, $lines);
}

sub shcmd {
    my ($self, $cmd) = @_;
    my $result = $self->issue_cmd($cmd);
    return($result->{BEFORE});
}

sub cmd_check_echo {
    my ($self, $cmd, $echo, $lines) = @_;
    if ($echo ne $cmd) {
	my $msg = "Got unexpected echo in response to '$cmd':\n'" .
	    join("\n", $echo, @$lines) ."'";
	$self->abort_cmd($msg);
    }
}

sub get_cmd_output {
    my ($self, $cmd) = @_;
    my $out = $self->shcmd($cmd);
    my $need_reload;
    $self->{RELOAD_SCHEDULED} and
	$self->handle_reload_banner(\$out) and $need_reload = 1;
    # NX-OS uses mixed line breaks: \r, \r\n, \r\r\n
    my @lines = split(/\r{0,2}\n|\r/, $out);
    my $echo = shift(@lines);
    $self->cmd_check_echo($cmd, $echo, \@lines);
    $need_reload and $self->schedule_reload(2);
    return(\@lines);
}

sub cmd_abort_on_error {
    my ($self, $cmd, $lines) = @_;
    if ($self->cmd_check_error($cmd, $lines)) {
	$self->abort_cmd("Unexpected output of '$cmd'", @$lines);
    }
}

# Send 2 commands in one data packet to device.
sub two_cmd {
    my ($self, $cmd1, $cmd2) = @_;

    if ( $self->{COMPARE} ) {
	print("> $cmd1\\N $cmd2\n");
    }
    else {
	my $con = $self->{CONSOLE};
	$con->con_send_cmd("$cmd1\n$cmd2\n");
	my $prompt = $self->{ENAPROMPT};
	my $need_reload;

	# Read first prompt and check output of first command.
	$con->con_wait($prompt);
	my $out = $con->{RESULT}->{BEFORE};
	$self->{RELOAD_SCHEDULED} and
	    $self->handle_reload_banner(\$out) and $need_reload = 1;
	my @lines1 = split(/\r{0,2}\n|\r/, $out);
	my $echo = shift(@lines1);
	$self->cmd_check_echo($cmd1, $echo, \@lines1);

	# Read second prompt and check output of second command.
	$con->con_wait($prompt);
	$out = $con->{RESULT}->{BEFORE};
	$self->{RELOAD_SCHEDULED} and
	    $self->handle_reload_banner(\$out) and $need_reload = 1;
	my @lines2 = split(/\r{0,2}\n|\r/, $out);
	$echo = shift(@lines2);
	$self->cmd_check_echo($cmd2, $echo, \@lines2);

	$self->cmd_abort_on_error("$cmd1\\N $cmd2\n", [ @lines1, @lines2 ]);
	$need_reload and $self->schedule_reload(2);
    }
}

sub abort_cmd {
    my ($self, @msg) = @_;
    $self->cancel_reload('force');
    abort(@msg);
}

# Default: No op.
sub schedule_reload {
    my ($self, $minutes) = @_;
}

# Default: No op.
sub cancel_reload {
    my ($self, $force) = @_;
}

sub checkidentity {
    my ($self) = @_;
    my $name = $self->get_identity();
    my $conf_name = $self->{NAME};

    # Strip optional prefix.
    $conf_name =~ s/^host://;

    $name eq $conf_name or
	abort("Wrong device name: $name, expected: $conf_name");
}

sub search_banner {
    my ($self, $string) = @_;
    return ($self->{PRE_LOGIN_LINES} =~ /$string/);
}

sub checkbanner {
    my ($self) = @_;
    my $check = $self->{CONFIG}->{checkbanner} or return;
    if (!$self->search_banner($check)) {
        if ($self->{COMPARE}) {
            warn_info("Missing banner at NetSPoC managed device");
        }
        else {
            abort("Missing banner at NetSPoC managed device");
        }
    }
}

sub get_version {
    my ($self) = @_;
    $self->parse_version();
    if (! defined($self->{VERSION})) {
	abort("Can't identify device version");
    }
    $self->{HARDWARE} ||= 'unknown';
    info("DINFO: $self->{HARDWARE} $self->{VERSION}");
}

sub banner_msg {
    my ($msg) = @_;
    my $time = localtime;
    my $result = <<"END";

********************************************************
  $msg: at > $time <
********************************************************
END
    return $result;
}

# Move existing logfile
sub move_logfile {
    my ($logfile) = @_;
    if (-f $logfile) {
        my $date = time();
        system("mv $logfile $logfile.$date") == 0
            or abort("Can't backup $logfile: $!");
    }
}

sub con_setup {
    my ($self) = @_;
    $self->{CONSOLE} and abort("Console already created");
    my $con = $self->{CONSOLE} = Netspoc::Approve::Console->new_console();
    $con->{TIMEOUT} = $self->{CONFIG}->{timeout};
    $con->{LOGIN_TIMEOUT} = $self->{CONFIG}->{login_timeout};
}

sub con_shutdown {
    my ($self) = @_;
    my $con = $self->{CONSOLE};
    if (!$con->{RESULT}->{ERROR}) {
        $con->{TIMEOUT} = $con->{LOGIN_TIMEOUT};
        $con->con_issue_cmd('exit', eof);
    }
    delete $self->{CONSOLE};
}

sub con_set_logtype {
    my ($self, $type) = @_;
    my $logdir = $self->{OPTS}->{L} or return;
    my $logfile = "$logdir/$self->{NAME}.$type";
    move_logfile($logfile);
    my $con = $self->{CONSOLE};
    $con->set_logfile($logfile);
}

sub connect_ssh {
    my ($self, $user) = @_;
    my($con, $ip) = @{$self}{qw(CONSOLE IP)};
    my $expect = $con->{EXPECT};
    info("Trying SSH for login");
    if (my $cmd = $ENV{SIMULATE_ROUTER}) {
        $expect->spawn("$^X $cmd")
            or abort("Cannot spawn simulation': $!");
    }
    else {
        $expect->spawn('ssh', '-l', $user, $ip)
            or abort("Cannot spawn ssh: $!");
    }
    return $con, $ip;
}

sub prepare_device {
    my ($self) = @_;
    $self->con_set_logtype('login');
    $self->login_enable();
    $self->set_terminal();
    $self->get_version();
    $self->checkidentity();
    $self->checkbanner();
}

sub mark_as_changed {
    my ( $self, $parse_name ) = @_;
    $self->{CHANGE}->{$parse_name} = 1;
}

# Create hash entry with false value, so that
# get_change_status outputs status for
# unchanged object types too.
sub mark_as_unchanged {
    my ( $self, $parse_name ) = @_;
    $self->{CHANGE}->{$parse_name} ||= 0;
}

sub print_change_status {
    my ($self) = @_;
    for my $key (sort keys %{$self->{CHANGE}}) {
	if($self->{CHANGE}->{$key}) {
	    info("comp: *** $key changed ***");
	}
	else {
	    info("comp: $key unchanged");
	}
    }
}

sub found_changes {
    my ($self) = @_;
    return(grep { $_ } values %{ $self->{CHANGE} });
}

sub compare_common  {
    my ($self, $conf1, $conf2) = @_;
    $self->transfer($conf1, $conf2);
    $self->print_change_status();
    return($self->found_changes());
}

sub compare {
    my ($self, $spoc_path) = @_;
    $self->{COMPARE} = 1;
    $self->con_setup();
    $self->prepare_device();
    my $spoc_conf = $self->load_spoc($spoc_path);
    my $device_conf = $self->load_device();
    my $result = $self->compare_common($device_conf, $spoc_conf);
    $self->con_shutdown();
    return($result);
}

sub compare_files {
    my ($self, $path1, $path2) = @_;
    $self->{COMPARE} = 1;
    my $conf1 = $self->load_spoc($path1);
    my $conf2 = $self->load_spoc($path2);
    return $self->compare_common($conf1, $conf2);
}

sub approve {
    my ($self, $spoc_path) = @_;
    $self->con_setup();
    $self->prepare_device();
    my $spoc_conf = $self->load_spoc($spoc_path);
    my $device_conf = $self->load_device();
    $self->con_set_logtype('change');
    $self->transfer($device_conf, $spoc_conf);
    if($self->found_changes()) {
        info("Saving config to flash");
        $self->write_mem();
    }
    info("Approve done");
    $self->con_shutdown();
}

sub logging {
    my $self = shift;
    my $logfile = $self->{OPTS}->{LOGFILE} or
        return;
    my $dirname = dirname($logfile);

    # Create logdir
    if ($dirname && ! -d $dirname) {
        if (mkdir($dirname, 0755)) {
	    defined(chmod(0755, $dirname))
		or abort("Can't chmod logdir $dirname: $!");
	}

	# Check -d again, because some other process may have created
	# the directory in the meantime.
	elsif (! -d $dirname) {
	    abort("Can't create $dirname: $!");
	}
    }

    move_logfile($logfile);

    open(STDOUT, '>', $logfile) or abort("Can't open $logfile: $!");
    chmod(0644, $logfile) or abort("Can't chmod $logfile: $!");

    open(STDERR, ">&STDOUT")
        or abort("STDERR redirect: Can't open $logfile: $!");
}

{

    # A closure, because we need the lock in both functions.
    my $lock_fh;

    # Set lock for exclusive approval
    sub lock {
        my ($self) = @_;
        my $name = $self->{NAME};
        my $lockfile = "$self->{CONFIG}->{lockfiledir}/$name";
        my $file_exists = -f $lockfile;
        open($lock_fh, '>', $lockfile)
          or abort("Can't aquire lock file $lockfile: $!");

        # Make newly created lock file writable for other users.
        $file_exists
          or chmod(0666, $lockfile)
          or abort("Can't chmod lockfile $lockfile: $!");
        flock($lock_fh, LOCK_EX | LOCK_NB)
          or abort($!, "Approve in progress for $name");
    }

    sub unlock {
        my ($self) = @_;
        close($lock_fh) or abort("Can't unlock lockfile: $!");
    }
}

1;
