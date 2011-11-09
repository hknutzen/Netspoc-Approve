
package Netspoc::Approve::Cisco;

# Authors: Arne Spetzler, Heinz Knutzen, Daniel Brunkhorst
#
# Description:
# Module to remote configure cisco devices.


'$Id$' =~ / (.+),v (.+?) /;

my $id = "$1 $2";

sub version_drc2_cisco() {
    return $id;
}

use base "Netspoc::Approve::Device";
use strict;
use warnings;
use IO::Socket ();
use Netspoc::Approve::Helper;
use Netspoc::Approve::Parse_Cisco;
    
# Read indented lines of commands from Cisco device.
# Build an array where each command line is described by a hash
# - arg: an array of tokens split by whitespace
#      first element, the command name, consists of multiple tokens,
#      if prefix tokens are used.
# - subcmd: sub-commands related to current command
# 
# $config->[{args => [$cmd, @args], subcmd => [{args => [$cmd @args]}, ...]},
#           {args => [$cmd, @args], subcmd => [...]}
#        ..]
#           
sub analyze_conf_lines {
    my ($self, $lines, $parse_info) = @_;
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
	next if $line =~ /^ *$/;

	# Get number of leading spaces.
	my ($indent, $rest) = $line =~ /^( *)(.*)$/;
	my $sub_level = length($indent);

	if($sub_level == $level) {

	    # Got expected command or sub-command.
	}
	elsif($sub_level > $level) {

	    # Some older IOS versions use sub commands, 
	    # which have a higher indentation level than 1.
	    # This is only applicable for the first sub command.
	    if($first_subcmd) {

		# For unknown commands allow first command(s) to be 
		# indented deeper and following commands to be indented
		# only by one.		
		if (not $parse_info or not keys %$parse_info) {
		    push @stack, [ $config, $parse_info, $level ];
		    $config = undef;
		    $parse_info = undef;
		}
		$level = $sub_level;
	    }
	    else {
		die "Expected indentation '$level' but got '$sub_level'",
		" at line $counter:\n",
		">>$line<<\n";
	    }
	}
	else {
	    while($sub_level < $level && @stack) {
		($config, $parse_info, $level) = @{ pop @stack };
	    }
	    
	    # All sub commands need to use the same indentation level.
	    if ($sub_level != $level) {
		if ( ( ($level+1) == $sub_level ) && $rest eq 'quit' ) {
		    # Skip certificate data.
		}
		else {
		    die "Expected indentation '$level' but got '$sub_level'",
		    " at line $counter:\n",
		    ">>$line<<\n";
		}
	    }
	}
	$first_subcmd = 0;
	my @args;
	(my $cmd, @args) = split(' ', $rest);

	# Strip words from @args which belong to current command.
	# - add found words to $cmd 
	# - same for $lookup, but 
	#   - use wildcard pattern "_any" instead of matched word,
	#   - use "_skip" for skipped word, but no trailing "_skip".
	my $lookup = $cmd;
	if(my $prefix_info = $parse_info->{_prefix}) {
	    if ($prefix_info = $prefix_info->{$cmd}) {
		my $skip = 0;
		my @a = @args;
		my @c = ($cmd);
		my @l = ($lookup);
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
	}
	if (my $cmd_info = ($parse_info->{$lookup} || $parse_info->{_any})) {

	    # Remember current line number, set parse position.
	    # Remember a version of the unparsed line without duplicate 
	    # whitespace.
	    my $new_cmd = { line => $counter, 
			    pos => 0, 
			    orig => join(' ', $cmd, @args),
			    args => [ $cmd, @args ], 
			    cmd_info => $cmd_info,
			};
	    push(@$config, $new_cmd);
	    if (my $subcmd = $cmd_info->{subcmd}) {
		push @stack, [ $config, $parse_info, $level ];
		$level++;
		$parse_info = $subcmd;
		$config = [];
		$new_cmd->{subcmd} = $config;
		$first_subcmd = 1;
	    }
	    elsif ($end_banner_regex = $cmd_info->{banner}) {
		$new_cmd->{lines} = [];
		$in_banner = $new_cmd;
	    }
		
	}

	# Ignore unknown command.
	# Prepare to ignore subcommands as well.
	else {
	    push @stack, [ $config, $parse_info, $level ];
	    $config = undef;
	    $parse_info = undef;
	    $level++;
	    $first_subcmd = 1;
	}
    }
    while($level--) {
	($config, $parse_info, $level) = @{ pop @stack };
    }
    return $config;
}  

# ip mask
# host ip
# any
sub parse_address {
    my ($self, $arg) = @_;
    my ($ip, $mask);
    my $token = get_token($arg);
    if ($token eq 'any') {
        $ip = $mask = 0;
    }
    elsif ($token eq 'host') {
        $ip   = get_ip($arg);
        $mask = 0xffffffff;
    }
    else {
        $ip   = quad2int($token);
        $mask = $self->dev_cor(get_ip($arg));
    }
    return ({ BASE => $ip, MASK => $mask });
}

sub parse_port {
    my ($self, $arg, $proto) = @_;
    my $port = get_token($arg);
    if ($proto eq 'tcp') {
        $port = $PORT_Trans_TCP{$port} || $port;
    }
    else {
        $port = $PORT_Trans_UDP{$port} || $port;
    }
    $port =~ /^\d+$/ or err_at_line($arg, 'Expected port number');
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
        errpr "port specifier 'neq' not implemented\n";
    }
    elsif ($spec eq 'range') {
        $low = $port;
        $high = $self->parse_port($arg, $proto);
    }
    else {
        internal_err();
    }
    return ({ LOW => $low, HIGH => $high });
}

my $icmp_regex = join('|', '\d+', keys %ICMP_Trans);

# <message-name> | (/d+/ [/d+])
# ->{TYPE} / ->{CODE} (if defined)
sub parse_icmp_spec {
    my ($self, $arg) = @_;
    my ($type, $code);
    my $token = check_regex($icmp_regex, $arg);
    return({}) if not defined $token;
    if (my $spec = $ICMP_Trans{$token}) {
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
    $proto = $IP_Trans{$proto} || $proto;
    $proto =~ /^\d+$/ 
	or $self->err_at_line($arg, "Expected numeric proto '$proto'");
    $proto =~ /^(1|6|17)$/
	and $self->err_at_line($arg, "Don't use numeric proto for", 
			       " icmp|tcp|udp: '$proto'");
    return($proto);
}

# Rawdata processing
sub merge_acls {
    my ( $self, $spoc, $raw ) = @_;

    for my $intf_name ( keys %{ $raw->{IF} } ) {
	mypr " interface: $intf_name \n";
	my $raw_intf = $raw->{IF}->{$intf_name};
	my $spoc_intf = $spoc->{IF}->{$intf_name};

	if ( ! $spoc_intf ) {
	    warnpr "Interface $intf_name referenced in raw does " .
		"not exist in Netspoc.\n";
	    $spoc_intf = $spoc->{IF}->{$intf_name} = { name => $intf_name };
	}

	# Merge acls for possibly existing access-group of this interface.
	for my $direction ( qw( IN OUT ) ) {
	    my $access_group = "ACCESS_GROUP_$direction";
	    if ( my $raw_name = $raw_intf->{$access_group} ) {
		my $raw_acl = $raw->{ACCESS_LIST}->{$raw_name};

		if(my $spoc_name = $spoc_intf->{$access_group}) {

		    # Prepend raw acl.
		    my $raw_entries = $raw_acl->{LIST};
		    unshift(@{$spoc->{ACCESS_LIST}->{$spoc_name}->{LIST}}, 
			    @$raw_entries);
		    my $count = @$raw_entries;
		    mypr "  Prepended $count entries to $access_group.\n";
		}
		else {

		    # Copy raw acl.
		    $spoc->{ACCESS_LIST}->{$raw_name} and
			errpr "Name clash for '$raw_name' of ACCESS_LIST" .
			" from raw\n";
		    $spoc->{ACCESS_LIST}->{$raw_name} = $raw_acl;
		    $spoc_intf->{$access_group} = $raw_name;
		}
		$raw_acl->{merged} = 1;
	    }
	}
	$raw_intf->{merged} = 1;
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

sub route_add {
    my($self, $entry) = @_;
    return($entry->{orig});
}

sub route_del {
    my($self, $entry) = @_;
    return("no $entry->{orig}");
}

sub prepare {
    my ($self) = @_;
    $self->login_enable();
    mypr "logged in\n";

    # Force new prompt by issuing empty command.
    # Read hostname from prompt.
    $self->{ENAPROMPT} = qr/\r\n.*\#\s?$/;
    my $result = $self->issue_cmd('');
    $result->{MATCH} =~ m/^(\r\n\s?\S+)\#\s?$/;
    my $prompt_prefix = $1;
    $prompt_prefix =~ /\s*(.*)$/;
    my $name = $1;
    $self->checkidentity($name);

    # Set prompt again because of performance impact of standard prompt.
    $self->{ENAPROMPT} = qr/$prompt_prefix\S*\#\s?/;
}

sub login_enable {
    my ($self) = @_;
    my $std_prompt = qr/[\>\#]/;
    my($con, $ip, $user, $pass) = @{$self}{qw(CONSOLE IP LOCAL_USER PASS)};

    if(not $pass) {
	($user, $pass) = $self->get_aaa_password();
    }
    if ($user) {
        my $server = IO::Socket::INET->new(
            'PeerAddr' => $ip,
            'PeerPort' => 22
        );
        if ($server) {
            $server->close();
            mypr "Using SSH with username for login\n";
            $con->{EXPECT}->spawn("ssh", "-l", "$user", "$ip")
              or errpr "Cannot spawn ssh: $!\n";
            my $prompt = qr/password:|\(yes\/no\)\?/i;
            $con->con_wait($prompt) or $con->con_error();
            if ($con->{RESULT}->{MATCH} =~ qr/\(yes\/no\)\?/i) {
		$prompt = qr/password:/i;
                $con->con_issue_cmd("yes\n", $prompt) or $con->con_error();
                warnpr "SSH key for $ip permanently added to known hosts\n";
            }
	    $pass ||= $self->get_user_password($user);
	    $prompt = qr/password:|$std_prompt/i;
            $con->con_issue_cmd("$pass\n", $prompt) or $con->con_error();
            $self->{PRE_LOGIN_LINES} = $con->{RESULT}->{BEFORE};
        }
        else {
            mypr "Using telnet with username for login\n";
            $con->{EXPECT}->spawn("telnet", ($ip))
              or errpr "Cannot spawn telnet: $!\n";
            my $prompt = qr/username:/i;
            $con->con_wait($prompt) or $con->con_error();
            $self->{PRE_LOGIN_LINES} = $con->{RESULT}->{BEFORE};
	    $prompt = qr/password:/i;
            $con->con_issue_cmd("$user\n", $prompt) or $con->con_error();
	    $pass ||= $self->get_user_password($user);
	    $prompt = qr/username:|password:|$std_prompt/i;
            $con->con_issue_cmd("$pass\n", $prompt) or $con->con_error();
        }
    }
    else {
        mypr "Using simple telnet for login\n";
        $pass = $self->{PASS};
        $con->{EXPECT}->spawn("telnet", ($ip))
          or errpr "Cannot spawn telnet: $!\n";
        my $prompt = qr/PIX passwd:|password:/i;
        $con->con_wait($prompt) or $con->con_error();
        $self->{PRE_LOGIN_LINES} = $con->{RESULT}->{BEFORE};
	$prompt = qr/$prompt|$std_prompt/;
        $con->con_issue_cmd("$pass\n", $prompt) or $con->con_error();
    }
    my $match = $con->{RESULT}->{MATCH};
    if ($match eq '>') {

	# Enter enable mode. 
	my $prompt = qr/password:|\#/i;
	$con->con_issue_cmd("enable\n", $prompt) or $con->con_error();
	if ($con->{RESULT}->{MATCH} ne '#') {
	    
	    # Enable password required.
	    $pass = $self->{ENABLE_PASS} || $pass;
	    $con->con_issue_cmd("$pass\n", $prompt) or $con->con_error();
	}
	if ($con->{RESULT}->{MATCH} ne '#') {
	    errpr "Authentication for enable mode failed\n";
	}
    }
    elsif ($match ne '#') {
	errpr "Authentication failed\n";
    }
}

# All active interfaces on device must be known by Netspoc.
sub checkinterfaces {
    my ($self, $conf, $spoc) = @_;
    my @errors;
    for my $name (sort keys %{ $conf->{IF} }) {
	my $conf_intf = $conf->{IF}->{$name};
        next if $conf_intf->{SHUTDOWN};
        next if not $conf_intf->{ADDRESS};
        if (my $spoc_intf = $spoc->{IF}->{$name}) {

            # Compare mapping to VRF.
	    my $conf_vrf = $conf_intf->{VRF} || '-';
	    my $spoc_vrf = $spoc_intf->{VRF} || '-';
	    $conf_vrf eq $spoc_vrf or 
		push(@errors,
		     "Different VRFs defined for interface $name:" .
		     " Conf: $conf_vrf, Netspoc: $spoc_vrf");

            # Compare statefulness.
            my $conf_inspect = $conf_intf->{INSPECT} ? 'enabled' : 'disabled';
            my $spoc_inspect = $spoc_intf->{INSPECT} ? 'enabled' : 'disabled';
	    $conf_inspect eq $spoc_inspect or 
		push(@errors,
		     "Different 'ip inspect' defined for interface $name:" .
		     " Conf: $conf_inspect, Netspoc: $spoc_inspect");
	}
	else {
            warnpr "Interface $name on device is not known by Netspoc.\n";
        }
    }
    for my $name (sort keys %{ $spoc->{IF} }) {
	$conf->{IF}->{$name} or
	    push(@errors, "Interface $name from Netspoc not known on device");
    }
    if (@errors) {
        my $last = pop @errors;
        errpr_info "$_\n" for @errors;
	errpr("$last\n");
    }
}

# Packages must return a true value;
1;

