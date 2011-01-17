
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

sub prepare {
    my ($self) = @_;
    $self->{PROMPT}    = qr/\r\n.*[\%\>\$\#]\s?$/;
    $self->{ENAPROMPT} = qr/\r\n.*#\s?$/;
    $self->{ENA_MODE}  = 0;
    $self->login_enable() or exit -1;
    mypr "logged in\n";
    $self->{ENA_MODE} = 1;
    my $result = $self->issue_cmd('');
    $result->{MATCH} =~ m/^(\r\n\s?\S+)\#\s?$/;
    my $prompt_prefix = $1;
    $prompt_prefix =~ /\s*(.*)$/;
    my $name = $1;
    $self->checkidentity($name);

    # Set prompt again because of performance impact of standard prompt.
    $self->{ENAPROMPT} = qr/$prompt_prefix\S*#\s?/;
}

sub login_enable {
    my ($self) = @_;
    my($con, $ip, $user, $pass) = @{$self}{qw(CONSOLE IP LOCAL_USER PASS)};

    if(not $pass) {
	($user, $pass) = $self->get_aaa_password();
    }
    if ($user) {
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
              or errpr "Cannot spawn ssh: $!\n";
            my $prompt = qr/password:|\(yes\/no\)\?/i;
            $con->con_wait($prompt) or $con->con_error();
            if ($con->{RESULT}->{MATCH} =~ qr/\(yes\/no\)\?/i) {
                $con->con_dump();
                $con->con_issue_cmd("yes\n",qr/password:/i) or 
		    $con->con_error();
                mypr "\n";
                warnpr
                  "RSA key for $self->{IP} permanently added to the list of known hosts\n";
                $con->con_dump();
            }
	    $pass ||= $self->get_user_password($user);
            $con->con_issue_cmd("$pass\n", $self->{PROMPT}) or $con->con_error();
            $con->con_dump();
            $self->{PRE_LOGIN_LINES} = $con->{RESULT}->{BEFORE};
        }
        else {
            mypr "port 22 closed -  trying telnet for login\n";
            $con->{EXPECT}->spawn("telnet", ($ip))
              or errpr "Cannot spawn telnet: $!\n";
            my $prompt = "Username:";
            $con->con_wait($prompt) or $con->con_error();
            $con->con_dump();
            $self->{PRE_LOGIN_LINES} = $con->{RESULT}->{BEFORE};
            $con->con_issue_cmd("$user\n", "[Pp]assword:")
              or $con->con_error();
            $con->con_dump();
	    $pass ||= $self->get_user_password($user);
            $con->con_issue_cmd("$pass\n", $self->{PROMPT}) or $con->con_error();
            $con->con_dump();
        }
    }
    else {
        mypr "using simple TELNET for login\n";
        $pass = $self->{PASS};
        $con->{EXPECT}->spawn("telnet", ($ip))
          or errpr "Cannot spawn telnet: $!\n";
        my $prompt = "PIX passwd:|Password:";
        $con->con_wait($prompt) or $con->con_error();
        $con->con_dump();
        $self->{PRE_LOGIN_LINES} = $con->{RESULT}->{BEFORE};
        $con->con_issue_cmd("$pass\n", $self->{PROMPT}) or $con->con_error();
        $con->con_dump();
    }
    my $psave = $self->{PROMPT};
    $self->{PROMPT} = qr/Password:|#/;
    $self->issue_cmd('enable');
    unless ($con->{RESULT}->{MATCH} eq "#") {

        # Enable password required.
        $self->{PROMPT} = $psave;
        $self->issue_cmd($self->{ENABLE_PASS} || $pass);
    }
    return 1;
}

# All active interfaces on device must be known by Netspoc.
sub checkinterfaces {
    my ($self, $conf, $spoc) = @_;
    for my $name (sort keys %{ $conf->{IF} }) {
	my $intf = $conf->{IF}->{$name};
        next if $intf->{SHUTDOWN};
        next if not $intf->{ADDRESS};
        if (not $spoc->{IF}->{$name}) {
            warnpr "Interface $name on device is not known by Netspoc.\n";
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

sub route_add {
    my($self, $entry) = @_;
    return($entry->{orig});
}

sub route_del {
    my($self, $entry) = @_;
    return("no $entry->{orig}");
}
   
# Build textual representation from ACL entry for use with Algorithm::Diff.
# Ignore name of object-group. Object-groups are compared semantically later.
sub acl_entry2key {
    my ($e) = @_;
    my @r;
    push(@r, $e->{MODE});
    for my $where (qw(SRC DST)) {
	my $what = $e->{$where};
	push(@r, $what->{OBJECT_GROUP} 
	       ? 'object-group' 
	       : "$what->{BASE}/$what->{MASK}");
    }
    push @r, $e->{TYPE};
    if ($e->{TYPE} eq 'icmp') {
        my $s = $e->{SPEC};
	for my $where (qw(TYPE CODE)) {
	    my $v = $s->{TYPE};
	    push(@r, defined $v ? $v : '-');
	}
    }
    elsif ($e->{TYPE} eq 'tcp' or $e->{TYPE} eq 'udp') {
	for my $where (qw(SRC_PORT DST_PORT)) {
	    my $port = $e->{$where};
	    push(@r, "$port->{LOW}:$port->{HIGH}");
	}
	push(@r, 'established') if $e->{ESTA};
    }
    if($e->{LOG}) {
	push(@r, 'log');
	push(@r, $e->{LOG_MODE}) if $e->{LOG_MODE};
	push(@r, $e->{LOG_LEVEL}) if $e->{LOG_LEVEL};
	push(@r, "interval $e->{LOG_INTERVAL}") if $e->{LOG_INTERVAL};
    }
    return join(' ', @r);
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
# to prevent accidental lock out from device.
#
# ACL is changed on device in 2 passes:
# 1. Add new ACL entries and move entries upwards, top entries first.
#  a) add new entries which are not already present on device.
#  b) move entries upwards
# 2. Delete old ACL entries and move entries downward, bottom entries first.
#  a) delete entry which isn't used any longer.
#  b) move entry downwards
sub equalize_acl {
    my($self, $conf, $spoc, $conf_acl, $spoc_acl) = @_;
    my $conf_entries = $conf_acl->{LIST};
    my $spoc_entries = $spoc_acl->{LIST};

    my $diff = Algorithm::Diff->new( $conf_entries, $spoc_entries, 
				     { keyGen => \&acl_entry2key } );

    # Hash for finding duplicates when comparing old and new entries.
    my %dupl;

    # ACL lines which are moved upwards. 
    # Mapping from spoc entry to conf entry.
    my %move_up;

    # ACL lines which are moved downwards. 
    # Mapping from conf entry to spoc entry.
    my %move_down;

    # Entry needs not to be deleted because it was moved early.
    my %moved;

    # Collect entries 
    # - do be added on device (includes move_up)
    # - to be deleted on device (includes move_down).
    my (@add, @delete);

    # Device line numbers of ACL entries.
    my %device_line;

    # Collect commands to change ACL in place.
    my @cmds;

    # Conf line at which position a spoc line will be added.
    my %add_before;

    # Relative line numbers for added lines relativ to next conf line.
    # For IOS: -9999, -9998, -9997, ...
    # For ASA: 0, 0, 0, ...
    my %spoc_line_offset;

    my ($line_start, $line_incr, $add_offset, $add_incr) = 
	$self->ACL_line_discipline();

    # Add line numbers to ACL entries read from device.
    for (my $i = 0; $i < @$conf_entries; $i++) {
	$device_line{$conf_entries->[$i]} = $line_start + $i * $line_incr;
    }

    # 1. Process equal and to be deleted entries.
    while($diff->Next()) {

	# ACL lines are equal, but object-group may change.
	if($diff->Same()) {
	    my $conf_min = $diff->Min(1);
	    my $count = $diff->Max(1) - $conf_min;
	    my $spoc_min = $diff->Min(2);
	    for my $i (0 .. $count) {
		my $conf_entry = $conf_entries->[$conf_min+$i];
		my $spoc_entry = $spoc_entries->[$spoc_min+$i];
		if ($self->equalize_obj_group_in_ace($conf, $spoc, 
						     $conf_entry, $spoc_entry))
		{
		    
		    # Change ACL line to modified name of obj-group.
		    $add_before{$spoc_entry} = $conf_entry;
		    push @delete, $conf_entry;
		    $move_up{$spoc_entry} = $conf_entry;
		    $moved{$conf_entry} = 1;
		    push @add, $spoc_entry;
		}
	    }
	}

	# Process to be deleted entries.
	elsif ($diff->Diff() & 1) {
	    for my $conf_entry ($diff->Items(1)) {
		my $key = acl_entry2key($conf_entry);
		$dupl{$key} and internal_err "Duplicate ACL entry on device";
		$dupl{$key} = $conf_entry;
		push @delete, $conf_entry;
	    }
	}
    }

    # 2. Process to be added entries.
    $diff->Reset();
    while($diff->Next()) {
	if ($diff->Diff() & 2) {
	    my $next_conf_entry;
	    my $offset;
	    if (defined (my $conf_next = $diff->Min(1))) {
		$next_conf_entry = $conf_entries->[$conf_next];
		$offset = $add_offset;
	    }
	    for my $spoc_entry ($diff->Items(2)) {
		$self->mark_new_object_groups($spoc, $spoc_entry);

		# Remember conf line where to add new line.
		if ($next_conf_entry) {
		    $add_before{$spoc_entry} = $next_conf_entry;
		    $spoc_line_offset{$spoc_entry} = $offset;
		    $offset += $add_incr;
		}

		# Find lines already present on device
		my $key = acl_entry2key($spoc_entry);
		if (my $conf_entry = $dupl{$key}) {
		    $self->equalize_obj_group_in_ace($conf, $spoc, 
						     $conf_entry, $spoc_entry);

		    # Move upwards.
		    if ($next_conf_entry and
			$device_line{$next_conf_entry} < 
			$device_line{$conf_entry}) 
		    {
			$move_up{$spoc_entry} = $conf_entry;
			$moved{$conf_entry} = 1;
			push @add, $spoc_entry;
		    }

		    # Move downwards.
		    else {
			$move_down{$conf_entry} = $spoc_entry;
		    }
		}

		# Add.
		else {
		    push @add, $spoc_entry;
		}
	    }
	}
    }
    
    return undef if not (@cmds || @add || @delete);

    $self->check_max_acl_entries($conf_acl);
    $self->check_max_acl_entries($spoc_acl);

    # 1. Add lines from netspoc and move lines upwards.
    for my $spoc_entry (@add) {
	my $cmd1;
	if (my $conf_entry = $move_up{$spoc_entry}) {
	    my $line = $device_line{$conf_entry};
	    $cmd1 = $self->del_numbered_acl($line, $conf_entry->{orig});
	    $self->change_acl_numbers(\%device_line, $line+1, -1);
	}
	my $cmd2 = $self->subst_ace_name_og($spoc_entry, $conf_acl->{name}, 
					    $spoc);
	if (my $next_conf_entry = $add_before{$spoc_entry}) {
	    my $line = $device_line{$next_conf_entry} + 
		$spoc_line_offset{$spoc_entry};
	    $cmd2 = $self->add_numbered_acl($line, $cmd2);
	    $self->change_acl_numbers(\%device_line, $line, +1);
	}
	push(@cmds, $cmd1 ? [ $cmd1, $cmd2] : $cmd2);
    }

    # 2. Delete lines on device and move lines downwards.
    # Work from bottom to top. Otherwise
    # - we could lock out ourselves (on IOS only) or
    # - permit too much traffic for a short time.
    for my $conf_entry (reverse @delete) {
	next if $moved{$conf_entry};
	my $line = $device_line{$conf_entry};
	my $cmd1 = $self->del_numbered_acl($line, $conf_entry->{orig});
	$self->change_acl_numbers(\%device_line, $line+1, -1);
	my $cmd2;
	if (my $spoc_entry = $move_down{$conf_entry}) {
	    $cmd2 = $self->subst_ace_name_og($spoc_entry, $conf_acl->{name}, 
					     $spoc);
	    if (my $next_conf_entry = $add_before{$spoc_entry}) {
		my $line = $device_line{$next_conf_entry} + 
		    $spoc_line_offset{$spoc_entry};
		$cmd2 = $self->add_numbered_acl($line, $cmd2);
		$self->change_acl_numbers(\%device_line, $line, +1);
	    }
	}
	push(@cmds, $cmd2 ? [ $cmd1, $cmd2] : $cmd1);
    }

    return \@cmds;
}

# Packages must return a true value;
1;

