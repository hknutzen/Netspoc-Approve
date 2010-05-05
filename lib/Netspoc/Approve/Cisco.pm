
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
    $self->add_prefix_suffix_info($parse_info);
    my @stack;
    my $level = 0;
    my $config = [];
    my $counter = 0;
    my $in_banner = 0;
    my $first_subcmd = 0;

    for my $line (@$lines) {
	$counter++;	

	if(my $cmd = $in_banner) {
	    if($line =~ /^\^/) {
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
	my $prefix_any;
	if(my $prefix_info = $parse_info->{_prefix}) {
	    my $prefix = $cmd;
	    while($prefix_info = $prefix_info->{$prefix}) {
		$prefix = shift(@args);
		$prefix_any = $prefix_info->{_any} ? "$cmd _any" : undef;
		$cmd .= ' ' . $prefix;
	    }
	}
	if (my $suffix_hash = $parse_info->{_suffix}->{$cmd}) {
	    my $last_arg = $args[-1];
	    if($suffix_hash->{$last_arg}) {
		pop(@args);
		$cmd .= ' +' . $last_arg;
		$prefix_any .= ' +' . $last_arg if $prefix_any;
	    }
	}
	if (my $cmd_info = ($parse_info->{$cmd} || 
			    $parse_info->{_any} || 
			    $prefix_any && $parse_info->{$prefix_any}) )
	{

	    # Remember current line number, set parse position.
	    # Remember a version of the unparsed line without duplicate 
	    # whitespace.
	    my $new_cmd = { line => $counter, 
			    pos => 0, 
			    orig => join(' ', $cmd, @args),
			    args => [ $cmd, @args ], };
	    push(@$config, $new_cmd);
	    if (my $subcmd = $cmd_info->{subcmd}) {
		push @stack, [ $config, $parse_info, $level ];
		$level++;
		$parse_info = $subcmd;
		$config = [];
		$new_cmd->{subcmd} = $config;
		$first_subcmd = 1;
	    }
	    elsif ($cmd_info->{banner}) {
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
}

sub leave_conf_mode {
    my($self) = @_;
    $self->cmd('end');
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
    $self->{ENAPROMPT} = qr/$prompt_prefix\S*#\s?$/;
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
                $con->{PROMPT}  = qr/password:/i;
                $con->con_cmd("yes\n") or $con->con_error();
                mypr "\n";
                warnpr
                  "RSA key for $self->{IP} permanently added to the list of known hosts\n";
                $con->con_dump();
            }
            $con->{PROMPT}  = $self->{PROMPT};
            $con->con_cmd("$pass\n") or $con->con_error();
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
            $con->{PROMPT}  = $self->{PROMPT};
            $con->con_cmd("$pass\n") or $con->con_error();
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
        $con->{PROMPT}           = $self->{PROMPT};
        $con->con_cmd("$pass\n") or $con->con_error();
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

# Packages must return a true value;
1;

