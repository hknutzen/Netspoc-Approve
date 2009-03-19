
package Netspoc::Approve::Linux;

# Author: Heinz Knutzen
#
# Description:
# Module to remote configure Linux devices.


'$Id$' =~ / (.+),v (.+?) /;

my $id = "$1 $2";

use strict;
use warnings;
use base "Netspoc::Approve::Device";
use Netspoc::Approve::Helper;
use Netspoc::Approve::Parse_Cisco;

my $config = {
    device_routing_file => '/etc/network/routing',
    tmp_file => '/tmp/netspoc',
    store_flash_cmd => '/usr/sbin/backup',
};

sub get_parse_info {
    my ($self) = @_;
    my $result =
    { 
	'ip route' => {
	    store => 'ROUTING',
	    multi => 1,
	    parse => ['seq',
		      ['or',
		       { parse => qr/add/ },
		       { error => 'expected keyword "add"' } ],
		      { parse => qr/unicast|local|broadcast|multicast|throw|unreachable|prohibit|blackhole|nat/,
			store => 'TYPE', default => 'unicast' },
		      { parse => \&get_ip_prefix, 
			store_multi => ['BASE', 'MASK'] },
		      ['seq',
		       { parse => qr/via/ },
		       { parse => \&get_ip, store => 'NEXTHOP' } ],
		      ['seq',
		       { parse => qr/dev/ },
		       { parse => \&get_token, store => 'NIF' } ],
		      ['seq',
		       { parse => qr/tos/ },
		       { parse => \&get_token, store => 'TOS' } ],
		      ['seq',
		       { parse => qr/table/ },
		       { parse => \&get_token, store => 'TABLE' } ],
		      ['seq',
		       { parse => qr/proto/ },
		       { parse => \&get_token, store => 'PROTO' } ],
		      ['seq',
		       { parse => qr/scope/ },
		       { parse => \&get_token, store => 'SCOPE' } ],
		      ['seq',
		       { parse => qr/metric/ },
		       { parse => \&get_token, store => 'METRIC' } ],
		      ['seq',
		       { parse => qr/mpath/ },
		       { parse => \&get_token, store => 'MPATH' } ],
		      ['seq',
		       { parse => qr/weight/ },
		       { parse => \&get_ip, store => 'WEIGHT' } ],
		      {parse => qr/onlink|pervasive/, store => 'NHFLAGS' },
		      {parse => qr/equalize/, store => 'FLAGS' },
		      ['seq',
		       { parse => qr/mtu/ },
		       { parse => \&get_ip, store => 'MTU' } ],
		      ['seq',
		       { parse => qr/src/ },
		       { parse => \&get_ip, store => 'SRC' } ]]},
    };
    $result;
};

sub analyze_args {
    my ($lines) = @_;
    my $config = [];
    my $counter = 0;

    for my $line (@$lines) {
	$counter++;
	next if $line =~ /^#/;
	next if $line =~ /^\s*$/;
	my @args = split(' ', $line);

	# Remember current line number, set parse position.
	# Remember a version of the unparsed line without duplicate 
	# whitespace.
	my $new_cmd = { line => $counter, 
			pos  => 0, 
			orig => join(' ', @args),
			args => \@args, };
	push(@$config, $new_cmd);
    }
    return($config);
}
   
# Parse output of "ip route show".
# Output is like single "ip route add ..." commands 
# without the prefix "ip route add".
sub parse_routes {
    my ($self, $lines, $result) = @_;

    my $parse_route = $self->get_parse_info->{'ip route'};
    my $parser = $parse_route->{parse};

    # Remove 2. element 'add' from array.
    $parser = [ @$parser ];
    splice(@$parser, 1, 1);
    my $store = $parse_route->{store};
    $parse_route->{multi} or errpr  "internal: expected attribute 'multi'\n";
    my $args = analyze_args($lines);
    my @routes;
    for my $arg (@$args) {
	my $entry = $self->parse_line($arg, $parser);
	get_eol($arg);
	$entry->{orig} = $arg->{orig};
	push(@routes, $entry); 
    }
    $result->{$store} = \@routes;
}

# # Comment
# *filter
# :INPUT ACCEPT [68024:74200042]
# :FORWARD ACCEPT [0:0]
# :OUTPUT ACCEPT [54724:5982979]
# -A INPUT -s 10.1.2.3 -j ACCEPT 
# COMMIT
# # Comment
sub parse_iptables {
    my($self, $lines, $result) = @_;
    my %tables;
    my $table;
    my $chain;
    my $args = analyze_args($lines);
    for my $arg (@$args) {
	my $cmd = get_token($arg);
	if($cmd eq 'COMMIT') {
	    ;
	}
	elsif($cmd =~ /^\*(.+)$/) {
	    $table = $1;
	    $tables{$table} and 
		err_at_line($arg, 'Multiple occurences of $line');
	    $chain = {};
	    $tables{$table}->{chain} = $chain;
	}
	elsif($cmd =~ /^:(.+)$/) {
	    my $name = $1;
	    my $policy = get_token($arg);
	    if(not $policy eq '-') {
		$tables{$table}->{default_policy}->{$name} = $policy;
	    }
	}
	elsif($cmd eq '-A') {
	    my $name = get_token($arg);
	    my $rule;

	    # Store rule as hash.
	    # Only simple key / value pairs and "! --syn" allowed.
	    if($table eq 'filter') {
		$rule = {};
		while(my $key = check_token($arg)) {
		    if($key eq '!') {
			if(check_regex('--syn', $arg)) {
			    ;
			}
			else {
			    get_regex('--tcp-flags', $arg);
			    get_regex('FIN,SYN,RST,ACK', $arg);
			    get_regex('SYN', $arg);
			}
			$rule->{nosyn} = 1;
			next;
		    }
		    $key =~ /^-/ or 
			err_at_line($arg, 'Expected option starting with "-"');
		    my $value;
		    if($key eq '-s' || $key eq '-d') {
			my($base, $mask) = get_ip_prefix($arg);
			$value = [ $base, $mask ];
		    }
		    else {
			$value = get_token($arg);
		    }
		    $rule->{$key} = $value;
		}
	    }

	    # Store rule as string.
	    else {
		$rule = get_to_eol($arg);
	    }		
	    push @{ $chain->{name} }, $rule;

	}
	else {
	    err_at_line($arg, 'Syntax error');
	}
    }
    $result->{IPTABLES} = \%tables;
}
 
sub get_parsed_config_from_device {
    my ($self) = @_;
    my $config = {};    

    my $route_lines = $self->get_cmd_output('ip route show');
    $self->parse_routes($route_lines, $config);

    my $iptables_lines = $self->get_cmd_output('iptables-save');
    $self->parse_iptables($iptables_lines, $config);
    
    $self->postprocess_device_config($config);
    return $config;
}

sub postprocess_device_config {
    my ($self, $config) = @_;

    # Ignore entries with 'scope link'.
    # Ignore entries with 'proto xxx' except 'proto static'.
    # Ignore attribute 'dev', if 'via' is provided.
    my @routes;
    for my $entry (@{ $config->{ROUTING} }) {
	next if $entry->{SCOPE} && $entry->{SCOPE} eq 'link';
	next if $entry->{PROTO} && $entry->{PROTO} ne 'static';
	if($entry->{NEXTHOP}) {
	    delete $entry->{NIF};
	}
	push(@routes, $entry);
    }
    $config->{ROUTING} = \@routes;
    return($config);
}    

# NoOp.
sub postprocess_config {
    my ($self, $config) = @_;
} 
  
sub merge_rawdata {
    my ($self, $spoc_conf, $raw_conf) = @_;

    $self->merge_routing($spoc_conf, $raw_conf);
}

# NoOp.
sub checkinterfaces {
    my($self) = @_;
}

# NoOp.
sub check_firewall {
    my($self) = @_;
}

sub cmd {
    my ($self, $cmd) = @_;
    my $lines = $self->get_cmd_output($cmd);
    
    # Check for unexpected command output.
    $self->cmd_check_error($cmd, $lines);
}

sub status_ok {
    my($self) = @_;
    my $status = $self->get_cmd_output('echo $?');
    return(@$status == 1 and $status->[0] eq '0');
}

sub cmd_ok {
    my ($self, $cmd) = @_;

    # Ignore Output; only check exit status.
    my $lines = $self->get_cmd_output($cmd);
    return($self->status_ok);
}

my %valid_cmd_output = (
    $config->{store_flash_cmd} => q#tar: Removing leading `/' from member names#,
);

sub cmd_check_error($$) {
    my ($self, $cmd, $lines) = @_;
    if(@$lines) {
	if(not(@$lines == 1 and $lines->[0] eq $valid_cmd_output{$cmd})) {
	    errpr_info "$cmd failed\n";
	    for my $line (@$lines) {
		errpr_info "+++ $line\n";
	    }
	    errpr "+++\n";
	}
    }
    elsif(not $self->status_ok) {
	errpr "$cmd failed (exit status)\n";
    }
}

# NoOp.
sub schedule_reload {
    my($self, $time) = @_;
}

# NoOp.
sub cancel_reload {
    my($self) = @_;
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

# Entry from device is output of 'ip route show',
# but is full command in case of filecompare.
sub route_del {
    my($self, $entry) = @_;
    my $orig = $entry->{orig};
    $orig =~ s/^ip route add//;
    return("ip route del $orig");
}

sub write_startup_routing {
    my ($self, $conf, $file) = @_;
    $self->cmd("rm -f $file");
    $self->cmd("echo '#!/bin/sh' >> $file");
    $self->cmd("echo '# Generated by NetSPoC' >> $file");
    for my $entry (@{ $conf->{ROUTING} }) {
	my $cmd = $self->route_add($entry);
	$self->cmd("echo $cmd >> $file");
    }
}

sub transfer() {
    my ($self, $conf, $spoc_conf) = @_;

    # Change running configuration of device.
    $self->process_routing($conf, $spoc_conf) or return 0;

    # Change startup configuration of device.
    my $tmp_file = $config->{tmp_file};
    my $startup_file = $config->{device_routing_file};    
    if (not $self->{COMPARE}) {
        if (grep { $_ } values %{ $self->{CHANGE} }) {
            mypr "Writing startup config\n";  
	    $self->write_startup_routing($spoc_conf, $tmp_file);
	    $self->cmd("mv -f $tmp_file $startup_file");
            mypr "...done\n";
        }
        else {
            mypr "No changes to save - check if startup is uptodate\n";
	    $self->write_startup_routing($spoc_conf, $tmp_file);
	    if($self->cmd_ok("cmp $tmp_file $startup_file")) {
                mypr "Startup is uptodate\n";
            }
            else {
                warnpr "Startup is *NOT* uptodate - trying to fix:\n";
		$self->cmd("mv -f $tmp_file $startup_file");
		mypr "...done\n";
	    }
        }
	if(my $cmd = $config->{store_flash_cmd}) {
            mypr "Saving config to flash\n";  
	    $self->cmd($cmd);
            mypr "...done\n";
	}
    }
    else {
        mypr "compare finish\n";
    }
    return 1;
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
    $result->{MATCH} =~ m/^\r\n\s?(\S+):.*\#\s?$/;
    my $name = $1;
    $self->checkidentity($name);

    # Set prompt again because of performance impact of standard prompt.
    $self->{ENAPROMPT} = qr/\r\n\s?$name:.*\#\s?$/;

    # Parameter --noediting prevents \r to be inserted in echoed commands.
    $self->issue_cmd('exec /bin/bash --noediting');
}

sub login_enable {
    my ($self) = @_;
    my($con, $ip) = @{$self}{qw(CONSOLE IP)};
    $con->{EXPECT}->spawn('ssh', '-l', 'root', $ip)
	or errpr "Cannot spawn ssh: $!\n";
    my $prompt = qr/$self->{PROMPT}|password:|\(yes\/no\)\?/i;
    $con->con_wait($prompt) or $con->con_error();
    if ($con->{RESULT}->{MATCH} =~ qr/\(yes\/no\)\?/i) {
	$con->con_dump();
	$con->{PROMPT}  = qr/$self->{PROMPT}|password:/i;
	$con->con_cmd("yes\n") or $con->con_error();
	$con->{PROMPT}  = $self->{PROMPT};
	mypr "\n";
	$con->con_dump();
    }
    if($con->{RESULT}->{MATCH} =~ qr/password:/i) {
	my $pass = $self->get_password();
	$con->con_cmd("$pass\n") or $con->con_error();
	$con->con_dump();
    }
    $self->{PRE_LOGIN_LINES} = $con->{RESULT}->{BEFORE};
    return 1;
}

# Packages must return a true value;
1;

