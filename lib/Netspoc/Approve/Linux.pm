
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

sub get_spoc_parse_info {
    my ($self) = @_;
    my $result =
    { 
	'ip route' => {
	    store => 'ROUTING',
	    multi => 1,
	    parse => ['seq',
		      { parse => qr/unicast|local|broadcast|multicast|throw|unreachable|prohibit|blackhole|nat/,
			store => 'TYPE', default => 'unicast'},
		      { parse => \&get_ip_prefix, 
			store_multi => ['BASE', 'MASK'] },
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
		       { parse => qr/via/ },
		       { parse => \&get_ip, store => 'NEXTHOP' } ],
		      ['seq',
		       { parse => qr/dev/ },
		       { parse => \&get_ip, store => 'NIF' } ],
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

		      
sub parse_spoc {
    my ($self, $lines) = @_;

    Netspoc::Approve::Cisco->parse_device($lines);
}

sub analyse_args {
    my ($lines) = @_;
    my $config = [];
    my $counter = 0;

    for my $line (@$lines) {
	$counter++;	
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
    
sub get_parsed_config_from_device {
    my ($self) = @_;
    my $lines = $self->get_cmd_output('ip route show');
    my $parse_route = $self->get_parse_info->{'ip route'};
    my $parser = $parse_route->{parse};
    my $store = $parse_route->{store};
    $parse_route->{multi} or errpr  "internal: expected attribute 'multi'\n";
    my $args = analyze_args($lines);
    my @routes;
    for my $arg (@$args) {
	push(@routes, parse_line($self, $arg, $parser));
    }
    my $config = { $store => \@routes };
    $self->postprocess_device_config($config);
    return $config;
}

sub postprocess_device_config {
    my ($self, $config) = @_;
    $config->{ROUTING} = 
	[ grep { !$_->{PROTO} || $_->{PROTO} eq 'static'; }
	  @{ $config->{ROUTING} } ];
}    

# NoOp.
sub checkinterfaces {
    my($self) = @_;
}

# NoOp.
sub check_firewall {
    my($self) = @_;
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

sub route_add {
    my($self, $entry) = @_;
    return("route add $entry->{orig}");
}

sub route_del {
    my($self, $entry) = @_;
    return("route del $entry->{orig}");
}

sub prepare {
    my ($self) = @_;
    $self->{PROMPT}    = qr/\r\n.*[\%\>\$\#]\s?$/;
    $self->{ENAPROMPT} = qr/\r\n.*#\s?$/;
    $self->{ENA_MODE}  = 0;
    $self->ssh_login() or exit -1;
    mypr "logged in\n";
    $self->{ENA_MODE} = 1;
    my $result = $self->issue_cmd('');
    $result->{MATCH} =~ m/^\r\n\s?(\S+):\S*\#\s?$/;
    my $name = $1;
    $self->checkidentity($name) or exit -1;

    # Set prompt again because of performance impact of standard prompt.
    $self->{ENAPROMPT} = qr/\r\n\s?$name:\S*#\s?$/;
}

sub ssh_login {
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
}

# Packages must return a true value;
1;

