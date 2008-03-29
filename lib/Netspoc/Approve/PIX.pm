
package Netspoc::Approve::Device::Cisco::Firewall::PIX;

# Authors: Arne Spetzler, Heinz Knutzen, Daniel Brunkhorst
#
# Description:
# module to remote configure cisco pix
#

'$Id$ ' =~ / (.+),v (.+?) /;

my $id = "$1 $2";

use strict;
use warnings;

use base "Netspoc::Approve::Device::Cisco::Firewall";

sub version_drc2_pix() {
    return $id;
}

use FindBin;
use lib $FindBin::Bin;
use Fcntl;
use SDBM_File;
use IO::Socket ();

use Netspoc::Approve::Helper;
use Acltools;


my $con;

##############################################################
# issue command to nob
##############################################################
sub cmd_check_error($$$) {
    my ($self, $out, $type) = @_;

    # do ERROR if unexpected line appears
    if ($$out =~ /\n.*\n/m) {
        #### hack start ###
        ($$out =~ /\[OK\]/m) and return 1;    ### for write memory
        ($$out =~ /will be identity translated for outbound/)
          and return 1;                       # identity nat
        ($$out =~ /nat 0 0.0.0.0 will be non-translated/)
          and return 1;                       # identity nat
        ($$out =~ /Global \d+\.\d+\.\d+\.\d+ will be Port Address Translated/)
          and return 1;                       # PAT
        if ($$out =~ /overlapped\/redundant/) {
            ### overlapping statics from netspoc
            my @pre = split(/\n/, $$out);
            for my $line (@pre) {
                warnpr $line, "\n";
            }
            return 1;
        }
        if ($$out =~ /static overlaps/) {
            ### overlapping statics with global from netspoc
            my @pre = split(/\n/, $$out);
            for my $line (@pre) {
                warnpr $line, "\n";
            }
            return 1;
        }
        if ($$out =~ /Route already exists/) {
            ### route warnings
            my @pre = split(/\n/, $$out);
            for my $line (@pre) {
                warnpr $line, "\n";
            }
            return 1;
        }
        if ($$out =~ /ACE not added. Possible duplicate entry/) {
            ### ace warnings
            my @pre = split(/\n/, $$out);
            for my $line (@pre) {
                warnpr $line, "\n";
            }
            return 1;
        }
        ### hack end ###
        my @pre = split(/\n/, $$out);
        for my $line (@pre) {
            errpr_info "+++ ", $line, "\n";
        }
        errpr "+++\n";
        return 0;
    }
    return 1;
}

sub issue_cmd( $$$ ) {
    my ($self, $cmd, $prompt) = @_;
    my @output;

    $con->{PROMPT} = $prompt;
    $con->con_cmd("$cmd\n") or $con->con_error();
    @output = ($con->{RESULT}->{BEFORE}, $con->{RESULT}->{MATCH});
    return (\@output);

}

sub cmd( $$ ) {
    my ($self, $cmd) = @_;
    my $prompt = $self->{ENA_MODE} ? $$self{ENAPROMPT} : $$self{PROMPT};
    my $out = $self->issue_cmd($cmd, $prompt) or return 0;

    # check for  errors
    # argument is ref to prematch from issue_cmd
    return $self->cmd_check_error(\${$out}[0], $$self{TYPE});
}

sub shcmd( $$ ) {
    my ($self, $cmd) = @_;
    my $prompt = $self->{ENA_MODE} ? $$self{ENAPROMPT} : $$self{PROMPT};
    my $out = $self->issue_cmd($cmd, $prompt) or die "...giving up\n";
    return @$out;
}

sub login_enabel( $ ) {
    my ($self) = @_;
    my $ip = $self->{IP};
    my $user;
    my $pass;

    if ($self->{PASS} =~ /:/ or $self->{LOCAL_USER}) {
        if ($self->{LOCAL_USER}) {
            $pass = $self->{PASS};
            $user = $self->{LOCAL_USER} or die "no user found\n";
        }
        else {
            ($user, $pass) = split(/:/, $self->{PASS});
        }
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
              or die "Cannot spawn ssh: $!\n";
            my $prm = qr/password:|\(yes\/no\)\?/i;
            my $tmt = $self->{telnet_timeout};
            $con->con_wait("$prm", $tmt) or $con->con_error();
            if ($con->{RESULT}->{MATCH} =~ qr/\(yes\/no\)\?/i) {
                $con->con_dump();
                $con->{PROMPT}  = qr/password:/i;
                $con->{TIMEOUT} = $self->{telnet_timeout};
                $con->con_cmd("yes\n") or $con->con_error();
                mypr "\n";
                warnpr
                  "RSA key for $self->{IP} permanently added to the list of known hosts\n";
                $con->con_dump();
            }
            $con->{PROMPT}  = $$self{PROMPT};
            $con->{TIMEOUT} = $self->{telnet_timeout};
            $con->con_cmd("$pass\n") or $con->con_error();
            $con->con_dump();
            $self->{PRE_LOGIN_LINES} = $con->{RESULT}->{BEFORE};
        }
        else {
            mypr "port 22 closed -  trying telnet for login\n";
            $con->{EXPECT}->spawn("telnet", ($ip))
              or die "Cannot spawn telnet: $!\n";
            my $tmt = $self->{telnet_timeout};
            my $prm = "Username:";
            $con->con_wait("$prm", $tmt) or $con->con_error();
            $con->con_dump();
            $self->{PRE_LOGIN_LINES} = $con->{RESULT}->{BEFORE};
            $con->con_issue_cmd("$user\n", "[Pp]assword:", $tmt)
              or $con->con_error();
            $con->con_dump();
            $con->{PROMPT}  = $$self{PROMPT};
            $con->{TIMEOUT} = $tmt;
            $con->con_cmd("$pass\n") or $con->con_error();
            $con->con_dump();
        }
    }
    else {
        mypr "using simple TELNET for login\n";
        $pass = $self->{PASS};
        $con->{EXPECT}->spawn("telnet", ($ip))
          or die "Cannot spawn telnet: $!\n";
        my $prm = "PIX passwd:|Password:";
        my $tmt = $self->{telnet_timeout};
        $con->con_wait("$prm", $tmt) or $con->con_error();
        $con->con_dump();
        $self->{PRE_LOGIN_LINES} = $con->{RESULT}->{BEFORE};
        $con->{PROMPT}          = $$self{PROMPT};
        $con->{TIMEOUT}         = $self->{telnet_timeout};
        $con->con_cmd("$pass\n") or $con->con_error();
        $con->con_dump();
    }
    my $psave = $$self{PROMPT};
    $$self{PROMPT} = qr/Password:/;
    $self->cmd('enable') or return 0;
    $$self{PROMPT} = $psave;
    $self->cmd($$self{PASS}) or return 0;
    return 1;
}

#
#    *** some checking ***
#
sub checkidentity($$) {
    my ($self, $name) = @_;
    if ($name ne $self->{NAME}) {
        if ($self->{ALIAS} ne 0) {
            if ($name eq $self->{ALIAS}) {
                mypr "devicename matched by ALIAS \"$self->{ALIAS}\"\n";
                return 1;
            }
            else {
                errpr
                  "wrong device name: $name expected: $self->{NAME} or ALIAS $self->{ALIAS}\n ";
                return 0;
            }
        }
        else {
            errpr
              "wrong device name: $name expected: $self->{NAME} (no ALIAS defined)\n ";
            return 0;
        }
    }
    return 1;
}

sub checkinterfaces($$$) {
    my ($self, $devconf, $spocconf) = @_;
    mypr " === check for unknown or missconfigured interfaces at device ===\n";
    for my $intf (sort keys %{ $devconf->{IF} }) {
        next if ($devconf->{IF}->{$intf}->{SHUTDOWN} == 1);
        unless (exists $spocconf->{IF}->{$intf}) {
            warnpr "unknown interface detected: $intf\n";
        }
    }
    mypr " === done ===\n";
}

sub checkbanner($) {
    my ($self) = @_;    
    if ($self->{VERSION} < 6.3) {
        mypr "banner checking disabled for $self->{TYPE} $self->{VERSION}\n";
    }
    elsif ( $self->{CHECKBANNER}
        and $self->{PRE_LOGIN_LINES} !~ /$self->{CHECKBANNER}/)
    {
        if ($self->{APPROVE}) {
            errpr "Missing banner at NetSPoC managed device.\n";
        }
        else {
            warnpr "Missing banner at NetSPoC managed device.\n";
        }
    }
}
#######################################################
# telnet login, check name and set convenient options
#######################################################
sub prepare($) {
    my ($self) = @_; 
    $self->{PROMPT}    = qr/\n.*[\%\>\$\#]\s?$/;
    $self->{ENAPROMPT} = qr/\n.*#\s?$/;
    $self->{ENA_MODE}  = 0;
    $self->login_enabel() or exit -1;
    mypr "logged in\n";
    $self->{ENA_MODE} = 1;
    my @output = $self->shcmd('') or exit -1;
    $output[1] =~ m/^\n\s?(\S+)\#\s?$/;
    my $name = $1;

    unless ($self->{CHECKHOST} eq 'no') {
        $self->checkidentity($name) or exit -1;
    }
    else {
        mypr "hostname checking disabled!\n";
    }

    # setting Enableprompt again for pix because of performance impact of
    # standard prompt
    $self->{ENAPROMPT} = qr/\x0d$name\S*#\s?$/;

    #
    # set/check  pager settings
    #
    my @tmp = $self->shcmd('sh pager');
    if ($tmp[0] !~ /no pager/) {

        # pix OS 7.x needs conf mode for setting this - because of IDS do
        # not configure automatically
        errpr "pager not disabled - issue \'no pager\' by hand to continue\n";
    }
    mypr "---\n";

    # max. term width is 511 for pix 512 for ios
    @tmp = $self->shcmd('sh ver');
    $tmp[0] =~ /Version +(\d+\.\d+)/i
      or die "fatal error: could not identify PIX Version from $tmp[0]\n";
    $self->{VERSION} = $1;
    $tmp[0] =~ /Hardware:\s+(\S+),/i
      or die "fatal error: could not identify PIX Version from $tmp[0]\n";
    $self->{HARDWARE} = $1;
    @tmp = $self->shcmd('sh term');
    if ($tmp[0] !~ /511/) {

        if ($self->{VERSION} eq "6.3" or $self->{VERSION} =~ /7\./) {

            # only warn.  otherwise the generated configure message triggers IDS at night
            if ($tmp[0] =~ /idth\s+=\s+(\d+)/) {
                warnpr "Wrong terminal width: $1\n";
            }
            else {
                warnpr "Wrong terminal width: $tmp[0]\n";
            }
            warnpr "terminal width should be 511\n";
        }
        else {
            $self->cmd('term width 511') or exit -1;
        }
    }
    @tmp = $self->shcmd('sh fixup');
    if ($tmp[0] =~ /\n\s*fixup\s+protocol\s+smtp\s+25/) {
        unless ($self->{COMPARE}) {
            $self->cmd('configure terminal') or exit -1;
            $self->cmd('no fixup protocol smtp 25')
              or exit -1;    # needed for enhanced smtp faetures
            mypr "fixup for protocol smtp at port 25 now disabled!\n";
            $self->cmd('quit') or exit -1;
        }
    }
    mypr "-----------------------------------------------------------\n";
    mypr " DINFO: $self->{HARDWARE} $self->{TYPE} $self->{VERSION}\n";
    mypr "-----------------------------------------------------------\n";
}
#######################################################
#   parsing - helper
#######################################################
my %spotags = (
    START   => '^\s*!*\s*\[ BEGIN router:(.*) \]',
    MODEL   => '^\s*!*\s*\[ Model = (.*) \]',
    STOP    => '^\s*!*\s*\[ END router:(.*) \]',
    COMMENT => '^\s*!',
    IGNORE  => [ q(^\s*$), '^\[ ACL \]', '^\[ Routing \]', '^\[ Static \]', ]
);

sub eat_shit ( $$ ) {
    my($self, $l) = @_;
    if (   $l =~ /$spotags{START}/o
        or $l =~ /$spotags{MODEL}/o
        or $l =~ /$spotags{STOP}/o)
    {
        return 0;
    }
    if ($l =~ /$spotags{COMMENT}/o) {
        return 1;
    }
    for my $i (@{ $spotags{IGNORE} }) {
        if ($l =~ /$i/) {
            return 1;
        }
    }
    return 0;
}

# parse START - payload - STOP from config payload
sub parse_spocfile ( $$$ ) {
    my ($self, $p, $sfile) = @_;
    $p->{DEVICE} = '';
    while (defined(my $line = shift @$sfile)) {
        $self->eat_shit($line) and next;
        if ($line =~ /$spotags{START}/o) {
            $p->{DEVICE} = $1;
            next;
        }
        if ($line =~ /$spotags{MODEL}/o) {
            $p->{MODEL} = $1;
	    pix_parse($p, $sfile);
            last;
        }
        errpr "unexpected line: $line\n";
        return 0;
    }
    if (!$$p{DEVICE}) {
        errpr "START tag not found or no device name specified in spocfile\n";
        return 0;
    }
    if (@$sfile == 0) {
        errpr "unexpected end of spocfile\n";
        return 0;
    }

    # unified pixparser eats up all, so do not check for STOP Tag
    if ($p->{DEVICE} ne $self->{NAME}) {
        if ($self->{CHECK_DEVICE_IN_SPOCFILE} eq "yes") {
            errpr
              "wrong device name in spocfile - expected: $self->{NAME} found: $p->{DEVICE}\n";
            return 0;
        }
        elsif ($self->{CHECK_DEVICE_IN_SPOCFILE} eq "no") {
            mypr "compare $self->{NAME} and $p->{DEVICE}\n";
        }
        else {
            warnpr
              "wrong device name in spocfile - expected: $self->{NAME} found: $p->{DEVICE}\n";
            $p->{DEVICE} = $self->{NAME};

        }
    }
    return 1;
}

sub get_parsed_config_from_device( $$ ) {
    my ($self, $conf_hash) = @_;

    # *** FETCH CONFIG ***
    my @out;
    @out = $self->shcmd('wr t') or exit -1;
    my @conf = split /(?=\n)/, $out[0];
    mypr "got config from device\n";

    # *** PARSE CONFIG ***
    unless ($self->pix_parse($conf_hash, \@conf)) {
        errpr "could not parse pix config\n";
        return 0;
    }
    return 1;
}

sub get_config_from_device( $ ) {
    my($self) = @_;
    my ($conf_hash) = @_;

    # *** FETCH CONFIG ***
    my @out;
    @out = $self->shcmd('wr t') or exit -1;
    my @conf = split /(?=\n)/, $out[0];
    mypr "got config from device\n";
    return(\@conf);
}
##############################################################
# rawdata processing
##############################################################
sub process_rawdata( $$$$ ) {
    my ($self, $pspoc, $epilog) = @_;    
    my $epilogacl;
    my $spocacl;
    ### helper ###
    my $sec_time = time();    # for status info timestamps
    my $check    = sub {
        my ($intf, $epi) = @_;
        unless (exists $epi->{IF}->{$intf}->{ACCESS}) {
            mypr " - no acl in raw data -\n";
            return 0;
        }

        # there is an epilog acl for this interface
        my $ep_name = $epi->{IF}->{$intf}->{ACCESS};

## It is sufficient to check for spoc-interface below.
#
#        unless (exists $conf->{IF}->{$intf}) {
#            errpr "rawdata: interface not found on device: $intf\n";
#            exit -1;
#        }

        # the interface exists on the device
        my $sp_name;
        exists $pspoc->{IF}->{$intf}
          or die "rawdata: $intf not found in spocfile\n";
        unless (exists $pspoc->{IF}->{$intf}->{ACCESS}) {
            warnpr "rawdata: no spocacl for interface: $intf\n";
            return 0;
        }

        # there is a corresponding acl in the spocfile
        $sp_name = $pspoc->{IF}->{$intf}->{ACCESS};
        unless (exists $epi->{ACCESS}->{$ep_name}) {
            errpr
              "rawdata: no matching raw acl found for name $ep_name in interface definition\n";
            exit -1;
        }
        $epilogacl = $epi->{ACCESS}->{$ep_name};
        $spocacl   = $pspoc->{ACCESS}->{$sp_name};
        return 1;
    };
#    $cnob->{MIGRATE_STATUS}->{"NO LINES"} = 0;
    if (scalar @{ $epilog }) {
        my $epilog_conf = {};

        # *** PARSE RAWDATA ***
        mypr " *** rawdata parsed by NEWPARSER - no MIGRATE in effect ***\n";
        $epilog_conf->{STD} = {};
        $self->pix_parse($epilog_conf->{STD}, $epilog);
        ######################################################################
        # *** STANDARD ***
        ######################################################################
        mypr "--- STANDARD raw processing\n";
        my $std = $epilog_conf->{STD};
        ### ACL PROCESSING STD ###
#        my $active_std_interfaces = '';
        for my $intf (keys %{ $std->{IF} }) {
            mypr " interface: $intf\n";
            &$check($intf, $std) or next;

            # _prepend_
            my @remove = ();
            for (my $i = 0 ; $i < scalar @$spocacl ; $i++) {
                for my $epi (@$epilogacl) {
                    if (acl_line_a_eq_b($epi, $spocacl->[$i])) {
                        warnpr "RAW: double ACE \'"
                          . $self->acl_line_to_string($spocacl->[$i])
                          . "\' scheduled for remove from spocacl.\n";
                        push @remove, $i;
                    }
                }
            }
            for my $r (reverse sort @remove) {
                splice @$spocacl, $r, 1;
            }
            for (my $i = scalar @{$epilogacl} - 1 ; $i >= 0 ; $i--) {
                unshift @{$spocacl}, $$epilogacl[$i];
            }
            mypr "   entries prepended: " . scalar @{$epilogacl} . "\n";

# Attribute STD_ACCESS isn't used anywere.
#            $cnob->{IF}->{$intf}->{STD_ACCESS} = $epilogacl;
#            $cnob->{MIGRATE_STATUS}->{"STD ACL TRANS:: $intf"} =
#              scalar @{ $cnob->{IF}->{$intf}->{STD_ACCESS} };
#            $active_std_interfaces = $active_std_interfaces . " $intf";
        }
#        $cnob->{MIGRATE_STATUS}->{"STD INTERFACES"} = $active_std_interfaces;
        ### ROUTE PROCESSING STD ###
        if (defined $pspoc->{ROUTING}) {
            my $newroutes = ();
          SPOC: for (my $i = 0 ; $i < scalar @{ $pspoc->{ROUTING} } ; $i++) {
                my $se = $pspoc->{ROUTING}->[$i];
                for my $re (@{ $std->{ROUTING} }) {
                    if (route_line_a_eq_b($se, $re)) {
                        warnpr "RAW: double RE \'"
                          . $self->route_line_to_string($re)
                          . "\' scheduled for remove from spocconf.\n";
                        next SPOC;
                    }
                    elsif ( $re->{BASE} eq $se->{BASE}
                        and $re->{MASK} eq $se->{MASK})
                    {
                        warnpr
                          "RAW: inconsistent NEXT HOP in routing entries:\n";
                        warnpr "     spoc: "
                          . $self->route_line_to_string($se)
                          . " (scheduled for remove)\n";
                        warnpr "     raw:  "
                          . $self->route_line_to_string($re) . "\n";
                        next SPOC;
                    }
                }
                push @{$newroutes}, $se;
            }
            $pspoc->{ROUTING} = $newroutes;
        }
        for my $re (@{ $std->{ROUTING} }) {
            push @{ $pspoc->{ROUTING} }, $re;
        }
        mypr " attached routing entries: " . scalar @{ $std->{ROUTING} } . "\n";

# Attribute STD_ROUTING isn't used anywere.
#        $cnob->{STD_ROUTING} = $std->{ROUTING};

        ### STATIC PROCESSING ###
        my @std_static = ();
        if ($std->{STATIC}) {
            my @remove = ();
            for my $s (@{ $std->{STATIC} }) {
                my $covered = 0;
                for (my $i = 0 ; $i < scalar @{ $pspoc->{STATIC} } ; $i++) {
                    my $spoc  = $pspoc->{STATIC}[$i];
                    my $match = 0;
                    if (static_line_a_eq_b($spoc, $s)) {
                        warnpr "RAW: static coverd by: \'",
                          static_line_to_string($s),
                          "\' - RAW static discarded!\n";
                        $covered = 1;
                    }
                    elsif ($match = static_global_local_match_a_b($spoc, $s)) {
                        unless ($match == 3) {
                            mypr "RAW: spoc static \'",
                              static_line_to_string($spoc), " replaced by \'",
                              static_line_to_string($s),    "\'\n";
                            push @remove, $i;
                        }
                        else {
                            warnpr "RAW: weired match RAW: \'",
                              static_line_to_string($s), "\'\n";
                            warnpr "RAW: weired match SPOC: \'",
                              static_line_to_string($spoc), "\'\n";
                            warnpr "RAW: static discarded!\n";
                            $covered = 1;
                        }
                    }
                }
                $covered or push @std_static, $s;
            }
            for my $r (reverse sort @remove) {
                splice @{ $pspoc->{STATIC} }, $r, 1;
            }
            @{ $pspoc->{STATIC} } =
              (@{ $pspoc->{STATIC} }, @std_static),
              mypr " attached static entries: "
              . scalar @std_static . "\n";
        }
        ### GLOBAL PROCESSING ###
        my @std_global = ();
        if ($std->{GLOBAL}) {
            for my $s (@{ $std->{GLOBAL} }) {
                my $covered = 0;
                for (my $i = 0 ; $i < scalar @{ $pspoc->{GLOBAL} } ; $i++) {
                    my $spoc  = $pspoc->{GLOBAL}[$i];
                    my $match = 0;
                    if (pix_global_line_a_eq_b($spoc, $s)) {
                        warnpr "raw global coverd by: \'",
                          pix_global_line_to_string($s), "\'\n";
                        $covered = 1;
                    }
                }
                $covered or push @std_global, $s;
            }
            @{ $pspoc->{GLOBAL} } =
              (@{ $pspoc->{GLOBAL} }, @std_global),
              mypr " attached global entries: "
              . scalar @std_global . "\n";
        }
        ### NAT PROCESSING ###
        my @std_nat = ();
        if ($std->{NAT}) {
            for my $s (@{ $std->{NAT} }) {
                my $covered = 0;
                for (my $i = 0 ; $i < scalar @{ $pspoc->{NAT} } ; $i++) {
                    my $spoc  = $pspoc->{NAT}[$i];
                    my $match = 0;
                    if (pix_nat_line_a_eq_b($spoc, $s)) {
                        warnpr "raw nat coverd by: \'",
                          pix_nat_line_to_string($s), "\'\n";
                        $covered = 1;
                    }
                }
                $covered or push @std_nat, $s;
            }
            @{ $pspoc->{NAT} } = (@{ $pspoc->{NAT} }, @std_nat),
              mypr " attached nat entries: "
              . scalar @std_nat . "\n";
        }

    }
    else {
        mypr "--- raw processing: nothing to do\n";
    }
    mypr "--- raw processing: done\n";
    return 1;
}

#-------------- helper end

sub copy_structure {
    my $src = shift;

    #print "-$src-\n";
    if (ref $src eq 'SCALAR') {
        my $dst = $$src;
        return \$dst;
    }
    elsif (ref $src eq 'ARRAY') {
        my @dst = @$src;
        for my $entry (@dst) {
            (ref $entry) and $entry = copy_structure($entry);
        }
        return \@dst;
    }
    elsif (ref $src eq 'HASH') {
        my %dst = %$src;
        for my $entry (keys %dst) {
            (ref($dst{$entry})) and $dst{$entry} = copy_structure($dst{$entry});
        }
        return \%dst;
    }
    else {
        errpr meself(2) . "unsupported type" . ref($src) . "\n";
    }
}


#
# supports only object-group type 'network' !!
#
sub pix_expand_acl_entry($$$$) {
    my ($self, $ace, $parsed, $acl_name) = @_;

    my $groups = $parsed->{OBJECT_GROUP};
    my $replace;

    for my $adr ('SRC', 'DST') {
        if ($ace->{PROTO}->{$adr}->{OBJECT_GROUP}) {
            my $obj_id = $ace->{PROTO}->{$adr}->{OBJECT_GROUP};

            #check
            unless ($groups->{$obj_id}) {
                errpr meself(1), "no group name \'$obj_id\' found\n";
            }
            unless ($groups->{$obj_id}->{TYPE} eq 'network') {
                errpr meself(1),
                  "unsupported object type \'$groups->{$obj_id}->{TYPE}\'\n";
            }
            for my $network (@{ $groups->{$obj_id}->{NETWORK_OBJECT} }) {
                push @{ $replace->{$adr} }, $network;
            }

            # remeber that group $obj_id is referenced by ACL $acl
            $groups->{$obj_id}->{ACL_REFERENCES}->{$acl_name} = 1;
            $parsed->{ACCESS_LIST}->{$acl_name}->{GROUP_REFERENCES}->{$obj_id} =
              1;

        }
        else {
            push @{ $replace->{$adr} }, $ace->{PROTO}->{$adr};
        }
    }
    my @expanded;
    for my $src (@{ $replace->{SRC} }) {
        for my $dst (@{ $replace->{DST} }) {
            my $copy = copy_structure($ace);
            $copy->{PROTO}->{SRC}->{MASK} = $src->{MASK};
            $copy->{PROTO}->{SRC}->{BASE} = $src->{BASE};
            $copy->{PROTO}->{DST}->{MASK} = $dst->{MASK};
            $copy->{PROTO}->{DST}->{BASE} = $dst->{BASE};
            $copy->{EXPANDED_FROM}        = $ace;
            push @expanded, $copy;
        }
    }
    return \@expanded;
}

sub pix_parse ( $$$ ) {

    my ($self, $p, $conf) = @_;

    # standard conf arg is an arry :(
    my $conf_as_string = join '', @{$conf};

    # *** parse ***

    my $pix_parser = Dprs->new(MODE => 'pix');
    if ($self->{VERSION} =~ /7\./) {
        $pix_parser->pix7_write_term_config($p, \$conf_as_string);
    }
    else {
        $pix_parser->pix_write_term_config($p, \$conf_as_string);
    }

    #
    # *** postprocess ***
    #
    # expand aces
    my $acl_counter   = 0;
    my $d_acl_counter = 0;
    my $c_acl_counter = 0;
    for my $acl_name (sort keys %{ $p->{ACCESS_LIST} }) {
        my %temp;
        for my $entry (@{ $p->{ACCESS_LIST}->{$acl_name}->{RAW_ARRAY} }) {
            next
              unless $entry->{MODE};   # filter out 'remark', 'compiled', etc...
            my $e_acl = $self->pix_expand_acl_entry($entry, $p, $acl_name);

#	    push @{$p->{ACCESS}->{$acl_name}},@$e_acl;
#	    $acl_counter += scalar @$e_acl;
            for my $e_entry (@$e_acl) {
                my $aclstrg = acl_line_to_string('pix', $e_entry);
                unless (exists $temp{$aclstrg}) {
                    push @{ $p->{ACCESS}->{$acl_name} }, $e_entry;
                    $temp{$aclstrg} = 1;
                    $acl_counter++;
                }
                else {
                    $d_acl_counter++;
                }
            }
        }
    }

    # access-group
    for my $acl_name (sort keys %{ $p->{ACCESS_GROUP} }) {
        my $entry = $p->{ACCESS_GROUP}->{$acl_name};
        $p->{IF}->{ $entry->{IF_NAME} }->{ACCESS} = $acl_name;
        if (exists $p->{ACCESS_LIST}->{$acl_name}) {
            push @{ $p->{ACCESS_LIST}->{$acl_name}->{INTERFACE_REFERENCES} },
              $entry->{IF_NAME};
        }
    }

    # interface and nameif
    if ($self->{VERSION} =~ /7\./) {

        # bind ip address to IF_NAME
        for my $hw_id (sort keys %{ $p->{HWIF} }) {
            my $entry = $p->{HWIF}->{$hw_id};
            if (defined $entry->{IF_NAME}) {
                $p->{IF}->{ $entry->{IF_NAME} }->{SHUTDOWN} =
                  $entry->{SHUTDOWN};
                if (!$entry->{SHUTDOWN}) {
                    $p->{IF}->{ $entry->{IF_NAME} }->{ADDRESS}->{BASE} =
                      $entry->{ADDRESS}->{BASE};
                    $p->{IF}->{ $entry->{IF_NAME} }->{ADDRESS}->{MASK} =
                      $entry->{ADDRESS}->{MASK};
                }
            }
        }
    }
    else {
        for my $hw_id (sort keys %{ $p->{HWIF} }) {
            my $entry = $p->{HWIF}->{$hw_id};
            $p->{IF}->{ $entry->{IF_NAME} }->{SHUTDOWN} = $entry->{SHUTDOWN};
            if (!$entry->{SHUTDOWN}) {
                $p->{IF}->{ $entry->{IF_NAME} }->{ADDRESS}->{BASE} =
                  $p->{IP}->{ADDRESS}->{ $entry->{IF_NAME} }->{BASE};
                $p->{IF}->{ $entry->{IF_NAME} }->{ADDRESS}->{MASK} =
                  $p->{IP}->{ADDRESS}->{ $entry->{IF_NAME} }->{MASK};
            }
        }
    }
    for my $if (sort keys %{ $p->{IF} }) {
        if ($p->{IF}->{$if}->{SHUTDOWN}) {
            mypr meself(2) . "Interface $if: shutdown\n";
        }
        else {
            if (exists $p->{IF}->{$if}->{ADDRESS}) {
                my $adr = $p->{IF}->{$if}->{ADDRESS};
                if (defined $adr->{BASE} and defined $adr->{MASK}) {
                    mypr meself(2)
                      . "Interface $if: IP: "
                      . int2quad($adr->{BASE}) . "/"
                      . int2quad($adr->{MASK}) . "\n";
                }
                else {
                    warnpr
                      "undifined address for non-shutdown interface \'$if\'\n";
                }
            }
        }
    }

    # crypto maps
    for my $map_name (keys %{ $p->{CRYPTO}->{MAP} }) {
        for my $seq_num (keys %{ $p->{CRYPTO}->{MAP}->{$map_name}->{SEQ_NUM} })
        {
            if ($p->{CRYPTO}->{MAP}->{$map_name}->{SEQ_NUM}->{$seq_num}
                ->{MATCH_ADDRESS})
            {
                my $acl_name =
                  $p->{CRYPTO}->{MAP}->{$map_name}->{SEQ_NUM}->{$seq_num}
                  ->{MATCH_ADDRESS};
                if (exists $p->{ACCESS_LIST}->{$acl_name}) {
                    push
                      @{ $p->{ACCESS_LIST}->{$acl_name}->{CRYPTO_REFERENCES} },
                      { MAP => $map_name, SEQ_NUM => $seq_num };
                }
                else {
                    warnpr
                      "crypto map match address acl $acl_name does not exist\n";
                }
            }
        }
    }
    mypr meself(2)
      . ": CRYPTO MAPS found: "
      . scalar(keys %{ $p->{CRYPTO}->{MAP} }) . "\n";

    #
    # ****** TO DO: more consistence checking
    #
    mypr meself(2)
      . ": OBJECT GROUPS found: "
      . scalar(keys %{ $p->{OBJECT_GROUP} }) . "\n";
    mypr meself(2)
      . ": ACCESS LISTS found: "
      . scalar(keys %{ $p->{ACCESS} }) . "\n";
    for my $acl_name (sort keys %{ $p->{ACCESS_LIST} }) {
        if ($p->{ACCESS_LIST}->{$acl_name}->{CRYPTO_REFERENCES}) {
            $c_acl_counter++;
        }
        elsif ($p->{ACCESS_LIST}->{$acl_name}->{INTERFACE_REFERENCES}) {
            mypr meself(2)
              . ": $acl_name "
              . scalar @{ $p->{ACCESS}->{$acl_name} } . "\n";
        }
        else {
            $p->{ACCESS_LIST}->{$acl_name}->{NO_REFERENCES} = 1;
            mypr meself(2)
              . ": $acl_name "
              . scalar @{ $p->{ACCESS}->{$acl_name} }
              . " *** SPARE ***\n";
        }
    }
    ($c_acl_counter)
      and mypr "--> found $c_acl_counter acls referenced by crypto maps\n";
    mypr meself(2) . ": GLOBALS found: " . scalar @{ $p->{GLOBAL} } . "\n";
    mypr meself(2) . ": NATS    found: " . scalar @{ $p->{NAT} } . "\n";
    mypr meself(2) . ": STATICS found: " . scalar @{ $p->{STATIC} } . "\n";
    mypr meself(2) . ": ROUTES  found: " . scalar @{ $p->{ROUTING} } . "\n";

    # double entries in fetched pix config are impossible, so this could
    # only happen when parsing the epilog
    ($d_acl_counter)
      and mypr "double acl entries skipped: $d_acl_counter\n";
    return 1;
}

sub pix_transfer_lines( $$$$$ ) {
    my ($self, $printstring, $compare, $spoc_lines, $device_lines) = @_;
    my $counter;
    my $change = 0;
    mypr "compare device entries with netspoc:\n";
    scalar @{$device_lines} or mypr "-";
    for my $d (@{$device_lines}) {    # from device
        $counter++;
        mypr " $counter";
        for my $s (@{$spoc_lines}) {    # from netspoc
                                        #($s) or next;
            if (&$compare($d, $s)) {
                $d->{DELETE} = $s->{DELETE} = 1;
                last;
            }
        }
    }
    mypr "\n";
    unless ($self->{COMPARE}) {
        mypr "deleting non matching entries from device:\n";
        $counter = 0;
        for my $d (@{$device_lines}) {
            ($d->{DELETE}) and next;
            $counter++;
            my $tr = join ' ', "no", &$printstring($d);
            $self->cmd($tr) or exit -1;
            mypr " $counter";
        }
        $counter and $change = 1;
        mypr " $counter\n";
        mypr "transfer entries to device:\n";
        $counter = 0;
        for my $s (@{$spoc_lines}) {
            ($s->{DELETE}) and next;
            $counter++;
            $self->cmd(&$printstring($s)) or exit -1;
            mypr " $counter";
        }
        $counter and $change = 1;
        mypr " $counter\n";
    }
    else {

        # show compare results
        mypr "non matching entries on device:\n";
        $counter = 0;
        for my $d (@{$device_lines}) {
            ($d->{DELETE}) and next;
            $counter++;
            mypr &$printstring($d) . "\n";
        }
        mypr "total: " . $counter, "\n";
        ($counter) and $change = 1;
        mypr "additional entries from spoc:\n";
        $counter = 0;
        for my $s (@{$spoc_lines}) {
            ($s->{DELETE}) and next;
            $counter++;
            mypr &$printstring($s), "\n";
        }
        mypr "total: ", $counter, "\n";
        ($counter) and $change = 1;
    }
    return $change;
}

sub pix_acls_textual_identical($$$) {
    my ($self, $confacl, $spocacl) = @_;
    mypr "check for textual identity\n";
    if (scalar @{$spocacl} == scalar @{$confacl}) {
        mypr " acls have equal lenght: ", scalar @{$spocacl}, "\n";
        mypr " compare line by line: ";
        for (my $i = 0 ; $i < scalar @{$spocacl} ; $i++) {

            #mypr " $i";
            if (acl_line_a_eq_b($$spocacl[$i], $$confacl[$i])) {
                next;
            }
            else {
                mypr "equal lenght acls (", scalar @{$spocacl}, ") differ at ",
                  ++$i, "!\n";
                return 0;
            }
        }
        mypr "no diffs\n";
        return 1;
    }
    else {
        mypr "lenght of acls differ: at device ", scalar @{$confacl},
          " from netspoc ", scalar @{$spocacl}, "\n";
        return 0;
    }
}

sub pix_acls_semantical_indentical($$$$) {
    my ($self, $confacl, $spocacl, $if) = @_;
    unless ($self->{COMPARE}) {
        mypr "  do semantic compare - at interface $if:\n";
        if (
            acl_array_compare_a_in_b($spocacl, $confacl, 'pix', 4)    # 4 silent
            && acl_array_compare_a_in_b($confacl, $spocacl, 'pix', 4)
          )
        {
            mypr "   -> interface $if: acls identical\n";
            return 1;
        }
        else {
            mypr "   -> interface $if: acls differ\n";
            return 0;
        }
    }
    else {

        # show compare results
        mypr "#### BEGIN NEW in OLD - interface $if\n";
        my $newinold =
          acl_array_compare_a_in_b($spocacl, $confacl, 'pix', $self->{CMPVAL});
        mypr "#### END   NEW in OLD - interface $if\n";
        mypr "#### BEGIN OLD in NEW - interface $if\n";
        my $oldinnew =
          acl_array_compare_a_in_b($confacl, $spocacl, 'pix', $self->{CMPVAL});
        mypr "#### END   OLD in NEW - interface $if\n";
        if ($newinold && $oldinnew) {
            mypr "#### ACLs equal for interface $if\n";
            return 1;
        }
        else {
            mypr "#### ACLs differ - at interface $if ####\n";
            return 0;
        }
        mypr "#### --------------------------------\n";
    }
}

sub prepare_filemode($$$) {
    my ($self, $path1, $path2) = @_;
    my $parsed1 = {};
    my $parsed2 = {};

    my $conf1 = $self->load_spocfile($path1);
    my $epi1 = $self->load_epilog($self->get_epilog_name($path1));
    my $conf2 = $self->load_spocfile($path2);
    my $epi2 = $self->load_epilog($self->get_epilog_name($path2));
    if (!$self->parse_spocfile($parsed1, $conf1)) {
        errpr "parse error\n";
        return 0;
    }
    unless ($parsed1->{MODEL} eq "PIX") {
        mypr "wrong MODEL $parsed1->{MODEL} in parsed pix config\n";
        return 0;
    }

    if (!$self->parse_spocfile($parsed2, $conf2)) {
        errpr "parse error\n";
        return 0;
    }
    unless ($parsed2->{MODEL} eq "PIX") {
        mypr "wrong MODEL $parsed2->{MODEL} in parsed pix config\n";
        return 0;
    }

    #
    # *** merge EPILOG into SPOCCONFIG
    #
    $self->process_rawdata($parsed1, $epi1)  or return 0;
    $self->process_rawdata($parsed2, $epi2) or return 0;

    return($parsed1, $parsed2);
}

sub prepare_devicemode( $$$ ) {
    my ($self, $device_lines, $path) = @_;
    my $pspoc = {};
    my $conf  = {};

    my $spoc_lines = $self->load_spocfile($path);
    my $epilog_lines = $self->load_epilog($self->get_epilog_name($path));

    # *** PARSE SPOC CONFIG ***
    if (!$self->parse_spocfile($pspoc, $spoc_lines)) {
        errpr "parse error\n";
        return 0;
    }
    unless ($pspoc->{MODEL} eq "PIX") {
        mypr "wrong MODEL $pspoc->{MODEL} in parsed pix config\n";
        return 0;
    }

    # *** PARSE DEVICE CONFIG ***
    unless ($self->pix_parse($conf, $device_lines)) {
        errpr "could not parse pix config\n";
        return 0;
    }

    # *** check for unknown interfaces at device ***
    $self->checkinterfaces($conf, $pspoc);

    #
    # *** merge EPILOG into SPOCCONFIG
    #
    $self->process_rawdata($pspoc, $epilog_lines) or return 0;
    return($conf, $pspoc);
}

sub pixtrans () {
    my($self, $conf, $pspoc) = @_;

    # *** BEGIN TRANSFER ***
    unless ($self->{COMPARE}) {
        $self->cmd('configure terminal') or exit -1;
    }

    #
    # *** routing ***
    #
    if ($pspoc->{ROUTING} and scalar @{ $pspoc->{ROUTING} }) {

        #mypr "found:\n";
        my $counter;
        if (exists $conf->{ROUTING} && !scalar(@{ $conf->{ROUTING} })) {
            errpr "ERROR: no routing entries found on device\n";
            return 0;
        }

        # sort netspoc-generated routing entries (long masks first)
        my @route_sort =
          sort { $b->{MASK} <=> $a->{MASK} } @{ $pspoc->{ROUTING} };
        $pspoc->{ROUTING} = \@route_sort;
        mypr "==== compare routing information ====\n\n";
        mypr " routing entries on device:    ", scalar @{ $conf->{ROUTING} },
          "\n";
        mypr " routing entries from netspoc: ", scalar @{ $pspoc->{ROUTING} },
          "\n";
        for my $c (@{ $conf->{ROUTING} }) {    # from device
            $counter++;

            #unless($self->{COMPARE}){
            #	mypr " $counter";
            #   }
            for my $s (@{ $pspoc->{ROUTING} }) {    # from netspoc
                                                  #($s) or next;
                if (route_line_a_eq_b($c, $s)) {
                    $c->{DELETE} = $s->{DELETE} = 1;
                    last;

                    # double entries in spocfile are *not* deleted :(
                }
            }
        }
        mypr "\n";
        unless ($self->{COMPARE}) {
            mypr "transfer routing entries to device:\n";
            $counter = 0;
            for my $r (@{ $pspoc->{ROUTING} }) {
                ($r->{DELETE}) and next;
                $counter++;

                # pix did not allow 2 entries for same destination
                for my $c (@{ $conf->{ROUTING} }) {
                    ($c->{DELETE}) and next;
                    if (route_line_destination_a_eq_b($r, $c)) {
                        my $tr = join ' ', "no",
                          route_line_to_string('pix', $c);
                        $self->cmd($tr) or exit -1;
                        $c->{DELETE} = 1;    # could not deleted 2 times
                    }
                }
                $self->cmd(route_line_to_string('pix', $r)) or exit -1;
                mypr " $counter";
            }
            $counter and $self->{ROUTE_CHANGE} = '*** routing changed ***';
            mypr " $counter";
            mypr "\n";
            mypr "deleting non matching routing entries from device:\n";
            $counter = 0;
            for my $r (@{ $conf->{ROUTING} }) {
                ($r->{DELETE}) and next;
                $counter++;
                my $tr = join ' ', "no", route_line_to_string('pix', $r);
                $self->cmd($tr) or exit -1;
                mypr " $counter";
            }
            $counter and $self->{ROUTE_CHANGE} = '*** routing changed ***';
            mypr " $counter";
            mypr "\n";
        }
        else {

            # show compare results
            mypr "additional routing entries from spoc:\n";
            $counter = 0;
            for my $r (@{ $pspoc->{ROUTING} }) {
                ($r->{DELETE}) and next;
                $counter++;
                mypr route_line_to_string('pix', $r), "\n";
            }
            mypr "total: $counter\n";
            ($counter) and $self->{ROUTE_CHANGE} = '*** routing changed ***';
            mypr "non matching routing entries on device:\n";
            $counter = 0;
            for my $r (@{ $conf->{ROUTING} }) {
                ($r->{DELETE}) and next;
                $counter++;
                mypr route_line_to_string('pix', $r), "\n";
            }
            mypr "total: $counter\n";
            ($counter) and $self->{ROUTE_CHANGE} = '*** routing changed ***';
        }
        mypr "==== done ====\n";
    }
    else {
        mypr "no routing entries specified - leaving routes untouched\n";
    }

    #
    # *** access-lists ***
    #
    my $get_acl_names_and_objects = sub {
        my ($intf)  = @_;
        my $sa_name = $pspoc->{IF}->{$intf}->{ACCESS};
        my $spocacl = $pspoc->{ACCESS}->{$sa_name};
        my $ca_name =
          (exists $conf->{IF}->{$intf}->{ACCESS})
          ? $conf->{IF}->{$intf}->{ACCESS}
          : '';
        my $confacl = $ca_name ? $conf->{ACCESS}->{$ca_name} : '';
        return ($confacl, $spocacl, $ca_name, $sa_name);
    };

    # generate new names for transfer
    #
    # possible names are (per name convention):  <spoc-name>-DRC-<index>
    #
    my $generate_names_for_transfer = sub {
        my ($obj_id, $objects) = @_;
        my $new_id_prefix = "$obj_id-DRC-";
        my $new_id_index  = 0;
        while (exists $objects->{"$new_id_prefix$new_id_index"}) {
            $new_id_index++;
        }
        return "$new_id_prefix$new_id_index";
    };
    my $pix_mark_for_transfer;
    $pix_mark_for_transfer = sub {
        my ($acl_name) = @_;
        ($pspoc->{ACCESS_LIST}->{$acl_name}->{TRANSFER}) and return;
        $pspoc->{ACCESS_LIST}->{$acl_name}->{TRANSFER} = 1;
        mypr "marked acl $acl_name for transfer\n";
        for my $gid (
            keys %{ $pspoc->{ACCESS_LIST}->{$acl_name}->{GROUP_REFERENCES} })
        {
            unless ($pspoc->{OBJECT_GROUP}->{$gid}->{TRANSFER}) {
                $pspoc->{OBJECT_GROUP}->{$gid}->{TRANSFER} = 1;
                print "marked group $gid for transfer\n";
            }
            for my $name (
                keys %{ $pspoc->{OBJECT_GROUP}->{$gid}->{ACL_REFERENCES} })
            {
                &$pix_mark_for_transfer($name);
            }
        }
    };
    my $pix_mark_for_remove;
    $pix_mark_for_remove = sub {

        # non recursive!
        my ($acl_name) = @_;
        ($conf->{ACCESS_LIST}->{$acl_name}->{REMOVE})
          and errpr "unexpected REMOVE mark\n";
        $conf->{ACCESS_LIST}->{$acl_name}->{REMOVE} = 1;
        mypr "marked acl $acl_name for remove\n";
        for my $gid (
            keys %{ $conf->{ACCESS_LIST}->{$acl_name}->{GROUP_REFERENCES} })
        {
            next if ($conf->{OBJECT_GROUP}->{$gid}->{REMOVE});
            my $remove_group = "OK";
            for
              my $name (keys %{ $conf->{OBJECT_GROUP}->{$gid}->{ACL_REFERENCES} })
            {

                # only remove group from pix if all ACLs that reference
                # this group are renewed by netspoc!
                unless ($pspoc->{ACCESS_LIST}->{$name}->{TRANSFER}) {
                    $remove_group = "NO";
                    last;
                }
            }
            if ($remove_group eq "OK") {
                $conf->{OBJECT_GROUP}->{$gid}->{REMOVE} = 1;
                mypr "marked group $gid for remove\n";

            }
        }
    };
    unless (exists $pspoc->{IF}) {
        warnpr " no interfaces specified - leaving access-lists untouched\n";
    }
    else {
        mypr "processing access-lists\n";

        mypr keys %{ $pspoc->{IF} };
        mypr "+++\n";

        for my $intf (keys %{ $pspoc->{IF} }) {
            unless (exists $conf->{IF}->{$intf}) {
                errpr
                  "netspoc configured interface \'$intf\' not found on device\n";

                #errpr "skiping\n";
                #next;
                return 0;
            }
        }

        # detect diffs
        if ($self->{COMPARE}) {
            for my $intf (keys %{ $pspoc->{IF} }) {
                mypr "interface $intf\n";
                my ($confacl, $spocacl, $confacl_name, $spocacl_name) =
                  &$get_acl_names_and_objects($intf);

                if ($confacl_name && $confacl) {
                    unless (
                        $self->pix_acls_textual_identical($confacl, $spocacl)
                        or $self->pix_acls_semantical_indentical(
                            $confacl, $spocacl, $intf
                        )
                      )
                    {
                        $self->{ACL_CHANGE} = '*** acls    changed ***';
                    }
                }
                else {

                    $self->{ACL_CHANGE} = '*** new acls!       ***';
                    mypr "#### OOPS:  $spocacl_name at interface $intf:\n";
                    mypr "#### OOPS:  no corresponding acl on device\n";
                }
                mypr "-------------------------------------------------\n";
            }
        }
        else {

            # mark objects to transfer
            for my $intf (keys %{ $pspoc->{IF} }) {
                mypr "interface $intf\n";
                my ($confacl, $spocacl, $confacl_name, $spocacl_name) =
                  &$get_acl_names_and_objects($intf);
                if ($pspoc->{ACCESS_LIST}->{$spocacl_name}->{TRANSFER}) {
                    mypr " ...already marked for transfer\n";
                    next;
                }
                if (!$confacl) {
                    warnpr "interface $intf no acl on device - new acl has ",
                      scalar @{ $pspoc->{ACCESS}->{$spocacl_name} }, " entries\n";
                    $self->{ACL_CHANGE} = 1;
                    &$pix_mark_for_transfer($spocacl_name);
                }
                elsif (!$self->pix_acls_textual_identical($confacl, $spocacl)
                    && !$self->pix_acls_semantical_indentical($confacl, $spocacl,
                        $intf))
                {

                    # either there is no acl on $intf or the acl differs
                    # mark groups and interfaces recursive for transfer of spocacls
                    $self->{ACL_CHANGE} = 1;
                    &$pix_mark_for_transfer($spocacl_name);
                }
                elsif ($self->{FORCE_TRANSFER}) {
                    warnpr "Interface $intf: transfer of ACL forced!\n";
                    $self->{ACL_CHANGE} = 1;
                    &$pix_mark_for_transfer($spocacl_name);
                }
                mypr "-------------------------------------------------\n";
            }

            # mark objects to remove
            for my $intf (keys %{ $pspoc->{IF} }) {

                #next if($conf->{IF}->{$intf}->{REMOVE}); # allready marked
                my ($confacl, $spocacl, $confacl_name, $spocacl_name) =
                  &$get_acl_names_and_objects($intf);
                next unless ($pspoc->{ACCESS_LIST}->{$spocacl_name}->{TRANSFER});
                next unless ($confacl);    # no ACL on device - nothing to mark
                &$pix_mark_for_remove($confacl_name);
            }

            # generate names for transfer
            for my $obj_id (keys %{ $pspoc->{OBJECT_GROUP} }) {
                next unless ($pspoc->{OBJECT_GROUP}->{$obj_id}->{TRANSFER});
                $pspoc->{OBJECT_GROUP}->{$obj_id}->{TRANSFER_ID} =
                  &$generate_names_for_transfer($obj_id, $conf->{OBJECT_GROUP});
            }
            for my $obj_id (keys %{ $pspoc->{ACCESS_LIST} }) {
                next unless ($pspoc->{ACCESS_LIST}->{$obj_id}->{TRANSFER});
                $pspoc->{ACCESS_LIST}->{$obj_id}->{TRANSFER_ID} =
                  &$generate_names_for_transfer($obj_id, $conf->{ACCESS_LIST});
            }
            my $pix_printer = Dprs->new(MODE => 'pix', PRINT => 'yes');

            # transfer groups
            mypr "transfer object-groups to device\n";
            for my $obj_id (keys %{ $pspoc->{OBJECT_GROUP} }) {
                next unless ($pspoc->{OBJECT_GROUP}->{$obj_id}->{TRANSFER});
                mypr
                  "object-group $pspoc->{OBJECT_GROUP}->{$obj_id}->{TRANSFER_ID}\n";
                my $copy = copy_structure($pspoc->{OBJECT_GROUP}->{$obj_id});

                # build transfer object group
                my $group_obj =
                  ({ $pspoc->{OBJECT_GROUP}->{$obj_id}->{TRANSFER_ID} => $copy });

                # generate commands
                my $string;
                $pix_printer->pix_object_group($group_obj, \$string);

                # build cmd array
                my @cmd_array = split '\n', $string;
                push @cmd_array, 'exit';
                my %DDH;    # detect double hash
                for (@cmd_array) {
                    if ($DDH{$_}) {
                        mypr "discard double entry $_ in group $obj_id\n";
                    }
                    else {
                        $DDH{$_} = 1;
                        $self->cmd($_) or exit -1;
                    }
                }
            }

            # transfer ACLs
            mypr "transfer access-lists to device\n";
            for my $obj_id (keys %{ $pspoc->{ACCESS_LIST} }) {
                next unless ($pspoc->{ACCESS_LIST}->{$obj_id}->{TRANSFER});
                my $transfer_id = $pspoc->{ACCESS_LIST}->{$obj_id}->{TRANSFER_ID};
                mypr "access-list $transfer_id\n";
                my $counter = 0;
                my $tr;
                for my $ace (@{ $pspoc->{ACCESS}->{$obj_id} }) {
                    if ($ace->{EXPANDED_FROM}) {
                        next if ($ace->{EXPANDED_FROM}->{COLLAPSED});
                        $ace->{EXPANDED_FROM}->{COLLAPSED} =
                          1;    # only one entry has to be transferred
                        my $new_ace = copy_structure($ace->{EXPANDED_FROM});
                        my $gid;
                        if ($new_ace->{PROTO}->{SRC}->{OBJECT_GROUP}) {
                            $gid = $new_ace->{PROTO}->{SRC}->{OBJECT_GROUP};
                            $new_ace->{PROTO}->{SRC}->{OBJECT_GROUP} =
                              $pspoc->{OBJECT_GROUP}->{$gid}->{TRANSFER_ID};
                        }
                        if ($new_ace->{PROTO}->{DST}->{OBJECT_GROUP}) {
                            $gid = $new_ace->{PROTO}->{DST}->{OBJECT_GROUP};
                            $new_ace->{PROTO}->{DST}->{OBJECT_GROUP} =
                              $pspoc->{OBJECT_GROUP}->{$gid}->{TRANSFER_ID};
                        }
                        $tr = join ' ', "access-list", $transfer_id,
                          acl_line_to_string('pix', $new_ace);
                    }
                    else {
                        $tr = join ' ', "access-list", $transfer_id,
                          acl_line_to_string('pix', $ace);
                    }
                    $self->cmd($tr) or exit -1;

                    #mypr "$tr\n";
                    $counter++;
                    mypr " $counter";
                }
                mypr "\n";

                # assign list to interface
                my $intf = $pspoc->{ACCESS_GROUP}->{$obj_id}->{IF_NAME};
                mypr "access-group $transfer_id in interface $intf\n";
                $self->cmd("access-group $transfer_id in interface $intf") or exit -1;
            }

            # remove ACLs (first, because otherwise group remove would not work)
            mypr "remove spare acls from device\n";
            for my $acl_name (keys %{ $conf->{ACCESS_LIST} }) {
                if (   $conf->{ACCESS_LIST}->{$acl_name}->{REMOVE}
                    or $conf->{ACCESS_LIST}->{$acl_name}->{NO_REFERENCES})
                {
                    if ($self->{VERSION} =~ /7\./) {
                        mypr " clear configure access-list $acl_name\n";
                        $self->cmd("clear configure access-list $acl_name") or exit -1;
                    }
                    else {
                        mypr " no access-list $acl_name\n";
                        $self->cmd("no access-list $acl_name") or exit -1;
                    }
                }
            }

            # remove groups
            mypr "remove spare object-groups from device\n";
            for my $gid (keys %{ $conf->{OBJECT_GROUP} }) {
                my $type = $conf->{OBJECT_GROUP}->{$gid}->{TYPE};
                if (!$conf->{OBJECT_GROUP}->{$gid}->{ACL_REFERENCES}
                    or $conf->{OBJECT_GROUP}->{$gid}->{REMOVE})
                {
                    mypr " no object-group $type $gid\n";
                    $self->cmd("no object-group $type $gid") or exit -1;
                }
            }

        }
    }

    #
    # *** static nat ***
    #
    mypr " === processing statics ===\n";
    $self->pix_transfer_lines(\&static_line_to_string, \&static_line_a_eq_b,
        $pspoc->{STATIC}, $conf->{STATIC})
      and $self->{STAT_CHANGE} = '*** statics changed ***';

    #
    # *** global pools ***
    #
    mypr " === processing global pools ===\n";
    $self->pix_transfer_lines(\&pix_global_line_to_string, \&pix_global_line_a_eq_b,
        $pspoc->{GLOBAL}, $conf->{GLOBAL})
      and $self->{GLOB_CHANGE} = '*** globals changed ***';

    #
    # *** (dynamic) nat ***
    #
    mypr " === processing nat ===\n";
    $self->pix_transfer_lines(\&pix_nat_line_to_string, \&pix_nat_line_a_eq_b,
        $pspoc->{NAT}, $conf->{NAT})
      and $self->{NAT_CHANGE} = '*** nat changed ***';

    unless ($self->{COMPARE}) {
        if (   $self->{ROUTE_CHANGE}
            or $self->{ACL_CHANGE}
            or $self->{STAT_CHANGE}
            or $self->{GLOB_CHANGE}
            or $self->{NAT_CHANGE})
        {
            mypr "saving config to flash\n";
            $self->cmd('write memory') or exit -1;
            mypr "...done\n";
        }
        else {
            mypr "no changes to save\n";
        }
    }
    else {
        mypr "compare finish\n";
    }
    return 1;
}
##################################################################
#    adaption layer
##################################################################

sub adaption($) {
    my($self) = @_;

    $self->{telnet_timeout} = $self->{OPTS}->{t} || 300;
    $self->{telnet_port}    = $self->{OPTS}->{T} || 23;
    $self->{telnet_logs}    = $self->{OPTS}->{L} || undef;

    $self->{CHECKHOST}   = $self->{GLOBAL_CONFIG}->{CHECKHOST};
    $self->{CHECKBANNER} = $self->{GLOBAL_CONFIG}->{CHECKBANNER};

    $self->{CHECK_DEVICE_IN_SPOCFILE} = $self->{OPTS}->{h} || "yes";
    $self->{FORCE_TRANSFER} = $self->{OPTS}->{F};
    $self->{PRINT_STATUS} = $self->{OPTS}->{S} ? "yes" : "no";
}

sub con_setup( $$ ) {
    my ($self, $startup_message) = @_;
    my $logfile =   $self->{telnet_logs} 
                  ? "$self->{telnet_logs}$self->{NAME}.tel"
		  : '';

    # Set global variable.
    $con =
          drc2_helper->new_console($self, "telnet", $logfile, $startup_message);
}

sub con_shutdown( $$ ) {
    my ($self, $shutdown_message) = @_;
    $con->con_issue_cmd("exit\n", eof, 5);
    $con->shutdown_console("$shutdown_message");
}

##################################################################
#    methods
##################################################################

sub check_device( $ ) {
    my($self)   = @_;
    my $retries = $self->{OPTS}->{p} || 3;
    return &checkping($self->{IP}, $retries);
}

sub check_crypto( $ ) {
    my($self) = @_;
    mypr "Sorry - Check Crypto Config not supported for devices of "
      . "type \'$self->{JOBTYPE}\'\n";
}

sub remote_execute( $ ) {
    my($self) = @_;
    $self->adaption();
    $self->con_setup(
        "START: execute user command at > " . scalar localtime() . " < ($id)");
    $self->prepare();
    $self->{OPTS}->{E} =~ s/\\n/\n/g;
    for my $line (split /[;]/, $self->{OPTS}->{E}) {
        my @output = $self->shcmd($line) or exit -1;
        mypr @output, "\n";
    }
    mypr "\n";
    $self->con_shutdown("STOP");
}

sub approve( $$ ) {
    my($self, $spoc_path) = @_;
    $self->adaption();

    # remember approve mode
    $self->{APPROVE}       = 1;
    $self->{COMPARE}       = undef;
    $self->{ROUTE_CHANGE}  = $self->{ACL_CHANGE} = $self->{STAT_CHANGE} =
      $self->{GLOB_CHANGE} = $self->{NAT_CHANGE} = 0;

    # set up console
    $self->con_setup("START: $self->{OPTS}->{P} (telnet) at > "
		     . scalar localtime()
		     . " < ($id)");

    # prepare device for configuration
    $self->prepare();

    # check if Netspoc message in device banner
    $self->checkbanner();

    # fetch device configuration
    my $device_lines = $self->get_config_from_device();

    #
    # now do the main thing
    #
    my ($device_conf, $spoc_conf) = 
	$self->prepare_devicemode($device_lines, $spoc_path) 
	or errpr "devicemode prepare failed\n";
    if ($self->pixtrans($device_conf, $spoc_conf)) {
        mypr "approve done\n";
    }
    else {
        errpr "approve failed\n";
    }
    $self->con_shutdown("STOP: $self->{OPTS}->{P} (telnet) at > "
			. scalar localtime()
			. " < ($id)");
}

sub compare( $$ ) {
    my($self, $spoc_path) = @_;
    $self->adaption();

    # save compare mode
    $self->{COMPARE}      = 1;
    $self->{CMPVAL}       = $self->{OPTS}->{C};
    $self->{ROUTE_CHANGE} = 'routing unchanged';
    $self->{ACL_CHANGE}   = 'acls unchanged';
    $self->{STAT_CHANGE}  = 'statics unchanged';
    $self->{GLOB_CHANGE}  = 'globals unchanged';
    $self->{NAT_CHANGE}   = 'nat unchanged';

    # set up console
    $self->con_setup("START: $self->{OPTS}->{P} (telnet) at > "
		     . scalar localtime()
		     . " < ($id)");

    # prepare device for configuration
    $self->prepare();

    # check if Netspoc message in device banner
    $self->checkbanner();

    # fetch device configuration
    my $device_lines = $self->get_config_from_device();

    #
    # now do the main thing
    #
    my ($device_conf, $spoc_conf) = 
	$self->prepare_devicemode($device_lines, $spoc_path) 
	or errpr "devicemode prepare failed\n";
    if ($self->pixtrans($device_conf, $spoc_conf)) {
        mypr "compare done\n";
    }
    else {
        errpr "compare failed\n";
    }

    $self->con_shutdown("STOP: $self->{OPTS}->{P} (telnet) at > "
			. scalar localtime()
			. " < ($id)");
    mypr "comp: $self->{OPTS}->{P} ", scalar localtime, " ($id)\n";
    mypr "comp: $self->{OPTS}->{P} $self->{NAME} $self->{ROUTE_CHANGE}\n";
    mypr "comp: $self->{OPTS}->{P} $self->{NAME} $self->{ACL_CHANGE}\n";
    mypr "comp: $self->{OPTS}->{P} $self->{NAME} $self->{STAT_CHANGE}\n";
    mypr "comp: $self->{OPTS}->{P} $self->{NAME} $self->{GLOB_CHANGE}\n";
    mypr "comp: $self->{OPTS}->{P} $self->{NAME} $self->{NAT_CHANGE}\n";

    if (   $self->{ROUTE_CHANGE} ne 'routing unchanged'
        or $self->{ACL_CHANGE}  ne 'acls unchanged'
        or $self->{STAT_CHANGE} ne 'statics unchanged'
        or $self->{GLOB_CHANGE} ne 'globals unchanged'
        or $self->{NAT_CHANGE}  ne 'nat unchanged')
    {
        return 1;
    }
    else {

        # no changes to report
        return 0;
    }
}

sub compare_files( $$$) {
    my ($self, $path1, $path2) = @_;
    &adaption($self);

    # save compare mode
    $self->{COMPARE} = 1;

    # default compare is silent(4) mode
    $self->{CMPVAL} = $self->{OPTS}->{C} || 4;

    $self->{ROUTE_CHANGE} = 'routing unchanged';
    $self->{ACL_CHANGE}   = 'acls unchanged';
    $self->{STAT_CHANGE}  = 'statics unchanged';
    $self->{GLOB_CHANGE}  = 'globals unchanged';
    $self->{NAT_CHANGE}   = 'nat unchanged';
    $self->{VERSION}      = "unknown";

    my ($conf1, $conf2) = $self->prepare_filemode($path1, $path2) 
	or errpr "filemode prepare failed\n";

    if ($self->pixtrans($conf1, $conf2)) {
        mypr "compare done\n";
    }
    else {
        errpr "compare failed\n";
    }
    mypr "comp: ", scalar localtime, " ($id)\n";
    mypr "comp: $self->{NAME} $self->{ROUTE_CHANGE}\n";
    mypr "comp: $self->{NAME} $self->{ACL_CHANGE}\n";
    mypr "comp: $self->{NAME} $self->{STAT_CHANGE}\n";
    mypr "comp: $self->{NAME} $self->{GLOB_CHANGE}\n";
    mypr "comp: $self->{NAME} $self->{NAT_CHANGE}\n";

    if (   $self->{ROUTE_CHANGE} ne 'routing unchanged'
        or $self->{ACL_CHANGE}  ne 'acls unchanged'
        or $self->{STAT_CHANGE} ne 'statics unchanged'
        or $self->{GLOB_CHANGE} ne 'globals unchanged'
        or $self->{NAT_CHANGE}  ne 'nat unchanged')
    {
        return 1;
    }
    else {

        # no changes to report
        return 0;
    }
}

# Packages must return a true value;
1;

