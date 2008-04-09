
package Netspoc::Approve::Device;

#
# Authors: Arne Spetzler, Heinz Knutzen, Daniel Brunkhorst
#
# Description:
# Module to fetch all Data available prior to connecting to device(s)
# needed to run the netspoc job.
#
# Base class for the different varieties of devices (IOS, PIX, etc.).
#

'$Id$ ' =~ / (.+),v (.+?) /;

my $id = "$1 $2";

sub version_drc2_job() {
    return $id;
}

use FindBin;
use lib $FindBin::Bin;
use strict;
use warnings;
use Fcntl qw/:flock/;    # import LOCK_* constants

use File::Basename;

use Netspoc::Approve::Helper;

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
sub get_global_config($) {
    my ($self) = @_;
    my $config = {};

    # Set masterdirectory and read global parameters.
    my $madhome = '/home/hk/';
    my $rcmad   = $madhome . '.rcmadnes';
    open(RCMAD, $rcmad) or die "Can't open $rcmad: $!\n";

    $config->{BINHOME}        = '';
    $config->{NETSPOC}        = '';
    $config->{CHECKHOST}      = '';
    $config->{EPILOGPATH}     = '';
    $config->{CODEPATH}       = '';
    $config->{STATUSPATH}     = '';
    $config->{MIGSTATPATH}    = '';
    $config->{VPNTMPDIR}      = '';
    $config->{CHECKBANNER}    = '';
    $config->{DEVICEDBPATH}   = '';
    $config->{LOCKFILEPATH}   = "$madhome/lock";
    $config->{AAA_CREDENTAIL} = '';
    $config->{SYSTEMUSER}     = '';

    while (<RCMAD>) {
        /^\s*BINHOME\s*=\s*(\S+)\s*$/       and $config->{BINHOME}      = $1;
        /^\s*NETSPOC\s*=\s*(\S+)\s*$/       and $config->{NETSPOC}      = $1;
        /^\s*CHECKHOSTNAME\s*=\s*(\S+)\s*$/ and $config->{CHECKHOST}    = $1;
        /^\s*CHECKBANNER\s*=\s*(\S+)\s*$/   and $config->{CHECKBANNER}  = $1;
        /^\s*EPILOGPATH\s*=\s*(\S+)\s*$/    and $config->{EPILOGPATH}   = $1;
        /^\s*CODEPATH\s*=\s*(\S+)\s*$/      and $config->{CODEPATH}     = $1;
        /^\s*STATUSPATH\s*=\s*(\S+)\s*$/    and $config->{STATUSPATH}   = $1;
        /^\s*MIGSTATPATH\s*=\s*(\S+)\s*$/   and $config->{MIGSTATPATH}  = $1;
        /^\s*VPNTMPDIR\s*=\s*(\S+)\s*$/     and $config->{VPNTMPDIR}    = $1;
        /^\s*DEVICEDB\s*=\s*(\S+)\s*$/      and $config->{DEVICEDBPATH} = $1;
        /^\s*AAA_CREDENTIALS\s*=\s*(\S+)\s*$/
          and $config->{AAA_CREDENTIAL} = $1;
        /^\s*SYSTEMUSER\s*=\s*(\S+)\s*$/ and $config->{SYSTEMUSER} = $1;
    }
    close RCMAD or die "could not close $rcmad\n";

    $config->{NETSPOC}    or die "netspoc basedir missing in $rcmad\n";
    $config->{EPILOGPATH} or die "path for epilog not found in $rcmad\n";
    $config->{STATUSPATH}
      or die "path for status update not found in $rcmad\n";
    $config->{DEVICEDBPATH} or die "missing DEVICEDB setting in $rcmad\n";
    $config->{VPNTMPDIR}    or die "missing VPNTMPDIR setting in $rcmad\n";
    $config->{SYSTEMUSER}   or die "name of privileged user not set\n";
    return $config;
}

sub build_db ($$) {
    my ($self, $path) = @_;

    my %LEG_ALL_DB;
    my %LEG_IP_DB;
    my %LEG_NAME_DB;
    my %LEG_ALIAS_DB;
    my %CW_IP_DB;

    my %NAME_HASH;
    my %IP_HASH;

    # get password data from cw_pass
    open(CSVDB, "$path/cw_pass") or die "could not open $path/cw_pass\n$!\n";
    for my $line (<CSVDB>) {
        $line =~ /^;/ and next;
        $line =~ s/[\"\r\n]//g;
        ($line) or next;
        my %OBJ;
        (
            $OBJ{NAME},     # Name (including domain or simply an IP)
            $OBJ{RO},       # RO community string
            $OBJ{RW},       # RW community string
            $OBJ{SN},       # Serial Number
            $OBJ{UF1},      # User Field 1 <-- Geraet hinter "ISDN" oder "Stand"
            $OBJ{UF2},      # User Field 2 <-- Zugehoerigkeit zu einer
                            # Netz-Gruppe (LN,SH,KR,DZ)
            $OBJ{CW_TYP},   # User Field 3 <-- Typ (sw,rt,pix) fuer
                            # switch,router,pix
            $OBJ{UF4},      # User Field 4
            $OBJ{TELNET_PASS},        # Name = Telnet password
            $OBJ{ENABLE_PASS},        # Name = Enable password
            $OBJ{ENABLE_SEC},         # = 11; Name = Enable secret
            $OBJ{TAC_USER},           # = 12; Name = Tacacs user
            $OBJ{TAC_PASS},           # = 13; Name = Tacacs password
            $OBJ{TAC_ENABLE_PASS},    # = 14; Name = Tacacs enable user
            $OBJ{TAC_ENABLE_USER},    # = 15; Name = Tacacs enable password
            $OBJ{LOCAL_USER},         # = 16; Name = Local user
            $OBJ{LOCAL_PASS},         # = 17; Name = Local password
            $OBJ{RCP_USER},           # = 18; Name = Rcp user
            $OBJ{RCP_PASS}            # = 19; Name = Rcp password
        ) = split /[,]/, $line;
        unless (exists $NAME_HASH{ $OBJ{NAME} }) {
            $NAME_HASH{ $OBJ{NAME} }->{SOURCE}->{LINE} = $line;
            $NAME_HASH{ $OBJ{NAME} }->{NAME}           = $OBJ{NAME};
            $NAME_HASH{ $OBJ{NAME} }->{PASS}           = $OBJ{TELNET_PASS};
            $NAME_HASH{ $OBJ{NAME} }->{ENABLE_PASS}    = $OBJ{ENABLE_PASS};
            $NAME_HASH{ $OBJ{NAME} }->{LOCAL_USER}     = $OBJ{LOCAL_USER};
            $NAME_HASH{ $OBJ{NAME} }->{TYPE}           = $OBJ{CW_TYP};
        }
        else {
            mypr "PASS_DBB: CiscoWorks pass db: discarded line \'$line\'\n";
            mypr "PASS_DBB:  -> object name already found in "
              . "\'$NAME_HASH{$OBJ{NAME}}->{SOURCE}->{LINE}\'\n";
        }
    }
    close CSVDB;

    # use data from cw_ip to obtain ip adresses for objects from cw_pass
    #
    #   the data in cw_ip is actually expected to be the LMHOSTS file
    #   from an microsoft Windows CiscoWorks machine
    #
    open(CSVDB, "$path/cw_ip") or die "could not open $path/cw_ip\n$!\n";
    for my $line (<CSVDB>) {
        $line =~ /^#/ and next;
        $line =~ s/[\"\r\n]//g;
        ($line) or next;
        my %OBJ;
        ($OBJ{IP}, $OBJ{NAME}) = split " ", $line;
        unless (exists $CW_IP_DB{ $OBJ{NAME} }) {
            $CW_IP_DB{ $OBJ{NAME} }->{SOURCE}->{LINE} = $line;
            $CW_IP_DB{ $OBJ{NAME} }->{NAME}           = $OBJ{NAME};
            $CW_IP_DB{ $OBJ{NAME} }->{IP}             = $OBJ{IP};
        }
        else {
            unless ($line eq $CW_IP_DB{ $OBJ{NAME} }->{SOURCE}->{LINE}) {
                mypr "PASS_DBB: CiscoWorks ip db: discarded line "
                  . "\'$line\'\n";
                mypr "PASS_DBB:   -> object name already found "
                  . "in \'$CW_IP_DB{$OBJ{NAME}}->{SOURCE}->{LINE}\'\n";
            }
        }
    }
    close CSVDB;
    for my $entry (values %NAME_HASH) {
        if (exists $CW_IP_DB{ $entry->{NAME} }) {
            $entry->{IP} = $CW_IP_DB{ $entry->{NAME} }->{IP};

            # now add this entry also to %IP_HASH
            unless (exists $IP_HASH{ $entry->{IP} }) {
                $IP_HASH{ $entry->{IP} } = $entry;
            }
            else {
                mypr "PASS_DBB: CiscoWorks ip db:  NOT added to IP_HASH DB"
                  . " \'$entry->{SOURCE}->{LINE}\'\n";
            }
        }
        elsif (defined quad2int_2($entry->{NAME})) {

            # no ip for this object found - so this may be a switch without
            # name - and we should not bother
            $entry->{IP} = $entry->{NAME};
            $IP_HASH{ $entry->{IP} } = $entry;
        }
        elsif ($entry->{NAME} =~ /Cisco Systems NM data import/) {

            #nothing to do
        }
        else {
            mypr "PASS_DBB: CiscoWorks ip db: no ip address found for objekt"
              . " \'$entry->{SOURCE}->{LINE}\'\n";
        }
    }

    #
    # at this point we currently know nothing about aliases and object types
    # so we still need the 'old' allp.csv file:
    #
    # data from lecagy db
    open(CSVDB, "$path/allp.csv") or die "could not open $path/allp.csv\n$!\n";
    for my $line (<CSVDB>) {
        $line =~ /^#/ and next;
        $line =~ s/[\"\n]//g;
        ($line) or next;
        my %OBJ;
        (
            $OBJ{NAME}, $OBJ{IP}, $OBJ{PASS}, $OBJ{ALIAS}, my $status,
            $OBJ{TYPE}, $OBJ{ENABLE_PASS}
        ) = split(/,/, $line);
        $OBJ{SOURCE}->{LINE} = $line;
        ($status =~ "aktiv") or mypr "PASS_DBB: status is $status\n";
        $LEG_ALL_DB{ \%OBJ } = \%OBJ;

        unless (exists $LEG_NAME_DB{ $OBJ{NAME} }) {
            $LEG_NAME_DB{ $OBJ{NAME} } = \%OBJ;
        }
        else {

            #unless($line eq $LEG_NAME_DB{$OBJ{NAME}}->{SOURCE}->{LINE}){
            mypr "PASS_DBB: legacy name db: discarded line     \'$line\'\n";
            mypr "PASS_DBB:   -> object name already found in "
              . "\'$LEG_NAME_DB{$OBJ{NAME}}->{SOURCE}->{LINE}\'\n";

            #}
        }
        if ($OBJ{ALIAS}) {    # assume no alias if literally "0"
            unless (exists $LEG_ALIAS_DB{ $OBJ{ALIAS} }) {
                $LEG_ALIAS_DB{ $OBJ{ALIAS} } = \%OBJ;
            }
            else {

                #unless($line eq $LEG_ALIAS_DB{$OBJ{ALIAS}}->{SOURCE}->{LINE}){
                mypr "PASS_DBB: legacy alias db: discarded line  "
                  . "\'$line\'\n";
                mypr "PASS_DBB:    -> object alias already found "
                  . "in \'$LEG_ALIAS_DB{$OBJ{ALIAS}}->{SOURCE}->{LINE}\'\n";

                #}
            }
        }
        unless (exists $LEG_IP_DB{ $OBJ{IP} }) {
            $LEG_IP_DB{ $OBJ{IP} } = \%OBJ;
        }
        else {

            #unless($line eq $LEG_IP_DB{$OBJ{IP}}->{SOURCE}->{LINE}){
            mypr "PASS_DBB: legacy ip db:   discarded line     \'$line\'\n";
            mypr "PASS_DBB:    -> object ip already found in  "
              . "\'$LEG_IP_DB{$OBJ{IP}}->{SOURCE}->{LINE}\'\n";

            #}
        }
    }
    close CSVDB;

    # enhance %NAME_HASH (%IP_HASH implicitly) by data from legacy db
    # if no data from legacy available:
    #
    # set TYPE  as IOS if NAME_HASH TYPE empty
    # guess ALIAS as 0
    #
    # !!! treat data from CiscoWorks as more reliable as legacy data !!!
    #
    # mark "used" entries in legacy db
    for my $entry (values %NAME_HASH) {
        $entry->{TYPE} or $entry->{TYPE} = "ios";
        $entry->{TYPE} eq 'L3sw'
          and $entry->{TYPE} = "ios";    # Switches are handled as routers
        my $found;
        if (exists $LEG_NAME_DB{ $entry->{NAME} }) {
            $found = $LEG_NAME_DB{ $entry->{NAME} };

            # use password from Cisco Works in legacy DB!
            $found->{PASS} = $entry->{PASS};

            # use password from Cisco Works in legacy DB!
            $found->{ENABLE_PASS} = $entry->{ENABLE_PASS};

            # use user from Cisco Works in legacy DB!
            $found->{LOCAL_USER} = $entry->{LOCAL_USER};
            $entry->{ALIAS}      = $found->{ALIAS};

            # mark as used
            $found->{USED} = 1;
        }
        if (exists $LEG_ALIAS_DB{ $entry->{NAME} }) {
            if ($found) {
                if ($found ne $LEG_ALIAS_DB{ $entry->{NAME} }) {
                    mypr "PASS_DBB: while enhancing %NAME_HASH: "
                      . "name match \'$found->{SOURCE}->{LINE}\'\n";
                    mypr "PASS_DBB:          alias match \' "
                      . "$LEG_ALIAS_DB{$entry->{NAME}}->{SOURCE}->{LINE}\'\n";
                }
            }
            else {
                $found = $LEG_ALIAS_DB{ $entry->{NAME} };

                # use password from Cisco Works in legacy DB!
                $found->{PASS} = $entry->{PASS};

                # use password from Cisco Works in legacy DB!
                $found->{ENABLE_PASS} = $entry->{ENABLE_PASS};

                # use user from Cisco Works in legacy DB!
                $found->{LOCAL_USER} = $entry->{LOCAL_USER};
                $entry->{ALIAS}      = $entry->{NAME};
                $entry->{NAME}       = $found->{NAME};

                # mark as used
                $found->{USED} = 1;
            }
        }
        if ($entry->{IP} and exists $LEG_IP_DB{ $entry->{IP} }) {
            if ($found) {
                if ($found ne $LEG_IP_DB{ $entry->{IP} }) {
                    errpr "while enhancing %NAME_HASH: name/alias "
                      . "match \'$found->{SOURCE}->{LINE}\'\n";
                    errpr "                                    ip match "
                      . "\'$LEG_IP_DB{$entry->{IP}}->{SOURCE}->{LINE}\'\n";
                }
            }
            else {
                $found = $LEG_IP_DB{ $entry->{IP} };

                # use password from Cisco Works in legacy DB!
                $found->{PASS} = $entry->{PASS};

                # use password from Cisco Works in legacy DB!
                $found->{ENABLE_PASS} = $entry->{ENABLE_PASS};

                # use user from Cisco Works in legacy DB!
                $found->{LOCAL_USER} = $entry->{LOCAL_USER};
                $entry->{ALIAS}      = $found->{ALIAS};

                # mark as used
                $found->{USED} = 1;
                unless ($found->{PASS} eq $entry->{PASS}) {
                    mypr "PASS_DBB: while enhancing %NAME_HASH: "
                      . "match \'$entry->{SOURCE}->{LINE}\'\n";
                    mypr "PASS_DBB:           through ip address "
                      . "with \'$found->{SOURCE}->{LINE}\'\n";
                }
            }
        }
        unless ($found) {

            # "guess"
            #$entry->{TYPE} or $entry->{TYPE}  = "ios";
            $entry->{ALIAS} = 0;
        }
    }
    my $used_entrys = 0;
    for my $val (values %LEG_ALL_DB) {
        if ($val->{USED}) {
            ++$used_entrys;
        }
    }

    return {
        NAME_HASH   => \%NAME_HASH,
        IP_HASH     => \%IP_HASH,
        LEG_NAME_DB => \%LEG_NAME_DB,
        LEG_IP_DB   => \%LEG_IP_DB
    };
}

# take name or ip and retrieve passwd, name, ip (and type)
sub get_obj_info($$$$) {
    my ($self, $spec, $db_path, $global_config) = @_;
    my $db     = $self->build_db($db_path);
    my $object = $db->{NAME_HASH}->{$spec}
      || $db->{IP_HASH}->{$spec}
      || $db->{LEG_NAME_DB}->{$spec}
      || $db->{LEG_IP_DB}->{$spec}
      or die "object $spec not found\n";
    $object->{NAME} or die "no object name found\n";
    $object->{IP}   or die "no address found\n";
    $object->{TYPE} or die "no object type found\n";
    unless ($object->{PASS}) {
        my $user = getpwuid($>);
        if ($user ne $global_config->{SYSTEMUSER}) {
            print STDOUT "Running in non privileged mode an no "
              . "password founf in database.\n";
            print STDOUT "Password for $user?";
            system('stty', '-echo');
            my $password = <STDIN>;
            system('stty', 'echo');
            print STDOUT "  ...thank you :)\n";
            chomp $password;
            $object->{PASS}       = $password;
            $object->{LOCAL_USER} = $user;
        }
        else {

            # no pasword in Database - use aaa_credentials
            open(AAA, $global_config->{AAA_CREDENTIAL})
              or die "could not open "
              . "$self->{GLOBAL_CONFIG}->{AAA_CREDENTIAL} $!\n";
            my $credentials = <AAA>;
            $credentials =~ (/^\s*(\S+)\s*(\S+)\s*$/)
              or die "no aaa credential found\n";
            $object->{PASS} = $2;

            # overwrite user
            $object->{LOCAL_USER} = $1;
            mypr "User $1 from aaa credentials extracted\n";
            close(AAA);
        }
    }
    return ($object);
}

sub get_spoc_type($$$) {
    my ($self, $name, $global_config) = @_;

    # Get type of object from newest spoc file.
    my $spocfile =
      "$global_config->{NETSPOC}/current/".
      "$global_config->{CODEPATH}$name";
    my $type;
    open(FILE, $spocfile) or die "Can't open $spocfile: $!\n";
    while (my $line = <FILE>) {
        if ($line =~ /\[ Model = (\S+) ]/) {
            $type = $1;
            last;
        }
    }
    close FILE;
    return $type;
}

sub get_epilog_name( $$ ) {
    my ($self, $path) = @_;
    $path =~
      s/$self->{GLOBAL_CONFIG}->{CODEPATH}/$self->{GLOBAL_CONFIG}->{EPILOGPATH}/;
    return $path;
}

sub load_spocfile($$) {
    my ($self, $path) = @_;
    my @result;

    # read (spoc) config
    if ($path eq "STDIN") {
        (open(NET, "<&STDIN")) or die "could not dup STDIN\n$!\n";
        @result = <NET>;
        close(NET);
    }
    elsif (-f $path) {
        (open(NET, $path)) or die "could not open spocfile: $path\n$!\n";
        @result = <NET>;
        close(NET);
    }
    elsif (-f "${path}.gz") {
        mypr "decompressing config file...";
        @result = `gunzip -c "$path.gz"`;
        $? and die "error running gunzip\n";
        mypr "done.\n";
    }
    else {
        die "spocfile \'$path\' not found!\n";
    }
    mypr "config file ($path) for  ", $self->{NAME}, " has ", scalar @result,
      " lines\n";
    return \@result;
}

sub load_epilog($$) {
    my ($self, $path) = @_;
    my @result;
    if (-f $path) {
        open(EPI, "<$path") or die "could not open rawdata: $path\n$!\n";
        @result = <EPI>;
        close EPI;
        mypr "rawdata file ($path) for ", $self->{NAME}, " has ",
          scalar @result, " lines\n";
    }
    elsif (-f "${path}.gz") {
        mypr "decompressing raw file...";
        @result = `gunzip -c "${path}.gz"`;
        $? and die "error running gunzip\n";
        mypr "done.\n";
    }
    else {
        @result = ();
        mypr "no rawdata found...\n";
    }
    return \@result;
}

sub prepare_filemode($$$) {
    my ($self, $path1, $path2) = @_;
    my $parsed1 = {};
    my $parsed2 = {};

    my $conf1 = $self->load_spocfile($path1);
    my $epi1  = $self->load_epilog($self->get_epilog_name($path1));
    my $conf2 = $self->load_spocfile($path2);
    my $epi2  = $self->load_epilog($self->get_epilog_name($path2));
    if (!$self->parse_spocfile($parsed1, $conf1)) {
        errpr "parse error\n";
        return;
    }
    if (!$self->parse_spocfile($parsed2, $conf2)) {
        errpr "parse error\n";
        return;
    }
    if (not $parsed1->{MODEL} eq $parsed2->{MODEL}) {
        mypr "MODELs must be equal in parsed spoc config:",
          " $parsed1->{MODEL}, $parsed2->{MODEL}\n";
        return;
    }

    #
    # *** merge EPILOG into SPOCCONFIG
    #
    $self->process_rawdata($parsed1, $epi1) or return;
    $self->process_rawdata($parsed2, $epi2) or return;

    return ($parsed1, $parsed2);
}

sub prepare_devicemode( $$$ ) {
    my ($self, $device_lines, $path) = @_;
    my $pspoc = {};
    my $conf  = {};

    my $spoc_lines   = $self->load_spocfile($path);
    my $epilog_lines = $self->load_epilog($self->get_epilog_name($path));

    # *** PARSE SPOC CONFIG ***
    if (!$self->parse_spocfile($pspoc, $spoc_lines)) {
        errpr "parse error\n";
        return;
    }

    # *** PARSE DEVICE CONFIG ***
    if (not $self->pix_parse($conf, $device_lines)) {
        errpr "could not parse device config\n";
        return;
    }

    # *** check for unknown interfaces at device ***
    $self->checkinterfaces($conf, $pspoc);

    #
    # *** merge EPILOG into SPOCCONFIG
    #
    $self->process_rawdata($pspoc, $epilog_lines) or return;
    return ($conf, $pspoc);
}

##################################################################
#    adaption layer
##################################################################

sub adaption($) {
    my ($self) = @_;

    $self->{telnet_timeout} = $self->{OPTS}->{t} || 300;
    $self->{telnet_port}    = $self->{OPTS}->{T} || 23;
    $self->{telnet_logs}    = $self->{OPTS}->{L} || undef;

    $self->{CHECKHOST}   = $self->{GLOBAL_CONFIG}->{CHECKHOST};
    $self->{CHECKBANNER} = $self->{GLOBAL_CONFIG}->{CHECKBANNER};

    $self->{CHECK_DEVICE_IN_SPOCFILE} = $self->{OPTS}->{h} || "yes";
    $self->{FORCE_TRANSFER}           = $self->{OPTS}->{F};
    $self->{PRINT_STATUS}             = $self->{OPTS}->{S} ? "yes" : "no";
}

sub con_setup( $$ ) {
    my ($self, $startup_message) = @_;
    my $logfile =
      $self->{telnet_logs}
      ? "$self->{telnet_logs}$self->{NAME}.tel"
      : '';

    $self->{CONSOLE} =
	Netspoc::Approve::Helper->new_console($self, "telnet", $logfile,
					      $startup_message);
}

sub con_shutdown( $$ ) {
    my ($self, $shutdown_message) = @_;
    my $con = $self->{CONSOLE};
    $con->con_issue_cmd("exit\n", eof, 5);
    $con->shutdown_console("$shutdown_message");
}

sub check_device( $ ) {
    my ($self) = @_;
    my $retries = $self->{OPTS}->{p} || 3;
    return $self->checkping($self->{IP}, $retries);
}

sub remote_execute( $ ) {
    my ($self) = @_;
    $self->adaption();

    # to prevent configured by console messages
    # in compare mode prepare() does not change router config
    $self->{COMPARE} = 1;
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
    my ($self, $spoc_path) = @_;
    $self->adaption();
    my $policy = $self->{OPTS}->{P};

    # remember approve mode
    $self->{APPROVE}       = 1;
    $self->{COMPARE}       = undef;

    # set up console
    $self->con_setup("START: $policy (telnet) at > "
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
    if ($self->transfer($device_conf, $spoc_conf)) {
        mypr "approve done\n";
    }
    else {
        errpr "approve failed\n";
    }
    $self->con_shutdown("STOP: $policy (telnet) at > "
          . scalar localtime()
          . " < ($id)");
}

sub compare( $$ ) {
    my ($self, $spoc_path) = @_;
    $self->adaption();
    my $policy = $self->{OPTS}->{P};

    # save compare mode
    $self->{COMPARE}      = 1;
    $self->{CMPVAL}       = $self->{OPTS}->{C};

    # set up console
    $self->con_setup("START: $policy (telnet) at > "
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
    if ($self->transfer($device_conf, $spoc_conf)) {
        mypr "compare done\n";
    }
    else {
        errpr "compare failed\n";
    }

    $self->con_shutdown("STOP: $policy (telnet) at > "
          . scalar localtime()
          . " < ($id)");
    mypr "comp: $policy ", scalar localtime, " ($id)\n";
    for my $key (keys %{$self->{CHANGE}}) {
	mypr "comp: $policy $self->{NAME} *** $key changed ***\n";
    }

    return $self->{CHANGE};
}

sub compare_files( $$$) {
    my ($self, $path1, $path2) = @_;
    $self->adaption();

    # save compare mode
    $self->{COMPARE} = 1;

    # default compare is silent(4) mode
    $self->{CMPVAL} = $self->{OPTS}->{C} || 4;

    $self->{VERSION}      = "unknown";

    my ($conf1, $conf2) = $self->prepare_filemode($path1, $path2)
      or errpr "filemode prepare failed\n";

    if ($self->transfer($conf1, $conf2)) {
        mypr "compare done\n";
    }
    else {
        errpr "compare failed\n";
    }
    mypr "comp: ", scalar localtime, " ($id)\n";
    for my $key (keys %{$self->{CHANGE}}) {
	mypr "comp: $self->{NAME} *** $key changed ***\n";
    }

    return $self->{CHANGE};
}

sub logging($) {
    my $self = shift;
    open($self->{STDOUT}, ">&STDOUT")
      or die "could not save STDOUT for Password prompt $!\n";
    return unless ($self->{OPTS}->{LOGFILE});    # logging not enabled!
    my $logfile = $self->{OPTS}->{LOGFILE};
    if ($logfile !~ /\A\//) {

        # $logfile given as relative path - enhance to absolute path
        my $wd = `pwd`;
        chomp $wd;
        $logfile = "$wd/$logfile";
    }
    my $basename = basename($self->{OPTS}->{LOGFILE});
    $basename or die "no filename for logging specified\n";
    my $dirname = dirname($self->{OPTS}->{LOGFILE});

    # check for/create logdir
    unless (-d $dirname) {
        (mkdir $dirname) or die "could not create $dirname\n$!\n";
        (defined chmod 0755, "$dirname")
          or die " couldn't chmod logdir $dirname\n$!\n";
    }
    my $appmode;
    if ($self->{OPTS}->{LOGAPPEND}) {
        $appmode = ">>";    # append
    }
    else {
        $appmode = ">";     # clobber
        if ($self->{OPTS}->{LOGVERSIONS}) {
            if (-f "$logfile") {
                my $date = time();
                system("mv $logfile $logfile.$date") == 0
                  or die "could not backup $logfile\n$!\n";
                $self->{OPTS}->{NOLOGMESSAGE}
                  or mypr "existing logfile saved as \'$logfile.$date\'\n";
            }
        }
    }
    $self->{OPTS}->{NOLOGMESSAGE}
      or mypr "--- output redirected to $logfile\n";

    # print the above message *before* redirecting!
    unless (-f "$logfile") {
        (open(STDOUT, "$appmode$logfile"))
          or die "could not open $logfile\n$!\n";
        defined chmod 0644, "$logfile"
          or die " couldn't chmod $logfile\n$!\n";
    }
    else {
        (open(STDOUT, "$appmode$logfile"))
          or die "could not open $logfile\n$!\n";
    }
    (open(STDERR, ">&STDOUT"))
      or die "STDERR redirect: could not open $logfile\n$!\n";
}

{

    # a closure, beause we need the lock
    my $lock;

    sub lock( $$ ) {
        my ($self, $name) = @_;

        # set lock for exclusive approval
        my $lockfile = "$self->{GLOBAL_CONFIG}->{LOCKFILEPATH}/$name";
        unless (-f "$lockfile") {
            open($lock->{$name}, ">$lockfile")
              or die "could not aquire lock file: $lockfile\n$!\n";
            defined chmod 0666, "$lockfile"
              or die " couldn't chmod lockfile $lockfile\n$!\n";
        }
        else {
            open($lock->{$name}, ">$lockfile")
              or die "could not aquire lock file: $lockfile\n$!\n";
        }
        unless (flock($lock->{$name}, LOCK_EX | LOCK_NB)) {
            mypr "$!\n";
            return 0;
        }
    }

    sub unlock( $$ ) {
        my ($self, $name) = @_;
        close($lock->{$name}) or die "could not unlock lockfile\n$!\n";
    }
}

# return 0 if no answer
sub checkping ($$$) {
    my ($self, $addr, $retries) = @_;

    for (my $i = 1 ; $i <= $retries ; $i++) {

        my $result = `ping -q -w $i -c 1 $addr`;

        $result =~ /(\d+) received/;

        $1 == 1 and return $i;

    }
    return "0";
}

1;
