
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

use strict;
use warnings;
use Fcntl qw/:flock/;    # import LOCK_* constants

use File::Basename;

use Netspoc::Approve::Helper;
use Netspoc::Approve::Console;
use Netspoc::Approve::Parse_Cisco;

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
    my $madhome = '/home/diamonds/';
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
        elsif (defined quad2int($entry->{NAME})) {

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

# Take name or ip and retrieve name, ip and optional password.
sub get_obj_info {
    my ($self, $spec, $db_path) = @_;
    my $db     = $self->build_db($db_path);
    my $object = $db->{NAME_HASH}->{$spec}
      || $db->{IP_HASH}->{$spec}
      || $db->{LEG_NAME_DB}->{$spec}
      || $db->{LEG_IP_DB}->{$spec};
    return if not $object;
    if(my $pass = $object->{PASS} && ! $object->{LOCAL_USER}) {
	if($pass =~ /^(.*?):(.*)$/) {
	    $object->{LOCAL_USER} = $1;
	    $object->{PASS} = $2;
	}
    }
    return $object;
}

sub get_aaa_password {
    my ($self) = @_;
    my $pass;
    my $user = getpwuid($>);
    if ($user eq $self->{GLOBAL_CONFIG}->{SYSTEMUSER}) {

	# Use AAA credentials.
	my $aaa_credential = $self->{GLOBAL_CONFIG}->{AAA_CREDENTIAL};
	open(AAA, $aaa_credential)
	    or die "Could not open $aaa_credential: $!\n";
	my $credentials = <AAA>;
	close(AAA);
	($user, $pass) = $credentials =~ (/^\s*(\S+)\s*(\S+)\s*$/)
	    or die "No AAA credential found\n";
	mypr "User $1 from aaa credentials extracted\n";
    }
    else {
	print STDOUT "Running in non privileged mode an no "
	    . "password found in database.\n";
	print STDOUT "Password for $user?";
	system('stty', '-echo');
	$pass = <STDIN>;
	system('stty', 'echo');
	print STDOUT "  ...thank you :)\n";
	chomp $pass;
    }
    return ($user, $pass);
}

# Read name and IP addresses from header of spoc file.
sub get_spoc_data {
    my ($self, $global_config, $name, $codepath) = @_;

    # Get data from newest spoc file or from $codepath if called 
    # by 'local' compare.
    my $spocfile = 
	$codepath ? 
	$codepath :
	"$global_config->{NETSPOC}current/$global_config->{CODEPATH}$name";

    # Empty string is used for lookup of fallback class.
    my $type = '';
    my @ip;
    open(FILE, $spocfile) or return $type;
    while (my $line = <FILE>) {
        if ($line =~ /\[ Model = (\S+) ]/) {
            $type = $1;
        }
        if ($line =~ /\[ IP = (\S+) ]/) {
            @ip = split(/,/, $1);
	    last;
        }
    }
    close FILE;
    return($type, @ip);
}

# code/device -> src/raw/device || -> netspoc/raw/device
sub get_raw_name( $$ ) {
    my ($self, $path) = @_;
    my $raw_path;
    my $code_dir = $self->{GLOBAL_CONFIG}->{CODEPATH};

    # ToDo: Change EPILOGPATH to 'netspoc/raw' here and in newpolicy.
    for my $raw_dir ($self->{GLOBAL_CONFIG}->{EPILOGPATH}, 'netspoc/raw/') {
	$raw_path = $path;
	if($raw_path =~ s/$code_dir/$raw_dir/) {
	    return($raw_path) if -f $raw_path;
	}
    }
    return;
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

sub load_raw($$) {
    my ($self, $path) = @_;
    my @result;
    return \@result if not $path;
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

sub load_spoc {
    my ($self, $path) = @_;
    my $lines     = $self->load_spocfile($path);
    my $conf      = $self->parse_config($lines);
    my $raw_lines = $self->load_raw($self->get_raw_name($path));
    my $raw_conf  = $self->parse_config($raw_lines);
    $self->merge_rawdata($conf, $raw_conf);
    return($conf);
}

sub prepare_devicemode {
    my ($self, $path) = @_;
    my $spoc_conf = $self->load_spoc($path);
    my $conf = $self->get_parsed_config_from_device();

    # Check for unknown interfaces at device.
    $self->checkinterfaces($conf, $spoc_conf);

    # Check if active firewall feature matches device type.
    $self->check_firewall($conf);

    return ($conf, $spoc_conf);
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
		my @values = parse_line($self, $arg, $parser, @evaled) 
		    if $parser;
		for(my $i = 0; $i < @values; $i++) {
		    $result->{$keys->[$i]} = $values[$i];
		}
		$part_success = @values;
	    }
	    else {
		my $value = parse_line($self, $arg, $parser, @evaled) 
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
	if($type eq 'or') {
	    last if $success;
	}
	elsif($type eq 'seq') {

	    # Stop if first arg doesn't match.
	    last if not $success;
	}
	else {
	    errpr "internal: unexpected 'seq' type $type\n";
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
	errpr "internal: unexpected parse attribute: $info\n";
    }
}

# $config are prepared config lines.
# $parse_info describes grammar.
sub parse_config1 {
    my($self, $config, $parse_info) = @_;
    my $result = {};
    for my $arg (@$config) {
	my $cmd = get_token($arg);
        my $cmd_info = $parse_info->{$cmd} or 
	    errpr "internal: parsed unexpected cmd: $cmd\n";
	if(my $msg = $cmd_info->{error}) {
	    err_at_line($arg, $msg);
	}
	my $named = $cmd_info->{named};
	my $name;
	if($named and $named ne 'from_parser') {
	    $name = get_token($arg);
	}
	my $parser = $cmd_info->{parse};
	my $value = parse_line($self, $arg, $parser) if $parser;
	if($named and $named eq 'from_parser') {
	    $name = $value->{name} or err_at_line($arg, 'Missing name');
	}
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
	if(ref($value) eq 'HASH') {
	    $named and $value->{name} = $name;
	    $value->{orig} = $arg->{orig};
	}
	my $store = $cmd_info->{store};
	my @extra_keys = ref $store ? @$store : $store;
	my $key;
	if($named) {
	    $key = $name;
	}
	else {
	    $key = pop @extra_keys;
	}
	my $dest = $result;
	for my $x (@extra_keys) {
	    $dest->{$x} ||= {};
	    $dest = $dest->{$x};
	}
	if($cmd_info->{multi}) {
	    push(@{ $dest->{$key} }, $value);
	}
	else {
	    defined $dest->{$key} and
		err_at_line($arg, 'Multiple occurences of command not allowed');
	    $dest->{$key} = $value;
	}
    }
    return($result);
}

sub parse_config {
    my ($self, $lines) = @_;

    my $parse_info = $self->get_parse_info();
    my $config = analyze_conf_lines($lines, $parse_info);
    my $result = $self->parse_config1($config, $parse_info);
    $self->postprocess_config($result);
    return $result;
}

# Rawdata processing
sub merge_routing {
    my ($self, $spoc_conf, $raw_conf) = @_;
    
    # Route processing.
    if ($spoc_conf->{ROUTING}) {
	my $newroutes = ();
      SPOC: for (my $i = 0 ; $i < scalar @{ $spoc_conf->{ROUTING} } ; $i++) {
	  my $se = $spoc_conf->{ROUTING}->[$i];
	  for my $re (@{ $raw_conf->{ROUTING} }) {
	      if ($self->route_line_a_eq_b($se, $re)) {
		  warnpr "RAW: double RE '$re->{orig}'" .
		      " scheduled for remove from spocconf.\n";
		  next SPOC;
	      }
	      elsif ( $re->{BASE} eq $se->{BASE}
		      and $re->{MASK} eq $se->{MASK})
	      {
		  warnpr "RAW: inconsistent NEXT HOP in routing entries:\n";
		  warnpr "     spoc: $se->{orig} (scheduled for remove)\n";
		  warnpr "     raw:  $re->{orig} \n";
		  next SPOC;
	      }
	  }
	  push @{$newroutes}, $se;
      }
	$spoc_conf->{ROUTING} = $newroutes;
    }
    for my $re (@{ $raw_conf->{ROUTING} }) {
	push @{ $spoc_conf->{ROUTING} }, $re;
    }
    mypr " attached routing entries: "
	. scalar @{ $raw_conf->{ROUTING} } . "\n";
}

sub route_line_a_eq_b {
    my ($self, $a, $b) = @_;
    ($a->{BASE} == $b->{BASE} && $a->{MASK} == $b->{MASK})
      or return 0;
    for my $key (qw(IF NIF NEXTHOP METRIC MISC MISC_ARG)) {
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

sub process_routing {
    my ($self, $conf, $spoc_conf) = @_;
    my $spoc_routing = $spoc_conf->{ROUTING};
    my $conf_routing = $conf->{ROUTING};
    if ($spoc_routing) {
        if (not $conf_routing) {
            if (not $conf->{OSPF}) {
                errpr "ERROR: no routing entries found on device\n";
            }
            else {
                mypr "no routing entries found on device - but OSPF found...\n";

                # generate empty routing config for device:
                $conf_routing = $conf->{ROUTING} = [];
            }
        }
	$self->{CHANGE}->{ROUTE} = 0;
        my $counter;
        mypr "==== compare routing information ====\n";
        mypr " routing entries on device:    ", scalar @$conf_routing, "\n";
        mypr " routing entries from netspoc: ", scalar @$spoc_routing, "\n";
        for my $c (@$conf_routing) {
            for my $s (@$spoc_routing) {
                if ($self->route_line_a_eq_b($c, $s)) {
                    $c->{DELETE} = $s->{DELETE} = 1;
                    last;
                }
            }
        }
        unless ($self->{COMPARE}) {

            #
            # *** SCHEDULE RELOAD ***
            #
            # TODO: check if 10 minutes are OK
            #
            $self->schedule_reload(10);

            # Transfer to device.
            $self->enter_conf_mode;
            mypr "transfer routing entries to device:\n";
            $counter = 0;
	    
	    # Add routes with long mask first.
	    # If we switch the default route, this ensures, that we have the
	    # new routes available before deleting the old default route.
            for my $r ( sort {$b->{MASK} <=> $a->{MASK}} 
			@{ $spoc_conf->{ROUTING} }) {
                ($r->{DELETE}) and next;
                $counter++;
		
		# PIX and ASA don't allow two routes to identical destination.
		# Remove old route immediatly before adding the new one.
		for my $c (@$conf_routing) {
		    next if $c->{DELETE};
		    if($self->route_line_destination_a_eq_b($r, $c)){
			$self->cmd($self->route_del($c));
			$c->{DELETE} = 1; # Must not delete again.
		    }
		}
                $self->cmd($self->route_add($r));
            }
            mypr " $counter\n";
            ($counter) and $self->{CHANGE}->{ROUTE} = 1;
            mypr "deleting non matching routing entries from device\n";
            $counter = 0;
            for my $r (@$conf_routing) {
                ($r->{DELETE}) and next;
                $counter++;
                $self->cmd($self->route_del($r));
            }
            mypr " $counter\n";
            $self->leave_conf_mode;
            $counter and $self->{CHANGE}->{ROUTE} = 1;
            $self->cancel_reload();
        }
        else {

            # show compare results
            mypr "additional routing entries from spoc:\n";
            $counter = 0;
            for my $r (@$spoc_routing) {
                ($r->{DELETE}) and next;
                $counter++;
                mypr $self->route_add($r), "\n";
            }
            mypr "total: ", $counter, "\n";
            ($counter) and $self->{CHANGE}->{ROUTE} = 1;
            mypr "non matching routing entries on device:\n";
            $counter = 0;
            for my $r (@$conf_routing) {
                $r->{DELETE} and next;
                $counter++;
                mypr $self->route_del($r), "\n";
            }
            mypr "total: ", $counter, "\n";
            ($counter) and $self->{CHANGE}->{ROUTE} = 1;
        }
        mypr "==== done ====\n";
    }
    else {
        mypr "no routing entries specified - leaving routes untouched\n";
    }
}

sub checkidentity {
    my ($self, $name) = @_;
    if($self->{GLOBAL_CONFIG}->{CHECKHOST} eq 'no') {
	 mypr "hostname checking disabled\n";
    }
    elsif($name ne $self->{NAME}) {
	errpr "wrong device name: $name, expected: $self->{NAME}\n";
    }
}

sub checkbanner {
    my ($self) = @_;
    my $check = $self->{GLOBAL_CONFIG}->{CHECKBANNER} or return;
    if ( $self->{PRE_LOGIN_LINES} !~ /$check/) {
        if ($self->{COMPARE}) {
            warnpr "Missing banner at NetSPoC managed device.\n";
        }
        else {
            errpr "Missing banner at NetSPoC managed device.\n";
        }
    }
}

sub adaption {
    my ($self) = @_;

    $self->{telnet_timeout} = $self->{OPTS}->{t} || 300;
    $self->{telnet_logs}    = $self->{OPTS}->{L} || undef;

    $self->{FORCE_TRANSFER}           = $self->{OPTS}->{F};
    $self->{PRINT_STATUS}             = $self->{OPTS}->{S};
}

sub con_setup {
    my ($self, $startup_message) = @_;
    my $logfile =
      $self->{telnet_logs}
      ? "$self->{telnet_logs}$self->{NAME}.tel"
      : '';

    my $con = $self->{CONSOLE} =
	Netspoc::Approve::Console->new_console($self, "telnet", $logfile,
					      $startup_message);
    $con->{TIMEOUT} = $self->{telnet_timeout};
}

sub con_shutdown {
    my ($self, $shutdown_message) = @_;
    my $con = $self->{CONSOLE};
    $con->{TIMEOUT} = 5;
    $con->con_issue_cmd("exit\n", eof);
    $con->shutdown_console("$shutdown_message");
}

sub issue_cmd {
    my ($self, $cmd) = @_;

    my $con = $self->{CONSOLE};
    $con->{PROMPT} = $self->{ENA_MODE} ? $self->{ENAPROMPT} : $self->{PROMPT};
    $con->con_cmd("$cmd\n") or $con->con_error();
    return($con->{RESULT});
}

sub cmd {
    my ($self, $cmd) = @_;
    my $result = $self->issue_cmd($cmd);

    # check for  errors
    # argument is ref to prematch from issue_cmd
    $self->cmd_check_error(\$result->{BEFORE}) or exit -1;
}

sub shcmd {
    my ($self, $cmd) = @_;
    my $result = $self->issue_cmd($cmd);
    return($result->{BEFORE});
}

sub get_cmd_output {
    my ($self, $cmd) = @_;
    my @lines = split(/\r?\n/, $self->shcmd($cmd));
    my $echo = shift(@lines);
    $echo =~ /^\s*$cmd\s*$/ or 
	errpr "Got unexpected echo in response to '$cmd': '$echo'\n";
    return(\@lines);
}

# Return 0 if no answer.
sub check_device {
    my ($self) = @_;
    my $retries = $self->{OPTS}->{p} || 3;

    for my $i (1 ..3) {
        my $result = `ping -q -w $i -c 1 $self->{IP}`;
	return $i if $result =~ /1 received/;
    }
    return 0;
}

sub remote_execute {
    my ($self, $cmd) = @_;
    $self->adaption();

    # tell the Helper not to print message approve aborted
    errpr_mode("COMPARE");

    # to prevent configured by console messages
    # in compare mode prepare() does not change router config
    $self->{COMPARE} = 1;
    $self->con_setup(
        "START: execute user command at > " . scalar localtime() . " < ($id)");
    $self->prepare();
    $cmd =~ s/\\n/\n/g;
    for my $line (split /[;]/, $cmd) {
        my $output = $self->shcmd($line);
        mypr $output, "\n";
    }
    mypr "\n";
    $self->con_shutdown("STOP");
}

sub approve {
    my ($self, $spoc_path) = @_;
    $self->adaption();
    my $policy = $self->{OPTS}->{P};

    $self->{COMPARE}       = undef;
    $self->{CMPVAL}        = 4;      # silent

    # set up console
    my $time = localtime();
    $self->con_setup("START: $policy at > $time < ($id)");

    # prepare device for configuration
    $self->prepare();

    # Check for Netspoc message in device banner.
    $self->checkbanner();

    # now do the main thing
    my ($device_conf, $spoc_conf) = $self->prepare_devicemode($spoc_path);
    if ($self->transfer($device_conf, $spoc_conf)) {
        mypr "approve done\n";
    }
    else {
        errpr "approve failed\n";
    }
    $time = localtime();
    $self->con_shutdown("STOP: $policy at > $time < ($id)");
}

sub get_change_status {
    my ($self) = @_;
    my $time = localtime();
    mypr "compare: $time ($id)\n";
    for my $key (sort keys %{$self->{CHANGE}}) {
	my $status = $self->{CHANGE}->{$key} ? 'changed' : 'unchanged';
	mypr "compare: $self->{NAME} *** $key $status ***\n";
    }
    return(grep { $_ } values %{ $self->{CHANGE} });
}

sub compare {
    my ($self, $spoc_path) = @_;
    $self->adaption();
    my $policy = $self->{OPTS}->{P};

    # save compare mode
    $self->{COMPARE}      = 1;
    $self->{CMPVAL}       = $self->{OPTS}->{C};

    # set up console
    my $time = localtime();
    $self->con_setup("START: $policy at > $time < ($id)");

    # prepare device for configuration
    $self->prepare();

    # check if Netspoc message in device banner
    $self->checkbanner();

    # now do the main thing
    my ($device_conf, $spoc_conf) = $self->prepare_devicemode($spoc_path);
    if ($self->transfer($device_conf, $spoc_conf)) {
        mypr "compare done\n";
    }
    else {
        errpr "compare failed\n";
    }

    $time = localtime();
    $self->con_shutdown("STOP: $policy at > $time < ($id)");
    return($self->get_change_status());
}

sub compare_files {
    my ($self, $path1, $path2) = @_;
    $self->adaption();

    # save compare mode
    $self->{COMPARE} = 1;

    # Default compare is silent(4) mode
    $self->{CMPVAL} = $self->{OPTS}->{C};
    defined($self->{CMPVAL}) or $self->{CMPVAL} = 4;

    my $conf1 = $self->load_spoc($path1);
    my $conf2 = $self->load_spoc($path2);

    if ($self->transfer($conf1, $conf2)) {
        mypr "compare done\n";
    }
    else {
        errpr "compare failed\n";
    }
    return($self->get_change_status());
}

sub logging {
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

1;
