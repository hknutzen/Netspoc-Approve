
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

use drc2_helper;

############################################################
# --- constructor ---
############################################################
sub new {
    my $class = shift;
    my $opts  = shift;
    my $self  = {};

    # save command line options
    $self->{OPTS} = $opts;

    # define slot for global config
    $self->{GLOBAL_CONFIG} = {};

    # define slot to save device info
    $self->{DEVICES} = {};
    bless( $self, $class );
    return $self;
}
###########################################################################
#   methods
###########################################################################
sub get_global_config($) {

    my $job  = shift;
    my $self = $job->{GLOBAL_CONFIG};

    # set masterdirectory and read global parms

    my $madhome = '/home/diamonds/';
    my $rcmad = join '', $madhome, '.rcmadnes';
    open( RCMAD, $rcmad ) or die "$rcmad does not exist \n";

    $self->{BINHOME}        = '';
    $self->{NETSPOC}        = '';
    $self->{CHECKHOST}      = '';
    $self->{EPILOGPATH}     = '';
    $self->{CODEPATH}       = '';
    $self->{STATUSPATH}     = '';
    $self->{MIGSTATPATH}    = '';
    $self->{VPNTMPDIR}      = '';
    $self->{CHECKBANNER}    = '';
    $self->{DEVICEDBPATH}   = '';
    $self->{LOCKFILEPATH}   = "$madhome/lock";
    $self->{AAA_CREDENTAIL} = '';
    $self->{SYSTEMUSER}     = '';

    while ( <RCMAD> ) {
        ( /^\s*BINHOME\s*=\s*(\S+)\s*$/ )       and $self->{BINHOME}      = $1;
        ( /^\s*NETSPOC\s*=\s*(\S+)\s*$/ )       and $self->{NETSPOC}      = $1;
        ( /^\s*CHECKHOSTNAME\s*=\s*(\S+)\s*$/ ) and $self->{CHECKHOST}    = $1;
        ( /^\s*CHECKBANNER\s*=\s*(\S+)\s*$/ )   and $self->{CHECKBANNER}  = $1;
        ( /^\s*EPILOGPATH\s*=\s*(\S+)\s*$/ )    and $self->{EPILOGPATH}   = $1;
        ( /^\s*CODEPATH\s*=\s*(\S+)\s*$/ )      and $self->{CODEPATH}     = $1;
        ( /^\s*STATUSPATH\s*=\s*(\S+)\s*$/ )    and $self->{STATUSPATH}   = $1;
        ( /^\s*MIGSTATPATH\s*=\s*(\S+)\s*$/ )   and $self->{MIGSTATPATH}  = $1;
        ( /^\s*VPNTMPDIR\s*=\s*(\S+)\s*$/ )     and $self->{VPNTMPDIR}    = $1;
        ( /^\s*DEVICEDB\s*=\s*(\S+)\s*$/ )      and $self->{DEVICEDBPATH} = $1;
        ( /^\s*AAA_CREDENTIALS\s*=\s*(\S+)\s*$/ )
          and $self->{AAA_CREDENTIAL} = $1;
        ( /^\s*SYSTEMUSER\s*=\s*(\S+)\s*$/ ) and $self->{SYSTEMUSER} = $1;
    }
    close RCMAD or die "could not close $rcmad\n";

    ( $self->{NETSPOC} )    or die "netspoc basedir missing in $rcmad\n";
    ( $self->{EPILOGPATH} ) or die "path for epilog not found in $rcmad\n";
    ( $self->{STATUSPATH} )
      or die "path for status update not found in $rcmad\n";
    ( $self->{MIGSTATPATH} )
      or die "path for migrate status info not found in $rcmad\n";
    ( $self->{DEVICEDBPATH} ) or die "missing DEVICEDB setting in $rcmad\n";
    ( $self->{VPNTMPDIR} )    or die "missing VPNTMPDIR setting in $rcmad\n";
    ( $self->{SYSTEMUSER} )   or die "name of privileged user not set\n";
}

sub build_db ($) {
    my $self = shift;

    my $db;
    $db = $self->{OPTS}->{D} or $db = $self->{GLOBAL_CONFIG}->{DEVICEDBPATH};

    my %LEG_ALL_DB;
    my %LEG_IP_DB;
    my %LEG_NAME_DB;
    my %LEG_ALIAS_DB;
    my %CW_IP_DB;

    my %NAME_HASH;
    my %IP_HASH;

    # get password data from cw_pass
    open( CSVDB, "$db/cw_pass" ) or die "could not open $db/cw_pass\n$!\n";
    for my $line ( <CSVDB> ) {
        $line =~ /^;/ and next;
        $line =~ s/[\"\r\n]//g;
        ( $line ) or next;
        my %OBJ;
        (
            $OBJ{NAME},    # Name (including domain or simply an IP)
            $OBJ{RO},      # RO community string
            $OBJ{RW},      # RW community string
            $OBJ{SN},      # Serial Number
            $OBJ{UF1}
            , # User Field 1  <-- Hier Eintrag ob Geraet hinter "ISDN" oder "Stand"
            $OBJ{UF2}
            , # User Field 2  <-- Zugehoerigkeit zu einer Netz-Gruppe (LN,SH,KR,DZ)
            $OBJ{CW_TYP}
            ,    # User Field 3  <-- Typ (sw,rt,pix) fuer switch,router,pix
            $OBJ{UF4},                # User Field 4
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
        ) = split /,/, $line;
        unless ( exists $NAME_HASH{ $OBJ{NAME} } ) {
            $NAME_HASH{ $OBJ{NAME} }->{SOURCE}->{LINE} = $line;
            $NAME_HASH{ $OBJ{NAME} }->{NAME}           = $OBJ{NAME};
            $NAME_HASH{ $OBJ{NAME} }->{PASS}           = $OBJ{TELNET_PASS};
            $NAME_HASH{ $OBJ{NAME} }->{ENABLE_PASS}    = $OBJ{ENABLE_PASS};
            $NAME_HASH{ $OBJ{NAME} }->{LOCAL_USER}     = $OBJ{LOCAL_USER};
            $NAME_HASH{ $OBJ{NAME} }->{TYPE}           = $OBJ{CW_TYP};
        }
        else {
            mypr "PASS_DBB: CiscoWorks pass db: discarded line \'$line\'\n";
            mypr
"PASS_DBB:  -> object name already found in \'$NAME_HASH{$OBJ{NAME}}->{SOURCE}->{LINE}\'\n";
        }
    }
    close CSVDB;

    # use data from cw_ip to obtain ip adresses for objects from cw_pass
    #
    #   the data in cw_ip is actually expected to be the LMHOSTS file
    #   from an microsoft Windows CiscoWorks machine
    #
    open( CSVDB, "$db/cw_ip" ) or die "could not open $db/cw_ip\n$!\n";
    for my $line ( <CSVDB> ) {
        $line =~ /^#/ and next;
        $line =~ s/[\"\r\n]//g;
        ( $line ) or next;
        my %OBJ;
        ( $OBJ{IP}, $OBJ{NAME} ) = split " ", $line;
        unless ( exists $CW_IP_DB{ $OBJ{NAME} } ) {
            $CW_IP_DB{ $OBJ{NAME} }->{SOURCE}->{LINE} = $line;
            $CW_IP_DB{ $OBJ{NAME} }->{NAME}           = $OBJ{NAME};
            $CW_IP_DB{ $OBJ{NAME} }->{IP}             = $OBJ{IP};
        }
        else {
            unless ( $line eq $CW_IP_DB{ $OBJ{NAME} }->{SOURCE}->{LINE} ) {
                mypr "PASS_DBB: CiscoWorks ip db: discarded line   \'$line\'\n";
                mypr
"PASS_DBB:    -> object name already found in \'$CW_IP_DB{$OBJ{NAME}}->{SOURCE}->{LINE}\'\n";
            }
        }
    }
    close CSVDB;
    for my $entry ( values %NAME_HASH ) {
        if ( exists $CW_IP_DB{ $entry->{NAME} } ) {
            $entry->{IP} = $CW_IP_DB{ $entry->{NAME} }->{IP};

            # now add this entry also to %IP_HASH
            unless ( exists $IP_HASH{ $entry->{IP} } ) {
                $IP_HASH{ $entry->{IP} } = $entry;
            }
            else {
                mypr "PASS_DBB: CiscoWorks ip db:  NOT added to IP_HASH DB"
                  . " \'$entry->{SOURCE}->{LINE}\'\n";
            }
        }
        elsif ( defined quad2int_2( $entry->{NAME} ) ) {

            # no ip for this object found - so this may be a switch without
            # name - and we should not bother
            $entry->{IP} = $entry->{NAME};
            $IP_HASH{ $entry->{IP} } = $entry;
        }
        elsif ( $entry->{NAME} =~ /Cisco Systems NM data import/ ) {

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
    open( CSVDB, "$db/allp.csv" ) or die "could not open $db/allp.csv\n$!\n";
    for my $line ( <CSVDB> ) {
        $line =~ /^#/ and next;
        $line =~ s/[\"\n]//g;
        ( $line ) or next;
        my %OBJ;
        (
            $OBJ{NAME}, $OBJ{IP}, $OBJ{PASS}, $OBJ{ALIAS}, my $status,
            $OBJ{TYPE}, $OBJ{ENABLE_PASS}
        ) = split( /,/, $line );
        $OBJ{SOURCE}->{LINE} = $line;
        ( $status =~ "aktiv" ) or mypr "PASS_DBB: status is $status\n";
        $LEG_ALL_DB{ \%OBJ } = \%OBJ;

        unless ( exists $LEG_NAME_DB{ $OBJ{NAME} } ) {
            $LEG_NAME_DB{ $OBJ{NAME} } = \%OBJ;
        }
        else {

            #unless($line eq $LEG_NAME_DB{$OBJ{NAME}}->{SOURCE}->{LINE}){
            mypr "PASS_DBB: legacy name db: discarded line     \'$line\'\n";
            mypr
"PASS_DBB:    -> object name already found in \'$LEG_NAME_DB{$OBJ{NAME}}->{SOURCE}->{LINE}\'\n";

            #}
        }
        if ( $OBJ{ALIAS} ) {    # assume no alias if literally "0"
            unless ( exists $LEG_ALIAS_DB{ $OBJ{ALIAS} } ) {
                $LEG_ALIAS_DB{ $OBJ{ALIAS} } = \%OBJ;
            }
            else {

                #unless($line eq $LEG_ALIAS_DB{$OBJ{ALIAS}}->{SOURCE}->{LINE}){
                mypr
                  "PASS_DBB: legacy alias db: discarded line     \'$line\'\n";
                mypr
"PASS_DBB:    -> object alias already found in \'$LEG_ALIAS_DB{$OBJ{ALIAS}}->{SOURCE}->{LINE}\'\n";

                #}
            }
        }
        unless ( exists $LEG_IP_DB{ $OBJ{IP} } ) {
            $LEG_IP_DB{ $OBJ{IP} } = \%OBJ;
        }
        else {

            #unless($line eq $LEG_IP_DB{$OBJ{IP}}->{SOURCE}->{LINE}){
            mypr "PASS_DBB: legacy ip db:   discarded line     \'$line\'\n";
            mypr
"PASS_DBB:    -> object ip already found in   \'$LEG_IP_DB{$OBJ{IP}}->{SOURCE}->{LINE}\'\n";

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
    for my $entry ( values %NAME_HASH ) {
        $entry->{TYPE} or $entry->{TYPE} = "ios";
        $entry->{TYPE} eq 'L3sw'
          and $entry->{TYPE} = "ios";    # Switches are handled as routers
        my $found;
        if ( exists $LEG_NAME_DB{ $entry->{NAME} } ) {
            $found = $LEG_NAME_DB{ $entry->{NAME} };
            $found->{PASS} =
              $entry->{PASS};    # use password from Cisco Works in legacy DB!
            $found->{ENABLE_PASS} = $entry
              ->{ENABLE_PASS};    # use password from Cisco Works in legacy DB!
            $found->{LOCAL_USER} =
              $entry->{LOCAL_USER};    # use user from Cisco Works in legacy DB!
                                       # enhance
                                       #$entry->{TYPE}  = $found->{TYPE};
            $entry->{ALIAS} = $found->{ALIAS};

            # mark as used
            $found->{USED} = 1;
        }
        if ( exists $LEG_ALIAS_DB{ $entry->{NAME} } ) {
            if ( $found ) {
                if ( $found ne $LEG_ALIAS_DB{ $entry->{NAME} } ) {
                    mypr
"PASS_DBB: while enhancing %NAME_HASH: name match \'$found->{SOURCE}->{LINE}\'\n";
                    mypr
"PASS_DBB:                            alias match \'$LEG_ALIAS_DB{$entry->{NAME}}->{SOURCE}->{LINE}\'\n";
                }
            }
            else {
                $found = $LEG_ALIAS_DB{ $entry->{NAME} };
                $found->{PASS} =
                  $entry->{PASS};  # use password from Cisco Works in legacy DB!
                $found->{ENABLE_PASS} = $entry
                  ->{ENABLE_PASS}; # use password from Cisco Works in legacy DB!
                $found->{LOCAL_USER} = $entry
                  ->{LOCAL_USER};    # use user from Cisco Works in legacy DB!
                                     # enhance
                                     #$entry->{TYPE}  = $found->{TYPE};
                $entry->{ALIAS} = $entry->{NAME};
                $entry->{NAME}  = $found->{NAME};

                # mark as used
                $found->{USED} = 1;
            }
        }
        if ( $entry->{IP} and exists $LEG_IP_DB{ $entry->{IP} } ) {
            if ( $found ) {
                if ( $found ne $LEG_IP_DB{ $entry->{IP} } ) {
                    errpr
"while enhancing %NAME_HASH: name/alias match \'$found->{SOURCE}->{LINE}\'\n";
                    errpr
"                                    ip match \'$LEG_IP_DB{$entry->{IP}}->{SOURCE}->{LINE}\'\n";
                }
            }
            else {
                $found = $LEG_IP_DB{ $entry->{IP} };
                $found->{PASS} =
                  $entry->{PASS};  # use password from Cisco Works in legacy DB!
                $found->{ENABLE_PASS} = $entry
                  ->{ENABLE_PASS}; # use password from Cisco Works in legacy DB!
                $found->{LOCAL_USER} = $entry
                  ->{LOCAL_USER};    # use user from Cisco Works in legacy DB!
                                     # enhance
                                     #$entry->{TYPE}  = $found->{TYPE};
                $entry->{ALIAS} = $found->{ALIAS};

                # mark as used
                $found->{USED} = 1;
                unless ( $found->{PASS} eq $entry->{PASS} ) {
                    mypr
"PASS_DBB: while enhancing %NAME_HASH: match \'$entry->{SOURCE}->{LINE}\'\n";
                    mypr
"PASS_DBB:           through ip address with \'$found->{SOURCE}->{LINE}\'\n";
                }
            }
        }
        unless ( $found ) {

            # "guess"
            #$entry->{TYPE} or $entry->{TYPE}  = "ios";
            $entry->{ALIAS} = 0;
        }
    }
    my $used_entrys = 0;
    for my $val ( values %LEG_ALL_DB ) {
        if ( $val->{USED} ) {
            ++$used_entrys;
        }

        #else{
        #    mypr "unused: $val->{SOURCE}->{LINE}\'\n";
        #}
    }

#mypr "legacy DB: ". (scalar (values %LEG_ALL_DB) - $used_entrys)." out of ".scalar (values %LEG_ALL_DB)." entries not covered by CiscoWorks DB\n";

    $self->{DEVICEDATABASE} = {
        NAME_HASH   => \%NAME_HASH,
        IP_HASH     => \%IP_HASH,
        LEG_NAME_DB => \%LEG_NAME_DB,
        LEG_IP_DB   => \%LEG_IP_DB
    };
}

# take name or ip and retrieve passwd, name, ip (and type)
sub build_obj($$) {
    my ( $self, $spec ) = @_;
    my $DB;
    my $object;
    if ( $self->{OPTS}->{Z} ) {

        # build dummy object
        $object->{NAME} = $spec;
        $object->{IP}   = '0.0.0.0';
        $object->{PASS} = 'dummy';
        $object->{TYPE} = $self->{OPTS}->{Z};
    }
    else {
        $DB = $self->{DEVICEDATABASE};
        if ( exists $DB->{NAME_HASH}->{$spec} ) {

            #mypr "found object by name in CiscoWorks DB\n";
            $object = $DB->{NAME_HASH}->{$spec};
        }
        elsif ( exists $DB->{IP_HASH}->{$spec} ) {

            #mypr "found object by ip in CiscoWorks DB\n";
            $object = $DB->{IP_HASH}->{$spec};
        }
        elsif ( exists $DB->{LEG_NAME_DB}->{$spec} ) {

            #mypr "found object by name in legacy DB\n";
            $object = $DB->{LEG_NAME_DB}->{$spec};
        }
        elsif ( exists $DB->{LEG_IP_DB}->{$spec} ) {

            #mypr "found object by ip in legacy DB\n";
            $object = $DB->{LEG_IP_DB}->{$spec};
        }
        else {
            die "object $spec not found\n";
        }
    }
    unless ( $object->{PASS} ) {
        my $user = getpwuid( $> );
        if ( $user ne $self->{GLOBAL_CONFIG}->{SYSTEMUSER} ) {
            my $fh = $self->{STDOUT};
            print $fh
"Running in non privileged mode an no password in database found.\n";
            print $fh "Password for $user?";
            system( 'stty', '-echo' );
            my $password = <STDIN>;
            system( 'stty', 'echo' );
            print $fh "  ...thank you :)\n";
            chomp $password;
            $object->{PASS}       = $password;
            $object->{LOCAL_USER} = $user;
        }
        else {

            # no pasword in Database - use aaa_credentials
            open( AAA, $self->{GLOBAL_CONFIG}->{AAA_CREDENTIAL} )
              or die
              "could not open $self->{GLOBAL_CONFIG}->{AAA_CREDENTIAL} $!\n";
            my $credentials = <AAA>;
            $credentials =~ ( /^\s*(\S+)\s*(\S+)\s*$/ )
              or die "no aaa credential found\n";
            $object->{PASS} = $2;

            # overwrite user
            $object->{LOCAL_USER} = $1;
            mypr "User $1 from aaa credentials extracted\n";
            close( AAA );
        }
    }
    ( $object->{NAME} ) or die "no object name found\n";
    ( $object->{IP} )   or die "no address found\n";

    ( $object->{TYPE} ) or die "no object type found\n";
    my $name = $object->{NAME};
    $self->{DEVICES}->{$name}->{NAME}        = $object->{NAME};
    $self->{DEVICES}->{$name}->{ALIAS}       = $object->{ALIAS};
    $self->{DEVICES}->{$name}->{IP}          = $object->{IP};
    $self->{DEVICES}->{$name}->{PASS}        = $object->{PASS};
    $self->{DEVICES}->{$name}->{ENABLE_PASS} = $object->{ENABLE_PASS};
    $self->{DEVICES}->{$name}->{LOCAL_USER}  = $object->{LOCAL_USER};
    $self->{DEVICES}->{$name}->{TYPE}        = $object->{TYPE};

    #mypr "name: $nob->{NAME} alias: $nob->{ALIAS} ip: $nob->{IP}\n";
    #$self->{JOBNAME} = $object->{NAME};
    #$self->{JOBTYPE} = $object->{TYPE};

    return ( $object->{NAME}, $object->{TYPE} );
}

sub load_epilog($) {
    my $self = shift;
    my $epilog;
    if ( $self->{OPTS}->{G} ) {
        $epilog = $self->{OPTS}->{G};
    }
    elsif ( -d $self->{GLOBAL_CONFIG}->{EPILOGPATH} ) {
        $epilog = "$self->{GLOBAL_CONFIG}->{EPILOGPATH}$self->{JOBNAME}";
    }
    else {
        die "no file for rawdata specified and standard raw DIR doesn't exist;";
    }
    if ( -f $epilog ) {
        open( EPI, "<$epilog" ) or die "could not open rawdata: $epilog\n$!\n";
        @{ $self->{EPILOG} } = <EPI>;
        mypr "rawdata file ($epilog) for ", $self->{JOBNAME}, " has ",
          scalar @{ $self->{EPILOG} }, " lines\n";
        close EPI;
    }
    elsif ( -f "${epilog}.gz" ) {
        mypr "decompressing raw file...";
        @{ $self->{EPILOG} } = `gunzip -c "${epilog}.gz"`;
        $? and die "error running gunzip\n";
        mypr "done.\n";
    }
    else {
        @{ $self->{EPILOG} } = ();
        mypr "no rawdata found...\n";
    }
    return scalar @{ $self->{EPILOG} };
}

sub load_spocfile($) {
    my $self = shift;

    # read (spoc) config
    if ( $self->{OPTS}->{N} eq "STDIN" ) {
        ( open( NET, "<&STDIN" ) ) or die "could not dup STDIN\n$!\n";
        @{ $self->{SPOCFILE} } = <NET>;
        close( NET );
    }
    elsif ( -f $self->{OPTS}->{N} ) {
        ( open( NET, $self->{OPTS}->{N} ) )
          or die "could not open spocfile: $self->{OPTS}->{N}\n$!\n";
        @{ $self->{SPOCFILE} } = <NET>;
        close( NET );
    }
    elsif ( -f "$self->{OPTS}->{N}.gz" ) {
        mypr "decompressing config file...";
        @{ $self->{SPOCFILE} } = `gunzip -c "$self->{OPTS}->{N}.gz"`;
        $? and die "error running gunzip\n";
        mypr "done.\n";
    }
    else {
        die "spocfile \'$self->{OPTS}->{N}\' not found!\n";
    }
    mypr "config file ($self->{OPTS}->{N}) for  ", $self->{JOBNAME}, " has ",
      scalar @{ $self->{SPOCFILE} }, " lines\n";
    return scalar @{ $self->{SPOCFILE} };
}

sub logging($) {
    my $self = shift;
    open( $self->{STDOUT}, ">&STDOUT" )
      or die "could not save STDOUT for Password prompt $!\n";
    return unless ( $self->{OPTS}->{LOGFILE} );    # logging not enabled!
    my $logfile = $self->{OPTS}->{LOGFILE};
    if ( $logfile !~ /\A\// ) {

        # $logfile given as relative path - enhance to absolute path
        my $wd = `pwd`;
        chomp $wd;
        $logfile = "$wd/$logfile";
    }
    my $basename = basename( $self->{OPTS}->{LOGFILE} );
    $basename or die "no filename for logging specified\n";
    my $dirname = dirname( $self->{OPTS}->{LOGFILE} );

    # check for/create logdir
    unless ( -d $dirname ) {
        ( mkdir $dirname ) or die "could not create $dirname\n$!\n";
        ( defined chmod 0755, "$dirname" )
          or die " couldn't chmod logdir $dirname\n$!\n";
    }
    my $appmode;
    if ( $self->{OPTS}->{LOGAPPEND} ) {
        $appmode = ">>";    # append
    }
    else {
        $appmode = ">";     # clobber
        if ( $self->{OPTS}->{LOGVERSIONS} ) {
            if ( -f "$logfile" ) {
                my $date = time();
                system( "mv $logfile $logfile.$date" ) == 0
                  or die "could not backup $logfile\n$!\n";
                $self->{OPTS}->{NOLOGMESSAGE}
                  or mypr "existing logfile saved as \'$logfile.$date\'\n";
            }
        }
    }
    $self->{OPTS}->{NOLOGMESSAGE}
      or mypr "--- output redirected to $logfile\n";

    # print the above message *before* redirecting!
    unless ( -f "$logfile" ) {
        ( open( STDOUT, "$appmode$logfile" ) )
          or die "could not open $logfile\n$!\n";
        defined chmod 0644, "$logfile" or die " couldn't chmod $logfile\n$!\n";
    }
    else {
        ( open( STDOUT, "$appmode$logfile" ) )
          or die "could not open $logfile\n$!\n";
    }
    ( open( STDERR, ">&STDOUT" ) )
      or die "STDERR redirect: could not open $logfile\n$!\n";
}
{

    # a closure, beause we need the lock
    my $lock;

    sub lock( $$ ) {
        my ( $self, $name ) = @_;

        # set lock for exclusive approval
        exists $self->{DEVICES}->{$name}
          or die "$name: no such device\n";
        $self->{DEVICES}->{$name}->{NAME} eq $name
          or die "devicename mismatch\n";
        my $lockfile = "$self->{GLOBAL_CONFIG}->{LOCKFILEPATH}/$name";
        unless ( -f "$lockfile" ) {
            open( $lock->{$name}, ">$lockfile" )
              or die "could not aquire lock file: $lockfile\n$!\n";
            defined chmod 0666, "$lockfile"
              or die " couldn't chmod lockfile $lockfile\n$!\n";
        }
        else {
            open( $lock->{$name}, ">$lockfile" )
              or die "could not aquire lock file: $lockfile\n$!\n";
        }
        unless ( flock( $lock->{$name}, LOCK_EX | LOCK_NB ) ) {
            mypr "$!\n";
            return 0;
        }
    }

    sub unlock( $$ ) {
        my ( $self, $name ) = @_;
        exists $self->{DEVICES}->{$name}
          or die "$name: no such device\n";
        $self->{DEVICES}->{$name}->{NAME} eq $name
          or die "devicename mismatch\n";
        close( $lock->{$name} ) or die "could not unlock lockfile\n$!\n";
    }
}
1;
