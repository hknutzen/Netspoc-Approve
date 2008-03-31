
package Netspoc::Approve::Helper;

#
# Author: Arne Spetzler
#
# Description:
# module with misc helpers to drc2
#

'$Id$ ' =~ / (.+),v (.+?) /;
my $id = "$1 $2";

sub version_drc2_helper() {
    return $id;
}

require Exporter;
use FindBin;
use lib $FindBin::Bin;
use strict;
use warnings;
use Fcntl;
use Expect;
use File::Basename;

our @ISA    = qw(Exporter);
our @EXPORT = qw( mypr errpr check_erro errpr_mode errpr_info
  warnpr check_warn meself quad2int int2quad writestatu
  formatstatus getstatus getfullstatus updatestatus
  open_status expect_error
);

my %statfields = (
    DEVICENAME  => 0,
    APP_MESSAGE => 1,
    APP_STATUS  => 3,     # same as for DEV_STATUS and ***UNFINISHED APPROVE***
    APP_POLICY  => 2,
    APP_TIME    => 4,     # seconds since 1970 Cleartext
    APP_USER    => 5,
    DEV_MESSAGE => 6,
    DEV_STATUS  => 8,     # ***WARNINGS***, ***ERRORS***  or OK
    DEV_POLICY  => 7,
    DEV_TIME    => 9,     # seconds since 1970 Cleartext
    DEV_USER    => 10,
    COMP_COMP   => 11,
    COMP_RESULT => 12,    # DIFF or UPTODATE
    COMP_POLICY => 13,
    COMP_CTIME  => 14,    # seconds since 1970 Cleartext
    COMP_TIME   => 15,    # seconds since 1970
    COMP_DTIME  => 16,    # DEV_TIME in seconds
    FC_FC       => 17,
    FC_LAST_OK  => 18,    #last policy which seems to be identical to DEV_POLICY
    FC_STATE    => 19,    # result of last file compare: DIFF or OK
    FC_CTIME    => 20,    # seconds since 1970 Cleartext
    FC_TIME     => 21,    # seconds since 1970 (last change in state)
    MAX         => 21
);

my $warn     = "NO";      # sorry its global...
my $erro     = "NO";      # same applies to this :(
my $err_mode = "";

sub meself( $ ) {
    my $l    = $_[0];
    my $subs = "";
    for (my $i = 1 ; $i <= $l ; $i++) {
        my ($package, $file, $ln, $sub) = caller $i;
        $sub and $subs = $sub . " " . $subs;
    }
    return $subs;
}

sub mypr {
    print STDOUT @_;
}

sub errpr {
    $erro = "YES";
    print STDERR "ERROR>>> ", @_;
    unless ($err_mode eq "COMPARE") {
        print STDERR "ERROR>>> --- approve aborted ---\n";
        exit -1;
    }
}

sub errpr_mode( $ ) {
    $err_mode = shift;
    $err_mode eq "COMPARE" or die "COMPARE expected\n";
}

sub check_erro() {
    return $erro;
}

sub errpr_info {
    print STDERR "ERROR>>> ", @_;
}

sub warnpr {
    $warn = "YES";
    print STDOUT "WARNING>>> ", @_;
}

sub check_warn() {
    return $warn;
}

sub writestatus ( $ ) {
    my $stat = shift;

    # disable output buffering for status messages
    # due to better reliability
    my $oldselect   = select STATUS;
    my $oldbuffmode = $|;
    unless ($oldbuffmode == 1) {
        $| = 1;
    }
    seek STATUS, 0, 0;
    print join ';', @$stat;
    truncate STATUS, tell STATUS or die "could not truncate statfile\n";
    $| = $oldbuffmode;
    select $oldselect;
}

sub formatstatus ( $ ) {
    my $stat = shift;
    for (my $i = 0 ; $i <= $statfields{MAX} ; $i++) {
        unless (exists $stat->[$i]
            and $stat->[$i] =~ /\S/
            and $stat->[$i] ne 'undef')
        {
            if ($i == $statfields{APP_MESSAGE}) {
                $stat->[ $statfields{APP_MESSAGE} ] = 'LAST_APPROVE';
            }
            elsif ($i == $statfields{DEV_MESSAGE}) {
                $stat->[ $statfields{DEV_MESSAGE} ] = 'LAST_SUCCESS';
            }
            elsif ($i == $statfields{DEV_POLICY}) {
                $stat->[ $statfields{DEV_POLICY} ] = 'p0';
            }
            elsif ($i == $statfields{COMP_COMP}) {
                $stat->[ $statfields{COMP_COMP} ] = 'COMPARE';
            }
            elsif ($i == $statfields{COMP_POLICY}) {
                $stat->[ $statfields{COMP_POLICY} ] = 'p0';
            }
            elsif ($i == $statfields{COMP_TIME}) {
                $stat->[ $statfields{COMP_TIME} ] = 0;
            }
            elsif ($i == $statfields{COMP_DTIME}) {
                $stat->[ $statfields{COMP_DTIME} ] = 0;
            }
            elsif ($i == $statfields{FC_FC}) {
                $stat->[ $statfields{FC_FC} ] = 'FILE_COMPARE';
            }
            elsif ($i == $statfields{FC_LAST_OK}) {
                $stat->[ $statfields{FC_LAST_OK} ] = 0;
            }
            elsif ($i == $statfields{FC_TIME}) {
                $stat->[ $statfields{FC_TIME} ] = 0;
            }
            else {
                $stat->[$i] = 'undef';
            }
        }
    }
    $stat->[ $statfields{MAX} + 1 ] = "\n";
    writestatus($stat);
}

sub getstatus ( $ ) {
    my $position = shift;
    seek STATUS, 0, 0;
    my @stat = split ';', <STATUS>;

    # @stat may be  empty
    if ($#stat < $statfields{MAX} + 1) {
        formatstatus(\@stat);
    }
    (exists $statfields{$position})
      || die "unknown status field $position\n";

    return $stat[ $statfields{$position} ];
}

sub getfullstatus () {
    my $fst = {};
    for my $pos (keys %statfields) {
        $fst->{$pos} = getstatus($pos);
    }
    return $fst;
}

sub updatestatus ( $$ ) {
    my ($position, $value) = @_;

    # disable output buffering for status messages
    # due to better reliability
    seek STATUS, 0, 0;
    my @stat = split ';', <STATUS>;

    # @stat may be  empty
    if ($#stat < $statfields{MAX} + 1) {
        formatstatus(\@stat);
    }
    (exists $statfields{$position})
      || die "unknown status field $position\n";

    @stat[ $statfields{$position} ] = $value;

    writestatus(\@stat);
}

sub open_status( $ ) {
    my $job        = shift;
    my $devicename = $job->{JOBNAME};
    my $statuspath = $job->{GLOBAL_CONFIG}->{STATUSPATH};

    # open status file for update and checking
    unless (-f "$statuspath$devicename") {
        (sysopen(STATUS, "$statuspath$devicename", O_RDWR | O_CREAT))
          or die "could not open/create file: $statuspath$devicename\n$!\n";
        defined chmod 0644, "$statuspath$devicename"
          or die " couldn't chmod lockfile $statuspath$devicename\n$!\n";
    }
    else {
        (sysopen(STATUS, "$statuspath$devicename", O_RDWR))
          or die "could not open file: $statuspath$devicename\n$!\n";
    }
}

sub quad2int ($) {
    ($_[0] =~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/) or return undef;
    ($1 < 256 && $2 < 256 && $3 < 256 && $4 < 256) or return undef;
    return $1 << 24 | $2 << 16 | $3 << 8 | $4;
}

sub int2quad ($) {
    return join('.', unpack('C4', pack("N", $_[0])));
}

#--------------------------- CONSOLE HELPER --------------------------
sub new_console ($$$$) {
    my ($class, $nob, $name, $logfile, $startup_message) = @_;
    if (exists $nob->{CONSOLE}->{$name}) {
        die "console \'$name\' already created\n";
    }
    $nob->{CONSOLE}->{$name}->{NAME} = $name;
    my $CON = $nob->{CONSOLE}->{$name};
    $CON->{NAME}   = $name;
    $CON->{PARENT} = $nob->{CONSOLE};
    my $console = Expect->new();
    $CON->{EXPECT} = $console;

    if ($logfile) {
        my $fh;
        unless (-f "$logfile") {
            (open($fh, ">>$logfile"))
              or die "could not open $logfile\n$!\n";

            # because we create the file here, we have to chmod to
            # allow access by group members!
            defined chmod 0644, "$logfile"
              or die " couldn't chmod $logfile\n$!\n";
        }
        else {
            (open($fh, ">>$logfile"))
              or die "could not open $logfile\n$!\n";
        }
        print $fh "\n";
        print $fh "********************************************************\n";
        print $fh "  $startup_message\n";
        print $fh "********************************************************\n";
        print $fh "\n";
        $console->log_file($logfile);
        $CON->{LOG} = $fh;
    }
    $console->debug(0);
    $console->exp_internal(0);

    #$Expect::Debug = 1;
    $console->raw_pty(1);
    $console->log_stdout(0);
    bless($CON, $class);
    return $CON;
}

sub shutdown_console ($$) {
    my ($CON, $shutdown_message) = @_;
    if (exists $CON->{LOG}) {
        my $fh = $CON->{LOG};
        print $fh "\n";
        print $fh "********************************************************\n";
        print $fh "  $shutdown_message\n";
        print $fh "********************************************************\n";
        print $fh "\n";
    }

    # do the right thing... (maybe we have to close something else...)
    #print $ssh->fileno()."\n";
    $CON->{EXPECT}->soft_close();    # or die $ssh->error();
    delete $CON->{PARENT}->{ $CON->{NAME} };
}

#    If called in an array context expect() will return
#    ($matched_pattern_position, $error, $success-
#    fully_matching_string, $before_match, and
#    $after_match).

#    Possible values of $error are undef, indi-
#    cating no error, '1:TIMEOUT' indicating that $timeout
#    seconds had elapsed without a match, '2:EOF' indicat-
#    ing an eof was read from $object, '3: spawn
#    id($fileno) died' indicating that the process exited
#    before matching and '4:$!' indicating whatever error
#    was set in $ERRNO during the last read on $object's
#    handle.

sub con_wait($$$) {
    my ($CON, $prompt, $timeout) = @_;
    my ($package, $file, $ln, $sub) = caller 1;
    $sub eq "drc2_ios_exp::issue_cmd" or delete $CON->{RESULT};
    my @result;
    if (defined $CON->{PAGER}) {
        @result =
          $CON->{EXPECT}
          ->expect($timeout, '-re', $prompt, '-re', $CON->{PAGER});
    }
    else {
        @result = $CON->{EXPECT}->expect($timeout, '-re', $prompt);
    }
    $CON->{RESULT}->{PROMPT} = $prompt;
    defined $CON->{PAGER} and $CON->{RESULT}->{PAGER} = $CON->{PAGER};
    $CON->{RESULT}->{TIMEOUT} = $timeout;
    $CON->{RESULT}->{ERROR}   = $result[1];
    $CON->{RESULT}->{MPPOS}   = $result[0];
    $CON->{RESULT}->{MATCH}   = $result[2];
    $CON->{RESULT}->{BEFORE}  = $result[3];
    $CON->{RESULT}->{AFTER}   = $result[4];
    defined $CON->{RESULT}->{ERROR} and return 0;
    return 1;
}

sub con_issue_cmd ($$$$) {
    my ($CON, $cmd, $prompt, $timeout) = @_;
    $CON->{RESULT}->{CMD} = $cmd;

    $CON->{EXPECT}->send($cmd);
    $CON->con_wait($prompt, $timeout) or return 0;
    if (defined $CON->{PAGER}) {
        my $bbuffer = '';
        while ($CON->{RESULT}->{MATCH} =~ $CON->{PAGER}) {
            $bbuffer = $bbuffer . $CON->{RESULT}->{BEFORE};
            $CON->{EXPECT}->send($CON->{PAGER_KEY});
            $CON->con_wait($prompt, $timeout) or return 0;
        }
        $CON->{RESULT}->{BEFORE} = $bbuffer . $CON->{RESULT}->{BEFORE};
    }
    return 1;
}

sub con_cmd ($$) {
    my ($CON, $cmd) = @_;
    my $prompt  = $CON->{PROMPT};
    my $timeout = $CON->{TIMEOUT};
    return $CON->con_issue_cmd($cmd, $prompt, $timeout);
}

sub con_error {
    my $CON  = shift;
    my $subs = "";
    for (my $i = 1 ; $i <= 3 ; $i++) {
        my ($package, $file, $ln, $sub) = caller $i;
        $sub and $subs = "$sub($ln) $subs";
    }
    mypr "\n";
    errpr_info "$subs\n";
    for my $key (keys %{ $CON->{RESULT} }) {
        my $value =
          defined $CON->{RESULT}->{$key} ? $CON->{RESULT}->{$key} : "";
        errpr_info "$key $value\n";
    }
    exit -1;
}

sub con_dump( $ ) {
    my $CON = shift;
    mypr "$CON->{RESULT}->{BEFORE}$CON->{RESULT}->{MATCH}";
}
1;
