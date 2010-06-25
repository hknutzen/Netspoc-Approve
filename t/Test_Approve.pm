# $Id$
package Test_Approve;
our @ISA    = qw(Exporter);
our @EXPORT = qw(approve);

use File::Temp qw/ tempfile tempdir /;

my $device_name = 'test';
my $dir = tempdir(CLEANUP => 1) or die "Can't create tmpdir: $!\n";
my $code_dir = "$dir/code";
my $spoc_dir = "$dir/netspoc";
my $raw_dir = "$dir/netspoc/raw";
mkdir($code_dir) or die "Can't create $code_dir: $!\n";
mkdir($spoc_dir) or die "Can't create $spoc_dir: $!\n";
mkdir($raw_dir) or die "Can't create $spoc_dir: $!\n";

sub approve {
    my($type, $conf, $spoc) = @_;

    # Header for all Netspoc input
    my $header = <<END;
! [ BEGIN router:$device_name ]
! [ Model = $type ]
END

    $spoc = $header . $spoc;

    # Prepare input files.
    my $spoc_file = "$code_dir/spoc";
    my $conf_file = "$code_dir/conf";
    open(FILE, '>', $spoc_file) or die "Can't open $spoc_file: $!\n";
    print(FILE $spoc) or die "$!\n";
    close(FILE);
    open(FILE, '>', $conf_file) or die "Can't open $conf_file: $!\n";
    print(FILE $conf) or die "$!\n";
    close(FILE);

    # redirect STDERR to STDOUT.
    my $cmd = 
	"perl -I lib bin/drc3.pl -F1 $conf_file -F2 $spoc_file $device_name" .
	" 2>&1";
	
    # Start file compare, get output.
    open(APPROVE, '-|', $cmd) or die "Can't execute drc3.pl: $!\n";
    my @output = <APPROVE>;
    if (not close(APPROVE)) {
	$! and  die "Syserr closing pipe from drc3.pl: $!\n";
	my $exit_value = $? >> 8;

	# 0: Success, 1: compare found diffs
 	$exit_value == 0 || $exit_value == 1 or 
	    die "Status from drc3.pl: $exit_value\n";
    }

    # Collect commands and messages from output.
    my @cmds = 
	map { m/^> (.*)/ } grep { m/^> |^(?:ERROR|WARNING)\>\>\>/} @output;
    my %ignore = 
	(
	 'configure terminal' => 1,
	 'end' => 1,
	 'write memory' => 1,
	 );
    @cmds = grep { !$ignore{$_}} @cmds;
    return(join("\n", @cmds, ''));
}

1;
