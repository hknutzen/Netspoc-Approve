# $Id$
package Test_Approve;
our @ISA    = qw(Exporter);
our @EXPORT = qw(approve);

use File::Temp qw/ tempfile tempdir /;

my $device_name = 'asatest';
my $dir = tempdir(CLEANUP => 1) or die "Can't create tmpdir: $!\n";
my $code_dir = "$dir/code";
my $spoc_dir = "$dir/netspoc";
my $raw_dir = "$dir/netspoc/raw";
mkdir($code_dir) or die "Can't create $code_dir: $!\n";
mkdir($spoc_dir) or die "Can't create $spoc_dir: $!\n";
mkdir($raw_dir) or die "Can't create $spoc_dir: $!\n";

# Header for all Netspoc input
my $header = <<END;
! [ BEGIN router:$device_name ]
! [ Model = ASA ]
END

sub approve {
    my($conf, $spoc) = @_;
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

    # Start file compare, get output.
    open(APPROVE, '-|', 
	 "perl -I lib bin/drc3.pl -F1 $conf_file -F2 $spoc_file $device_name") 
	or die "Can't execute drc3.pl: $!\n";
    my @output = <APPROVE>;
    close(APPROVE);

    # Collect commands from output.
    my @cmds = map { m/^> (.*)/ } @output;
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
