# $Id$
package Test_Approve;
our @ISA    = qw(Exporter);
our @EXPORT = qw(approve check_parse_and_unchanged);


use strict;
use Test::More;
use Test::Differences;
use File::Temp qw/ tempfile tempdir /;

my $device_name = 'test';
my $dir = tempdir(CLEANUP => 1) or die "Can't create tmpdir: $!\n";
my $code_dir = "$dir/code";
my $spoc_dir = "$dir/netspoc";
my $raw_dir = "$dir/netspoc/raw";
mkdir($code_dir) or die "Can't create $code_dir: $!\n";
mkdir($spoc_dir) or die "Can't create $spoc_dir: $!\n";
mkdir($raw_dir) or die "Can't create $spoc_dir: $!\n";

sub write_file {
    my($name, $data) = @_;
    my $fh;
    open($fh, '>', $name) or die "Can't open $name: $!\n";
    print($fh $data) or die "$!\n";
    close($fh);
}

sub approve {
    my($type, $conf, $spoc, $raw) = @_;

    # Header for all Netspoc input
    my $comment = $type eq 'Linux' ? '#' : '!';
    my $header = <<END;
$comment [ BEGIN router:$device_name ]
$comment [ Model = $type ]
$comment [ IP = 10.1.13.33 ]

END

    $spoc = $header . $spoc;

    # Prepare input files.
    my $conf_file = "$code_dir/conf";
    my $spoc_file = "$code_dir/spoc";
    write_file($conf_file, $conf);
    write_file($spoc_file, $spoc);
    write_file("$spoc_file.raw", $raw) if $raw;

    my $cmd = 
	"perl -I lib bin/drc3.pl $conf_file $spoc_file"

	# redirect STDERR to STDOUT.
	# disabled, because we can't debug tests.
	# and because we die on error anyway.
#	. " 2>&1"
	;
	
    # Start file compare, get output.
    open(my $approve, '-|', $cmd) or die "Can't execute drc3.pl: $!\n";
    my @output = <$approve>;
    if (not close($approve)) {
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

# Check whether output is as expected with given input
# AND whether output is empty for identical input.
sub check_parse_and_unchanged {
    my ( $type, $minimal_device, $in, $out, $title ) = @_;
    eq_or_diff( approve( $type, $minimal_device, $in ), $out, $title );

    $out = '';
    $title =~ /^Parse (.*)/ or
	die "Need title starting with 'Parse' as argument!";
    $title = "Empty out on identical in ($1)";
    eq_or_diff( approve( $type, $in, $in ), $out, $title );
}    
    

1;
