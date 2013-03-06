# $Id$
package Test_Approve;

use strict;
use warnings;

our @ISA    = qw(Exporter);
our @EXPORT = qw(approve approve_err check_parse_and_unchanged);

use Test::More;
use Test::Differences;
use IPC::Run3;
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

sub run {
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

    my $cmd = "perl -I lib bin/drc3.pl -q $conf_file $spoc_file";
    my ($stdout, $stderr);
    run3($cmd, \undef, \$stdout, \$stderr);
    my $status = $? >> 1;
    return($status, $stdout, $stderr);
}

my %ignore = 
    (
     'configure terminal' => 1,
     'end' => 1,
     'configure session Netspoc' => 1,
     'verify' => 1,
     'commit' => 1,
     'write memory' => 1,
    );

sub approve {
    my($type, $conf, $spoc, $raw) = @_;
    my ($status, $stdout, $stderr) = run($type, $conf, $spoc, $raw);

    # 0: Success, 1: compare found diffs
#    $status == 0 || $status == 1 or die "Unexpected status: $status\n";
    $stderr and die "STDERR:\n$stderr\n";
    my @output = split /\n/, $stdout;

    # Collect commands from output.
    my @cmds = map { s/^> //; $_ } @output;
    @cmds = grep { !$ignore{$_}} @cmds;
    return(join("\n", @cmds, ''));
}

sub approve_err {
    my($type, $conf, $spoc, $raw) = @_;
    my ($status, $stdout, $stderr) = run($type, $conf, $spoc, $raw);
    return($stderr);
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
