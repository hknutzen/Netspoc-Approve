package Test_Approve;

use strict;
use warnings;

our @ISA    = qw(Exporter);
our @EXPORT = qw(approve approve_err approve_status check_parse_and_unchanged
                 simul_run simul_err simul_compare write_file
                 run check_output);

use Test::More;
use Test::Differences;
use IPC::Run3;
use File::Temp qw/ tempdir /;

my $dir = tempdir(CLEANUP => 1) or die "Can't create tmpdir: $!\n";
my $code_dir = "$dir/code";
mkdir($code_dir) or die "Can't create $code_dir: $!\n";

sub write_file {
    my($name, $data) = @_;
    my $fh;
    open($fh, '>', $name) or die "Can't open $name: $!\n";
    print($fh $data) or die "$!\n";
    close($fh);
}

sub prepare_spoc {
    my ($type, $device_name, $spoc4, $spoc6, $raw4, $raw6, $hdr4, $hdr6) = @_;

    # Header for Netspoc input
    my $comment = $type eq 'Linux' ? '#' : '!';
    ($hdr4 and $hdr6) or my $header = <<"END";
$comment [ BEGIN router:$device_name ]
$comment [ Model = $type ]
$comment [ IP = 10.1.13.33 ]

END

    my @filename = ("$code_dir/$device_name", "$code_dir/ipv6/$device_name");
    my @file = ($spoc4, $spoc6);
    my @raw = ($raw4, $raw6);
    my @header = ($hdr4, $hdr6);

    -e "$code_dir/ipv6/" or `mkdir "$code_dir/ipv6/"`;
    for (my $i=0; $i <= 1; $i++) {
        defined $file[$i] and $file[$i] =
            ($header? $header : $header[$i]) . $file[$i];
        $file[$i] and write_file($filename[$i], $file[$i]);
        not $file[$i] and -e $filename[$i] and `rm $filename[$i]`;
        $raw[$i] and write_file("$filename[$i].raw", $raw[$i]);
        not $raw[$i] and -e "$filename[$i].raw" and `rm $filename[$i].raw`;
    }
    (defined $spoc6 or defined $raw6) or `rmdir "$code_dir/ipv6/"`;

    return "$code_dir/$device_name";
}

sub run {
    my ($cmd) = @_;

    # Propagate options to perl process.
    my $perl_opt = $ENV{HARNESS_PERL_SWITCHES} || '';

    $cmd = "$^X $perl_opt -I lib $cmd";
    my ($stdout, $stderr);
    run3($cmd, \undef, \$stdout, \$stderr);

    # Child was stopped by signal.
    die if $? & 127;

    my $status = $? >> 8;
    return($status, $stdout, $stderr);
}

sub simulate {
    my ($type, $scenario, $spoc, $options) = @_;
    $options ||= '';

    my $device_name = 'router';
    my $spoc_file = prepare_spoc($type, $device_name, $spoc);

    # Prepare simulation command.
    # Tell drc3.pl to use simulation by setting environment variable.
    my $scenario_file = "$dir/scenario";
    write_file($scenario_file, $scenario);
    my $simulation_cmd = "t/simulate-cisco.pl $device_name $scenario_file";
    $ENV{SIMULATE_ROUTER} = $simulation_cmd;

    # Prepare credentials file. Declare current user as system user.
    my $id = getpwuid($<);
    my $credentials_file = "$dir/credentials";
    write_file($credentials_file, <<"END");
* $id secret
END

    # Prepare config file.
    my $config_file = "$dir/.netspoc-approve";
    write_file($config_file, <<"END");
netspocdir = $dir
lockfiledir = $dir
checkbanner = NetSPoC
systemuser = $id
aaa_credentials = $credentials_file
timeout = 1
END

    # Set new HOME directory, because $config_file is searched there.
    $ENV{HOME} = $dir;

    return run("bin/drc3.pl -q -L $dir $options $spoc_file");
}

sub compare_files {
    my($type, $conf, $spoc4, $spoc6, $raw4, $raw6, $hdr4, $hdr6) = @_;

    my $spoc_file = prepare_spoc($type, 'test', $spoc4, $spoc6,
                                 $raw4, $raw6, $hdr4, $hdr6);

    # Prepare device file.
    my $conf_file = "$dir/conf";
    write_file($conf_file, $conf);

    return run("bin/drc3.pl -q $conf_file $spoc_file");
}

my %ignore =
    (
     'configure terminal' => 1,
     'end' => 1,
     'exit' => 1,
     'configure session Netspoc' => 1,
     'verify' => 1,
     'commit' => 1,
     'write memory' => 1,
    );

sub filter_compare_output {
    my ($output) = @_;
    my @lines = split /\n/, $output;
    my @cmds = map { s/^> //; $_ } @lines;
    @cmds = grep { !$ignore{$_}} @cmds;
    return(join("\n", @cmds, ''));
}

sub approve {
    my($type, $conf, $spoc4, $spoc6, $raw4, $raw6, $hdr4, $hdr6) = @_;
    my ($status, $stdout, $stderr) =
        compare_files($type, $conf, $spoc4, $spoc6, $raw4, $raw6, $hdr4, $hdr6);

    # 0: Success, 1: compare found diffs
    if ($status != 0 && $status != 1) {
        $stderr ||= '';
        BAIL_OUT "Unexpected status: $status\n$stderr\n";
    }
    $stderr and BAIL_OUT "STDERR:\n$stderr\n";
    return filter_compare_output($stdout);
}

sub approve_err {
    my($type, $conf, $spoc_v4, $spoc_v6, $raw4, $raw6, $hdr4, $hdr6) = @_;
    my ($status, $stdout, $stderr) =
        compare_files($type, $conf, $spoc_v4, $spoc_v6, $raw4, $raw6,
                      $hdr4, $hdr6);
    return($stderr);
}

sub approve_status {
    my($type, $conf, $spoc, $raw) = @_;
    my ($status, $stdout, $stderr) = compare_files($type, $conf, $spoc, $raw);
    return($status);
}

# Blocks of expected output are split by single lines,
# each line starting with dashes and followed by a file name.
# First optional block contains expected warnings.
sub check_output {
    my ($title, $dir, $expected, $stderr) = @_;
    my  ($warnings, @expected) = split(/^-+[ ]*(\S+)[ ]*\n/m, $expected);

    if ($warnings or $stderr) {
        eq_or_diff($stderr, $warnings, $title);
    }

    while (@expected) {
        my $fname = shift @expected;
        my $block = shift @expected;
        chomp $block;
        $block =~ s/\n/\r\n/g;

        open(my $out_fh, '<', "$dir/$fname") or die "Can't open $fname";
        my $output;
        {
            local $/ = undef;	    # Read all output at once.
            $output = <$out_fh>;
        }
        close($out_fh);
        eq_or_diff($output, $block, "$title: $fname");
    }
}

sub simul_run {
    my($title, $type, $scenario, $spoc, $expected) = @_;
    my ($status, $stdout, $stderr) = simulate($type, $scenario, $spoc);
    $stderr ||= '';
    if ($status != 0) {
        diag("Unexpected failure:\n$stderr");
        fail($title);
        return;
    }
    check_output($title, $dir, $expected, $stderr);
}

sub simul_err {
    my($title, $type, $scenario, $spoc, $expected) = @_;
    my ($status, $stdout, $stderr) = simulate($type, $scenario, $spoc);
    if ($status == 0) {
        diag("Unexpected success");
        diag($stderr) if $stderr;
        fail($title);
        return;
    }

    eq_or_diff($stderr, $expected, $title);
}

sub simul_compare {
    my($title, $type, $scenario, $spoc, $expected) = @_;
    my ($status, $stdout, $stderr) = simulate($type, $scenario, $spoc, '-C');
    $stderr ||= '';
    if ($status != 0) {
        diag("Unexpected failure:\n$stderr");
        fail($title);
        return;
    }
    my $output = filter_compare_output($stderr.$stdout);
    eq_or_diff($output, $expected, $title);
}

# Check whether output is as expected with given input
# AND whether output is empty for identical input.
sub check_parse_and_unchanged {
    my ( $type, $minimal_device, $in, $out, $title ) = @_;
    eq_or_diff( approve( $type, $minimal_device, $in ), $out, $title );

    $out = '';
    $title =~ /^Parse (.*)/ or
	BAIL_OUT "Need title starting with 'Parse' as argument!";
    $title = "Empty out on identical in ($1)";
    eq_or_diff( approve( $type, $in, $in ), $out, $title );
}

1;
