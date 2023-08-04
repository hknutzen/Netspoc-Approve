package Test_Approve;

use strict;
use warnings;

our @ISA    = qw(Exporter);
our @EXPORT = qw(test_run test_warn test_err test_status
                 check_parse_and_unchanged
                 prepare_simulation
                 simul_run simul_err simul_compare write_file
                 run check_output drc3_err missing_approve);

use Test::More;
use Test::Differences;
use IPC::Run3;
use File::Temp qw/ tempdir /;
use File::Basename;
use lib '/lib';

my $dir = tempdir(CLEANUP => 1) or die "Can't create tmpdir: $!\n";
my $code_dir = "$dir/code";
mkdir($code_dir) or die "Can't create $code_dir: $!\n";

my $device_name = 'router';
sub write_file {
    my($name, $data) = @_;
    my $fh;
    open($fh, '>', $name) or die "Can't open $name: $!\n";
    print($fh $data) or die "$!\n";
    close($fh);
}

sub prepare_spoc {
    my ($type, $spoc) = @_;

    my $code_dir = "$dir/code";
    `rm -rf $code_dir`;
    mkdir($code_dir) or die "Can't create $code_dir: $!\n";

    # Header for Netspoc input
    my $comment = $type eq 'Linux' ? '#' : '!';
    my $header = <<"END";
$comment [ BEGIN router:$device_name ]
$comment [ Model = $type ]
$comment [ IP = 10.1.13.33 ]

END

    if (ref($spoc) ne 'HASH') {
        $spoc = { spoc4 => $spoc };
    }

    my $spoc_file = "$code_dir/$device_name";
    mkdir("$code_dir/ipv6");
    for my $v (4, 6) {
        my $fname = $spoc_file;
        if ($v == 6) {
            $fname = "$code_dir/ipv6/$device_name"
        }
        if (defined(my $code = $spoc->{"spoc$v"})) {
            $code = ($spoc->{"hdr$v"} || $header) . $code;
            write_file($fname, $code);
        }
        if (my $raw = $spoc->{"raw$v"}) {
            write_file("$fname.raw", $raw);
        }
    }

    return $spoc_file;
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

# Prepare simulation command.
# Tell drc3.pl to use simulation by setting environment variable.
sub prepare_simulation {
    my ($scenario) = @_;
    my $scenario_file = "$dir/scenario";
    write_file($scenario_file, $scenario);
    my $simulation_cmd = "t/simulate-cisco.pl $device_name $scenario_file";
    $ENV{SIMULATE_ROUTER} = $simulation_cmd;
}

sub simulate {
    my ($type, $scenario, $spoc, $options) = @_;
    $options ||= '';

    my $spoc_file = prepare_spoc($type, $spoc);
    prepare_simulation($scenario);

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
    my($type, $conf, $spoc) = @_;

    my $spoc_file = prepare_spoc($type, $spoc);

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

sub approve_warn {
    my($type, $conf, $spoc) = @_;
    my ($status, $stdout, $stderr) =
        compare_files($type, $conf, $spoc);

    # 0: Success, 1: compare found diffs
    if ($status != 0 && $status != 1) {
        $stderr ||= '';
        BAIL_OUT "Unexpected status: $status\n$stderr\n";
    }
    my $changes = filter_compare_output($stdout);
    if ($changes and $status == 0) {
        BAIL_OUT "Got status 'unchanged', but changes found:\n$changes";
    }
    elsif (not $changes and $status == 1) {
        BAIL_OUT "Got status 'changed' but no changes found";
    }
    return ($changes, $stderr);
}

sub test_warn {
    my($title, $type, $conf, $spoc, $warn, $expected) = @_;
    my ($o, $e) = approve_warn($type, $conf, $spoc);
    eq_or_diff($o, $expected, "$title changes");
    eq_or_diff($e, $warn, "$title warnings");
}

sub approve {
    my($type, $conf, $spoc) = @_;
    my ($changes, $stderr) = approve_warn($type, $conf, $spoc);
    $stderr and BAIL_OUT "STDERR:\n$stderr\n";
    return $changes;
}

sub test_run {
    my($title, $type, $conf, $spoc, $expected) = @_;
    eq_or_diff(approve($type, $conf, $spoc), $expected, $title);
}

sub test_err {
    my($title, $type, $conf, $spoc, $expected) = @_;
    my ($status, $stdout, $stderr) = compare_files($type, $conf, $spoc);
    eq_or_diff($stderr, $expected, $title);
}

sub test_status {
    my($title, $type, $conf, $spoc, $num) = @_;
    my ($status, $stdout, $stderr) = compare_files($type, $conf, $spoc);
    ok($status == $num, $title);
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

        open(my $out_fh, '<', "$dir/$fname") or die "Can't open $fname";
        my $output;
        {
            local $/ = undef;	    # Read all output at once.
            $output = <$out_fh>;
        }
        close($out_fh);
        $output =~ s/\r\n/\n/g;

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
    my ($title, $type, $minimal_device, $in, $out) = @_;
    eq_or_diff(approve( $type, $minimal_device, $in ), $out, $title);

    $out = '';
    $title =~ /^Parse (.*)/ or
	BAIL_OUT "Need title starting with 'Parse' as argument!";
    $title = "Empty out on identical in ($1)";
    eq_or_diff(approve( $type, $in, $in ), $out, $title);
}

sub drc3_err {
    my ($title, $type, $spoc, $expected) = @_;
    my $spoc_file = prepare_spoc($type, $spoc);

    # Prepare config file.
    my $config_file = "$dir/.netspoc-approve";
    write_file($config_file, <<"END");
netspocdir = $dir
lockfiledir = $dir
checkbanner = NetSPoC
timeout = 1
END
    $ENV{HOME} = $dir;

    my ($status, $stdout, $stderr) = run("bin/drc3.pl -q $spoc_file");
    $stderr =~ s/\Q$dir\E\/code\///g;
    eq_or_diff($stderr, $expected, $title);
}



1;
