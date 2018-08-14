package Test_Approve;

use strict;
use warnings;

our @ISA    = qw(Exporter);
our @EXPORT = qw(approve approve_err approve_status check_parse_and_unchanged
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

    # Header for Netspoc input
    my $comment = $type eq 'Linux' ? '#' : '!';
    my $header = <<"END";
$comment [ BEGIN router:$device_name ]
$comment [ Model = $type ]
$comment [ IP = 10.1.13.33 ]

END

    if (ref($spoc) ne 'HASH') {
        $spoc = $header . $spoc;
        my $spoc_file = "$code_dir/$device_name";
        write_file($spoc_file, $spoc);
        -e "$spoc_file.raw" and `rm $spoc_file.raw`;
        -e "$code_dir/ipv6/"
            and `rm -r "$code_dir/ipv6/"`;
        return $spoc_file;
    }

    my $spec = {
        ipv4 => {
            filename => "$code_dir/$device_name",
            file  => $spoc->{spoc4},
            raw => $spoc->{raw4},
            header => $spoc->{hdr4}? $spoc->{hdr4} : $header },
        ipv6 => {
            filename => "$code_dir/ipv6/$device_name",
            file  => $spoc->{spoc6},
            raw => $spoc->{raw6},
            header => $spoc->{hdr6}? $spoc->{hdr6} : $header },
    };

    -e "$code_dir/ipv6/" or `mkdir "$code_dir/ipv6/"`;
    for my $v (qw(ipv4 ipv6)) {
        defined $spec->{$v}->{file} and
            $spec->{$v}->{file} = $spec->{$v}->{header} . $spec->{$v}->{file};
        $spec->{$v}->{file} and write_file($spec->{$v}->{filename},
                                           $spec->{$v}->{file});
        not $spec->{$v}->{file} and -e $spec->{$v}->{filename} and
            `rm $spec->{$v}->{filename}`;
        $spec->{$v}->{raw} and write_file("$spec->{$v}->{filename}.raw",
                                          $spec->{$v}->{raw});
        not $spec->{$v}->{raw} and -e "$spec->{$v}->{filename}.raw" and
            `rm $spec->{$v}->{filename}.raw`;
    }

    (defined $spoc->{spoc6} or defined $spoc->{raw6}) or
        `rmdir "$code_dir/ipv6/"`;

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

    my $spoc_file = prepare_spoc($type, 'test', $spoc);

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
    my($type, $conf, $spoc) = @_;
    my ($status, $stdout, $stderr) =
        compare_files($type, $conf, $spoc);

    # 0: Success, 1: compare found diffs
    if ($status != 0 && $status != 1) {
        $stderr ||= '';
        BAIL_OUT "Unexpected status: $status\n$stderr\n";
    }
    $stderr and BAIL_OUT "STDERR:\n$stderr\n";
    return filter_compare_output($stdout);
}

sub approve_err {
    my($type, $conf, $spoc) = @_;
    my ($status, $stdout, $stderr) =
        compare_files($type, $conf, $spoc);
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
    my ( $type, $minimal_device, $in, $out, $title ) = @_;
    eq_or_diff( approve( $type, $minimal_device, $in ), $out, $title );

    $out = '';
    $title =~ /^Parse (.*)/ or
	BAIL_OUT "Need title starting with 'Parse' as argument!";
    $title = "Empty out on identical in ($1)";
    eq_or_diff( approve( $type, $in, $in ), $out, $title );
}

sub drc3_err {
    my ($type, $devicename, $spoc, $expected, $title) = @_;
    my $spoc_file = prepare_spoc($type, $devicename, $spoc);

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
    eq_or_diff($stderr, $expected, $title);
}



1;
