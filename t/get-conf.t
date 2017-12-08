#!/usr/bin/perl
# get-config.t

use strict;
use warnings;
use Test::More;
use Test::Differences;
use IPC::Run3;
use File::Temp qw/ tempdir /;

my $dir = tempdir(CLEANUP => 1) or die "Can't create tmpdir: $!\n";

# Set new HOME directory, because $config_file is searched there.
$ENV{HOME} = $dir;

sub write_file {
    my($name, $data) = @_;
    my $fh;
    open($fh, '>', $name) or die "Can't open $name: $!\n";
    print($fh $data) or die "$!\n";
    close($fh);
}

sub run {
    my ($config, $key) = @_;

    # Prepare config file.
    my $config_file = "$dir/.netspoc-approve";
    write_file($config_file, $config);

    my $cmd = "bin/get-netspoc-approve-conf $key";

    # Propagate options to perl process.
    my $perl_opt = $ENV{HARNESS_PERL_SWITCHES} || '';

    $cmd = "$^X $perl_opt -I lib $cmd";
    my ($stdout, $stderr);
    run3($cmd, \undef, \$stdout, \$stderr);
    my $status = $? >> 8;
    my $success = $status == 0;
    $stderr ||= '';

    # Normalize input path: remove temp. dir.
    $stderr =~ s/\Q$dir\E\///g;
    return($success, $stdout, $stderr);
}

sub test_run {
    my ($title, $config, $key, $expected) = @_;
    my ($success, $stdout, $stderr) = run($config, $key);
    if (not $success) {
        diag("Unexpected failure:\n$stderr");
        fail($title);
        return;
    }
    eq_or_diff($stderr.$stdout, $expected, $title);
}

sub test_err {
    my ($title, $config, $key, $expected) = @_;
    my ($status, $success, $stderr) = run($config, $key);
    if ($success) {
        diag("Unexpected success");
        diag($stderr) if $stderr;
        fail($title);
        return;
    }
    eq_or_diff($stderr, $expected, $title);
}

my ($title, $config, $expected);

############################################################
$title = "Missing argument";
############################################################

$config = <<'END';
netspocdir = /tmp
lockfiledir = /tmp
checkbanner = NetSPoC
END

$expected = <<'END';
Usage: bin/get-netspoc-approve-conf KEY
END

test_err($title, $config, '', $expected);

############################################################
$title = "Missing required option";
############################################################

$config = <<'END';
lockfiledir = /tmp
checkbanner = NetSPoC
END

$expected = <<'END';
Missing 'netspocdir' in configuration file at bin/get-netspoc-approve-conf line 28.
END

test_err($title, $config, 'checkbanner', $expected);

############################################################
$title = "Read default value";
############################################################

$config = <<'END';
netspocdir = /tmp
lockfiledir = /tmp
END

$expected = <<'END';
60
END

test_run($title, $config, 'timeout', $expected);

############################################################
$title = "Read changed default value";
############################################################

$config = <<'END';
netspocdir = /tmp
lockfiledir = /tmp
timeout = 10
END

$expected = <<'END';
10
END

test_run($title, $config, 'timeout', $expected);

############################################################
$title = "Duplicate option";
############################################################

$config = <<'END';
netspocdir = /tmp
lockfiledir = /tmp
timeout = 10
timeout = 20
END

$expected = <<'END';
Ignoring duplicate key 'timeout' in .netspoc-approve at bin/get-netspoc-approve-conf line 28.
10
END

test_run($title, $config, 'timeout', $expected);

############################################################
$title = "Ignore multi word value";
############################################################

$config = <<'END';
netspocdir = /tmp
lockfiledir = /tmp
checkbanner = NetSPoC managed device
END

$expected = <<'END';
Ignoring line 'checkbanner = NetSPoC managed device' in .netspoc-approve at bin/get-netspoc-approve-conf line 28.
Missing value for key checkbanner
END

test_err($title, $config, 'checkbanner', $expected);

############################################################
$title = "Warn on invalid config lines";
############################################################

$config = <<'END';
netspocdir = /tmp
INVALID
lockfiledir = /tmp
KEY = VALUE
checkbanner = NetSPoC
timeout = 1
END

$expected = <<'END';
Ignoring line 'INVALID' in .netspoc-approve at bin/get-netspoc-approve-conf line 28.
Ignoring key 'KEY' in .netspoc-approve at bin/get-netspoc-approve-conf line 28.
NetSPoC
END

test_run($title, $config, 'checkbanner', $expected);

############################################################
done_testing;
