#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::Differences;
use IPC::Run3;
use File::Basename;
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
    my ($spocfiles, $current, $statusfiles) = @_;
    # Create and fill netspoc directory.
    my $netspoc_dir = "$dir/netspoc";
    mkdir($netspoc_dir) or die "Can't create $netspoc_dir: $!\n";
    while (my ($file, $content) = each %$spocfiles) {
        my $dirname = $netspoc_dir;
        my $filedir = dirname($file);
        my @dirs = split(/\//,  $filedir);
        while (@dirs) {
            $dirname .= "/";
            $dirname .= shift(@dirs);
            -e $dirname or (mkdir("$dirname")
                            or die "Can't create $dirname: $!\n");
        }
        write_file("$netspoc_dir/$file", $content);
    }
    # Create symbolic link for current.
    -e "$netspoc_dir/$current" and
        `ln -s "$netspoc_dir/$current" "$netspoc_dir/current"`;


    # Create and fill status directory.
    my $status_dir = "$dir/status";
    mkdir($status_dir) or die "Can't create $status_dir: $!\n";
    while (my ($file, $content) = each %$statusfiles) {
#        -e "$status_dir/$file" or
#            (mkdir("$status_dir/$file") or
#             die "Can't create $status_dir/$file: $!\n");
        write_file("$status_dir/$file", $content);
    }

    # Prepare config file.
    my $config_file = "$dir/.netspoc-approve";
    write_file($config_file, <<"END");
netspocdir = $netspoc_dir
statusdir = $status_dir
lockfiledir = $dir
END

    # Set new HOME directory, because $config_file is searched there.
    $ENV{HOME} = $dir;

    # Run missing approve and return output.
    $ENV{PATH} = $ENV{PATH} .=':./bin';
    $ENV{PERL5LIB}="./lib";

    my ($stdout, $stderr);
    run3("bin/missing-approve", undef, \$stdout, \$stderr);

    # Child was stopped by signal.
    die if $? & 127;

    my $status = $? >> 8;
    `rm -r $dir/netspoc`;
    `rm -r $dir/status`;
    return( $status, $stdout, $stderr);
}

sub test_run {
    my ($spocfiles, $current, $statusfiles, $expected, $title) = @_;
    my ($success, $stdout, $stderr) = run($spocfiles, $current, $statusfiles);
    eq_or_diff($stdout, $expected, $title);
}




# Input from Netspoc IPv4 and IPv6, output from approve.
my ($spocfiles, $statusfiles, $current, $out);
my $title;

############################################################
$title = "missing approve - no status file for ipv4 device";
############################################################
$spocfiles = {

'p501/code/A' => <<END
lalala
END
};

$current = 'p501';
$out = <<END;
A
END

test_run($spocfiles, $current, $statusfiles, $out, $title);

############################################################
$title = "missing approve - no status file for ipv4 and ipv6 devices";
############################################################

$spocfiles = {

'p501/code/A' => <<END
Code for device A.
END
,
'p501/code/ipv6/B' => <<END
Code for device B.
END
};

$current = 'p501';
$out = <<END;
A
B
END

test_run($spocfiles, $current, $statusfiles, $out, $title);

############################################################
$title = "last approved/compared version differs from current version";
############################################################
$spocfiles = {

'p501/code/A' => <<END
Code for device A.
END
,
'p501/code/ipv6/B' => <<END
Code for device B.
END
,
'p500/code/A' => <<END
Old Code for Device A.
END
,
'p500/code/ipv6/B' => <<END
Old code for device B.
END
};

$statusfiles = {

'A' => <<END
f1;f2;p500;OK;f5;f6;f7;f8;f9;f10;f11;f12;UPTODATE;p500;f15;1519980299;1519980388;
END
,
'B' => <<END
f1;f2;p501;***ERRORS***;f5;f6;f7;f8;f9;f10;f11;f12;UPTODATE;p500;f15;1519980492;1519980388;
END
,
};

$current = 'p501';

$out = <<END;
A
B
END

test_run($spocfiles, $current, $statusfiles, $out, $title);

############################################################
$title = "last approved/compared version equals current version";
############################################################

$spocfiles = {

'p501/code/A' => <<END
Code for device A.
END
,
'p501/code/ipv6/B' => <<END
Code for device B.
END
,
'p500/code/A' => <<END
Code for device A.
END
,
'p500/code/ipv6/B' => <<END
Code for device B.
END
};

$statusfiles = {

'A' => <<END
f1;f2;p500;OK;f5;f6;f7;f8;f9;f10;f11;f12;UPTODATE;p500;f15;1519980299;1519980388;
END
,
'B' => <<END
f1;f2;p501;***ERRORS***;f5;f6;f7;f8;f9;f10;f11;f12;UPTODATE;p500;f15;1519980492;1519980388;
END
};

$current = 'p501';
$out = '';

test_run($spocfiles, $current, $statusfiles, $out, $title);

############################################################
done_testing;
