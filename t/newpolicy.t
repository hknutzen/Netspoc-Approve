#!/usr/bin/env perl

use strict;
use warnings;
use File::Spec::Functions qw/ file_name_is_absolute splitpath catdir catfile /;
use File::Path 'make_path';
use Cwd;
use File::Temp qw/ tempdir /;
use IPC::Run3;
use Time::HiRes qw(usleep);
use Test::More;
use Test::Differences;

my $APPROVE_DIR = cwd;

# Set up PATH and PERL5LIB, such that files and libraries are searched
# in $HOME/Netspoc-Approve
$ENV{PATH} = "$APPROVE_DIR/bin:$ENV{PATH}";
{
    my $lib = "$APPROVE_DIR/lib";
    if (my $old = $ENV{PERL5LIB}) {
        $lib .= ":$old";
    }
    $ENV{PERL5LIB} = $lib;
}

# Create working directory, set as current directory for relative paths.
# Set as HOME directory for config file .netspoc-approve.
my $dir = tempdir(CLEANUP => 1);
chdir $dir;
$ENV{HOME} = $dir;

my $orig_cvs = `which cvs`;
chomp $orig_cvs;

sub write_file {
    my($name, $data) = @_;
    my $fh;
    open($fh, '>', $name) or die "Can't open $name: $!\n";
    print($fh $data) or die "$!\n";
    close($fh);
}

# Fill $dir with files from $input.
# $input consists of one or more blocks.
# Each block is preceeded by a single line
# starting with one or more of dashes followed by a filename.
sub prepare_dir {
    my($dir, $input) = @_;
    my $delim  = qr/^-+[ ]*(\S+)[ ]*\n/m;
    my @input = split($delim, $input);
    my $first = shift @input;

    # Input doesn't start with filename.
    if ($first) {
        BAIL_OUT("Missing filename before first input block");
        return;
    }
    while (@input) {
        my $path = shift @input;
        my $data = shift @input;
        if (file_name_is_absolute $path) {
            BAIL_OUT("Unexpected absolute path '$path'");
            return;
        }
        my (undef, $dir_part, $file) = splitpath($path);
        my $full_dir = catdir($dir, $dir_part);
        make_path($full_dir);
        my $full_path = catfile($full_dir, $file);
        write_file($full_path, $data);
    }
}

sub setup_netspoc {
    my ($dir, $in) = @_;

    # Initialize empty CVS repository.
    mkdir 'cvsroot';
    $ENV{CVSROOT} = "$dir/cvsroot";
    system "$orig_cvs init";

    # Create initial netspoc files and put them under CVS control.
    mkdir('import');
    prepare_dir('import', $in);
    chdir 'import';
    system "$orig_cvs -Q import -m start netspoc vendor version";
    chdir $dir;
    system 'rm -r import';
    system "$orig_cvs -Q checkout netspoc";

    # Create config file .netspoc-approve for newpolicy
    mkdir('policydb');
    mkdir('lock');
    write_file('.netspoc-approve', <<"END");
netspocdir = $dir/policydb
lockfiledir = $dir/lock
END
}

sub change_netspoc {
    my ($in) = @_;
    prepare_dir('netspoc', $in);
    system "$orig_cvs -Q commit -m test netspoc";
}

sub setup_bin {
    my ($dir) = @_;

    # Install slow version of cvs, that is called inside newpolicy.pl,
    # so we can observe parallel execution.
    mkdir("$dir/my-bin");
    write_file("$dir/my-bin/cvs", <<"END");
#!/bin/sh
$orig_cvs "\$@"
sleep 0.5
END

    # Install suid-newpolicy, that simply calls newpolicy.pl
    symlink "$APPROVE_DIR/bin/newpolicy.pl", "$dir/my-bin/suid-newpolicy";

    system "chmod a+x $dir/my-bin/*";
    $ENV{PATH} = "$dir/my-bin:$ENV{PATH}";
}

sub check_newpolicy {
    my ($fh, $expected, $title) = @_;

    # Read all lines at once.
    local $/ = undef;
    my $got = <$fh>;
    close $fh;
    $got =~ s|\Q$dir/policydb/||;
    eq_or_diff($got, $expected, $title);
}

setup_bin($dir);
setup_netspoc($dir, <<'END');
-- config
verbose = 0;
-- topology
network:n1 = { ip = 10.1.1.0/24; }
END

open(my $fh1, '-|', 'newpolicy 2>&1');
usleep 60000;
open(my $fh2, '-|', 'newpolicy 2>&1');
change_netspoc(<<'END');
-- topology
network:n1 = { ip = 10.1.1.0/24; }  # Comment
END

open(my $fh3, '-|', 'newpolicy 2>&1');
usleep 1000000;
open(my $fh4, '-|', 'newpolicy 2>&1');

check_newpolicy($fh1, <<'END', 'Start and show');
Processing current changeset
Updated current policy to 'p1'
END

check_newpolicy($fh2,  <<'END', 'Show running');
Newest changeset is currently processed
Updated current policy to 'p1'
END

check_newpolicy($fh3, <<'END', 'After commit');
Waiting for current process to be finished
Updated current policy to 'p1'
---
Processing current changeset
Updated current policy to 'p2'
END

check_newpolicy($fh4, <<'END', 'Later after commit');
Waiting for current process to be finished
Processing current changeset
Updated current policy to 'p2'
END

open($fh1, '-|', 'newpolicy 2>&1');

check_newpolicy($fh1, <<'END', 'Up to date');
Newest changeset is already available as current p2
END

change_netspoc(<<'END');
-- topology
network:n1 = { ip = 10.1.1.0/24; }  BAD SYNTAX
END

open($fh1, '-|', 'newpolicy 2>&1');

check_newpolicy($fh1, <<'END', 'Failed to compile');
Processing current changeset
Syntax error: Typed name expected at line 1 of next/src/topology, near "BAD<--HERE--> SYNTAX"
New policy failed to compile
Left current policy as 'p2'
END

############################################################
done_testing;
