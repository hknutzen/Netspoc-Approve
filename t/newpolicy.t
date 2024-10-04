#!/usr/bin/env perl

use strict;
use warnings;
use File::Spec::Functions qw/ file_name_is_absolute splitpath catdir catfile /;
use File::Path 'make_path';
use Cwd;
use File::Temp qw/ tempdir /;
use IPC::Run3;
use Fcntl qw(:DEFAULT :flock);
use Time::HiRes qw(usleep);
use Test::More;
use Test::Differences;

# Don't run this test on CI server, where netspoc isn't installed.
if (system('which netspoc >/dev/null') != 0) {
    plan skip_all => 'Program "netspoc" not available';
}

# newpolicy.pl checks for SUDO_USER in environment.
# In this case tests would fail.
delete $ENV{SUDO_USER};

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
my $dir = tempdir(CLEANUP => 1, DIR => $APPROVE_DIR);
chdir $dir;
$ENV{HOME} = $dir;

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

    # Prevent warnings from git.
    system 'git config --global user.name "Test User"';
    system 'git config --global user.email ""';
    system 'git config --global init.defaultBranch master';
    system 'git config --global pull.rebase true';

    my $tmp = "$dir/tmp-git";
    mkdir $tmp;
    prepare_dir($tmp, $in);
    chdir $tmp;
    # Initialize git repository.
    system 'git init --quiet';
    system 'git add .';
    system 'git commit -m initial >/dev/null';
    chdir $dir;
    # Checkout into bare directory
    my $bare = "$dir/netspoc.git";
    system "git clone --quiet --bare $tmp $bare";
    system "rm -rf $tmp";
    # Checkout into directory 'netspoc'
    system "git clone --quiet $bare netspoc";

    # Create config file .netspoc-approve for newpolicy
    mkdir('policydb');
    mkdir('lock');
    write_file('.netspoc-approve', <<"END");
netspocdir = $dir/policydb
lockfiledir = $dir/lock
netspoc_git = file://$bare
END
}

sub change_netspoc {
    my ($in) = @_;
    prepare_dir('netspoc', $in);
    chdir 'netspoc';
    system 'git add .';
    system 'git commit -m test >/dev/null';
    system 'git pull --quiet';
    system 'git push --quiet';
    chdir $dir;
}

sub setup_bin {
    my ($dir) = @_;

    # Install version of git, that can be controlled to wait after
    # completion.
    mkdir("$dir/my-bin");
    my $orig_bin = `which git`;
    chomp $orig_bin;
    write_file("$dir/my-bin/git", <<"END");
#!/bin/sh
$orig_bin "\$@"
status=\$?

# Wait when "git clone" is called inside newpolicy.pl
if echo \$* | grep -q '^clone'; then
   flock $dir/do-wait -c true 2>/dev/null

# Signal that 'uptodate' check in 'newpolicy' has started.
elif echo \$* | grep -q '^rev-parse'; then
   touch $dir/is-started
fi

exit \$status
END

    # Install sudo-newpolicy, that simply calls newpolicy.pl
    # Use current perl interpreter.
    write_file("$dir/my-bin/sudo-newpolicy", <<"END");
#!/bin/sh
$^X $APPROVE_DIR/bin/newpolicy.pl
END

    system "chmod a+x $dir/my-bin/*";
    $ENV{PATH} = "$dir/my-bin:$ENV{PATH}";
}

sub start_newpolicy {
    open(my $fh, '-|', "$APPROVE_DIR/bin/newpolicy 2>&1");
    return $fh;
}

sub wait_newpolicy_started {
        usleep 1000;
    while(not -f 'is-started') {
        usleep 1000;
    }
    system 'rm -f is-started';
}

sub check_newpolicy {
    my ($fh, $expected, $title) = @_;

    my $got = '';
    while(my $line = <$fh>) {
        $got .= $line;
        chomp $line;
#        diag $line;
    }
    close $fh;
    $got =~ s|\Q$dir/policydb/||;
    eq_or_diff($got, $expected, $title);
}

setup_netspoc($dir, <<'END');
-- config
quiet = 1;
-- topology
network:n1 = { ip = 10.1.1.0/24; }
END
setup_bin($dir);

system 'touch policydb/LOCK';

# Let newpolicy.pl wait.
sysopen my $wait_fh, 'do-wait', O_RDONLY | O_CREAT;
flock($wait_fh, LOCK_EX);
my $fh1 = start_newpolicy();
# Wait until netspoc files have been cloned.
while(not -f 'policydb/next/src/.git/refs/heads/master') {
    usleep 1000;
}

my $fh2 = start_newpolicy();
wait_newpolicy_started();

change_netspoc(<<'END');
-- topology
network:n1 = { ip = 10.1.1.0/24; }  # Comment
END

my $fh3 = start_newpolicy();
wait_newpolicy_started();

# Let newpolicy.pl proceed.
close $wait_fh;

my $fh4 = start_newpolicy();

check_newpolicy($fh1, <<'END', 'Start and show');
Processing current changeset
Finished 'p1'
END

check_newpolicy($fh2,  <<'END', 'Show running');
Newest changeset is currently processed
Finished 'p1'
END

check_newpolicy($fh3, <<'END', 'After commit');
Waiting for current process to be finished
Finished 'p1'
Processing current changeset
Finished 'p2'
END

check_newpolicy($fh4, <<'END', 'Later after commit');
Waiting for current process to be finished
Finished 'p1'
Processing current changeset
Finished 'p2'
END

$fh1 = start_newpolicy();

check_newpolicy($fh1, <<'END', 'Up to date');
Newest changeset is already available as current p2
END

change_netspoc(<<'END');
-- topology
network:n1 = { ip = 10.1.1.0/24; }  BAD SYNTAX
END

$fh1 = start_newpolicy();

check_newpolicy($fh1, <<'END', 'Failed to compile');
Processing current changeset
Error: Typed name expected at line 1 of next/src/topology, near "10.1.1.0/24; }  --HERE-->BAD"
Aborted
New policy failed to compile
Left current policy as 'p2'
END

change_netspoc(<<'END');
-- topology
network:n1 = { ip = 10.1.1.0/24; }  # GOOD AGAIN
END

$fh1 = start_newpolicy();

check_newpolicy($fh1, <<'END', 'Up to date again');
Processing current changeset
Finished 'p3'
END

change_netspoc(<<'END');
-- topology
network:n1 = { ip = 10.1.1.0/24; }  # Changed
END
# Remove link in policydb and check if policy number is restored from
# file src/POLICY.
system 'rm policydb/current';

$fh1 = start_newpolicy();

check_newpolicy($fh1, <<'END', 'Restore policy number');
Processing current changeset
Finished 'p4'
END

############################################################
done_testing;
