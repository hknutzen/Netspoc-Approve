#!/usr/bin/env perl

=head1 NAME

newpolicy.pl -- Checkout configuration from Netspoc for Approve

=head1 DESCRIPTION

Integrates NetSPoC with version control / build management.
- creates a new directory 'next' in policy db
- extracts newest configuration from repository into 'next'
- identifies the current policy from policy db
- calculates the next policy tag
- compiles the new policy
- renames directory 'next' to name of next policy tag
- marks new policy in policy db as current

=head1 COPYRIGHT AND DISCLAIMER

https://github.com/hknutzen/Netspoc-Approve
(c) 2018 by Heinz Knutzen <heinz.knutzen@gmail.com>

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

=cut

use strict;
use warnings;
use IO::Handle;
use Fcntl qw(:DEFAULT :flock);
use Netspoc::Approve::Load_Config;

sub abort { die "Error:", @_, "\n"; }

my $config = Netspoc::Approve::Load_Config::load();

# Path of policy database.
my $policydb = $config->{netspocdir};

# Name of netspoc compiler, PATH from sanitized environment (see below).
my $compiler = 'netspoc';

# Name of cvs module in repository.
my $module = 'netspoc';

# Link to current policy.
my $link = "$policydb/current";

# Intermediate name for next policy
my $next = "$policydb/next";

# The lock file for preventing concurrent updates.
my $lock = "$policydb/LOCK";

# Set secure path, if run as other user.
# Real UID != effective UID or started by sudo.
if ($> != $< or $ENV{SUDO_USER}) {
    $ENV{PATH} = "/usr/local/bin:/usr/bin:/bin";
}

# Lock policy database.
sysopen my $lock_fh, "$lock", O_RDONLY | O_CREAT or
    abort("Error: can't open $lock: $!");

# Status code 2 signals, that a process is already running.
# Not error message needed, because this is only called from wrapper script.
flock($lock_fh, LOCK_EX | LOCK_NB) or exit 2;

# Cleanup leftovers from possible previous unsuccessful build of this policy.
system('rm', '-rf', $next);

# Create directory for new policy.
print STDERR "Creating new policy\n";
mkdir $next or abort("Error: can't create $next: $!");

# Directory and file names of new policy in policy database.
my $psrc  = "$next/src";
my $pcode = "$next/code";
my $plog  = "$next/compile.log";

# Open $plog
open my $log_fh, '>', $plog or abort("Can't open $plog: $!");
sub log_line {
    my ($line) = @_;
    print $log_fh $line;
    print STDERR $line;
}

sub log_abort {
    my ($line) = @_;
    log_line("Error: $line\n");
    exit 1;
}

# Lock $plog
# After lock is removed, outside programs know, that logging has finished.
flock($log_fh, LOCK_EX) or log_abort("Can't lock $plog");

# So other programs reading from this file see the output immediately.
$log_fh->autoflush(1);

# In server mode, cvs commands need relative pathnames.
# Hence change into parent directory.
chdir($next) or log_abort("Can't 'cd $next': $!");

# Check out newest files from repository into subdirectory "src" of
# new policy directory.  Must not use option '-P' to prune empty
# directories, so up-to-date check (cvs -n -q update) of outer
# 'newpolicy' script can differ between empty and new directories: Old
# but empty directories are checked out and found to be equal, while
# new directories are not checked out and lead to an --ignored
# message.
# Ignore '.cvsrc' to not accidently activate option '-P'.
system('cvs', '-Q', '-f', 'checkout', '-d', 'src', $module) == 0 or
    log_abort("Can't checkout to $psrc: $!");

# Read current policy name from POLICY file.
my $fcount = 0;
my $policy_file = "$psrc/$module/POLICY";
if (open(my $policy_fh, '<', $policy_file)) {
    my $line = <$policy_fh>;
    close($policy_fh);

    # $pfile contains one line: "# p22 comment .."
    ($fcount) = ($line =~ m'^#? *p(\d+) ') or
        log_abort("No valid policy name found in $policy_file");
}

# Read current policy name from symbolic link.
my $lcount = 0;
my $prev_policy;
if($prev_policy = readlink $link) {

    # Link must have name "p<number>". Untaint $prev_policy.
    ($prev_policy, $lcount) = ($prev_policy =~ /^(p(\d+))$/) or
        log_abort("Invalid policy name '$prev_policy' found in $link");
}

# Create symlink from new to old code directory,
# to speed up pass 2 of Netspoc compiler.
my $prev_link;
if ($prev_policy) {
   mkdir $pcode or abort("Error: can't create $pcode: $!");
   my $prev_code = "../../$prev_policy/code";
   $prev_link = "$pcode/.prev";
   symlink $prev_code, $prev_link or
       log_abort("Failed to create symlink $prev_link to $prev_code");
}

# Compare $fcount and $lcount.
# Typically both values are identical.
# Take maximum if values are different.
my $count = $fcount > $lcount ? $fcount : $lcount;

# Increment counter.
$count++;

# Get next policy name.
my $policy = "p$count";

# Compile new policy.
open(my $compile_fh, '-|', "$compiler $psrc $pcode 2>&1") or
    log_abort("Can't execute $compiler: $!");

while(my $line = <$compile_fh>) {
    log_line($line);
}
close $compile_fh;

# Compiled successfully.
if ($? == 0) {

    # Update POLICY file of current version.
    # In server mode, "cvs add" needs to be inside "src" directory.
    chdir("$next/src") or log_abort("Can't cd to $next/src: $!");

    my $pfile = 'POLICY';
    my $exists = -e $pfile;
    if ($exists) {
        system('cvs', 'edit', $pfile) == 0 or log_abort("Aborted");
    }
    open  my $policy_fh, '>', $pfile or log_abort("Can't open $pfile: $!");
    print $policy_fh "# $policy # Current policy, don't edit manually!\n";
    close $policy_fh;
    if (!$exists) {
        system('cvs', 'add', $pfile) == 0 or log_abort("Aborted");
    }
    system('cvs', 'commit', '-m', $policy , $pfile) == 0 or
        log_abort("Aborted");

    # Move temporary directory to final name
    chdir $policydb or log_abort("Can't cd to $policydb: $!");
    rename 'next', $policy or log_abort "Can't rename $next to $policy";

    # Mark new policy as current.
    unlink $link;
    symlink $policy, $link or
        log_abort("Failed to create symlink $link to $policy");
    log_line("Updated current policy to '$policy'\n");

    # Cleanup previous code directory.
    # Remove huge and no longer used files from pass 1.
    if ($prev_policy) {
        my $prev_code = "$policydb/$prev_policy/code";
        unlink glob("$prev_code/*.config $prev_code/*.rules");
        if ( -e "$prev_code/ipv6") {
            unlink glob("$prev_code/ipv6/*.config $prev_code/ipv6/*.rules");
        }
    }

    # Success.
    exit 0;
}

# Failed to compile.
else {
    log_line("New policy failed to compile\n");

    # Mark data as failed for use in wrapper.
    system("touch $next/failed");
    my $current = readlink $link;
    $current and log_line("Left current policy as '$current'\n");

    # Failure.
    exit 1;
}

# Unlock policy database: implicitly by exit.
