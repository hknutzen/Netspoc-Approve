#!/usr/bin/perl
# newpolicy.pl -- Checkout configuration from Netspoc for Approve
# http://hknutzen.github.com/Netspoc
# (c) 2014 by Heinz Knutzen <heinz.knutzen@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
# Description:
# Integrates NetSPoC with version control / build management.
# - creates a new directory 'next' in policy db
# - extracts newest configuration from repository into 'next'
# - identifies the current policy from policy db
# - calculates the next policy tag
# - compiles the new policy
# - renames directory 'next' to name of next policy tag
# - marks new policy in policy db as current
#

use strict;
use warnings;
use IO::Handle;
use Fcntl qw(:DEFAULT :flock);
use Netspoc::Approve::Load_Config;

sub abort { die "Error:", @_, "\n"; }

my $config = Netspoc::Approve::Load_Config::load();

# Get real UID of calling user (not the effective UID from setuid wrapper).
my $real_uid = $<;

# Get users pw entry.
my @pwentry = getpwuid($real_uid) or 
    abort("Can't get pwentry of UID $real_uid: $!");

# Get users home directory.
my $home = $pwentry[7] or abort("Can't get home directory for UID $real_uid");

# Users netspoc directory.
my $working = "$home/netspoc";

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

# Set secure path.
$ENV{PATH} = "/usr/local/bin:/usr/bin:/bin";

# Lock policy database.
sysopen my $lock_fh, "$lock", O_RDONLY | O_CREAT or
    abort("Error: can't open $lock: $!");
if (not flock($lock_fh, LOCK_EX | LOCK_NB)) {

# Not needed, because this is only used from wrapper script.
#    # Read user and time from lockfile.
#    open(my $fh, '<', $lock) or abort("Can't open $lock for reading: $!");
#    my $status = <$fh> || '';
#    close $fh;
#    chomp $status;
#    print STDERR "Another $0 is running. $status\n";

    # Status code 2 signals, that a process is already running.
    exit 2
}

# Write user and time to lockfile for better error message.
my $user =  $pwentry[0] or abort("Can't get user name for UID $real_uid");
open(my $fh, '>', $lock) or abort("Can't open $lock for writing: $!");
my $status = "Started by $user at " . localtime() . "\n";
print $fh $status;
close $fh;

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

# Check out newest files from repository
# into subdirectory "src" of new policy directory.
# Prune empty directories.
system('cvs', '-Q', 'checkout', '-P', '-d', 'src', $module) == 0 or
    log_abort("Can't checkout to $psrc: $!");

# Read current policy name from POLICY file.
my $fcount;
my $policy_file = "$psrc/$module/POLICY";
if (open(my $policy_fh, '<', $policy_file)) {
    my $line = <$policy_fh>;
    close($policy_fh);

    # $pfile contains one line: "# p22 comment .."
    ($fcount) = ($line =~ m'^#? *p(\d+) ') or
	log_abort("No valid policy name found in $policy_file");
}
else {
    $fcount = 0;
}

# Read current policy name from symbolic link.
my $lcount;
if(my $name = readlink $link) {

    # Link must have name "p<number>".
    ($lcount) = ($name =~ /^p(\d+)$/) or
	log_abort("Invalid policy name '$name' found in $link");
}
else {
    $lcount = 0;
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

    # Run newpolicy_hooks on newly created policy.
    if (my $hooks = $config->{newpolicy_hooks}) {
        for my $hook (split(/\s*[,\s]\s*/, $hooks)) {
            system($hook) == 0 or warn "Failed to run hook $hook\n";
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
