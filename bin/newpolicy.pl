#!/usr/bin/perl
# newpolicy -- integrates NetSPoC with CVS
# http://netspoc.berlios.de
# (c) 2002 by Heinz Knutzen <heinz.knutzen@web.de>,<heinz.knutzen@dzsh.de>
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
# Integrates NetSPoC with version control / build management
# The current user must have a working directory 'netspoc'
# in his home directory with NetSPoC files checked out
# from the CVS repository.
# - checks if working directory 
#   - is updated and 
#   - all changes are commited, 
#   - aborts if not
# - identifies the current policy 
# - calculates the next policy tag
# - tags users current configuration with new policy tag
# - extracts the tagged configuration into the policy database
# - compiles the new policy
# - marks the new directory as current policy
#
# $Id$

use strict;
use warnings;
use Fcntl qw(:DEFAULT :flock);

my $project = '/home/hk/project';
my $compiler = '/home/hk/develop/netspoc';
my $log = 'compile.log';
# name of cvs module
my $module = 'netspoc';
# policy database
my $policydb = "$project/netspoc";
# link to current policy
my $link = "$policydb/current";
# LOCK for preventing concurrent updates
my $lock = "$policydb/LOCK";
my $home = $ENV{HOME};
# users working directory
my $working = "$home/netspoc";
# policy file, contains current policy number
my $pfile = "$working/POLICY";
$ENV{CVSROOT} or die "Abort: No CVSROOT specified!\n";

# user must have an updated and checked in current policy
chdir $working or die "Error: can't change to $working: $!\n";
system("cvs -nQ tag -c test") == 0 or die "Aborted\n";
    
# Lock policy database
sysopen LOCK, "$lock", O_RDONLY | O_CREAT or
    die "Error: can't open $lock: $!";
flock(LOCK, LOCK_EX | LOCK_NB) or die "Abort: Another $0 is running\n";

# update, read, increment,commit current policy from working directory
# update
system("cvs update $pfile") == 0 or die "Aborted\n";
# read
open PFILE, $pfile or die "Can't open $pfile: $!\n";
my $line = <PFILE>;
close PFILE;
# $pfile contains one line: "! p22 comment .."
my(undef, $policy) = split ' ', $line;
my($count) = ($policy =~ /^p(\d+)$/) or
    die "Error: found invalid policy name '$policy' in $pfile";
# increment policy counter
$count++;
$policy = "p$count";
open PFILE, ">", $pfile or die "Can't open $pfile: $!\n";
print PFILE "# $policy # current policy, don't edit manually!\n";
close PFILE;
# commit
system("cvs commit $pfile") == 0 or die "Aborted\n";

print STDERR "Saving policy $count\n";

# tagging policy
system("cvs -Q tag -c $policy") == 0 or die "Aborted\n";

# check out new policy into policy database
chdir $policydb or die "Error: can't cd to $policydb: $!\n";
my $pdir = "$policydb/$policy";
mkdir $pdir or die "Error: can't create $pdir: $!\n";
chdir $policy or die "Error: can't cd to $pdir: $!\n";
system("cvs -Q checkout -d src -r $policy $module") == 0 or
    die "Error: can't checkout $policy to $pdir/src\n";

# compile new policy
chdir $pdir or die "Error: can't cd to $pdir: $!\n";
print STDERR "Compiling policy $count\n";
my $failed;
open COMPILE, '-|', "$compiler src code" or
    die "Can't execute $compiler: $!\n";
open LOG, '>', $log or die "Can' open $log: $!\n";
while(<COMPILE>) {
    print LOG; 
    print STDERR;
}
close LOG;
close COMPILE;
($? == 0) or $failed = 1;

# make new policy read only
system("chmod -R a-w *") == 0 or warn "Can't make $pdir/* read only\n";
system("chmod a+w .") == 0 or warn "Can't make $pdir world writable\n";

if($failed) {
    print STDERR "New policy failed to compile\n";
    my $current = readlink $link;
    $current and print STDERR "Left current policy as '$current'\n";
} else {
    # mark new policy as current, only if compiled successfully
    chdir $policydb or die "Error: can't cd to $policydb: $!\n";
    unlink $link;
    symlink $policy, $link or
	die "Error: failed to create symlink $link to $policy\n";
    
    print STDERR "Updated current policy to '$policy'\n";
}
# Unlock policy database: implicitly by exit
