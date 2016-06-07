#!/usr/bin/perl
#
# Description:
# Approving device with netspoc configuration.
#
# https://github.com/hknutzen/Netspoc-Approve
# (c) 2016 by Heinz Knutzen <heinz.knutzen@gmail.com>
# (c) 2007 by Arne Spetzler
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
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

use strict;
use warnings;
use Fcntl qw/:flock/;    # import LOCK_* constants
use Fcntl;
use Getopt::Long;
use Netspoc::Approve::Load_Config;
use Netspoc::Approve::Device;
use Netspoc::Approve::Linux;
use Netspoc::Approve::IOS;
use Netspoc::Approve::ASA;
use Netspoc::Approve::NX_OS;
use Netspoc::Approve::ACE;
use Netspoc::Approve::Helper;

# VERSION: inserted by DZP::OurPkgVersion
my $version = __PACKAGE__->VERSION || 'devel';
$| = 1;    # output char by char

my %type2class = (
    Linux   => 'Netspoc::Approve::Linux',
    IOS     => 'Netspoc::Approve::IOS',
    ASA     => 'Netspoc::Approve::ASA',
    'NX-OS' => 'Netspoc::Approve::NX_OS',
    'ACE'   => 'Netspoc::Approve::ACE',
);

####################################################################
# main
####################################################################
#
# read command line switches:

sub usage {
    print STDERR <<END;
usage: 'drc3.pl [options] <file>'
   or: 'drc3.pl <file1> <file2>'
Compare / approve file with device or compare two files.
 -C                   compare only
 -u <username>        use username for login to remote device
 -q                   suppress info messages to STDERR
 -L <logdir>          path for saving telnet logs
 --LOGFILE <fullpath> path to redirect STDOUT and STDERR
 -v                   print program version

END
    exit -1;
}

sub banner_msg {
    my ($msg) = @_;
    my $time = localtime;
    info('*' x 68);
    info(" $msg: at > $time <");
    info('*' x 68);
}

Getopt::Long::Configure("no_ignore_case");

my %opts;

&GetOptions(
    \%opts,
    'C',
    'u=s',
    'q',
    'L=s',
    'LOGFILE=s',
    'v',
);

if ($opts{v}) {
    info $version;
    exit;
}
delete($opts{q}) and quiet();

my $file1 = shift or usage();
my $file2 = shift;
@ARGV and usage();

# Take basename of file as device name.
(my $name = $file1) =~ s|^.*/||;

# Get type and IP addresses from spoc file.
my $spoc_file = $file2 || $file1;
my ($type, @ip) = Netspoc::Approve::Device->get_spoc_data($spoc_file);

$type or abort("Can't get device type from $spoc_file");

# Get class from type.
my $class = $type2class{$type}
  or abort("Can't find class for [ Model = $type ] from $spoc_file");

my $job = $class->new(
    NAME   => $name,
    OPTS   => \%opts,
    IP     => shift(@ip),
);


# Handle file compare first, which can be run
# - without device's IP and password
# - without calling Load_Config (so we can use compare_files for testing).
if ($file2) {
    keys %opts and usage;
    exit($job->compare_files($file1, $file2) ? 1 : 0)
}

$job->{USER} = delete $opts{u} || getpwuid($>);
$job->{IP} or abort("Can't get IP from $spoc_file");
$job->{CONFIG} = Netspoc::Approve::Load_Config::load();

# Enable logging if configured.
$job->logging();

$job->lock($name);

# Start compare / approve.
banner_msg('START');
if ($opts{C}) {
    $job->compare($file1);
}
else {
    $job->approve($file1);
}
banner_msg('STOP');

$job->unlock($name);


