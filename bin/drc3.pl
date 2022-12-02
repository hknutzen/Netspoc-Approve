#!/usr/bin/env perl
#
# Description:
# Approving device with netspoc configuration.
#
# https://github.com/hknutzen/Netspoc-Approve
# (c) 2022 by Heinz Knutzen <heinz.knutzen@gmail.com>
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
use Netspoc::Approve::Helper;

our $VERSION = '3.005'; # VERSION: inserted by DZP::OurPkgVersion
my $version = __PACKAGE__->VERSION || 'devel';
$| = 1;    # output char by char

my %type2class = (
    Linux   => 'Netspoc::Approve::Linux',
    IOS     => 'Netspoc::Approve::IOS',
    ASA     => 'Netspoc::Approve::ASA',
    'NX-OS' => 'Netspoc::Approve::NX_OS',
    'PAN-OS' => 'drc-pan-os',
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
 -L <logdir>          path for saving session logs
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

my @orig_args = @ARGV;
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
    info "drc3.pl, version $version";
    exit;
}
delete($opts{q}) and quiet();

my $file1 = shift or usage();
my $file2 = shift;
@ARGV and usage();
$file2 and keys %opts and usage;

# Take basename of file as device name.
(my $name = $file1) =~ s|^.*/||;

# Get type and IP addresses from spoc file.
my $spoc_file = $file2 || $file1;
my ($type, $ip, $err) = Netspoc::Approve::Device::get_spoc_data($spoc_file);

$type or abort("Can't get device type from $spoc_file");

# Enable logging.
if (my $logfile = $opts{LOGFILE}) {
    Netspoc::Approve::Device::logging($logfile);
}

# Set lock if necessary.
my $config;
if (not $file2) {
    $config = Netspoc::Approve::Load_Config::load();
    Netspoc::Approve::Device::set_lock($name, $config->{lockfiledir});
}

# Get class or program name from type.
my $class_or_prog = $type2class{$type}
  or abort("Can't find definition for [ Model = $type ] from $spoc_file");

# Exec external program and then terminate.
if ($class_or_prog !~ /^Netspoc::Approve::/) {
    my $prog = $class_or_prog;
    my @args = ($prog);
    # Remove two parameters '--LOGFILE FILE'
    my $file = 0;
    for my $arg (@orig_args) {
        if ($arg eq '--LOGFILE') {
            $file = 1;
            next;
        }
        if ($file) {
            $file = 0;
            next;
        }
        push @args, $arg;
    }
    system(@args);
    if ($? == -1) {
        abort("Can't execute '$prog': $!");
    }
    elsif ($? & 127) {
        abort("'$prog' died with signal: " . ($? & 127));
    }
    else {
        exit ($? >> 8);
    }
}

my $job = $class_or_prog->new(
    NAME   => $name,
    OPTS   => \%opts,
    IP     => shift(@$ip),
);

# Handle file compare first, which can be run
# - without device's IP and password
# - without calling Load_Config (so we can use compare_files for testing).
if ($file2) {
    exit($job->compare_files($file1, $file2) ? 1 : 0)
}

$job->{USER} = delete $opts{u} || getpwuid($>);
$job->{IP} or abort($err);
$job->{CONFIG} = $config;

# Start compare / approve.
banner_msg('START');
if ($opts{C}) {
    $job->compare($file1);
}
else {
    $job->approve($file1);
}
banner_msg('STOP');
