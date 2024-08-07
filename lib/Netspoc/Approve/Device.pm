
=head1 DESCRIPTION

Base class for all supported devices

=head1 COPYRIGHT AND DISCLAIMER

https://github.com/hknutzen/Netspoc-Approve
(c) 2024 by Heinz Knutzen <heinz.knutzen@gmail.com>
(c) 2009 by Daniel Brunkhorst <daniel.brunkhorst@web.de>
(c) 2007 by Arne Spetzler

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

package Netspoc::Approve::Device;

use strict;
use warnings;
use Fcntl qw/:flock/;    # import LOCK_* constants
use File::Basename;
use JSON;
use JSON::XS;
use Netspoc::Approve::Helper;

# VERSION: inserted by DZP::OurPkgVersion

# Read type from spoc info file.
sub get_spoc_type {
    my ($path) = @_;
    my($info, $checked) = get_device_info($path);
    my $model =$info->{model} or
        abort("Can't get device type from file(s): @$checked");
    return $model;
}

# Read data from info file.
sub get_device_info {
    my ($path) = @_;
    my $path6 = get_ipv6_path($path);
    my @checked;
    my $result = {};
    for my $file ($path, $path6) {
        my $i_file = "$file.info";
        if (-e $i_file) {
            push @checked, $i_file;
            local $/;
            open(my $fh, '<', $i_file) or die("Can't open $i_file: $!");
            $result = decode_json(<$fh>);
            close($fh);
        }
        else {
            next;
        }
        # Must also read IPv6 file if v4 file has no IP.
        last if $result->{ip_list};
    }
    return $result, \@checked;
}

sub get_ipv6_path {
    my ($path) = @_;
    my $dir = dirname($path);
    my $filename = basename($path);
    return "$dir/ipv6/$filename";
}

# Renames an existing logfile.
sub move_logfile {
    my ($logfile) = @_;
    if (-f $logfile) {
        my $date = time();
        system("mv $logfile $logfile.$date") == 0
            or abort("Can't backup $logfile: $!");
    }
}

sub logging {
    my ($logfile) = @_;
    my $dirname = dirname($logfile);

    # Create logdir
    if ($dirname && ! -d $dirname) {
        if (mkdir($dirname, 0755)) {
            defined(chmod(0755, $dirname))
                or abort("Can't chmod logdir $dirname: $!");
        }

        # Check -d again, because some other process may have created
        # the directory in the meantime.
        elsif (! -d $dirname) {
            abort("Can't create $dirname: $!");
        }
    }

    move_logfile($logfile);

    open(STDOUT, '>', $logfile) or abort("Can't open $logfile: $!");
    chmod(0644, $logfile) or abort("Can't chmod $logfile: $!");

    open(STDERR, ">&STDOUT")
        or abort("STDERR redirect: Can't open $logfile: $!");
}

# Set lock for exclusive approval
# Store file handle in global var, so it isn't closed immediately.
# File is closed automatically after program exit.
my $lock_fh;
sub set_lock {
    my ($name, $lockdir) = @_;
    my $lockfile = "$lockdir/$name";
    my $file_exists = -f $lockfile;
    open($lock_fh, '>', $lockfile)
        or abort("Can't aquire lock file $lockfile: $!");

    # Make newly created lock file writable for other users.
    $file_exists
        or chmod(0666, $lockfile)
        or abort("Can't chmod lockfile $lockfile: $!");
    flock($lock_fh, LOCK_EX | LOCK_NB)
        or abort($!, "Approve in progress for $name");
}

1;
