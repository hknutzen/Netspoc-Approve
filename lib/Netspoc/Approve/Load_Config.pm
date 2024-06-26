
=head1 COPYRIGHT AND DISCLAIMER

https://github.com/hknutzen/Netspoc-Approve
(c) 2023 by Heinz Knutzen <heinz.knutzen@gmail.com>

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

package Netspoc::Approve::Load_Config;

use strict;
use warnings;
use Carp;

# Valid keys in config file.
# Value is either '_required' for required keys or a default value.
my $config = {
    netspocdir      => '_required',
    lockfiledir     => '_required',
    netspoc_git     => undef, #'_required',
    historydir      => undef,
    statusdir       => undef,
    checkbanner     => undef,   # regex
    aaa_credentials => undef,   # path
    systemuser      => undef,   # username
    server_ip_list  => undef,   # list of IP addresses of this server
    timeout         => 60,
    login_timeout   => 3,
    keep_history    => 365,     # delete history older than this (in days)
    compress_at     => 7,       # compress netspocdir after that many days
};

my @prefix = (glob('~/.'), '/usr/local/etc/', '/etc/');
my @paths = map("${_}netspoc-approve", @prefix);

# Use most specific config file; ignore others.
# Files are trusted; values are untainted by pattern match.
sub load {
    my ($file) = grep { -f } @paths or die("No config file found in\n @paths\n");
    my $result;
    open(my $fh, '<', $file) or carp("Can't open $file: $!");
    while (<$fh>){
        chomp;
        s/^\s*//;
        s/\s*$//;
        next if /^$/;
        next if /^[#;]/;
        if (my ($key, $val) = /^ \s* (\w+) \s* = \s* (\S+) \s* $/x) {
            if (exists $config->{$key}) {
                if (exists $result->{$key}) {
                    carp("Ignoring duplicate key '$key' in $file");
                    next;
                }
                $result->{$key} = $val;
            }
            else {
                carp("Ignoring key '$key' in $file");
            }
        }
        else {
            carp("Ignoring line '$_' in $file");
        }
    }
    for my $key (keys %$config) {
        my $default = $config->{$key};
        next if !defined $default;
        if ($default eq '_required') {
            $result->{$key} or croak "Missing '$key' in configuration file";
        }
        else {
            exists $result->{$key} or $result->{$key} = $default;
        }
    }
    return $result;
}

1;
