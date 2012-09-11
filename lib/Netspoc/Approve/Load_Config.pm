package Netspoc::Approve::Load_Config;

use strict;
use warnings;
use Carp;

my $config = {
    NETSPOCDIR      => 1,
    LOCKFILEDIR     => 1,
    HISTORYDIR      => 0,
    STATUSDIR       => 0,
    CHECKBANNER     => 0,	# regex
    PASSWDPATH      => 0,
    AAA_CREDENTIALS => 1,	# path
    SYSTEMUSER      => 1,	# username
};

my @paths = 
    </etc/netspoc-approve /usr/local/etc/netspoc-approve ~/.netspoc-approve>;

# Files are trusted; values are untainted by pattern match.
sub load {
    my $result;
    for my $file (@paths) {
        -f $file or next;
        open(my $fh, '<', $file) or carp("Can't open $file: $!");
        while (<$fh>){
            chomp;
            s/^\s*//;
            s/\s*$//;
            next if /^$/;
            next if /^[#;]/;
            if (my ($key, $val) = /^ \s* (\w+) \s* = \s* (\S+) \s* $/x) {
                if (exists $config->{$key}) {
                    $result->{$key} = $val;
                }
                else {
                    carp("Unknown '$key' in $file");
                }
            }
            else {
                carp("Ignoring '$_' in $file");
            }
	}
    }
    for my $key (keys %$config) {
        next if ! $config->{$key};
        $result->{$key} or croak "Missing '$key' in configuration file";
    }
    return $result;
}

1;
