package Netspoc::Approve::Load_Config;

use strict;
use warnings;
use Carp;

my $config = {
    netspocdir      => 1,
    lockfiledir     => 1,
    historydir      => 0,
    statusdir       => 0,
    checkbanner     => 0,	# regex
    passwdpath      => 0,
    aaa_credentials => 0,	# path
    systemuser      => 0,	# username
    newpolicy_hooks => 0,
};

my @prefix = ('/etc/', '/usr/local/etc/', glob('~/.'));
my @paths = map("${_}netspoc-approve", @prefix);

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
