package Netspoc::Approve::Load_Config;

use strict;
use warnings;
use Carp;

# Valid keys in config file.
# Value is either '_required' for required keys or a default value.
my $config = {
    netspocdir      => '_required',
    lockfiledir     => '_required',
    historydir      => undef,
    statusdir       => undef,
    checkbanner     => undef,	# regex
    passwdpath      => undef,
    aaa_credentials => undef,	# path
    systemuser      => undef,	# username
    newpolicy_hooks => undef,	# list of paths
    timeout         => 60,
    login_timeout   => 3,
    try_telnet      => undef,
};

my @prefix = ('/etc/', '/usr/local/etc/', glob('~/.'));
my @paths = map("${_}netspoc-approve", @prefix);

# Files are trusted; values are untainted by pattern match.
sub load {
    my $result;
    for my $file (@paths) {
        -f $file or next;
        open(my $fh, '<', $file) or  ## no critic (ProhibitUnusedVariables)
          carp("Can't open $file: $!");
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
