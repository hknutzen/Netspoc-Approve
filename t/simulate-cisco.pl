#!/usr/bin/env perl

=head1 NAME

simulate-cisco.pl - Simulate Cisco device

=head1 SYNOPSIS

simulate-cisco.pl DEVICE-NAME SCENARIO-FILE

=head1 DESCRIPTION

Reads from STDIN and writes to STDOUT.

A scenario file controls the simulation.
It has multiple sections.
The first section, in front of line starting with '#' is called preamble.
Other sections are pairs of
 # command line
 command output line 1
 ...

The preamble is sent on startup, before reading any input.
After that, single lines are read from STDIN.
If a line equals some command of any section, this command
together with the corresponding command output is sent to STDOUT.
If an input line doesn't equal some command, it is sent unchanged to STDOUT.
After processing a single line of input, a prompt is sent.
Prompt is "DEVICE-NAME#" without an end-of-line character.

If an input line starts with prefix "do ", this prefix is discarded before
searching for a matching command line.

If one or more character sequences '<!>' are found in preamble or
command output, then additional lines of input are read and discared
for each occurrence of '<!>'.

This script allows to simulate banner messages, that are printed
asynchroneously into a command line.
Special line "# /MARKER\" starts definition of banner.
Corresponding output lines are used as banner text.
Insert /MARKER\ into command line of any section.
The simulation will print this command line garbled by banner text.

MARKER is any non empty string of word characters.

=cut

use strict;
use warnings;

sub usage { die "Usage: $0 device-name scenario-file\n"; }

my $device = shift or usage();
my $file = shift or usage();
usage() if @ARGV;

# Read scenario file.
my $data;
{

    # Undef input record separator to read all lines at once.
    local $/ = undef;
    open(my $fh, '<', "$file") or die "Can't open $file: $!\n";
    $data = <$fh>;
    close($fh);
}

my $delim = qr/^[#][ ]*(.*)[ ]*\n/m;

# Split into preamble, cmd-a, output-a, cmd-b, output-b, ...
my ($preamble, @output) = split($delim, $data);

# Remove trailing linefeed.
# In case of last line of preamble being a prompt.
# If linefeed is really needed, then add two linefeeds to scenario file.
chomp $preamble if $preamble;

# Build mapping from command line to output lines.
my %cmd2out;
while (@output) {
    my $cmd = shift @output;
    my $text = shift @output;
    $cmd2out{$cmd} = $text;
}

# Handle banner markers.
my %cmd2b_cmd;
if (my @banners = grep { m/^ \\ \w+ \/ $/x } keys %cmd2out) {

    # Find banner definitions.
    my %banner2out;
    for my $banner (@banners) {
        my $out = delete $cmd2out{$banner};

        # Special case: Remove linefeed if prompt is part of output.
        $out =~ s/#\n$/#/m;

        $banner2out{$banner} = $out;
    }

    # Substite banner markers by banner text in command lines.
    my @cmd_list = keys %cmd2out;
    for my $b_cmd (@cmd_list) {
        my ($marker) = $b_cmd =~ /(\\\w+\/)/ or next;
        my $banner = $banner2out{$marker} or
            die "Unknown banner marker: $marker\n";

        # Restore original command.
        (my $cmd = $b_cmd) =~ s/\\\w+\///;
        $cmd2out{$cmd} = delete $cmd2out{$b_cmd};

        # Build mapping from original command
        # to command garbled by banner text.
        $b_cmd =~ s/(\\\w+\/)/$banner/;
        $cmd2b_cmd{$cmd} = $b_cmd;
    }
}

# Send line to STDOUT.
# Replace LF character by CRLF,
# wait for input on each occurrence of <!>.
sub send_line;
sub send_line {
    my ($line) = @_;
    $line =~ s/\n/\r\n/g;
    my @parts = split /<!>/, $line;
    while (@parts > 1) {
        print shift @parts;
        my $input = <>;
        send_line $input;
    }
    print @parts;
}

# Send preamble on startup.
$preamble ||= '';
send_line $preamble;

# Read command,
# send command echo,
# send corresponding output lines,
# send prompt.
while (my $cmd = <>) {
    chomp $cmd;
    my $lookup = $cmd;

    # Ignore "do " prefix for lookup.
    my $has_do = $lookup =~ s/^do //;

    # Echo garbled command if available.
    if (my $b_cmd = $cmd2b_cmd{$lookup}) {
        $b_cmd = "do $b_cmd" if $has_do;
        send_line "$b_cmd\n";
    }
    else {
        send_line "$cmd\n";
    }

    last if $lookup eq 'exit';
    if (my $out = $cmd2out{$lookup}) {
        send_line $out;
    }

    # Print prompt.
    send_line "$device#";
}
