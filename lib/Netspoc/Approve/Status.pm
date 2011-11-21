
package Netspoc::Approve::Status;

# Author: Arne Spetzler, Heinz Knutzen
#
# Description:
# Write status files for approve and compare.
#
# $Id$

use strict;
use warnings;
use Carp;
use Fcntl;

############################################################
# --- constructor ---
############################################################
sub new {
    my ($class, %attributes) = @_;
    my $device = $attributes{device} or croak "Missing attribute 'device'";
    my $path   = $attributes{path} or croak "Missing attribute 'path'";

    my $fh;
    my $fullpath = "$path$device";
    if (-f "$path$device") {
        sysopen($fh, $fullpath, O_RDWR)
          or die "Can't open file: $fullpath: $!\n";
    }
    else {
        sysopen($fh, "$fullpath", O_RDWR | O_CREAT)
          or die "Can't create file: $fullpath: $!\n";
        defined chmod 0644, "$fullpath"
          or die "Can't chmod $fullpath: $!\n";
    }
    $attributes{fh} = $fh;

    return bless \%attributes, $class;
}

my %statfields = (
    DEVICENAME  => 0,
    APP_MESSAGE => 1,
    APP_POLICY  => 2,
    APP_STATUS  => 3,     # same as for DEV_STATUS and ***UNFINISHED APPROVE***
    APP_TIME    => 4,     # seconds since 1970 Cleartext
    APP_USER    => 5,
    DEV_MESSAGE => 6,
    DEV_POLICY  => 7,
    DEV_STATUS  => 8,     # ***WARNINGS***, ***ERRORS***  or OK
    DEV_TIME    => 9,     # seconds since 1970 Cleartext
    DEV_USER    => 10,
    COMP_COMP   => 11,
    COMP_RESULT => 12,    # DIFF or UPTODATE
    COMP_POLICY => 13,
    COMP_CTIME  => 14,    # seconds since 1970 Cleartext
    COMP_TIME   => 15,    # seconds since 1970
    COMP_DTIME  => 16,    # DEV_TIME in seconds
    FC_FC       => 17,
    FC_LAST_OK  => 18,    #last policy which seems to be identical to DEV_POLICY
    FC_STATE    => 19,    # result of last file compare: DIFF or OK
    FC_CTIME    => 20,    # seconds since 1970 Cleartext
    FC_TIME     => 21,    # seconds since 1970 (last change in state)
    MAX         => 21,              
);

sub format {
    my ($self, $stat) = @_;
    for (my $i = 0 ; $i <= $statfields{MAX} ; $i++) {
        unless (exists $stat->[$i]
            and $stat->[$i] =~ /\S/
            and $stat->[$i] ne 'undef')
        {
            if ($i == $statfields{APP_MESSAGE}) {
                $stat->[ $statfields{APP_MESSAGE} ] = 'LAST_APPROVE';
            }
            elsif ($i == $statfields{DEV_MESSAGE}) {
                $stat->[ $statfields{DEV_MESSAGE} ] = 'LAST_SUCCESS';
            }
            elsif ($i == $statfields{DEV_POLICY}) {
                $stat->[ $statfields{DEV_POLICY} ] = 'p0';
            }
            elsif ($i == $statfields{COMP_COMP}) {
                $stat->[ $statfields{COMP_COMP} ] = 'COMPARE';
            }
            elsif ($i == $statfields{COMP_POLICY}) {
                $stat->[ $statfields{COMP_POLICY} ] = 'p0';
            }
            elsif ($i == $statfields{COMP_TIME}) {
                $stat->[ $statfields{COMP_TIME} ] = 0;
            }
            elsif ($i == $statfields{COMP_DTIME}) {
                $stat->[ $statfields{COMP_DTIME} ] = 0;
            }
            elsif ($i == $statfields{FC_FC}) {
                $stat->[ $statfields{FC_FC} ] = 'FILE_COMPARE';
            }
            elsif ($i == $statfields{FC_LAST_OK}) {
                $stat->[ $statfields{FC_LAST_OK} ] = 0;
            }
            elsif ($i == $statfields{FC_TIME}) {
                $stat->[ $statfields{FC_TIME} ] = 0;
            }
            else {
                $stat->[$i] = 'undef';
            }
        }
    }
    $stat->[ $statfields{MAX} + 1 ] = "\n";
    return $stat;
}

sub write {
    my ($self, $stat) = @_;
    my $fh = $self->{fh};

    # disable output buffering for status messages
    # due to better reliability
    my $oldselect   = select $fh;
    my $oldbuffmode = $|;
    unless ($oldbuffmode == 1) {
        $| = 1;
    }
    seek $fh, 0, 0;
    print join ';', @$stat;
    truncate $fh, tell $fh or die "could not truncate $self->{device}\n";
    $| = $oldbuffmode;
    select $oldselect;
}

sub getall {
    my ($self) = @_;
    my $fh = $self->{fh};
    
    seek $fh, 0, 0;
    my $stat = [ split ';', <$fh> ];
    if (@$stat < $statfields{MAX} + 2) {
        $self->format($stat);
    }
    return $stat;
}

sub getindex {
    my ($self, $field) = @_;
    exists($statfields{$field}) || die "Unknown status field $field\n";
    return $statfields{$field};
}

sub get {
    my ($self, $field) = @_;
    my $stat  = $self->getall();
    my $index = $self->getindex($field);

    return $stat->[ $index ];
}

sub update {
    my ($self, $field, $value) = @_;
    my $stat  = $self->getall();
    my $index = $self->getindex($field);

    $stat->[ $index ] = $value;

    $self->write($stat);
}

## High level methods.

sub start_approve {
    my ($self, $policy, $user) = @_;
    $self->update('APP_TIME',   scalar localtime());
    $self->update('APP_STATUS', '***UNFINISHED APPROVE***');
    $self->update('APP_USER',   $user);
    $self->update('APP_POLICY', $policy);
}

sub finish_approve {
    my ($self, $result, $policy, $user) = @_;
    my $sec_time = time();
    my $time     = localtime($sec_time);
    $self->update('APP_TIME',   $time);
    $self->update('DEV_TIME',   $time);
    $self->update('COMP_DTIME', $sec_time);
    $self->update('DEV_USER',   $user);
    $self->update('DEV_POLICY', $policy);
    $self->update('APP_STATUS', $result);
    $self->update('DEV_STATUS', $result);
}

sub finish_compare {
    my ($self, $changed, $policy) = @_;
    my $set_result;

    if (not $changed) {
        $set_result = 'UPTODATE';
    }

    # Changed.
    # Only update compare status, 
    # - if status changes to diff for first time,
    # - or device was approved since last compare.
    elsif ($self->get('COMP_RESULT') ne 'DIFF' ||
           $self->get('COMP_TIME') < $self->get('COMP_DTIME')) 
    {
        $set_result = 'DIFF';
    }

    if ($set_result) {
        $self->update('COMP_RESULT', $set_result);
        $self->update('COMP_POLICY', $policy);
        $self->update('COMP_TIME',   time());
        $self->update('COMP_CTIME',  scalar localtime(time()));
    }
}
