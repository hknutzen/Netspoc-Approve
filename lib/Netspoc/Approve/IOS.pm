
package Netspoc::Approve::Device::Cisco::IOS;

use strict;
use warnings;

use base "Netspoc::Approve::Device::Cisco";

use Netspoc::Approve::Helper;

sub dev_cor ($$) {
    my ($self, $addr) = @_;
    return ~$addr & 0xffffffff;
}

############################################################
# --- parsing ---
############################################################

#
# ios only
#
# ip inspect name inspection-name ...
#
# only subset implemented !!!!!
#
sub parse_ip_inspect_line( $$$ ) {
    my ($self, $il, $ih) = @_;
    my $p = 0;    # progress indicator
    for (split " ", $il) {
        if ($p == 0) {
            ($_ eq 'ip') && do { $p++; next; };
            die "unexpected token while parsing 'ip' in $il\n";
        }
        if ($p == 1) {
            ($_ eq 'inspect') && do { $p++; next; };
            die "unexpected token while parsing 'inspect' in $il\n";
        }
        if ($p == 2) {
            ($_ eq 'name') && do { $p++; next; };
            if ($_ eq 'audit-trail') {
                $ih->{AUDIT_TRAIL} = 1;
                last;
            }
            elsif ($_ eq 'tcp') {

                # the eats up 'tcp idle-time'
                last;
            }
            die "unexpected token while parsing 'name' in $il\n";
        }
        if ($p == 3) {
            $ih->{NAME} = $_;
            $p++;
            next;
        }
        if ($p == 4) {
            $ih->{SPEC} = $_;
            $p++;
            next;
        }
        if ($p == 5) {
            ($ih->{SPEC} eq "rpc")
              or die "unexpected token $_ in $il\n";
            $ih->{PROG} = $_;
            $p++;
            next;
        }
        if ($p == 6) {
            ($ih->{SPEC} eq "rpc")
              or die "unexpected token $_ in $il\n";
            $ih->{NUM} = $_;
            $p++;
            next;
        }
        if ($p == 7) {
            die "unexpected token $_ in  $il\n";
        }
    }
    return 1;
}

sub parse_route_line ($$$) {
    my ($self, $rl, $rh) = @_;
    my $p = 0;    # progress indicator
                  # ip route destination-prefix destination-prefix-mask
                  #          [interface-type card/subcard/port] forward-addr
         #          [metric | permanent | track track-number | tag tag-value]
         #
         # (partial implemented)
    for (split " ", $rl) {

        if ($p == 0) {
            ($_ eq 'ip') && do { $p++; next; };
            die "unexpected token while parsing 'ip' in $rl\n";
        }
        if ($p == 1) {
            ($_ eq 'route') && do { $p++; next; };
            die "unexpected token while parsing 'route' in $rl\n";
        }
        if ($p == 2) {
            defined($rh->{BASE} = quad2int($_)) && do { $p++; next; };
            die "illegal tupel $_ in $rl\n";
        }
        if ($p == 3) {
            defined($rh->{MASK} = quad2int($_)) && do { $p++; next; };
            die "illegal tupel $_ in $rl\n";
        }
        if ($p == 4) {
            defined($rh->{NEXTHOP} = quad2int($_)) && do { $p++; next; };

            # maybe NexthopInterFace is specified
            unless (exists $rh->{NIF}) {
                $rh->{NIF} = $_;
                $p++;
                next;
            }

            # die "(4) illegal tupel $_ in $rl\n";
        }
        if ($p == 5 or $p == 6) {

            # tag tag-value doesnt work yet
            if ($_ =~ /(\d+)/) {
                if (exists $rh->{MISC} and $rh->{MISC} eq 'track') {
                    $rh->{TRACK_NUMBER} = $1;
                }
                else {
                    $rh->{METRIC} = $1;
                }
                $p++;
                next;
            }
            elsif ($_ eq 'permanent') {
                $rh->{MISC} = $_;
                $p++;
                next;
            }
            elsif ($_ eq 'track') {
                $rh->{MISC} = $_;
                $p++;
                next;
            }

            die "(5) illegal tupel $_ in $rl\n";
        }
        die "unexpected token $_ in $rl\n";
    }

    # to do: check for correct mask
    return 1;
}

sub parse_acl_line ( $$$ ) {
    my ($self, $al, $ah) = @_;
    $self->acl_entry($ah, \$al);
}

#######################################################
# --- printing ---
#######################################################
#
# ios only !
#
sub ip_inspect_line_to_string($$) {
    my ($self, $i) = @_;
    my $r = join ' ', "ip inspect name", $i->{NAME}, $i->{SPEC};
    if ($i->{SPEC} eq 'rpc') {
        $r = join ' ', $r, $i->{PROG}, $i->{NUM};
    }
    return $r;
}

sub route_line_to_string ($$) {
    my ($self, $o) = @_;
    my $r;
    $r = join ' ', "ip route", int2quad $$o{BASE}, int2quad $$o{MASK};
    (exists $$o{NIF})      and do { $r = join ' ', $r, $$o{NIF} };
    (defined $$o{NEXTHOP}) and do { $r = join ' ', $r, int2quad $$o{NEXTHOP} };
    (defined $$o{METRIC})  and do { $r = join ' ', $r, $$o{METRIC} };
    (defined $$o{MISC})    and do { $r = join ' ', $r, $$o{MISC} };
    (defined $$o{TRACK_NUMBER}) and do { $r = join ' ', $r, $$o{TRACK_NUMBER} };
    return $r;
}

sub acl_line_to_string ($$) {
    my ($self, $a) = @_;
    my $s;
    $self->acl_entry($a, \$s);
    return $s;
}

sub print_icmpmessage ($$$) {
    my ($self, $ah, $al) = @_;

    # we prefer textual output of icmp message due to
    # problems in the ios ace parser:
    #
    # in ios holds:   icmp 8 0 != icmp echo
    # because of this echo is coded as type 8 code -1
    #
    if (exists $ah->{TYPE}) {
        if (exists $ah->{CODE}) {

# ToDo
#	    if(exists $ICMP_Re_Trans{$ah->{TYPE}}->{$ah->{CODE}}){
#		$$al =join ' ',$$al,$ICMP_Re_Trans{$ah->{TYPE}}->{$ah->{CODE}};
#	    }
#	    else
            {
                $$al = join ' ', $$al, $ah->{TYPE};
                $ah->{CODE} != -1 and $$al = join ' ', $$al, $ah->{CODE};
            }
        }
        else {
            $$al = join ' ', $$al, $ah->{TYPE};
        }
    }
}

# Packages must return a true value;
1;

