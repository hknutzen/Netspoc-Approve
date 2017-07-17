
=head1 DESCRIPTION

Base class for Cisco routers (IOS, NX-OS)

=head1 COPYRIGHT AND DISCLAIMER

https://github.com/hknutzen/Netspoc-Approve
(c) 2017 by Heinz Knutzen <heinz.knutzen@gmail.com>
(c) 2011 by Daniel Brunkhorst <daniel.brunkhorst@web.de>

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

package Netspoc::Approve::Cisco_Router;

# Authors: Heinz Knutzen
#
# Description:
# Base class for Cisco routers (IOS, NX-OS)
#

our $VERSION = '1.117'; # VERSION: inserted by DZP::OurPkgVersion

use base "Netspoc::Approve::Cisco";
use strict;
use warnings;
use Netspoc::Approve::Helper;


# ACL line numbers don't change during incremental ACL update.
sub change_acl_numbers {}

# ACL lines start at 10000, increment by 10000.
# When adding lines in front of some line n
# start at n-9999 and subsequent lines at n-9999+1, n-9999+1+1, ...
sub ACL_line_discipline {
    return (10000, 10000, -9999, 1);
}

sub mark_unneeded_object_group_from_acl {
    my ($self, $acl) = @_;
    for my $entry (@{ $acl->{LIST} }) {
        $self->mark_unneeded_object_group_from_acl_entry($entry);
    }
}

sub mark_unneeded_object_group_from_acl_entry {
    my ($self, $entry) = @_;
    for my $where (qw(TYPE SRC DST SRC_PORT DST_PORT)) {
        my $what = $entry->{$where};
        if(my $group = ref($what) && $what->{GROUP}) {
            if (!$group->{needed}) {
                $group->{remove} = 1;
            }
        }
    }
}

# Defines new ACL.
# Assumes that conf mode is already enabled
sub define_acl {
    my ($self, $conf, $spoc, $spoc_name) = @_;
    my $spoc_acl = $spoc->{ACCESS_LIST}->{$spoc_name};
    my $entries = $spoc_acl->{LIST};
    my $name = $self->generate_name_for_transfer($spoc_name,
                                                 $conf->{ACCESS_LIST});
    if (my $cmd = $spoc_acl->{orig}) {
        $cmd =~ s/$spoc_name\s*/$name/;
        $self->cmd($cmd);
    }
    for my $entry (@$entries) {
        my $subcmd = $self->subst_ace_name_og($entry, $name);
        $self->cmd($subcmd);
    }
    return $name;
}

sub modify_object_groups {
    my ($self, $conf, $spoc) = @_;
    my $hash = $spoc->{OBJECT_GROUP};
    for my $name (sort keys %$hash) {
        my $group = $hash->{$name};
        my $add = $group->{add_entries};
        my $del = $group->{del_entries};
        ($add || $del) or next;
        my $dev_name = $group->{name_on_dev};
        my $cmd = $group->{orig};
        $cmd =~ s/ $name $ /$dev_name/x;
        $self->cmd($cmd);
        if($add) {
            map( { $self->cmd( $_->{orig} ) } @$add );
        }
        if($del) {
            map( { $self->cmd( "no $_->{orig}" ) } @$del );
        }
    }
}

# Generate new name for transfer:
# <spoc-name>-DRC-<index>
sub generate_name_for_transfer {
    my ($self, $name, $objects) = @_;
    my $prefix = "$name-DRC-";
    my $index  = 0;
    my $new;
    while ($new = "$prefix$index", $objects->{$new}) {
        $index++;
    }
    return $new;
}

sub transfer_object_groups {
    my ($self, $conf, $spoc) = @_;
    my $conf_groups = $conf->{OBJECT_GROUP};
    my $spoc_groups = $spoc->{OBJECT_GROUP};
    for my $name (sort keys %$spoc_groups) {
        my $group = $spoc_groups->{$name};
        $group->{transfer} or next;
        my $new_name = $group->{new_name} =
            $self->generate_name_for_transfer($name, $conf_groups);
        my $cmd = $group->{orig};
        $cmd =~ s/ $name $ /$new_name/x;
        $self->cmd($cmd);
        map( { $self->cmd( $_->{orig} ) } @{ $group->{OBJECT} } );
    }
}

sub remove_object_groups {
    my ($self, $conf, $spoc) = @_;
    my $conf_groups = $conf->{OBJECT_GROUP};
    for my $name (sort keys %$conf_groups) {
        my $group = $conf_groups->{$name};
        if ($group->{remove}) {
            $self->cmd("no $group->{orig}");
        }
    }
}

sub gen_ace_cmd {
    my ($self, $hash) = @_;
    my $line = $hash->{line};
    my $cmd;
    if ($hash->{delete}) {
        $cmd = "no $line";
        $self->mark_unneeded_object_group_from_acl_entry($hash->{ace});
    }
    else {
        $cmd = $self->subst_ace_name_og($hash->{ace}, $hash->{name});
        $cmd = "$line $cmd";
    }
    return $cmd;
}

sub remove_acl {
    my ($self, $acl) = @_;
    my $cmd = $acl->{orig};
    $self->cmd("no $cmd");
}

sub assign_acl {
    my ($self, $intf, $acl_name, $in_out) = @_;
    my $direction = lc($in_out);
    $self->cmd($intf->{orig});
    $self->cmd("ip access-group $acl_name $direction");
}

sub unassign_acl   {
    my ($self, $intf, $acl_name, $in_out) = @_;
    my $direction = lc($in_out);
    $self->cmd($intf->{orig});
    $self->cmd("no ip access-group $acl_name $direction");
}

sub process_interface_acls {
    my ($self, $conf, $spoc) = @_;

    $self->enter_conf_mode('session');

    # Collect list of interface pairs.
    my @interface_pairs;
    my $spoc_interfaces = $spoc->{IF};
    my $conf_interfaces = $conf->{IF};
    for my $name (sort keys %$spoc_interfaces){
        my $conf_intf = $conf_interfaces->{$name} or internal_err;
	my $spoc_intf = $spoc_interfaces->{$name};
        push @interface_pairs, [ $conf_intf, $spoc_intf ];
    }

    # Analyze changes in all ACLs bound to interfaces.
    # Try to change ACLs incrementally.
    # Get list of ACL pairs, that need to be redefined, added or removed.
    my @acl_update_info =
        $self->equalize_acls_of_objects($conf, $spoc, \@interface_pairs);

    for my $info (@acl_update_info) {
        my ($intf, $in_out, $conf_acl, $spoc_acl) = @$info;
        $self->{CHANGE}->{ACCESS_LIST} = 1;

        # Add ACL to device.
        if ($spoc_acl) {
            $self->schedule_reload(5);
            my $aclname = $self->define_acl($conf, $spoc, $spoc_acl->{name});

            # Assign new acl to interface.
            $self->assign_acl($intf, $aclname, $in_out);
            $self->cancel_reload();
        }

        # Remove ACL from device.
        if ($conf_acl) {
            if (not $spoc_acl) {
                $self->unassign_acl($intf, $conf_acl->{name}, $in_out);
            }
            $self->remove_acl($conf_acl);
        }
    }
    $self->leave_conf_mode();
}

# Equalize ACLs for list of interface pairs or list of crypto map pairs.
sub equalize_acls_of_objects {
    my ($self, $conf, $spoc, $object_pairs) = @_;

    # Collect list of info
    # [interface/crypto_entry, in/out, conf_acl, spoc_acl],
    # about ACL pairs that need to be transferred and/or removed.
    my @acl_update_info;

    my %acl_ready;

    # Pass 1: Equalize object groups of matching ACL lines.
    for my $pair (@$object_pairs){
        my ($conf_obj, $spoc_obj) = @$pair;
	for my $in_out (qw(IN OUT)) {
	    my $direction = lc($in_out);
	    my $confacl_name = $conf_obj->{"ACCESS_GROUP_$in_out"} || '';
	    my $spocacl_name = $spoc_obj->{"ACCESS_GROUP_$in_out"} || '';
	    my $conf_acl = $conf->{ACCESS_LIST}->{$confacl_name};
	    my $spoc_acl = $spoc->{ACCESS_LIST}->{$spocacl_name};

	    # Try to change objects groups of existing ACL on device.
	    if ($conf_acl and $spoc_acl) {
		my $ready = $self->equalize_acl_groups($conf_acl, $spoc_acl);
                if($ready) {
                    $acl_ready{$spoc_acl} = 1;
                    next;
                }
	    }

            # ACL from netspoc will be transferred.
            # Mark referenced object groups.
	    elsif ($spoc_acl) {
                $self->mark_object_group_from_acl($spoc_acl);
	    }
	}
    }

    $self->modify_object_groups($conf, $spoc);
    $self->transfer_object_groups($conf, $spoc);

    # Pass 2: Try to equalize ACLs by incremental changes to ACL on device.
    my ($line_start, $line_incr) = $self->ACL_line_discipline();
    $self->{CHANGE}->{ACCESS_LIST} = 0;
    for my $pair (@$object_pairs){
        my ($conf_obj, $spoc_obj) = @$pair;
	for my $in_out (qw(IN OUT)) {
	    my $confacl_name = $conf_obj->{"ACCESS_GROUP_$in_out"} || '';
	    my $spocacl_name = $spoc_obj->{"ACCESS_GROUP_$in_out"} || '';
	    my $conf_acl = $conf->{ACCESS_LIST}->{$confacl_name};
	    my $spoc_acl = $spoc->{ACCESS_LIST}->{$spocacl_name};

            # Nothing to do, if both IN-ACL or both OUT-ACL don't exist.
            $conf_acl or $spoc_acl or next;

	    if ($conf_acl and $spoc_acl) {

                # We already know from group compare, that ACL doesn't change.
                next if $acl_ready{$spoc_acl};
                my $ready = $self->equalize_acl_entries($conf_acl, $spoc_acl);

                # ACL remains unchanged. This can occur, if some group
                # was recognized as unchanged later.
                next if $ready;

                if (my $vcmds = $spoc_acl->{modify_cmds} ) {
                    $self->{CHANGE}->{ACCESS_LIST} = 1;
                    my $acl_name = $conf_acl->{name};

                    # Change line numbers of ACL entries on device to the same
                    # values as used in ACL commands.
                    # Do resequence before schedule reload, because it may
                    # abort if this command isn't available on old IOS version.
                    $self->resequence_cmd($acl_name, $line_start, $line_incr);
                    $self->schedule_reload(5);
                    $self->cmd($conf_acl->{orig}) if $conf_acl->{orig};
                    for my $vcmd (@$vcmds) {
                        if (ref $vcmd eq 'ARRAY') {
                            my ($vcmd1, $vcmd2) = @$vcmd;
                            my $cmd1 = $self->gen_ace_cmd($vcmd1);
                            my $cmd2 = $self->gen_ace_cmd($vcmd2);
                            $self->two_cmd($cmd1, $cmd2);
                        }
                        else {
                            my $cmd = $self->gen_ace_cmd($vcmd);
                            $self->cmd($cmd);
                        }
                    }
                    $self->cancel_reload();
                    $self->resequence_cmd($acl_name, 10, 10);
                    next;
                }

                # No modify_cmds: Fall through; add ACL.
            }

	    if ($spoc_acl) {
                $self->mark_object_group_from_acl($spoc_acl);
            }
            if ($conf_acl) {
                $self->mark_unneeded_object_group_from_acl($conf_acl);
            }

            # Collect pair for later processing.
            push @acl_update_info, [$conf_obj, lc($in_out),
                                    $conf_acl, $spoc_acl];
	}
    }
    $self->remove_object_groups($conf, $spoc);
    return @acl_update_info;
}

# Check if mpls is enabled at one or more interfaces in any VRF.
sub check_mpls {
    my ($self, $conf) = @_;
    my $intf_hash = $conf->{IF};
    for my $intf (values %$intf_hash) {
        return 1 if $intf->{MPLS};
    }
    return;
}

# Netspoc creates a single configuration file for a device
# having different VRFs.
# Now remove that parts from the device configuration,
# which are related to VRFs not managed by Netspoc.
# This way, we leave unmanaged VRFs unchanged.
sub align_vrfs {
    my ($self, $conf, $spoc) = @_;

    # Find VRFs used in Netspoc configuration.
    my %spoc_vrf =
        map({ $_ => 1 }
            map($_->{VRF} || '', values %{ $spoc->{IF} }),
            keys %{ $spoc->{ROUTING_VRF} });

    # Remove parts from unmanaged VRFs.

    # Remove interfaces and referenced ACLs and object groups.
    my %removed;
    my $intf = $conf->{IF};
    for my $name (keys %$intf) {
        my $val = $intf->{$name};
        my $vrf = $val->{VRF} || '';
        next if $spoc_vrf{$vrf};
        next if $val->{SHUTDOWN};
        delete $intf->{$name};
        $removed{$vrf} = 1;
    }
    my $routing = $conf->{ROUTING_VRF};
    for my $vrf (keys %$routing) {
        if (!$spoc_vrf{$vrf}) {
            delete $routing->{$vrf};
            $removed{$vrf} = 1;
        }
    }
    for my $vrf (sort keys %removed) {
        $vrf ||= 'global';
        info("Leaving VRF $vrf untouched");
    }
}

sub transfer {
    my ($self, $conf, $spoc) = @_;

    # Check if any interface has mpls enabled.
    my $has_mpls = $self->check_mpls($conf);

    # Ignore unmanged VRFs of device.
    $self->align_vrfs($conf, $spoc);

    # Check for matching interfaces.
    $self->checkinterfaces($conf, $spoc, $has_mpls);

    # *** BEGIN TRANSFER ***
    $self->process_interface_acls($conf, $spoc);
    $self->process_routing($conf, $spoc);
}

1;
