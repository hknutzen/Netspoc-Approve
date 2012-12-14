
package Netspoc::Approve::Cisco_Router;

# Authors: Heinz Knutzen
#
# Description:
# Base class for Cisco routers (IOS, NX-OS)
#

# VERSION: inserted by DZP::OurPkgVersion

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
# Assumes that conf mode is already enabled.
sub define_acl {
    my ($self, $name, $spoc_acl) = @_;
    my $entries = $spoc_acl->{LIST};
    my $old_name = $spoc_acl->{name};
    my $cmd = $spoc_acl->{orig};
    $cmd =~ s/$old_name\s*/$name/;

    # Possibly there is an old acl with $aclname:
    # first remove old entries because acl should be empty - 
    # otherwise new entries would be appended only.
    $self->cmd("no $cmd");
    $self->cmd($cmd);
    for my $entry (@$entries) {
        my $subcmd = $entry->{orig};
        $self->cmd($subcmd);
    }
}

sub modify_object_groups {
    my ($self, $conf, $spoc) = @_;
    my $hash = $spoc->{OBJECT_GROUP};
    for my $group (values %$hash) {
        my $add = $group->{add_entries};
        my $del = $spoc->{del_entries};
        $add || $del or next;
        my $name = $group->{name};
        my $dev_name = $group->{name_on_dev};
        my $cmd = $spoc->{orig};
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
    for my $group (values %$spoc_groups) {
        $group->{transfer} or next;
        my $name = $group->{name};
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
    for my $group (values %$conf_groups) {
        if ($group->{remove}) {
            $self->cmd("no $group->{orig}");
        }
    }
}

sub process_interface_acls( $$$ ){
    my ($self, $conf, $spoc) = @_;
    $self->{CHANGE}->{ACCESS_LIST} = 0;
    $self->enter_conf_mode('session');

    my $gen_cmd = sub {
        my ($hash) = @_;
        my $line = $hash->{line};
        my $cmd;
        if ($hash->{delete}) {
            $cmd = "no $line";
            $self->mark_unneeded_object_group_from_acl_entry($hash->{ace});
        }
        else {
            $cmd = $hash->{ace}->{orig};
            $cmd = "$line $cmd" if defined $line;
        }
        $cmd;
    };

    # Analyze changes in all ACLs bound to interfaces.
    my %acl_ready;
    for my $intf (values %{$spoc->{IF}}){
	my $name = $intf->{name};
        my $conf_intf = $conf->{IF}->{$name} or internal_err;
	for my $in_out (qw(IN OUT)) {
	    my $direction = lc($in_out);
	    my $confacl_name = $conf_intf->{"ACCESS_GROUP_$in_out"} || '';
	    my $spocacl_name = $intf->{"ACCESS_GROUP_$in_out"} || '';
	    my $conf_acl = $conf->{ACCESS_LIST}->{$confacl_name};
	    my $spoc_acl = $spoc->{ACCESS_LIST}->{$spocacl_name};
	    
	    # Try to change existing ACL on device.
	    if ($conf_acl and $spoc_acl) {
		my $ready = $self->equalize_acl_groups($conf_acl, $spoc_acl);
                if($ready) {
                    $acl_ready{$spoc_acl} = 1;
                    next;
                }
	    }
	    if ($spoc_acl) {
                $self->mark_object_group_from_acl($spoc_acl);
	    }	
	}
    }

    $self->modify_object_groups($conf, $spoc);
    $self->transfer_object_groups($conf, $spoc);

    # Apply changes
    my ($line_start, $line_incr) = $self->ACL_line_discipline();
    $self->{CHANGE}->{ACCESS_LIST} = 0;
    for my $intf (values %{$spoc->{IF}}){
	my $name = $intf->{name};
        my $conf_intf = $conf->{IF}->{$name};
	for my $in_out (qw(IN OUT)) {
	    my $direction = lc($in_out);
	    my $confacl_name = $conf_intf->{"ACCESS_GROUP_$in_out"} || '';
	    my $spocacl_name = $intf->{"ACCESS_GROUP_$in_out"} || '';
	    my $conf_acl = $conf->{ACCESS_LIST}->{$confacl_name};
	    my $spoc_acl = $spoc->{ACCESS_LIST}->{$spocacl_name};
            
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
                    $self->cmd($conf_acl->{orig});
                    for my $vcmd (@$vcmds) {
                        if (ref $vcmd eq 'ARRAY') {
                            my ($vcmd1, $vcmd2) = @$vcmd;
                            my $cmd1 = $gen_cmd->($vcmd1);
                            my $cmd2 = $gen_cmd->($vcmd2);
                            $self->two_cmd($cmd1, $cmd2);
                        }
                        else {
                            my $cmd = $gen_cmd->($vcmd);
                            $self->cmd($cmd);
                        }
                    }
                    $self->cancel_reload();
                    $self->resequence_cmd($acl_name, 10, 10);
                    next;
                }

                # No modify_cmds: Fall through; add ACL.
            }

            # Add ACL to device.
	    if ($spoc_acl) {
                $self->mark_object_group_from_acl($spoc_acl);
                $self->{CHANGE}->{ACCESS_LIST} = 1;

                # New and old ACLs must use different names.
                # We toggle between -DRC-0 and DRC-1.
                my $aclindex = 0;
                if ($conf_acl) {
                    if ($confacl_name =~ /-DRC-([01])$/) {
                        $aclindex = (not $1) + 0;
                    }
                }
                my $aclname = "$spocacl_name-DRC-$aclindex";

                $self->schedule_reload(5);
                $self->define_acl($aclname, $spoc_acl);

                # Assign new acl to interface.
                info("Assigning new $in_out ACL $aclname to interface $name");
                $self->cmd($intf->{orig});
                $self->cmd("ip access-group $aclname $direction");
                $self->cancel_reload();
	    }

            # Remove ACL from device.
	    if ($conf_acl) {

                $self->{CHANGE}->{ACCESS_LIST} = 1;
                $self->schedule_reload(5);
                if (not $spoc_acl) {
                    info("Unassigning $in_out ACL from interface $name");
                    $self->cmd($intf->{orig});
                    $self->cmd("no ip access-group $confacl_name $direction");
                }
                $self->cancel_reload();
                my $cmd = $conf_acl->{orig};
                $self->cmd("no $cmd");

                $self->mark_unneeded_object_group_from_acl($conf_acl);
	    }		
	}
    }
    $self->remove_object_groups($conf, $spoc);
    $self->leave_conf_mode();
}

sub transfer {
    my ($self, $conf, $spoc) = @_;

    # Check for matching interfaces.
    $self->checkinterfaces($conf, $spoc);

    # *** BEGIN TRANSFER ***
    $self->process_interface_acls($conf, $spoc);
    $self->process_routing($conf, $spoc);
}

1;
