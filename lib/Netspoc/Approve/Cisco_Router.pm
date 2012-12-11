
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

# Defines new ACL.
# Assumes that conf mode is already enabled.
sub define_acl {
    my ($self, $name, $spoc_acl) = @_;
    my $entries = $spoc_acl->{LIST};
    my $cmd = $spoc_acl->{orig};

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

sub process_interface_acls( $$$ ){
    my ($self, $conf, $spoc) = @_;
    $self->{CHANGE}->{ACCESS_LIST} = 0;

    my $gen_cmd = sub {
        my ($hash) = @_;
        my $line = $hash->{line};
        my $cmd;
        if ($hash->{delete}) {
            $cmd = "no $line";
        }
        else {
            $cmd = $hash->{ace}->{orig};
            $cmd = "$line $cmd" if defined $line;
        }
        $cmd;
    };

    my ($line_start, $line_incr) = $self->ACL_line_discipline();
    $self->{CHANGE}->{ACCESS_LIST} = 0;
    for my $intf (values %{$spoc->{IF}}){
	my $name = $intf->{name};
        my $conf_intf = $conf->{IF}->{$name}
	   or abort("Interface not found on device: $name");
	for my $in_out (qw(IN OUT)) {
	    my $direction = lc($in_out);
	    my $confacl_name = $conf_intf->{"ACCESS_GROUP_$in_out"} || '';
	    my $spocacl_name = $intf->{"ACCESS_GROUP_$in_out"} || '';
	    my $conf_acl = $conf->{ACCESS_LIST}->{$confacl_name};
	    my $spoc_acl = $spoc->{ACCESS_LIST}->{$spocacl_name};
	    
	    # Try to change existing ACL on device.
	    if ($conf_acl and $spoc_acl) {
		my $ready = $self->equalize_acl($conf_acl, $spoc_acl);
                next if $ready;
                
                if (my $vcmds = $spoc_acl->{modify_cmds} ) {
                    $self->{CHANGE}->{ACCESS_LIST} = 1;
                    my $acl_name = $conf_acl->{name};

                    # Change line numbers of ACL entries on device to the same
                    # values as used in ACL commands.
                    # Do resequence before schedule reload, because it may
                    # abort if this command isn't available on old IOS version.
                    $self->enter_conf_mode('session');
                    $self->resequence_cmd($acl_name, $line_start, $line_incr);
                    $self->schedule_reload(5);
                    $self->cmd("ip access-list extended $acl_name");
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
                    $self->cmd('exit');
                    $self->cancel_reload();
                    $self->resequence_cmd($acl_name, 10, 10);
                    $self->leave_conf_mode();
                    next;
                }

                # No modify_cmds: Fall through; add ACL.
	    }

	    # Add ACL to device.
	    if ($spoc_acl) {
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
		$self->enter_conf_mode('session');
		$self->define_acl($aclname, $spoc_acl);

		# Assign new acl to interface.
		info("Assigning new $in_out ACL $aclname to interface $name");
		$self->cmd($intf->{orig});
		$self->cmd("ip access-group $aclname $direction");
		$self->leave_conf_mode();
		$self->cancel_reload();
	    }

	    # Remove ACL from device.
	    if ($conf_acl) {
		$self->{CHANGE}->{ACCESS_LIST} = 1;
		$self->schedule_reload(5);
		$self->enter_conf_mode('session');
		if (not $spoc_acl) {
		    info("Unassigning $in_out ACL from interface $name");
		    $self->cmd($intf->{orig});
		    $self->cmd("no ip access-group $confacl_name $direction");
		}
		$self->cancel_reload();
                my $cmd = $conf_acl->{orig};
		$self->cmd("no $cmd");
		$self->leave_conf_mode();
	    }		
	}
    }
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
