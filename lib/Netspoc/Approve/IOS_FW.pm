
package Netspoc::Approve::IOS_FW;

# Authors: Arne Spetzler, Heinz Knutzen, Daniel Brunkhorst
#
# Description:
# Remote configure cisco IOS router with firewall feature set.
#

'$Id$ ' =~ / (.+),v (.+?) /;

my $id = "$1 $2";

use base "Netspoc::Approve::IOS";
use strict;
use warnings;
use Netspoc::Approve::Helper;

sub version_drc2_IOS_FW() {
    return $id;
}


sub check_firewall ( $$ ) {
    my ($self, $conf) = @_;

    mypr "check for CBAC at ios firewall...\n";
    my $cbac_ok = 1;
    for my $intf (keys %{$conf->{IF}}){
	next if($conf->{IF}->{$intf}->{SHUTDOWN});
	mypr "   $intf";
	if(exists $conf->{IF}->{$intf}->{SWITCHPORT}){
	    mypr " - is a switchport - OK\n";
	}
	elsif($intf eq "Loopback0"){
	    mypr " - is a loopback device - OK\n";
	}
	elsif(exists $conf->{IF}->{$intf}->{INSPECT}){
	    mypr " - CBAC enabled - OK\n";
	}
	else{
	    mypr " - no CBAC found\n";
	    $cbac_ok = 0;
	}
    }
    $cbac_ok or errpr "missing CBAC configuration\n";
}

#
# *** access-lists processing *** 
#
sub remove_acl_entries( $$$ ) {
    my ($self, $name, $entries) = @_;

    # Remove ace's in reverse order!
    $self->cmd('configure terminal');

    #mypr "ip access-list extended $name\n";
    $self->cmd("ip access-list extended $name");
    my $counter = 0;
    for my $c (reverse @$entries) {
        my $acl = "no $c->{orig}";

        # *** HACK *** to handle NV ram slowdown
        my $output = $self->shcmd($acl);
        $self->cmd_check_error(\$output) or exit -1;
        if ($output =~ /Delete failed. NV generation of acl in progress/) {
            mypr "sleep 1 second and try again.\n";
            sleep 1;
            $self->cmd($acl);
        }
        # *** HACK END ***

        $counter++;
        mypr " $counter";
    }
    mypr "\n";
    $self->cmd('end');
}

sub smart_transfer_acl( $$$$$ ){
    my ($self,$intf,$aclname,$sa,$ca) = @_;
    #
    # clean up running config acl
    #
    # there may be garbage from earlier unsuccessfull transfers:
    # example:
    # in the case of         permit ip any any
    #                        permit ip any any log
    # or
    #                        permit ip any any log
    #                        permit ip any any
    #
    # we always(!) delete the second entry 
    #
    mypr "SMART: *** change acl \'$aclname\' at interface \'$intf\' ***\n";
    my $junk = 0;
    for(my $i = 0;$i<scalar @$ca;$i++){
	my $acl;
	my $ace = $$ca[$i];
	exists $ace->{REMARK} and warnpr "SMART: remark detected at $aclname!\n";
	if($ace->{LOG}){
	    $acl = $ace->{orig};
	    $acl =~ s/$ace->{LOG}//;
	}
	else{
	    $acl = "$ace->{orig} log";
	}
	my $outer = {};
	$self->parse_acl_line($acl,$outer);
	for(my $j = $i + 1;$j<scalar @$ca;$j++){
	    if($self->acl_line_a_eq_b($$ca[$j],$outer)){
	
		$$ca[$j]->{SMART}->{JUNK} = 1;
		warnpr "SMART: redundant logging entry at $j for $i scheduled for remove $j \n";
		$junk = 1;
		last;
	    }
	}
    }
    if($junk){

	# *** SCHEDULE RELOAD ***
	#
	# TODO: check if 10 minutes are OK
	#
	$self->schedule_reload(10);
	my @junk = ();
	mypr "SMART: removing junk\n";
	for my $ace (@$ca){
	    ($ace->{SMART}->{JUNK}) and push @junk,$ace;
	}
	$self->remove_acl_entries($aclname,\@junk);
	mypr "SMART: ... done\n";
    }
    #
    # initialize sync_conf acl
    #
    my @conf = ();
    for my $ace (@$ca){
	unless($ace->{SMART}->{JUNK} or exists $ace->{REMARK}){
	    push @conf,$ace;
	}
    }
    mypr "SMART: ",scalar @conf," out of ",scalar @$ca," entries taken into initial device acl\n";
    #
    # make a copy of spocacl
    #
    my @spoc = ();
    for my $ace (@$sa){
	if(exists $ace->{REMARK}){
	    warnpr "SMART: remark detected at spocacl!\n";	    
	}
	else{
	    push @spoc,$ace;
	}
    }
    my $round = 0;
    while(scalar @spoc){
	my @remove = ();
	#
	# check for leading correspondeces
	#
	my $match = 0;
	for(my $i = 0;$i< scalar @conf and $i < scalar @spoc;$i++){
	    if($self->acl_line_a_eq_b($conf[$i],$spoc[$i])){
		$match++;
	    }
	    else{
		last;
	    }
	} 
	@remove = splice @conf,$match;
	@conf = ();
	splice @spoc,0,$match;
	scalar @spoc or scalar @remove or next;
	$round++;

	# *** SCHEDULE RELOAD ***
	#
	# TODO: check if 10 minutes are OK
	#
	$self->schedule_reload(10);
	mypr "SMART: leading matches $match in round $round\n";
	#
	# check for double ace's invert and transfer aces 
	#
	mypr "SMART: append spocacl \n";
	for my $ace (@spoc){
	    my $ace_inv_log_line;
	    if($ace->{LOG}){
		$ace_inv_log_line = $ace->{orig};
		$ace_inv_log_line =~ s/$ace->{LOG}//;
	    }
	    else{
		$ace_inv_log_line = "$ace->{orig} log";
	    }
	    my $ace_inv_log = {};
	    $self->parse_acl_line($ace_inv_log_line,$ace_inv_log);
	    my $hit;
	    for my $r (@remove){
		if($self->acl_line_a_eq_b($r,$ace)){
		    push @conf,$ace_inv_log;
		    $hit = 1;
		}
		elsif($self->acl_line_a_eq_b($r,$ace_inv_log)){
		    push @conf,$ace;
		    $hit = 1;
		}
		else{
		    # we are free to invert or not!
		    # in most cases we have only 2 rounds
		    # if the free ones inverted.
		    $hit = 0;
		}
		$hit and last;
	    }
	    $hit or  push @conf,$ace_inv_log;
	}
	$self->append_acl_entries($aclname,\@conf);   
	#
	# remove old confacl (begining with last line!)
	#
	mypr "SMART: remove confacl\n";
	$self->remove_acl_entries($aclname,\@remove);
    }
    $self->cancel_reload();
    mypr "SMART: done\n";
}

sub process_interface_acls( $$$ ){
    my ($self, $conf, $spoc) = @_;
    mypr "======================================================\n";
    mypr "SMART: establish new acls for device\n";
    mypr "======================================================\n";

    # possible acl-names are (per name convention):
    #
    # <spoc-name>-DRC-0
    # <spoc-name>-DRC-1
    for my $intf (values %{$spoc->{IF}}){
	my $name = $intf->{name};
	$intf->{TRANSFER} or next;
	$self->{CHANGE}->{ACL} = 1;
	my $spocacl = $intf->{ACCESS};
	my $confacl = $conf->{IF}->{$name}->{ACCESS};
	if($confacl){
	    my $aclname = $confacl;
	    $self->smart_transfer_acl($name,
				      $aclname,
				      $spoc->{ACCESS}->{$spocacl},
				      $conf->{ACCESS}->{$confacl});
	}
	else{
	    warnpr "no access-list configured at interface $name\n";
	    my $aclname = "$spocacl-DRC";

	    # begin transfer
	    mypr "create *new* acl $aclname on device\n";
	    #
	    # maybe there is an old acl with $aclname:
	    # first remove old entries because acl should be empty - otherwise
	    # new entries are only appended - bad
	    #
	    $self->cmd('configure terminal');
	    $self->cmd("no ip access-list extended $aclname");
	    $self->cmd('end');
	    $self->append_acl_entries($aclname, $spoc->{ACCESS}->{$spocacl});

	    # *** SCHEDULE RELOAD ***
	    # TODO: check if 10 minutes are OK
	    $self->schedule_reload(10);

	    # Assign new acl to interface.
	    mypr "assign new acl:\n";
	    $self->cmd('configure terminal');
	    mypr " interface $name\n";
	    $self->cmd("interface $name");
	    mypr " ip access-group $aclname in\n";
	    $self->cmd("ip access-group $aclname in");
	    $self->cmd('end');
	    $self->cancel_reload();
	}
    }

    # Check if new config == spocacl (if necessary)
    if($self->{CHANGE}->{ACL}) {
	mypr "SMART: *** check for successfull acl change ***\n";
	my $lines = $self->get_config_from_device();
	my $new_conf  = $self->parse_config($lines);

	# Reset TRANSFER status.
	for my $intf (values %{$spoc->{IF}}){
	    delete $intf->{TRANSFER};
	}
	$self->compare_interface_acls($new_conf, $spoc, 1); 

	# Be verbose, because mismatch is fatal.
	for my $intf (values %{$spoc->{IF}}){
	    if($intf->{TRANSFER}){
		errpr "acl change at interface '$intf->{name}' not complete\n";
		for my $ace (@{$spoc->{ACCESS}->{$intf->{ACCESS}}}){
		    mypr "- $ace->{orig}\n";
		}
	    }
	}
	last;
    }
    mypr "======================================================\n";
    mypr "SMART: done\n";
    mypr "======================================================\n";
}


# Packages must return a true value;
1;


