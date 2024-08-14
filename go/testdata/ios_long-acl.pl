#!/usr/bin/env perl
# Generate test file "ios_long-acl.t"

my $acls = '';
for my $port (1 .. 10000) {
   $acls .= " permit tcp any host 10.0.1.2 eq $port\n";
}

(my $path = $0) =~ s/\.[^.]+$/.t/ or die;
open(my $fh, '>', $path) or die;
print $fh <<"END";
############################################################
# generated by "ios_long-acl.pl"
=TITLE=Can't insert more than ACL 9999 lines at once
=DEVICE=
interface Ethernet1
 ip access-group test in
ip access-list extended test
 permit tcp any host 10.0.1.1 eq 80
 permit tcp any host 10.0.1.3 eq 80
=NETSPOC=
interface Ethernet1
 ip access-group test in
ip access-list extended test
 permit tcp any host 10.0.1.1 eq 80
$acls
 permit tcp any host 10.0.1.3 eq 80
=ERROR=
ERROR>>> Can't insert more than 9999 ACL lines at once
=END=
END

close($fh);
