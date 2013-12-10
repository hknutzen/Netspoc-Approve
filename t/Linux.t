#!/usr/bin/perl
# Linux.t

use strict;
use Test::More;
use Test::Differences;
use lib 't';
use Test_Approve;

# Input from Netspoc.
# Input from device.
# Output from approve.
my($in, $device, $out);
my $type = 'Linux';
my $title;

my $minimal_device = '';

############################################################
$title = "Parse Routing";
############################################################
$in = <<END;
ip route add 10.1.11.0/24 via 10.10.1.6
ip route add 0.0.0.0/0 via 10.9.9.9
END

$out = $in;

check_parse_and_unchanged($type, $minimal_device, $in, $out, $title);

############################################################
$title = "Parse ACL with chains";
############################################################
$in = <<END;
#!/usr/sbin/iptables-restore <<EOF
*filter
:INPUT DROP
:FORWARD DROP
:OUTPUT ACCEPT
:eth0_self -
:eth0_in -
:c1 -
:c2 -
:c3 -
:c4 -
:c5 -
:c6 -
:droplog -
-A droplog -j LOG --log-level debug
-A droplog -j DROP
-A c1 -j ACCEPT -p icmp --icmp-type 0
-A c1 -j ACCEPT -p icmp --icmp-type 8
-A c2 -g c1 -d 10.1.1.2 -p icmp
-A c2 -g c1 -d 10.1.1.1 -p icmp
-A c3 -j ACCEPT -s 10.1.11.111 -d 10.10.1.2 -p tcp --dport 23
-A c3 -j ACCEPT -s 10.1.11.111 -d 10.10.1.1 -p tcp --dport 23
-A c4 -j ACCEPT -p udp --dport 3400:3500
-A c4 -j ACCEPT -p udp --dport 3978
-A c5 -j c4 -p udp --dport 3000:4000
-A c5 -j ACCEPT -s 10.1.11.111 -p udp
-A c6 -g c5 -d 10.10.2.2
-A c6 -g c5 -d 10.10.2.1

-A eth0_self -j ACCEPT -s 10.1.1.0/24 -d 224.0.0.18 -p 112
-A eth0_self -g c2 -d 10.1.1.0/30 -p icmp

-A eth0_in -g c3 -d 10.10.1.0/30 -p tcp
-A eth0_in -g c6 -d 10.10.2.0/24 -p udp

-A INPUT -j ACCEPT -m state --state ESTABLISHED,RELATED
-A INPUT -j eth0_self -i eth0 
-A INPUT -j droplog
-A FORWARD -j ACCEPT -m state --state ESTABLISHED,RELATED
-A FORWARD -j eth0_in -i eth0
-A FORWARD -j droplog
COMMIT
EOF
END

# Currently we don't see any output in compare mode,
# because iptables rules are always fully transferred, not incementally.
$out = '';

check_parse_and_unchanged($type, $minimal_device, $in, $out, $title);

############################################################
$title = "Change routing";
############################################################
$in = <<END;
ip route add 10.10.0.0/16 via 10.1.2.3
ip route add 10.20.0.0/16 via 10.1.2.3
ip route add 10.40.0.0/16 via 10.1.2.4
END

$device = <<END;
ip route add 10.20.0.0/16 via 10.1.2.3
ip route add 10.30.0.0/16 via 10.1.2.3
ip route add 10.40.0.0/16 via 10.1.2.3
END


$out = <<END;
ip route add 10.10.0.0/16 via 10.1.2.3
ip route del 10.40.0.0/16 via 10.1.2.3\\N ip route add 10.40.0.0/16 via 10.1.2.4
ip route del 10.30.0.0/16 via 10.1.2.3
END

eq_or_diff(approve($type, $device, $in), $out, $title);


############################################################
done_testing;
