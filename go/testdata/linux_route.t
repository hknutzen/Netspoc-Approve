
############################################################
=TITLE=Add routing
=NETSPOC=
ip route add 10.1.11.1 via 10.10.1.7
ip route add 10.1.11.0/24 via 10.10.1.6
ip route add default via 10.9.9.9
=OUTPUT=
ip route add 10.1.11.1 via 10.10.1.7
ip route add 10.1.11.0/24 via 10.10.1.6
ip route add default via 10.9.9.9
=END=

############################################################
=TITLE=Unchanged routing
=DEVICE=
ip route add 10.0.0.0/24 dev eth0 proto kernel scope link src 10.1.11.99
ip route add 10.0.1.0/24 dev eth0 proto kernel scope host src 10.1.11.88
ip route add 10.1.11.1 via 10.10.1.7 dev eth0
ip route add 10.1.11.0/24 via 10.10.1.6
ip route add default via 10.9.9.9
=NETSPOC=
ip route add 10.1.11.1 via 10.10.1.7
ip route add 10.1.11.0/24 via 10.10.1.6
ip route add 0.0.0.0/0 via 10.9.9.9
=OUTPUT=NONE

############################################################
=TITLE=Change routing
=DEVICE=
ip route add 10.20.0.0/16 via 10.1.2.3
ip route add 10.30.0.0/16 via 10.1.2.3
ip route add 10.40.0.0/16 via 10.1.2.3
ip route add default via 10.1.2.5
=NETSPOC=
ip route add 10.10.0.0/16 via 10.1.2.3
ip route add 10.20.0.0/16 via 10.1.2.3
ip route add 10.40.0.0/16 via 10.1.2.4
ip route add 0.0.0.0/0 via 10.1.2.6
=OUTPUT=
ip route add 10.10.0.0/16 via 10.1.2.3
ip route del 10.40.0.0/16 via 10.1.2.3\N ip route add 10.40.0.0/16 via 10.1.2.4
ip route del default via 10.1.2.5\N ip route add 0.0.0.0/0 via 10.1.2.6
ip route del 10.30.0.0/16 via 10.1.2.3
=END=

############################################################
=TITLE=Bad route command
=DEVICE=

=NETSPOC=
ip route del
=ERROR=
ERROR>>> Unexpected route: ip route del
=END=

############################################################
=TITLE=Unexpected attribute
=DEVICE=

=NETSPOC=
ip route add 10.1.1.0/24 via 10.1.1.1 vrf x
=ERROR=
ERROR>>> Unexpected route: ip route add 10.1.1.0/24 via 10.1.1.1 vrf x
=END=
