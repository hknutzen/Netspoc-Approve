############################################################
=TITLE=Check name of rule from raw
=DEVICE=
{}
=NETSPOC=
--router.raw
{
 "Rules": [{ "name": "test" }]
}
=ERROR=
ERROR>>> While reading file router.raw: Must only define name starting with 'Raw ': test
=END=

############################################################
=TITLE=Check name of group from raw
=DEVICE=
{}
=NETSPOC=
--router.raw
{
 "Groups": [{ "name": "test" }]
}
=ERROR=
ERROR>>> While reading file router.raw: Must only define name starting with 'Raw ': test
=END=

############################################################
=TITLE=Check name of TCP service from raw
=DEVICE=
{}
=NETSPOC=
--router.raw
{
 "TCP": [{ "name": "test" }]
}
=ERROR=
ERROR>>> While reading file router.raw: Must only define name starting with 'Raw ': test
=END=

############################################################
=TITLE=Check source of rule from raw
=DEVICE=
{}
=NETSPOC=
--router.raw
{
 "Rules": [{ "name": "Raw rule", "source": ["Raw ref", "Net_10.1.0.0-16"] }]
}
=ERROR=
ERROR>>> While reading file router.raw: Must not reference name from Netspoc in "Raw rule": Net_10.1.0.0-16
=END=

############################################################
=TITLE=Check service of rule from raw
=DEVICE=
{}
=NETSPOC=
--router.raw
{
 "Rules": [{ "name": "Raw rule", "service": ["http", "tcp_8080"] }]
}
=ERROR=
ERROR>>> While reading file router.raw: Must not reference name from Netspoc in "Raw rule": tcp_8080
=END=

############################################################
=TITLE=Check members of group from raw
=DEVICE=
{}
=NETSPOC=
--router.raw
{
 "Groups": [{ "name": "Raw group", "members": ["g_test Rule-2"] }]
}
=ERROR=
ERROR>>> While reading file router.raw: Must not reference name from Netspoc in "Raw group": g_test Rule-2
=END=

############################################################
=TITLE=Merge rule from raw with rule from netspoc
=DEVICE=
{ "Rules": [
 { "name": "rule_1", "action": "Accept", "service": ["http"] },
 { "name": "rule_2", "action": "Drop" }
]}
=NETSPOC=
-- router
{ "Rules": [
 { "name": "rule_1", "action": "Accept", "service": ["http"] },
 { "name": "rule_2", "action": "Drop" }
]}
-- router.raw
{ "Rules": [
   { "name": "Raw top", "action": "Accept", "service": ["https"] },
   { "name": "Raw bot", "action": "Accept", "service": ["smtp"], "append": true }
  ]
}
=OUTPUT=
add-access-rule
{"name":"Raw top","layer":"network","action":"Accept","source":null,"destination":null,"service":["https"],"install-on":null,"position":{"above":"rule_1"}}
add-access-rule
{"name":"Raw bot","layer":"network","action":"Accept","source":null,"destination":null,"service":["smtp"],"install-on":null,"position":{"above":"rule_2"}}
=END=

############################################################
=TITLE=Merge host, group, service and rule from raw
=DEVICE=
{ "Rules": [ { "name": "Cleanup rule", "action": "Drop" } ]
}
=NETSPOC=
-- router
{ "Rules": [
 { "name": "rule_1", "action": "Accept", "source": ["g1"], "service": ["tcp_8080"] },
 { "name": "Cleanup rule", "action": "Drop" } ],
 "Hosts": [
 { "name": "h_1", "ipv4-address": "10.1.8.1" } ],
 "Groups": [
 { "name": "g_1", "members": ["h_1"] } ],
 "TCP": [
 { "name": "tcp_8080", "port": "8080" } ]
}
-- router.raw
{ "Rules": [
 { "name": "Raw 2", "action": "Accept", "source": ["Raw g2"], "service": ["Raw s2"] } ],
 "Hosts": [
 { "name": "Raw h2", "ipv4-address": "10.1.8.2" } ],
 "Groups": [
 { "name": "Raw g2", "members": ["Raw h2"] } ],
 "TCP": [
 { "name": "Raw s2", "port": "8082" } ]
}
=OUTPUT=
add-host
{"name":"h_1","ipv4-address":"10.1.8.1"}
add-host
{"name":"Raw h2","ipv4-address":"10.1.8.2"}
add-group
{"name":"g_1","members":["h_1"]}
add-group
{"name":"Raw g2","members":["Raw h2"]}
add-service-tcp
{"name":"tcp_8080","port":"8080"}
add-service-tcp
{"name":"Raw s2","port":"8082"}
add-access-rule
{"name":"Raw 2","layer":"network","action":"Accept","source":["Raw g2"],"destination":null,"service":["Raw s2"],"install-on":null,"position":{"above":"Cleanup rule"}}
add-access-rule
{"name":"rule_1","layer":"network","action":"Accept","source":["g1"],"destination":null,"service":["tcp_8080"],"install-on":null,"position":{"above":"Cleanup rule"}}
=END=
