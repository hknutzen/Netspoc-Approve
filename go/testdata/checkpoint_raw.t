############################################################
=TITLE=Invalid JSON raw
=DEVICE=
{}
=NETSPOC=
--router.raw
{
 "TargetRules": INVALID
}
=ERROR=
ERROR>>> While reading file router.raw: invalid character 'I' looking for beginning of value
=END=

############################################################
=TITLE=Check name of rule from raw
=DEVICE=
{}
=NETSPOC=
--router.raw
{
 "TargetRules": {"fw1": [{ "name": "test" }]}
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
=TITLE=Invalid JSON: action of rule
=DEVICE=
{}
=NETSPOC=
--router.raw
{
 "TargetRules": {"fw1": [
  { "name": "Raw rule", "action": 42 }
 ]}
}
=ERROR=
ERROR>>> While reading file router.raw: json: cannot unmarshal number into Go struct field chkpRule.TargetRules.action of type struct { Name string }
=END=

############################################################
=TITLE=Invalid JSON: disabled rule
=DEVICE=
{}
=NETSPOC=
--router.raw
{
 "TargetRules": {"fw1": [
  { "name": "Raw rule", "enabled": 42 }
 ]}
}
=ERROR=
ERROR>>> While reading file router.raw: json: cannot unmarshal number into Go struct field chkpRule.TargetRules.enabled of type bool
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
 "TargetRules": {"fw1": [
  { "name": "Raw rule", "source": ["Raw ref", "Net_10.1.0.0-16"] }
 ]}
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
 "TargetRules": {"fw1":
  [{ "name": "Raw rule", "service": ["http", "tcp_8080"] }]
 }
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
=TITLE=Check attribute "install-on" from raw
=DEVICE=
{ "TargetPolicy": {"fw1": {"Name": "standard", "Layer": "network"}} }
=NETSPOC=
--router
{
  "TargetRules": {"fw1": []}
}
--router.raw
{
  "TargetRules": {"fw1": [
    {
      "name": "Raw http",
      "uid": "id-http",
      "action": "Accept",
      "source": ["Any"],
      "destination": ["Any"],
      "service": ["http"],
      "install-on": ["other-fw"]
    }
  ]}
}
=ERROR=
ERROR>>> While reading file router.raw: Must use "install-on": ["Policy Targets"] in rule "Raw http" of "fw1"
=END=

############################################################
=TITLE=Merge rule from raw with rule from netspoc
=DEVICE=
{ "TargetPolicy": {"fw1": {"Name": "standard", "Layer": "network"}},
  "TargetRules": {"fw1": [
   { "name": "rule_1", "uid": "id-1", "install-on": ["Policy Targets"],
     "action": "Accept", "service": ["http"] },
   { "name": "rule_2", "uid": "id-2", "install-on": ["Policy Targets"],
     "action": "Drop" }
  ]}
}
=NETSPOC=
-- router
{ "TargetRules": {"fw1": [
   { "name": "rule_1", "install-on": ["Policy Targets"],
     "action": "Accept", "service": ["http"] },
   { "name": "rule_2", "install-on": ["Policy Targets"],
     "action": "Drop" }
  ]}
}
-- router.raw
{ "TargetRules": {"fw1": [
   { "name": "Raw top", "install-on": ["Policy Targets"],
     "action": "Accept", "service": ["https"],"enabled":true},
   { "name": "Raw bot", "install-on": ["Policy Targets"],
     "action": "Accept", "service": ["smtp"], "append": true }
  ]}
}
=OUTPUT=
add-access-rule
{"name":"Raw top","layer":"network",
 "action":"Accept","source":null,"destination":null,"service":["https"],
 "install-on":["Policy Targets"],"position":{"above":"id-1"}}
add-access-rule
{"name":"Raw bot","layer":"network",
 "action":"Accept","source":null,"destination":null,"service":["smtp"],
 "install-on":["Policy Targets"],"position":{"above":"id-2"}}
=END=

############################################################
=TITLE=Merge host, group, service and rule from raw
=DEVICE=
{"TargetPolicy": {"fw1": {"Name": "standard", "Layer": "network"}},
 "TargetRules": {"fw1": [
  { "name": "Cleanup rule", "uid": "id", "install-on": ["Policy Targets"],
    "action": "Drop" }
 ]}
}
=NETSPOC=
-- router
{"TargetRules": {"fw1": [
   { "name": "rule_1", "install-on": ["Policy Targets"],
     "action": "Accept", "source": ["g1"], "service": ["tcp_8080"] },
   { "name": "Cleanup rule", "install-on": ["Policy Targets"],
     "action": "Drop" }
 ]},
 "Hosts": [
 { "name": "h_1", "ipv4-address": "10.1.8.1" } ],
 "Groups": [
 { "name": "g_1", "members": ["h_1"] } ],
 "TCP": [
 { "name": "tcp_8080", "port": "8080" } ]
}
-- router.raw
{"TargetRules": {"fw1": [
  { "name": "Raw 2", "install-on": ["Policy Targets"],
    "action": "Accept", "source": ["Raw g2"], "service": ["Raw s2"], "enabled": false } ]},
 "Hosts": [
 { "name": "Raw h2", "ipv4-address": "10.1.8.2" } ],
 "Groups": [
 { "name": "Raw g2", "members": ["Raw h2"] } ],
 "TCP": [
 { "name": "Raw s2", "port": "8082" } ]
}
=OUTPUT=
add-host
{"name":"h_1","ignore-warnings":true,"ipv4-address":"10.1.8.1"}
add-host
{"name":"Raw h2","ignore-warnings":true,"ipv4-address":"10.1.8.2"}
add-group
{"name":"g_1","members":["h_1"]}
add-group
{"name":"Raw g2","members":["Raw h2"]}
add-service-tcp
{"name":"tcp_8080","ignore-warnings":true,"port":"8080"}
add-service-tcp
{"name":"Raw s2","ignore-warnings":true,"port":"8082"}
add-access-rule
{"name":"Raw 2","layer":"network",
 "action":"Accept","source":["Raw g2"],"destination":null,"service":["Raw s2"],
 "enabled":false,"install-on":["Policy Targets"],"position":{"above":"id"}}
add-access-rule
{"name":"rule_1","layer":"network",
 "action":"Accept","source":["g1"],"destination":null,"service":["tcp_8080"],
 "install-on":["Policy Targets"],"position":{"above":"id"}}
=END=
