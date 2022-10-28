=TEMPL=allow
{
 "resource_type": "Rule",
 "id": "{{.id}}",
 "scope": [ "/infra/tier-0s/v1" ],
 "direction": "OUT",
 "sequence_number": 20,
 "action": "ALLOW",
 "source_groups": [ "{{.src}}" ],
 "destination_groups": [ "{{.dst}}" ],
 "services": [ "/infra/services/Netspoc-{{.srv}}" ]
}
=TEMPL=drop
{
 "resource_type": "Rule",
 "id": "{{.id}}",
 "scope": [ "/infra/tier-0s/v1" ],
 "direction": {{or .dir "OUT" | printf "%q"}},
 "sequence_number": 30,
 "action": "DROP",
 "source_groups": [ "ANY" ],
 "destination_groups": [ "ANY" ],
 "services": [ "ANY" ]
}
=TEMPL=group
{
 "id": "Netspoc-{{.id}}",
 "expression": [
  {
   "resource_type": "IPAddressExpression",
   "ip_addresses": [
    "{{.ip}}"
   ]
  }
 ]
}
=TEMPL=tcp
{
 "id": "Netspoc-tcp {{.}}",
 "service_entries": [
  {
   "resource_type": "L4PortSetServiceEntry",
   "l4_protocol": "TCP",
   "destination_ports": [ "{{.}}" ]
  }
 ]
}
=TEMPL=udp
{
 "id": "Netspoc-udp {{.}}",
 "service_entries": [
  {
   "resource_type": "L4PortSetServiceEntry",
   "l4_protocol": "UDP",
   "destination_ports": [ "{{.}}" ]
  }
 ]
}
=END=
=TEMPL=two_rules
{
 "policies": [
  {
   "id": "Netspoc-v1",
   "resource_type": "GatewayPolicy",
   "rules": [
[[allow { id: r1, src: 10.1.1.10, dst: 10.1.2.30, srv: "tcp 80" }]],
[[allow { id: r2, src: 10.1.1.10, dst: 10.1.2.40, srv: "udp 123" }]],
[[drop  { id: r3 }]],
[[drop  { id: r4, dir: IN }]]
   ]
  }
 ],
 "services": [
[[tcp 80]],
[[udp 123]]
 ]
}
=TEMPL=one_rule
{
 "policies": [
  {
   "id": "Netspoc-v1",
   "resource_type": "GatewayPolicy",
   "rules": [
[[allow { id: r1, src: 10.1.1.10, dst: 10.1.2.30, srv: "tcp 80" }]],
[[drop  { id: r3 }]],
[[drop  { id: r4, dir: IN }]]
   ]
  }
 ],
 "services": [
[[tcp 80]]
 ]
}
=END=

############################################################
=TITLE=No differences
=DEVICE=[[two_rules]]
=NETSPOC=[[two_rules]]
=OUTPUT=NONE

############################################################
=TITLE=No differences, renamed id of rule
=DEVICE=[[two_rules]]
=SUBST=/r1/r9/
=NETSPOC=[[two_rules]]
=OUTPUT=NONE

############################################################
=TITLE=Add to empty device
=DEVICE=
{}
=NETSPOC=
[[two_rules]]
=OUTPUT=
PUT
/policy/api/v1/infra/domains/default/gateway-policies/Netspoc-v1
[[two_rules]]
=END=

############################################################
=TITLE=Remove all from device
=DEVICE=
[[two_rules]]
=NETSPOC=
{}
=OUTPUT=
URL
Data
=END=

############################################################
=TITLE=Remove one rule
=DEVICE=
[[two_rules]]
=NETSPOC=
[[one_rule]]
=OUTPUT=
URL
Data
=END=

############################################################
=TITLE=Add one rule
=DEVICE=
[[one_rule]]
=NETSPOC=
[[two_rules]]
=OUTPUT=
URL
Data
=END=

############################################################
=TEMPL=group_rule
{
 "groups": [
[[group { id: g0, ip: '10.1.1.10","10.1.1.20' }]],
[[group { id: g1, ip: '10.1.2.30","10.1.2.40' }]]
 ],
 "policies": [
  {
   "id": "Netspoc-v1",
   "resource_type": "GatewayPolicy",
   "rules": [
[[allow
id: r1
src: /infra/domains/default/groups/Netspoc-g0
dst: /infra/domains/default/groups/Netspoc-g1
srv: 'tcp 80","/infra/services/Netspoc-udp 123'
]],
[[drop  { id: r2 }]],
[[drop  { id: r3, dir: IN }]]
   ]
  }
 ],
 "services": [
[[tcp 80]],
[[udp 123]]
 ]
}
=END=

############################################################
=TITLE=No differences with groups
=DEVICE=[[group_rule]]
=NETSPOC=[[group_rule]]
=OUTPUT=NONE

############################################################
=TITLE=Only group names differ
=DEVICE=[[group_rule]]
=SUBST=/g0/g2/
=NETSPOC=[[group_rule]]
=OUTPUT=NONE

############################################################
=TITLE=Change service of rule
=DEVICE=[[group_rule]]
=SUBST=|,"/infra/services/Netspoc-udp 123"||
=NETSPOC=[[group_rule]]
=SUBST=|"/infra/services/Netspoc-tcp 80",||
=SUBST=/g0/g2/
=OUTPUT=
/url
DATA
=END=

############################################################
=TITLE=Add element to group
=DEVICE=[[group_rule]]
=SUBST=|"10.1.1.10",||
=NETSPOC=[[group_rule]]
=OUTPUT=
/url
DATA
=END=

############################################################
=TITLE=Remove element from group
=DEVICE=[[group_rule]]
=NETSPOC=[[group_rule]]
=SUBST=|"10.1.1.10",||
=OUTPUT=
/url
DATA
=END=
