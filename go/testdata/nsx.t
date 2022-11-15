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
   "id": "id",
   "resource_type": "IPAddressExpression",
   "ip_addresses": [
    "{{.ip}}"
   ]
  }
 ]
}
=TEMPL=tcp
{
 "id": "Netspoc-tcp_{{.}}",
 "service_entries": [
  {
   "display_name": "Netspoc tcp {{.}}",
   "resource_type": "L4PortSetServiceEntry",
   "l4_protocol": "TCP",
   "destination_ports": [ "{{.}}" ]
  }
 ]
}
=TEMPL=udp
{
 "id": "Netspoc-udp_{{.}}",
 "service_entries": [
  {
  "display_name": "Netspoc udp {{.}}",
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
[[allow { id: r1, src: 10.1.1.10, dst: 10.1.2.30, srv: tcp_80 }]],
[[allow { id: r2, src: 10.1.1.10, dst: 10.1.2.40, srv: udp_123 }]],
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
[[allow { id: r1, src: 10.1.1.10, dst: 10.1.2.30, srv: tcp_80 }]],
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
PUT /policy/api/v1/infra/services/Netspoc-tcp_80
{"service_entries":[
 {
  "destination_ports":["80"],
  "display_name":"Netspoc tcp 80",
  "l4_protocol":"TCP",
  "resource_type":"L4PortSetServiceEntry",
  "source_ports":null
 }]}
PUT /policy/api/v1/infra/services/Netspoc-udp_123
{"service_entries":[
 {
  "destination_ports":["123"],
  "display_name":"Netspoc udp 123",
  "l4_protocol":"UDP",
  "resource_type":"L4PortSetServiceEntry",
  "source_ports":null
 }]}
PUT /policy/api/v1/infra/domains/default/gateway-policies/Netspoc-v1
{"id":"Netspoc-v1",
 "rules":[
 {
  "id":"r1",
  "action":"ALLOW",
  "sequence_number":20,
  "source_groups":["10.1.1.10"],
  "destination_groups":["10.1.2.30"],
  "services":["/infra/services/Netspoc-tcp_80"],
  "scope":["/infra/tier-0s/v1"],
  "direction":"OUT"
 },{
  "id":"r2",
  "action":"ALLOW",
  "sequence_number":20,
  "source_groups":["10.1.1.10"],
  "destination_groups":["10.1.2.40"],
  "services":["/infra/services/Netspoc-udp_123"],
  "scope":["/infra/tier-0s/v1"],
  "direction":"OUT"
 },{
  "id":"r3",
  "action":"DROP",
  "sequence_number":30,
  "source_groups":["ANY"],
  "destination_groups":["ANY"],
  "services":["ANY"],
  "scope":["/infra/tier-0s/v1"],
  "direction":"OUT"
 },{
  "id":"r4",
  "action":"DROP",
  "sequence_number":30,
  "source_groups":["ANY"],
  "destination_groups":["ANY"],
  "services":["ANY"],
  "scope":["/infra/tier-0s/v1"],
  "direction":"IN"}]}
=END=

############################################################
=TITLE=Remove all from device
=DEVICE=
[[two_rules]]
=NETSPOC=
{}
=OUTPUT=
DELETE /policy/api/v1/infra/domains/default/gateway-policies/Netspoc-v1

DELETE /policy/api/v1/infra/services/Netspoc-tcp_80

DELETE /policy/api/v1/infra/services/Netspoc-udp_123

=END=

############################################################
=TITLE=Remove one rule
=DEVICE=
[[two_rules]]
=NETSPOC=
[[one_rule]]
=OUTPUT=
DELETE /policy/api/v1/infra/domains/default/gateway-policies/Netspoc-v1/rules/r2

DELETE /policy/api/v1/infra/services/Netspoc-udp_123

=END=

############################################################
=TITLE=Add one rule
=DEVICE=
[[one_rule]]
=NETSPOC=
[[two_rules]]
=OUTPUT=
PUT /policy/api/v1/infra/services/Netspoc-udp_123
{"service_entries":[
 {
  "destination_ports":["123"],
  "display_name":"Netspoc udp 123",
  "l4_protocol":"UDP",
  "resource_type":"L4PortSetServiceEntry",
  "source_ports":null
 }]}
PUT /policy/api/v1/infra/domains/default/gateway-policies/Netspoc-v1/rules/r2
{
 "action":"ALLOW",
 "sequence_number":20,
 "source_groups":["10.1.1.10"],
 "destination_groups":["10.1.2.40"],
 "services":["/infra/services/Netspoc-udp_123"],
 "scope":["/infra/tier-0s/v1"],
 "direction":"OUT"}
=END=

############################################################
=TITLE=Add one rule with name clash
=DEVICE=
[[one_rule]]
=SUBST=/r1/r2/
=NETSPOC=
[[two_rules]]
=OUTPUT=
PUT /policy/api/v1/infra/services/Netspoc-udp_123
{"service_entries":[
 {
  "destination_ports":["123"],
  "display_name":"Netspoc udp 123",
  "l4_protocol":"UDP",
  "resource_type":"L4PortSetServiceEntry",
  "source_ports":null
 }]}
PUT /policy/api/v1/infra/domains/default/gateway-policies/Netspoc-v1/rules/r2-1
{
 "action":"ALLOW",
 "sequence_number":20,
 "source_groups":["10.1.1.10"],
 "destination_groups":["10.1.2.40"],
 "services":["/infra/services/Netspoc-udp_123"],
 "scope":["/infra/tier-0s/v1"],
 "direction":"OUT"}
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
srv: 'tcp_80","/infra/services/Netspoc-udp_123'
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
=TITLE=Add rule with group to empty device
=DEVICE=
{}
=NETSPOC=[[group_rule]]
=OUTPUT=
PUT /policy/api/v1/infra/services/Netspoc-tcp_80
{"service_entries":[{"destination_ports":["80"],"display_name":"Netspoc tcp 80","l4_protocol":"TCP","resource_type":"L4PortSetServiceEntry","source_ports":null}]}
PUT /policy/api/v1/infra/services/Netspoc-udp_123
{"service_entries":[{"destination_ports":["123"],"display_name":"Netspoc udp 123","l4_protocol":"UDP","resource_type":"L4PortSetServiceEntry","source_ports":null}]}
PUT /policy/api/v1/infra/domains/default/groups/Netspoc-g0
{"expression":[{"id":"id","resource_type":"IPAddressExpression","ip_addresses":["10.1.1.10","10.1.1.20"]}]}
PUT /policy/api/v1/infra/domains/default/groups/Netspoc-g1
{"expression":[{"id":"id","resource_type":"IPAddressExpression","ip_addresses":["10.1.2.30","10.1.2.40"]}]}
PUT /policy/api/v1/infra/domains/default/gateway-policies/Netspoc-v1
{"id":"Netspoc-v1","rules":[{"id":"r1","action":"ALLOW","sequence_number":20,"source_groups":["/infra/domains/default/groups/Netspoc-g0"],"destination_groups":["/infra/domains/default/groups/Netspoc-g1"],"services":["/infra/services/Netspoc-tcp_80","/infra/services/Netspoc-udp_123"],"scope":["/infra/tier-0s/v1"],"direction":"OUT"},{"id":"r2","action":"DROP","sequence_number":30,"source_groups":["ANY"],"destination_groups":["ANY"],"services":["ANY"],"scope":["/infra/tier-0s/v1"],"direction":"OUT"},{"id":"r3","action":"DROP","sequence_number":30,"source_groups":["ANY"],"destination_groups":["ANY"],"services":["ANY"],"scope":["/infra/tier-0s/v1"],"direction":"IN"}]}
=END=

############################################################
=TITLE=Reuse existing service and group when creating new policy
=DEVICE=
{
 "groups": [
[[group { id: g8, ip: '10.1.1.10","10.1.1.20' }]],
[[group { id: g9, ip: '10.1.2.30","10.1.2.40' }]]
 ],
 "services": [
[[tcp 80]],
[[udp 123]]
 ]
}
=NETSPOC=[[group_rule]]
=OUTPUT=
PUT /policy/api/v1/infra/domains/default/gateway-policies/Netspoc-v1
{"id":"Netspoc-v1","rules":[{"id":"r1","action":"ALLOW","sequence_number":20,"source_groups":["/infra/domains/default/groups/Netspoc-g8"],"destination_groups":["/infra/domains/default/groups/Netspoc-g9"],"services":["/infra/services/Netspoc-tcp_80","/infra/services/Netspoc-udp_123"],"scope":["/infra/tier-0s/v1"],"direction":"OUT"},{"id":"r2","action":"DROP","sequence_number":30,"source_groups":["ANY"],"destination_groups":["ANY"],"services":["ANY"],"scope":["/infra/tier-0s/v1"],"direction":"OUT"},{"id":"r3","action":"DROP","sequence_number":30,"source_groups":["ANY"],"destination_groups":["ANY"],"services":["ANY"],"scope":["/infra/tier-0s/v1"],"direction":"IN"}]}
=END=

############################################################
=TITLE=Only group names differ
=DEVICE=[[group_rule]]
=SUBST=/g0/g2/
=NETSPOC=[[group_rule]]
=OUTPUT=NONE

############################################################
=TITLE=Change service of rule
=DEVICE=[[group_rule]]
=SUBST=|,"/infra/services/Netspoc-udp_123"||
=NETSPOC=[[group_rule]]
=SUBST=|"/infra/services/Netspoc-tcp_80",||
=SUBST=/g0/g2/
=OUTPUT=
DELETE /policy/api/v1/infra/domains/default/gateway-policies/Netspoc-v1/rules/r1

PUT /policy/api/v1/infra/domains/default/gateway-policies/Netspoc-v1/rules/r1-1
{
 "action":"ALLOW",
 "sequence_number":20,
 "source_groups":["/infra/domains/default/groups/Netspoc-g0"],
 "destination_groups":["/infra/domains/default/groups/Netspoc-g1"],
 "services":["/infra/services/Netspoc-udp_123"],
 "scope":["/infra/tier-0s/v1"],
 "direction":"OUT"
 }
=END=

############################################################
=TITLE=Add element to group
=DEVICE=[[group_rule]]
=SUBST=|"10.1.1.10",||
=NETSPOC=[[group_rule]]
=OUTPUT=
POST /policy/api/v1/infra/domains/default/groups/Netspoc-g0/ip-address-expressions/id?action=add
{
 "ip_addresses":["10.1.1.10"]
 }
=END=

############################################################
=TITLE=Remove element from group
=DEVICE=[[group_rule]]
=NETSPOC=[[group_rule]]
=SUBST=|"10.1.1.10",||
=OUTPUT=
POST /policy/api/v1/infra/domains/default/groups/Netspoc-g0/ip-address-expressions/id?action=remove
{
 "ip_addresses":["10.1.1.10"]
 }
=END=

############################################################
=TITLE=Replace element in Group
=DEVICE=[[group_rule]]
=NETSPOC=[[group_rule]]
=SUBST=|"10.1.1.10",|"10.1.1.30",|
=OUTPUT=
POST /policy/api/v1/infra/domains/default/groups/Netspoc-g0/ip-address-expressions/id?action=remove
{
 "ip_addresses":["10.1.1.10"]
 }
POST /policy/api/v1/infra/domains/default/groups/Netspoc-g0/ip-address-expressions/id?action=add
{
 "ip_addresses":["10.1.1.30"]
 }
=END=

############################################################
=TITLE=Replace one group by two different groups
=DEVICE=
{
 "groups": [
[[group { id: g0, ip: '10.1.1.10","10.1.1.20' }]]
 ],
 "policies": [
  {
   "id": "Netspoc-v1",
   "resource_type": "GatewayPolicy",
   "rules": [
[[allow
id: r1
src: /infra/domains/default/groups/Netspoc-g0
dst: 10.2.1.10
srv: tcp_80
]],
[[allow
id: r2
src: /infra/domains/default/groups/Netspoc-g0
dst: 10.2.1.20
srv: tcp_80
]],
[[drop  { id: r3 }]],
[[drop  { id: r4, dir: IN }]]
   ]
  }
 ],
 "services": [
[[tcp 80]]
 ]
}
=NETSPOC=
{
 "groups": [
[[group { id: g0, ip: '10.1.1.10","10.1.1.20","10.1.1.30' }]],
[[group { id: g1, ip: '10.1.1.10","10.1.1.20","10.1.1.40' }]]
 ],
 "policies": [
  {
   "id": "Netspoc-v1",
   "resource_type": "GatewayPolicy",
   "rules": [
[[allow
id: r1
src: /infra/domains/default/groups/Netspoc-g0
dst: 10.2.1.10
srv: tcp_80
]],
[[allow
id: r2
src: /infra/domains/default/groups/Netspoc-g1
dst: 10.2.1.20
srv: tcp_80
]],
[[drop  { id: r3 }]],
[[drop  { id: r4, dir: IN }]]
   ]
  }
 ],
 "services": [
[[tcp 80]]
 ]
}
=OUTPUT=
POST /policy/api/v1/infra/domains/default/groups/Netspoc-g0/ip-address-expressions/id?action=add
{"ip_addresses":["10.1.1.30"]}
PUT /policy/api/v1/infra/domains/default/groups/Netspoc-g1
{
 "expression":[{
 "id":"id",
 "resource_type":"IPAddressExpression",
 "ip_addresses":["10.1.1.10","10.1.1.20","10.1.1.40"]
 }]
 }
PUT /policy/api/v1/infra/domains/default/gateway-policies/Netspoc-v1/rules/r2
{"action":"ALLOW",
 "sequence_number":20,
 "source_groups":["/infra/domains/default/groups/Netspoc-g1"],
 "destination_groups":["10.2.1.20"],
 "services":["/infra/services/Netspoc-tcp_80"],
 "scope":["/infra/tier-0s/v1"],
 "direction":"OUT"}
=END=

############################################################
=TITLE=Delete unused group from device
=DEVICE=[[group_rule]]
=NETSPOC=[[group_rule]]
=SUBST=|/infra/domains/default/groups/Netspoc-g1|10.2.1.20|
=OUTPUT=
DELETE /policy/api/v1/infra/domains/default/gateway-policies/Netspoc-v1/rules/r1

PUT /policy/api/v1/infra/domains/default/gateway-policies/Netspoc-v1/rules/r1-1
{"action":"ALLOW",
 "sequence_number":20,
 "source_groups":["/infra/domains/default/groups/Netspoc-g0"],
 "destination_groups":["10.2.1.20"],
 "services":["/infra/services/Netspoc-tcp_80","/infra/services/Netspoc-udp_123"],
 "scope":["/infra/tier-0s/v1"],
 "direction":"OUT"}
DELETE /policy/api/v1/infra/domains/default/groups/Netspoc-g1

=END=

############################################################
=TITLE=Must not find already used group on device
=DEVICE=
{
 "groups": [
[[group { id: g0, ip: '10.1.1.10","10.1.1.20' }]]
 ],
 "policies": [
  {
   "id": "Netspoc-v1",
   "resource_type": "GatewayPolicy",
   "rules": [
[[allow
id: r1
src: /infra/domains/default/groups/Netspoc-g0
dst: 10.1.2.10
srv: tcp_80
]]
   ]
  }
 ],
 "services": [ [[tcp 80]] ]
}
=NETSPOC=
{
 "groups": [
[[group { id: g1, ip: '10.1.1.10","10.1.1.20","10.1.1.30' }]],
[[group { id: g2, ip: '10.1.1.10","10.1.1.20' }]]
 ],
 "policies": [
  {
   "id": "Netspoc-v1",
   "resource_type": "GatewayPolicy",
   "rules": [
[[allow
id: r1
src: /infra/domains/default/groups/Netspoc-g1
dst: 10.1.2.10
srv: tcp_80
]],
[[allow
id: r2
src: /infra/domains/default/groups/Netspoc-g2
dst: 10.1.2.12
srv: tcp_80
]]
   ]
  }
 ],
 "services": [ [[tcp 80]] ]
}
=OUTPUT=
POST /policy/api/v1/infra/domains/default/groups/Netspoc-g0/ip-address-expressions/id?action=add
{"ip_addresses":["10.1.1.30"]}
PUT /policy/api/v1/infra/domains/default/groups/Netspoc-g2
{
 "expression":[{
 "id":"id",
 "resource_type":"IPAddressExpression",
 "ip_addresses":["10.1.1.10","10.1.1.20"]
 }]
 }
PUT /policy/api/v1/infra/domains/default/gateway-policies/Netspoc-v1/rules/r2
{
 "action":"ALLOW",
 "sequence_number":20,
 "source_groups":["/infra/domains/default/groups/Netspoc-g2"],
 "destination_groups":["10.1.2.12"],
 "services":["/infra/services/Netspoc-tcp_80"],
 "scope":["/infra/tier-0s/v1"],
 "direction":"OUT"}
=END=


############################################################
=TITLE=Must prevent name clash with group on device
=DEVICE=
{
 "groups": [
[[group { id: g2, ip: '10.1.1.10","10.1.1.20' }]]
 ],
 "policies": [
  {
   "id": "Netspoc-v1",
   "resource_type": "GatewayPolicy",
   "rules": [
[[allow
id: r1
src: /infra/domains/default/groups/Netspoc-g2
dst: 10.1.2.10
srv: tcp_80
]]
   ]
  }
 ],
 "services": [ [[tcp 80]] ]
}
=NETSPOC=
{
 "groups": [
[[group { id: g1, ip: '10.1.1.10","10.1.1.20' }]],
[[group { id: g2, ip: '10.1.1.10","10.1.1.20","10.1.1.30' }]]
 ],
 "policies": [
  {
   "id": "Netspoc-v1",
   "resource_type": "GatewayPolicy",
   "rules": [
[[allow
id: r1
src: /infra/domains/default/groups/Netspoc-g1
dst: 10.1.2.10
srv: tcp_80
]],
[[allow
id: r2
src: /infra/domains/default/groups/Netspoc-g2
dst: 10.1.2.10
srv: tcp_90
]]
   ]
  }
 ],
 "services": [ [[tcp 80]],[[tcp 90]] ]
}
=OUTPUT=
PUT /policy/api/v1/infra/services/Netspoc-tcp_90
{"service_entries":[
 {"destination_ports":["90"],
  "display_name":"Netspoc tcp 90",
  "l4_protocol":"TCP",
  "resource_type":"L4PortSetServiceEntry",
  "source_ports":null
 }]}
PUT /policy/api/v1/infra/domains/default/groups/Netspoc-g2-1
{"expression":[
 {"id":"id",
  "resource_type":"IPAddressExpression",
  "ip_addresses":["10.1.1.10","10.1.1.20","10.1.1.30"]
 }]}
PUT /policy/api/v1/infra/domains/default/gateway-policies/Netspoc-v1/rules/r2
{"action":"ALLOW",
 "sequence_number":20,
 "source_groups":["/infra/domains/default/groups/Netspoc-g2-1"],
 "destination_groups":["10.1.2.10"],
 "services":["/infra/services/Netspoc-tcp_90"],
 "scope":["/infra/tier-0s/v1"],"direction":"OUT"}
=END=