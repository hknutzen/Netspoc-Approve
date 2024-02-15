=TEMPL=config
{{define "group" -}}
 {{if not . -}}
  ANY
 {{- else if or (eq 'g' (index . 0)) (eq 'v' (index . 0)) -}}
  /infra/domains/default/groups/Netspoc-{{.}}
 {{- else -}}
  {{.}}
 {{- end -}}
{{- end}}
{
 "groups": [
{{$first := true}}
{{range .groups}}
{{if $first}}{{$first = false}}{{else}},{{end}}
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
{{end}}
 ],
{{if .rules}}
 "policies": [
  {
   "id": "Netspoc-v1",
   "resource_type": "GatewayPolicy",
   "rules": [
{{$first := true}}
{{range .rules}}
{{if $first}}{{$first = false}}{{else}},{{end}}
{
 "resource_type": "Rule",
 "id": "{{.id}}",
 {{with .logged}}"logged": {{.}},{{end}}
 {{with .disabled}}"disabled": {{.}},{{end}}
 {{with .tag}}"tag": "{{.}}",{{end}}
 {{with .unknownattribute}}"unknownattribute": "{{.}}",{{end}}
 "scope": [ "/infra/tier-0s/v1" ],
 "direction": "{{or .dir "OUT"}}",
 "ip_protocol": "{{or .proto "IPV4"}}",
 "sequence_number": {{or .seq 20}},
 "action": "{{or .act "ALLOW"}}",
 "source_groups": [ "{{template "group" .src}}" ],
 "destination_groups": [ "{{template "group" .dst}}" ],
 "services": [ "{{with .srv}}/infra/services/Netspoc-{{.}}{{else}}ANY{{end}}" ]
}
{{end}}
   ]
  }
 ],
{{end}}
 "services": [
{{$first := true}}
{{range .services}}
{{if $first}}{{$first = false}}{{else}},{{end}}
{{if eq "string" (printf "%T" .)}}{{.}}{{continue}}{{end}}
{{$port := index . 1}}
{{$proto := index . 0}}
{{$PROTO := or (and (eq $proto "udp") "UDP") "TCP"}}
{
 "id": "Netspoc-{{$proto}}_{{$port}}",
 "service_entries": [
  {
   "id": "id",
   "resource_type": "L4PortSetServiceEntry",
   "l4_protocol": "{{$PROTO}}",
   "destination_ports": [ "{{$port}}" ],
   "source_ports": []
  }
 ]
}
{{end}}
 ]
}
=TEMPL=one_rule
[[config
rules:
- { id: r1, src: 10.1.1.10, dst: 10.1.2.30, srv: tcp_80 }
- { id: r3, act: DROP, seq: 30 }
- { id: r4, act: DROP, seq: 30, dir: IN }
services:
- [tcp, 80]
]]
=TEMPL=two_rules
[[config
rules:
- { id: r1, src: 10.1.1.10, dst: 10.1.2.30, srv: tcp_80 }
- { id: r2, src: 10.1.1.10, dst: 10.1.2.40, srv: udp_123 }
- { id: r3, act: DROP, seq: 30 }
- { id: r4, act: DROP, seq: 30, dir: IN }
services:
- [ tcp, 80 ]
- [ udp, 123 ]
]]
=TEMPL=group_rule
[[config
groups:
- { id: g0, ip: '10.1.1.10","10.1.1.20' }
- { id: g1, ip: '10.1.2.30","10.1.2.40' }
rules:
- { id: r1, src: g0, dst: g1, srv: tcp_80 }
- { id: r2, act: DROP, seq: 30 }
- { id: r3, act: DROP, seq: 30, dir: IN }
services:
- [tcp, 80]
]]
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
  "id":"id",
  "l4_protocol":"TCP",
  "resource_type":"L4PortSetServiceEntry",
  "source_ports":[]
 }]}
PUT /policy/api/v1/infra/services/Netspoc-udp_123
{"service_entries":[
 {
  "destination_ports":["123"],
  "id":"id",
  "l4_protocol":"UDP",
  "resource_type":"L4PortSetServiceEntry",
  "source_ports":[]
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
  "direction":"OUT",
  "ip_protocol":"IPV4"
 },{
  "id":"r2",
  "action":"ALLOW",
  "sequence_number":20,
  "source_groups":["10.1.1.10"],
  "destination_groups":["10.1.2.40"],
  "services":["/infra/services/Netspoc-udp_123"],
  "scope":["/infra/tier-0s/v1"],
  "direction":"OUT",
  "ip_protocol":"IPV4"
 },{
  "id":"r3",
  "action":"DROP",
  "sequence_number":30,
  "source_groups":["ANY"],
  "destination_groups":["ANY"],
  "services":["ANY"],
  "scope":["/infra/tier-0s/v1"],
  "direction":"OUT",
  "ip_protocol":"IPV4"
 },{
  "id":"r4",
  "action":"DROP",
  "sequence_number":30,
  "source_groups":["ANY"],
  "destination_groups":["ANY"],
  "services":["ANY"],
  "scope":["/infra/tier-0s/v1"],
  "direction":"IN",
  "ip_protocol":"IPV4"}]}
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
  "id":"id",
  "l4_protocol":"UDP",
  "resource_type":"L4PortSetServiceEntry",
  "source_ports":[]
 }]}
PUT /policy/api/v1/infra/domains/default/gateway-policies/Netspoc-v1/rules/r2
{
 "action":"ALLOW",
 "sequence_number":20,
 "source_groups":["10.1.1.10"],
 "destination_groups":["10.1.2.40"],
 "services":["/infra/services/Netspoc-udp_123"],
 "scope":["/infra/tier-0s/v1"],
 "direction":"OUT",
 "ip_protocol":"IPV4"}
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
  "id":"id",
  "l4_protocol":"UDP",
  "resource_type":"L4PortSetServiceEntry",
  "source_ports":[]
 }]}
PUT /policy/api/v1/infra/domains/default/gateway-policies/Netspoc-v1/rules/r2-1
{
 "action":"ALLOW",
 "sequence_number":20,
 "source_groups":["10.1.1.10"],
 "destination_groups":["10.1.2.40"],
 "services":["/infra/services/Netspoc-udp_123"],
 "scope":["/infra/tier-0s/v1"],
 "direction":"OUT",
 "ip_protocol":"IPV4"}
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
{"service_entries":[{
  "destination_ports":["80"],
  "id":"id",
  "l4_protocol":"TCP",
  "resource_type":"L4PortSetServiceEntry",
  "source_ports":[]}]}
PUT /policy/api/v1/infra/domains/default/groups/Netspoc-g0
{"expression":[{"id":"id",
 "resource_type":"IPAddressExpression",
 "ip_addresses":["10.1.1.10","10.1.1.20"]}]}
PUT /policy/api/v1/infra/domains/default/groups/Netspoc-g1
{"expression":[{"id":"id",
 "resource_type":"IPAddressExpression",
 "ip_addresses":["10.1.2.30","10.1.2.40"]}]}
PUT /policy/api/v1/infra/domains/default/gateway-policies/Netspoc-v1
{"id":"Netspoc-v1",
 "rules":[{
  "id":"r1",
  "action":"ALLOW",
  "sequence_number":20,
  "source_groups":["/infra/domains/default/groups/Netspoc-g0"],
  "destination_groups":["/infra/domains/default/groups/Netspoc-g1"],
  "services":["/infra/services/Netspoc-tcp_80"],
  "scope":["/infra/tier-0s/v1"],
  "direction":"OUT",
  "ip_protocol":"IPV4"
  },{
  "id":"r2",
  "action":"DROP",
  "sequence_number":30,
  "source_groups":["ANY"],
  "destination_groups":["ANY"],
  "services":["ANY"],
  "scope":["/infra/tier-0s/v1"],
  "direction":"OUT",
  "ip_protocol":"IPV4"
  },{
  "id":"r3",
  "action":"DROP",
  "sequence_number":30,
  "source_groups":["ANY"],
  "destination_groups":["ANY"],
  "services":["ANY"],
  "scope":["/infra/tier-0s/v1"],
  "direction":"IN",
  "ip_protocol":"IPV4"}]}
=END=

############################################################
=TITLE=Remove rule with groups from device
=DEVICE=
[[config
groups:
- { id: g0, ip: '10.1.1.10","10.1.1.20' }
- { id: g1, ip: '10.1.2.30","10.1.2.40' }
- { id: g2, ip: '10.1.3.30","10.1.3.40' }
- { id: g3, ip: '10.1.4.30","10.1.4.40' }
- { id: g4, ip: '10.1.5.30","10.1.5.40' }
rules:
- { id: r1, src: g0, dst: g1, srv: tcp_80}
services:
- [tcp, 80]
- [udp, 123]
]]
=NETSPOC=
{}
=OUTPUT=
DELETE /policy/api/v1/infra/domains/default/gateway-policies/Netspoc-v1

DELETE /policy/api/v1/infra/services/Netspoc-tcp_80

DELETE /policy/api/v1/infra/services/Netspoc-udp_123

DELETE /policy/api/v1/infra/domains/default/groups/Netspoc-g0

DELETE /policy/api/v1/infra/domains/default/groups/Netspoc-g1

DELETE /policy/api/v1/infra/domains/default/groups/Netspoc-g2

DELETE /policy/api/v1/infra/domains/default/groups/Netspoc-g3

DELETE /policy/api/v1/infra/domains/default/groups/Netspoc-g4

=END=


############################################################
=TITLE=Reuse existing service and group when creating new policy
=DEVICE=
[[config
groups:
- { id: g8, ip: '10.1.1.10","10.1.1.20' }
- { id: g9, ip: '10.1.2.30","10.1.2.40' }
services:
- [tcp, 80]
]]
=NETSPOC=
[[config
groups:
- { id: g0, ip: '10.1.1.10","10.1.1.20' }
- { id: g1, ip: '10.1.2.30","10.1.2.40' }
rules:
- { id: r1, src: g0, dst: g1, srv: tcp_80 }
services:
- [tcp, 80]
]]
=OUTPUT=
PUT /policy/api/v1/infra/domains/default/gateway-policies/Netspoc-v1
{"id":"Netspoc-v1",
 "rules":[{
  "id":"r1",
  "action":"ALLOW",
  "sequence_number":20,
  "source_groups":["/infra/domains/default/groups/Netspoc-g8"],
  "destination_groups":["/infra/domains/default/groups/Netspoc-g9"],
  "services":["/infra/services/Netspoc-tcp_80"],
  "scope":["/infra/tier-0s/v1"],
  "direction":"OUT",
  "ip_protocol":"IPV4"}]}
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
=NETSPOC=[[group_rule]]
=SUBST=|/Netspoc-tcp_80"|/Netspoc-udp_123"|
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
 "direction":"OUT",
 "ip_protocol":"IPV4"
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
[[config
groups:
- { id: g0, ip: '10.1.1.10","10.1.1.20' }
rules:
- { id: r1, src: g0, dst: 10.2.1.10, srv: tcp_80 }
- { id: r2, src: g0, dst: 10.2.1.20, srv: tcp_80 }
services:
- [tcp, 80]
]]
=NETSPOC=
[[config
groups:
- { id: g0, ip: '10.1.1.10","10.1.1.20","10.1.1.30' }
- { id: g1, ip: '10.1.1.10","10.1.1.20","10.1.1.40' }
rules:
- { id: r1, src: g0, dst: 10.2.1.10, srv: tcp_80 }
- { id: r2, src: g1, dst: 10.2.1.20, srv: tcp_80 }
services:
- [tcp, 80]
]]
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
PATCH /policy/api/v1/infra/domains/default/gateway-policies/Netspoc-v1/rules/r2
{"action":"ALLOW",
 "sequence_number":20,
 "source_groups":["/infra/domains/default/groups/Netspoc-g1"],
 "destination_groups":["10.2.1.20"],
 "services":["/infra/services/Netspoc-tcp_80"],
 "scope":["/infra/tier-0s/v1"],
 "direction":"OUT",
 "ip_protocol":"IPV4"}
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
 "services":["/infra/services/Netspoc-tcp_80"],
 "scope":["/infra/tier-0s/v1"],
 "direction":"OUT",
 "ip_protocol":"IPV4"}
DELETE /policy/api/v1/infra/domains/default/groups/Netspoc-g1

=END=

############################################################
=TITLE=Find right group on device
=DEVICE=
[[config
groups:
- { id: g0, ip: 10.1.1.10 }
- { id: g1, ip: 10.1.1.20 }
rules:
- { id: r1, src: g0, dst: 10.1.2.0/24 }
- { id: r2, src: g1, dst: 10.1.3.0/24, srv: udp_123 }
services:
- [tcp, 80]
- [udp, 123]
]]
=NETSPOC=
[[config
groups:
- { id: g0, ip: 10.1.1.20 }
- { id: g1, ip: 10.1.1.10 }
rules:
- { id: r1, src: g1, dst: 10.1.2.0/24, srv: tcp_80 }
- { id: r2, src: g0, dst: 10.1.3.0/24 }
services:
- [tcp, 80]
]]
=OUTPUT=
DELETE /policy/api/v1/infra/domains/default/gateway-policies/Netspoc-v1/rules/r2

DELETE /policy/api/v1/infra/domains/default/gateway-policies/Netspoc-v1/rules/r1

PUT /policy/api/v1/infra/domains/default/gateway-policies/Netspoc-v1/rules/r1-1
{"action":"ALLOW","sequence_number":20,"source_groups":["/infra/domains/default/groups/Netspoc-g0"],"destination_groups":["10.1.2.0/24"],"services":["/infra/services/Netspoc-tcp_80"],"scope":["/infra/tier-0s/v1"],"direction":"OUT","ip_protocol":"IPV4"}
PUT /policy/api/v1/infra/domains/default/gateway-policies/Netspoc-v1/rules/r2-1
{"action":"ALLOW","sequence_number":20,"source_groups":["/infra/domains/default/groups/Netspoc-g1"],"destination_groups":["10.1.3.0/24"],"services":["ANY"],"scope":["/infra/tier-0s/v1"],"direction":"OUT","ip_protocol":"IPV4"}
DELETE /policy/api/v1/infra/services/Netspoc-udp_123

=END=

############################################################
=TITLE=Must not find already used group on device
=DEVICE=
[[config
groups:
- { id: g0, ip: '10.1.1.10","10.1.1.20' }
rules:
- { id: r1, src: g0, dst: 10.1.2.10, srv: tcp_80 }
services:
- [tcp, 80]
]]
=NETSPOC=
[[config
groups:
- { id: g1, ip: '10.1.1.10","10.1.1.20","10.1.1.30' }
- { id: g2, ip: '10.1.1.10","10.1.1.20' }
rules:
- { id: r1, src: g1, dst: 10.1.2.10, srv: tcp_80 }
- { id: r2, src: g2, dst: 10.1.2.12, srv: tcp_80 }
services:
- [tcp, 80]
]]
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
 "direction":"OUT",
 "ip_protocol":"IPV4"}
=END=

############################################################
=TITLE=Add new elements to group in one go
=DEVICE=
[[config
groups:
- { id: g1, ip: 10.1.1.20 }
rules:
- { id: r1, src: g1, dst: 10.1.2.0/24, srv: tcp_80 }
services:
- [tcp, 80]
]]
=NETSPOC=
[[config
groups:
- { id: g1, ip: '10.1.1.10","10.1.1.20","10.1.3.0/24' }
rules:
- { id: r1, src: g1, dst: 10.1.2.0/24, srv: tcp_80 }
services:
- [tcp, 80]
]]
=OUTPUT=
POST /policy/api/v1/infra/domains/default/groups/Netspoc-g1/ip-address-expressions/id?action=add
{"ip_addresses":["10.1.1.10","10.1.3.0/24"]}
=END=

############################################################
=TITLE=Patch elements of group instead of deleting many elements
=DEVICE=
[[config
groups:
- { id: g1, ip: '10.1.1.1","10.1.1.2","10.1.1.3","10.1.1.4","10.1.1.5' }
rules:
- { id: r1, src: 10.1.2.0/24, dst: g1, srv: tcp_80 }
services:
- [tcp, 80]
]]
=NETSPOC=
[[config
groups:
- { id: g1, ip: '10.1.1.1","10.1.1.2' }
rules:
- { id: r1, src: 10.1.2.0/24, dst: g1, srv: tcp_80 }
services:
- [tcp, 80]
]]
=OUTPUT=
PATCH /policy/api/v1/infra/domains/default/groups/Netspoc-g1/ip-address-expressions/id
{
 "resource_type":"IPAddressExpression",
 "ip_addresses":["10.1.1.1","10.1.1.2"]}
=END=

############################################################
=TITLE=Must prevent name clash with group on device
=DEVICE=
[[config
groups:
- { id: g2, ip: '10.1.1.10","10.1.1.20' }
rules:
- { id: r1, src: g2, dst: 10.1.2.10, srv: tcp_80 }
services:
- [tcp, 80]
]]
=NETSPOC=
[[config
groups:
- { id: g1, ip: '10.1.1.10","10.1.1.20' }
- { id: g2, ip: '10.1.1.10","10.1.1.20","10.1.1.30' }
rules:
- { id: r1, src: g1, dst: 10.1.2.10, srv: tcp_80 }
- { id: r2, src: g2, dst: 10.1.2.10, srv: tcp_90 }
services:
- [tcp, 80]
- [tcp, 90]
]]
=OUTPUT=
PUT /policy/api/v1/infra/services/Netspoc-tcp_90
{"service_entries":[
 {"destination_ports":["90"],
  "id":"id",
  "l4_protocol":"TCP",
  "resource_type":"L4PortSetServiceEntry",
  "source_ports":[]
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
 "scope":["/infra/tier-0s/v1"],
 "direction":"OUT",
 "ip_protocol":"IPV4"}
=END=

############################################################
=TITLE=Prevent name clash of rule from raw
=NETSPOC=
-- router.raw
[[config
rules:
- { id: r3-2-1}
]]
=ERROR=
ERROR>>> Must not use rule name starting with 'r<NUM>' in raw: r3-2-1
=END=

############################################################
=TITLE=Merge rule of raw policy into rule of netspoc policy
=DEVICE=
[[one_rule]]
=NETSPOC=
-- router
[[one_rule]]
-- router.raw
[[config
rules:
- { id: raw2, act: DROP, seq: 25, logged: true, tag: "testtag", disabled: true }
services:
- [tcp, 80]
]]
=OUTPUT=
PUT /policy/api/v1/infra/domains/default/gateway-policies/Netspoc-v1/rules/raw2
{"action":"DROP",
 "sequence_number":25,
 "source_groups":["ANY"],
 "destination_groups":["ANY"],
 "services":["ANY"],
 "scope":["/infra/tier-0s/v1"],
 "disabled":true,
 "logged":true,
 "tag":"testtag",
 "direction":"OUT",
 "ip_protocol":"IPV4"}
=END=

############################################################
=TITLE=Ignore unknown attribute
=DEVICE=
[[one_rule]]
=NETSPOC=
-- router
[[one_rule]]
-- router.raw
[[config
rules:
- { id: raw, unknownattribute: "testattribute"}
services:
- [tcp, 80]
]]
=OUTPUT=
PUT /policy/api/v1/infra/domains/default/gateway-policies/Netspoc-v1/rules/raw
{"action":"ALLOW",
 "sequence_number":20,
 "source_groups":["ANY"],
 "destination_groups":["ANY"],
 "services":["ANY"],
 "scope":["/infra/tier-0s/v1"],
 "direction":"OUT",
 "ip_protocol":"IPV4"}
=END=

############################################################
=TITLE=Invalid service length from netspoc
=NETSPOC=
[[one_rule]]
=SUBST=|/Netspoc-tcp_80"|/Netspoc-tcp_80","/infra/services/Netspoc-udp_123"|
=ERROR=
ERROR>>> While reading router: Expecting exactly one element in source/destination/service of rule r1
=END=

############################################################
=TITLE=Invalid sourcegroup length from device
=DEVICE=
[[one_rule]]
=SUBST=|10.1.1.10"|10.1.1.10","10.1.1.11"|
=NETSPOC=
[[one_rule]]
=ERROR=
ERROR>>> While reading device: Expecting exactly one element in source/destination/service of rule r1
=END=

############################################################
=TITLE=Invalid JSON from netspoc
=NETSPOC=
{invalid
=ERROR=
ERROR>>> While reading router: invalid character 'i' looking for beginning of object key string
=END=

############################################################
=TITLE=Invalid JSON from device
=DEVICE=
#Good

#Bad
=NETSPOC=
[[one_rule]]
=ERROR=
ERROR>>> While reading device: invalid character '#' looking for beginning of value
=END=

############################################################
=TITLE=Remove comment header from file
=DEVICE=
#Some comment
# More
# lines follow
[[one_rule]]
=NETSPOC=
[[one_rule]]
=OUTPUT=NONE

############################################################
=TITLE=File with only comment header
=DEVICE=# Some comment
=NETSPOC={}
=ERROR=
ERROR>>> While reading device: unexpected end of JSON input
=END=

############################################################
=TITLE=Patch existing Service
# Remove source_ports from service
=DEVICE=
[[one_rule]]
=SUBST=/[]/null/
=NETSPOC=
[[one_rule]]
=OUTPUT=
PATCH /policy/api/v1/infra/services/Netspoc-tcp_80
{"service_entries":[{"destination_ports":["80"],"id":"id","l4_protocol":"TCP","resource_type":"L4PortSetServiceEntry","source_ports":[]}]}
=END=

############################################################
=TITLE=Equal ICMP type and code
=DEVICE=
[[config
services:
- '{
 "id": "Netspoc-icmp_8",
 "service_entries": [
  {
   "id": "id",
   "resource_type": "ICMPTypeServiceEntry",
   "protocol": "ICMPv4",
   "icmp_type": 8,
   "icmp_code": 0
  }
 ]
}'
]]
=NETSPOC=
[[config
services:
- '{
 "id": "Netspoc-icmp_8",
 "service_entries": [
  {
   "id": "id",
   "resource_type": "ICMPTypeServiceEntry",
   "protocol": "ICMPv4",
   "icmp_type": 8,
   "icmp_code": 0
  }
 ]
}'
]]
=OUTPUT=NONE

############################################################
=TITLE=Change ICMP code
=DEVICE=
[[config
services:
- '{
 "id": "Netspoc-icmp_8",
 "service_entries": [
  {
   "id": "id",
   "resource_type": "ICMPTypeServiceEntry",
   "protocol": "ICMPv4",
   "icmp_type": 8
  }
 ]
}'
]]
=NETSPOC=
[[config
services:
- '{
 "id": "Netspoc-icmp_8",
 "service_entries": [
  {
   "id": "id",
   "resource_type": "ICMPTypeServiceEntry",
   "protocol": "ICMPv4",
   "icmp_type": 8,
   "icmp_code": 0
  }
 ]
}'
]]
=OUTPUT=
PATCH /policy/api/v1/infra/services/Netspoc-icmp_8
{"service_entries":[{
 "icmp_code":0,
 "icmp_type":8,
 "id":"id",
 "protocol":"ICMPv4",
 "resource_type":"ICMPTypeServiceEntry"}]}
=END=

############################################################
=TITLE=Change ICMP protocol version
=DEVICE=
[[config
services:
- '{
 "id": "Netspoc-icmp_8",
 "service_entries": [
  {
   "id": "id",
   "resource_type": "ICMPTypeServiceEntry",
   "protocol": "ICMPv6",
   "icmp_type": 8
  }
 ]
}'
]]
=NETSPOC=
[[config
services:
- '{
 "id": "Netspoc-icmp_8",
 "service_entries": [
  {
   "id": "id",
   "resource_type": "ICMPTypeServiceEntry",
   "protocol": "ICMPv4",
   "icmp_type": 8
  }
 ]
}'
]]
=OUTPUT=
PATCH /policy/api/v1/infra/services/Netspoc-icmp_8
{"service_entries":[{
 "icmp_type":8,
 "id":"id",
 "protocol":"ICMPv4",
 "resource_type":"ICMPTypeServiceEntry"}]}
=END=

############################################################
=TITLE=Change IP protocol
=DEVICE=
[[config
services:
- '{
 "id": "Netspoc-proto_52",
 "service_entries": [
  {
   "id": "id",
   "resource_type": "IPProtocolServiceEntry",
   "protocol_number": 54
  }
 ]
}'
]]
=NETSPOC=
[[config
services:
- '{
 "id": "Netspoc-proto_52",
 "service_entries": [
  {
   "id": "id",
   "resource_type": "IPProtocolServiceEntry",
   "protocol_number": 52
  }
 ]
}'
]]
=OUTPUT=
PATCH /policy/api/v1/infra/services/Netspoc-proto_52
{"service_entries":[{
 "id":"id",
 "protocol_number":52,
 "resource_type":"IPProtocolServiceEntry"}]}
=END=

############################################################
=TITLE=Two identical groups on device
=DEVICE=
[[config
groups:
- { id: g0, ip: '10.1.1.10","10.1.1.20' }
- { id: g1, ip: '10.1.2.30","10.1.2.40' }
- { id: g2, ip: '10.1.2.30","10.1.2.40' }
rules:
- { id: r1, src: g0, dst: g1, srv: tcp_80 }
- { id: r4, src: g0, dst: g2, srv: udp_123 }
services:
- [tcp, 80]
- [udp, 123]
]]
=NETSPOC=
[[config
groups:
- { id: g0, ip: '10.1.1.10","10.1.1.20' }
- { id: g1, ip: '10.1.2.30","10.1.2.40' }
rules:
- { id: r1, src: g0, dst: g1, srv: tcp_80 }
- { id: r4, src: g0, dst: g1, srv: udp_123 }
services:
- [tcp, 80]
- [udp, 123]
]]
=OUTPUT=
PATCH /policy/api/v1/infra/domains/default/gateway-policies/Netspoc-v1/rules/r4
{"action":"ALLOW",
 "sequence_number":20,
 "source_groups":["/infra/domains/default/groups/Netspoc-g0"],
 "destination_groups":["/infra/domains/default/groups/Netspoc-g1"],
 "services":["/infra/services/Netspoc-udp_123"],
 "scope":["/infra/tier-0s/v1"],
 "direction":"OUT",
 "ip_protocol":"IPV4"}
DELETE /policy/api/v1/infra/domains/default/groups/Netspoc-g2

=END=

############################################################
=TITLE=Two groups different length
=DEVICE=
[[config
groups:
- { id: g0, ip: '10.1.1.10","10.1.1.20","10.1.1.30' }
services:
- [tcp, 80]
rules:
- { id: r1, src: g0, dst: 10.1.1.1, srv: tcp_80 }
]]
=NETSPOC=
[[config
groups:
- { id: g8, ip: '10.1.1.10","10.1.1.20' }
services:
- [tcp, 81]
rules:
- { id: r1, src: g8, dst: 10.1.1.1, srv: tcp_81 }
]]
=OUTPUT=
PUT /policy/api/v1/infra/services/Netspoc-tcp_81
{"service_entries":[{"
 destination_ports":["81"],
 "id":"id",
 "l4_protocol":"TCP",
 "resource_type":"L4PortSetServiceEntry",
 "source_ports":[]}]}
DELETE /policy/api/v1/infra/domains/default/gateway-policies/Netspoc-v1/rules/r1

PUT /policy/api/v1/infra/domains/default/groups/Netspoc-g8
{"expression":[{"id":"id","resource_type":"IPAddressExpression","ip_addresses":["10.1.1.10","10.1.1.20"]}]}
PUT /policy/api/v1/infra/domains/default/gateway-policies/Netspoc-v1/rules/r1-1
{"action":"ALLOW",
 "sequence_number":20,
 "source_groups":["/infra/domains/default/groups/Netspoc-g8"],
 "destination_groups":["10.1.1.1"],
 "services":["/infra/services/Netspoc-tcp_81"],
 "scope":["/infra/tier-0s/v1"],
 "direction":"OUT",
 "ip_protocol":"IPV4"}
DELETE /policy/api/v1/infra/services/Netspoc-tcp_80

DELETE /policy/api/v1/infra/domains/default/groups/Netspoc-g0

=END=

############################################################
=TITLE=Two groups different element
=DEVICE=
[[config
groups:
- { id: g0, ip: '10.1.1.10","10.1.1.21' }
services:
- [tcp, 80]
rules:
- { id: r1, src: g0, dst: 10.1.1.1, srv: tcp_80 }
]]
=NETSPOC=
[[config
groups:
- { id: g8, ip: '10.1.1.10","10.1.1.20' }
services:
- [tcp, 81]
rules:
- { id: r1, src: g8, dst: 10.1.1.1, srv: tcp_81 }
]]
=OUTPUT=
PUT /policy/api/v1/infra/services/Netspoc-tcp_81
{"service_entries":[{
 "destination_ports":["81"],
 "id":"id",
 "l4_protocol":"TCP",
 "resource_type":"L4PortSetServiceEntry",
 "source_ports":[]}]}
DELETE /policy/api/v1/infra/domains/default/gateway-policies/Netspoc-v1/rules/r1

PUT /policy/api/v1/infra/domains/default/groups/Netspoc-g8
{"expression":[{
 "id":"id",
 "resource_type":"IPAddressExpression",
 "ip_addresses":["10.1.1.10","10.1.1.20"]}]}
PUT /policy/api/v1/infra/domains/default/gateway-policies/Netspoc-v1/rules/r1-1
{"action":"ALLOW",
 "sequence_number":20,
 "source_groups":["/infra/domains/default/groups/Netspoc-g8"],
 "destination_groups":["10.1.1.1"],
 "services":["/infra/services/Netspoc-tcp_81"],
 "scope":["/infra/tier-0s/v1"],
 "direction":"OUT",
 "ip_protocol":"IPV4"}
DELETE /policy/api/v1/infra/services/Netspoc-tcp_80

DELETE /policy/api/v1/infra/domains/default/groups/Netspoc-g0

=END=

############################################################
=TITLE=Use same group in two different rules
=DEVICE=
[[config
groups:
- { id: g0, ip: '10.1.1.10","10.1.1.20' }
- { id: g1, ip: '10.1.2.30","10.1.2.40' }
rules:
- { id: r1, src: g0, dst: g1, srv: tcp_80 }
services:
- [tcp, 80]
]]
=NETSPOC=
[[config
groups:
- { id: g0, ip: '10.1.1.10","10.1.1.20' }
- { id: g1, ip: '10.1.2.30","10.1.2.40' }
rules:
- { id: r0, src: g0, dst: g1, srv: tcp_81 }
- { id: r1, src: g0, dst: g1, srv: tcp_80 }
services:
- [tcp, 80]
- [tcp, 81]
]]
=OUTPUT=
PUT /policy/api/v1/infra/services/Netspoc-tcp_81
{
 "service_entries":[{
  "destination_ports":["81"],
  "id":"id",
  "l4_protocol":"TCP",
  "resource_type":"L4PortSetServiceEntry",
  "source_ports":[]}]}
PUT /policy/api/v1/infra/domains/default/gateway-policies/Netspoc-v1/rules/r0
{
 "action":"ALLOW",
 "sequence_number":20,
 "source_groups":["/infra/domains/default/groups/Netspoc-g0"],
 "destination_groups":["/infra/domains/default/groups/Netspoc-g1"],
 "services":["/infra/services/Netspoc-tcp_81"],
 "scope":["/infra/tier-0s/v1"],
 "direction":"OUT",
 "ip_protocol":"IPV4"}
=END=

############################################################
=TITLE=Rule with different action but same sequence_number
=DEVICE=
[[config
rules:
- { id: r1, src: 10.1.1.10, dst: 10.1.2.30, srv: tcp_80 }
- { id: r3, act: DROP, seq: 30 }
services:
- [tcp, 80]
]]
=NETSPOC=
[[config
rules:
- { id: r1, src: 10.1.1.10, dst: 10.1.2.30, srv: tcp_80 }
- { id: r2, act: DROP }
- { id: r3, act: DROP, seq: 30 }
services:
- [tcp, 80]
]]
=OUTPUT=
PUT /policy/api/v1/infra/domains/default/gateway-policies/Netspoc-v1/rules/r2
{"action":"DROP",
 "sequence_number":20,
 "source_groups":["ANY"],
 "destination_groups":["ANY"],
 "services":["ANY"],
 "scope":["/infra/tier-0s/v1"],
 "direction":"OUT",
 "ip_protocol":"IPV4"}
=END=

############################################################
=TITLE=Merge IPv4 and IPv6
=DEVICE=
{}
=NETSPOC=
-- router
[[config
groups:
- { id: g0, ip: '10.1.1.20","10.1.1.10' }
services:
- [ tcp, 80 ]
rules:
- { id: r1, src: g0, dst: 10.1.2.0/24, srv: tcp_80 }
]]
-- ipv6/router
[[config
groups:
- { id: v6g0, ip: '::a01:10a","::a01:114' }
services:
- [ tcp, 80 ]
rules:
- { id: v6r1, src: v6g0, dst: '::a01:200_120', srv: tcp_80, proto: IPV6 }
]]
=OUTPUT=
PUT /policy/api/v1/infra/services/Netspoc-tcp_80
{"service_entries":[{
 "destination_ports":["80"],
 "id":"id",
 "l4_protocol":"TCP",
 "resource_type":"L4PortSetServiceEntry",
 "source_ports":[]}]}
PUT /policy/api/v1/infra/domains/default/groups/Netspoc-g0
{"expression":[{
 "id":"id",
 "resource_type":"IPAddressExpression",
 "ip_addresses":["10.1.1.10","10.1.1.20"]}]}
PUT /policy/api/v1/infra/domains/default/groups/Netspoc-v6g0
{"expression":[{
 "id":"id",
 "resource_type":"IPAddressExpression",
 "ip_addresses":["::a01:10a","::a01:114"]}]}
PUT /policy/api/v1/infra/domains/default/gateway-policies/Netspoc-v1
{"id":"Netspoc-v1",
 "rules":[{
  "id":"r1",
  "action":"ALLOW",
  "sequence_number":20,
  "source_groups":["/infra/domains/default/groups/Netspoc-g0"],
  "destination_groups":["10.1.2.0/24"],
  "services":["/infra/services/Netspoc-tcp_80"],
  "scope":["/infra/tier-0s/v1"],
  "direction":"OUT",
  "ip_protocol":"IPV4"
  },{
  "id":"v6r1",
  "action":"ALLOW",
  "sequence_number":20,
  "source_groups":["/infra/domains/default/groups/Netspoc-v6g0"],
  "destination_groups":["::a01:200_120"],
  "services":["/infra/services/Netspoc-tcp_80"],
  "scope":["/infra/tier-0s/v1"],
  "direction":"OUT",
  "ip_protocol":"IPV6"}]}
=END=

############################################################
=TITLE=Empty IPv4 with IPv6
=DEVICE=
{}
=NETSPOC=
-- ipv6/router
[[config
groups:
- { id: v6g0, ip: '::a01:10a","::a01:114' }
services:
- [ tcp, 80 ]
rules:
- { id: v6r1, src: v6g0, dst: '::a01:200_120', srv: tcp_80, proto: IPV6 }
]]
=OUTPUT=
PUT /policy/api/v1/infra/services/Netspoc-tcp_80
{"service_entries":[{
 "destination_ports":["80"],
 "id":"id",
 "l4_protocol":"TCP",
 "resource_type":"L4PortSetServiceEntry",
 "source_ports":[]}]}
PUT /policy/api/v1/infra/domains/default/groups/Netspoc-v6g0
{"expression":[{
 "id":"id",
 "resource_type":"IPAddressExpression",
 "ip_addresses":["::a01:10a","::a01:114"]}]}
PUT /policy/api/v1/infra/domains/default/gateway-policies/Netspoc-v1
{"id":"Netspoc-v1",
 "rules":[{
  "id":"v6r1",
  "action":"ALLOW",
  "sequence_number":20,
  "source_groups":["/infra/domains/default/groups/Netspoc-v6g0"],
  "destination_groups":["::a01:200_120"],
  "services":["/infra/services/Netspoc-tcp_80"],
  "scope":["/infra/tier-0s/v1"],
  "direction":"OUT",
  "ip_protocol":"IPV6"}]}
=END=

############################################################
=TITLE=Add ICMP Service
=DEVICE=
{}
=NETSPOC=
{
 "services": [
  {
   "id": "Netspoc-icmp",
   "service_entries": [
    {
     "id": "id",
     "protocol": "ICMPv4",
     "resource_type": "ICMPTypeServiceEntry"
    }
   ]
  }
  ]
}
=OUTPUT=
PUT /policy/api/v1/infra/services/Netspoc-icmp
{"service_entries":[{"id":"id","protocol":"ICMPv4","resource_type":"ICMPTypeServiceEntry"}]}
=END=