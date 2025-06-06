=TEMPL=session
POST /api/session/create
H: x-xsrf-token: secret
=END=

############################################################
=TITLE=Device gives status 500
=SCENARIO=
POST /api
500
device not ready
=NETSPOC=NONE
=ERROR=
WARNING>>> status code: 500
ERROR>>> Devices unreachable: router
=OUTPUT=
--router.login
POST TESTSERVER/api/session/create
j_password=xxx&j_username=admin
500 Internal Server Error
=END=

############################################################
=TITLE=Device gives no valid answer
=SCENARIO=
POST /api
EOF
=NETSPOC=NONE
=ERROR=
WARNING>>> Post "TESTSERVER/api/session/create": EOF
ERROR>>> Devices unreachable: router
=OUTPUT=
--router.login
POST TESTSERVER/api/session/create
j_password=xxx&j_username=admin
=END=

############################################################
=TITLE=Only login succeeds
=SCENARIO=
[[session]]
=NETSPOC=NONE
=ERROR=
ERROR>>> status code: 404, method: GET, uri: /policy/api/v1/infra/domains/default/gateway-policies
ERROR>>> 404 page not found
=OUTPUT=
--router.login
POST TESTSERVER/api/session/create
j_password=xxx&j_username=admin
200 OK
=END=

############################################################
=TITLE=Invalid JSON response for gateway-policies
=SCENARIO=
[[session]]
GET /policy/api/v1/infra/domains/default/gateway-policies
invalid
=NETSPOC=NONE
=ERROR=
ERROR>>> while parsing /policy/api/v1/infra/domains/default/gateway-policies: invalid character 'i' looking for beginning of value
=END=

############################################################
=TITLE=Error reading single policy from device
=SCENARIO=
[[session]]
GET /policy/api/v1/infra/domains/default/gateway-policies/
EOF
GET /policy/api/v1/infra/domains/default/gateway-policies
{
 "result_count": 1,
 "results": [{"resource_type":"GatewayPolicy", "id":"Netspoc-v1"}]
}
GET /policy/api/v1/infra/services
{}
GET /policy/api/v1/infra/domains/default/groups
{}
=NETSPOC=NONE
=ERROR=
ERROR>>> Get "TESTSERVER/policy/api/v1/infra/domains/default/gateway-policies/Netspoc-v1": EOF
=END=

############################################################
=TITLE=Invalid JSON reading single policy from device
=SCENARIO=
[[session]]
GET /policy/api/v1/infra/domains/default/gateway-policies/
INVALID
GET /policy/api/v1/infra/domains/default/gateway-policies
{
 "result_count": 1,
 "results": [{"resource_type":"GatewayPolicy", "id":"Netspoc-v1"}]
}
GET /policy/api/v1/infra/services
{}
GET /policy/api/v1/infra/domains/default/groups
{}
=NETSPOC=NONE
=ERROR=
ERROR>>> While parsing JSON from device: json: error calling MarshalJSON for type json.RawMessage: invalid character 'I' looking for beginning of value
=END=

############################################################
=TITLE=Missing response for services
=SCENARIO=
[[session]]
GET /policy/api/v1/infra/domains/default/gateway-policies
{}
GET /policy/api/v1/infra/services
EOF
=NETSPOC=NONE
=ERROR=
ERROR>>> Get "TESTSERVER/policy/api/v1/infra/services?cursor=": EOF
=END=

############################################################
=TITLE=Invalid JSON response for services
=SCENARIO=
[[session]]
GET /policy/api/v1/infra/domains/default/gateway-policies
{}
GET /policy/api/v1/infra/services
=NETSPOC=NONE
=ERROR=
ERROR>>> while parsing /policy/api/v1/infra/services: unexpected end of JSON input
=END=

############################################################
=TITLE=Invalid JSON response for groups
=SCENARIO=
[[session]]
GET /policy/api/v1/infra/domains/default/gateway-policies
{}
GET /policy/api/v1/infra/services
{}
GET /policy/api/v1/infra/domains/default/groups
{
 "result_count": 1,
 "results": ["invalid"]
}
=NETSPOC=NONE
=ERROR=
ERROR>>> json: cannot unmarshal string into Go value of type struct { Id string }
=END=

############################################################
=TITLE=Unexpected group with multiple expressions
=SCENARIO=
[[session]]
GET /policy/api/v1/infra/domains/default/gateway-policies
{}
GET /policy/api/v1/infra/services
{}
GET /policy/api/v1/infra/domains/default/groups
{
 "result_count": 1,
 "results": [
  {
   "id": "Netspoc-g1",
   "expression": [
    {
     "id": "id1",
     "resource_type": "IPAddressExpression",
     "ip_addresses": ["10.1.1.1", "10.1.1.9"]
    },
    {
     "id": "id2",
     "resource_type": "IPAddressExpression",
     "ip_addresses": ["10.1.1.2", "10.1.1.8"]
    }
   ]
  }
 ]
}
=NETSPOC=NONE
=ERROR=
ERROR>>> While reading device: Expecting exactly one expression in group Netspoc-g1
=END=

############################################################
=TITLE=Empty policies, services and groups
=SCENARIO=
[[session]]
GET /policy/api/v1/infra/domains/default/gateway-policies
{}
GET /policy/api/v1/infra/services
{}
GET /policy/api/v1/infra/domains/default/groups
{}
=NETSPOC=NONE
=WARNING=NONE

############################################################
=TITLE=Leave non Netspoc policies unchanged
=SCENARIO=
[[session]]
GET /policy/api/v1/infra/domains/default/gateway-policies
{
 "result_count": 1,
 "results": [ { "resource_type": "GatewayPolicy", "id": "MAGIC" } ]
}
GET /policy/api/v1/infra/services
{}
GET /policy/api/v1/infra/domains/default/groups
{}
=NETSPOC=NONE
=WARNING=NONE

############################################################
=TITLE=Remove policy from device
=SCENARIO=
[[session]]
GET /policy/api/v1/infra/domains/default/gateway-policies/Netspoc-v1
{
 "resource_type": "GatewayPolicy",
 "id": "Netspoc-v1",
 "rules": [
  {"action":"DROP",
   "id":"r1",
   "source_groups":["ANY"],
   "destination_groups":["ANY"],
   "services":["ANY"],
   "scope":["/infra/tier-0s/v1"],
   "direction":"OUT",
   "ip_protocol":"IPV4"
  }]
}
DELETE /policy/api/v1/infra/domains/default/gateway-policies/Netspoc-v1
GET /policy/api/v1/infra/domains/default/gateway-policies
{
 "result_count": 1,
 "results": [{"resource_type":"GatewayPolicy", "id":"Netspoc-v1"}]
}
GET /policy/api/v1/infra/services
{}
GET /policy/api/v1/infra/domains/default/groups
{}
=NETSPOC=NONE
=OUTPUT=
--router.change
URI: DELETE /policy/api/v1/infra/domains/default/gateway-policies/Netspoc-v1
=END=

############################################################
=TITLE=Add ICMP service to empty device
=SCENARIO=
[[session]]
GET /policy/api/v1/infra/domains/default/gateway-policies
{}
GET /policy/api/v1/infra/services
{}
GET /policy/api/v1/infra/domains/default/groups
{}
PUT /policy/api/v1/infra/services/
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
--router.change
URI: PUT /policy/api/v1/infra/services/Netspoc-icmp
DATA: {"service_entries":[{"id":"id","protocol":"ICMPv4","resource_type":"ICMPTypeServiceEntry"}]}
RESP: {}

=END=

############################################################
=TITLE=Adding service fails
=SCENARIO=
[[session]]
GET /policy/api/v1/infra/domains/default/gateway-policies
{}
GET /policy/api/v1/infra/services
{}
GET /policy/api/v1/infra/domains/default/groups
{}
PUT /policy/api/v1/infra/services/
EOF
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
=ERROR=
ERROR>>> Put "TESTSERVER/policy/api/v1/infra/services/Netspoc-icmp": EOF
=END=

############################################################
=TITLE=Missing device name in info file
=SCENARIO=
[[session]]
=NETSPOC=
--router
{}
--router.info
{"model": "NSX", "ip_list": ["1.2.3.4"] }
=ERROR=
ERROR>>> Missing device name in [code/router.info]
=END=

############################################################
=TITLE=Empty device names
=SCENARIO=
[[session]]
=NETSPOC=
--router
{}
--router.info
{"model": "NSX", "name_list": [], "ip_list": [] }
=ERROR=
ERROR>>> Missing device name in [code/router.info]
=END=

############################################################
=TITLE=Missing IP address in info file
=SCENARIO=
[[session]]
=NETSPOC=
--router
{}
--router.info
{"model": "NSX", "name_list": ["router"] }
=ERROR=
ERROR>>> Missing IP address in [code/router.info]
=END=

############################################################
=TITLE=Non matching names and IP addresses
=SCENARIO=
[[session]]
=NETSPOC=
--router
{}
--router.info
{"model": "NSX", "name_list": ["router"], "ip_list": ["1.2.3.4", "5.6.7.8"] }
=ERROR=
ERROR>>> Number of device names and IP addresses don't match in [code/router.info]
=END=

############################################################
=TITLE=Error reading password
=SCENARIO=
[[session]]
=NETSPOC=
{}
=SETUP=
rm credentials
=ERROR=
ERROR>>> Can't open credentials: no such file or directory
=END=
