=TEMPL=session
POST /api/session/create
H: x-xsrf-token: secret
=END=

############################################################
=TITLE=Device gives no valid answer
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
