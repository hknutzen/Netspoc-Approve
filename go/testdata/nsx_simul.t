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
