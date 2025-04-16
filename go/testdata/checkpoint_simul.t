=TEMPL=standard
POST /web_api/login
{
  "sid": "secret"
}
POST /web_api/show-task
{
  "Tasks": [ {
    "status" : "succeeded",
    "task-name" : ""
  } ]
}
=END=

############################################################
=TITLE=Device gives status 500
=SCENARIO=
POST /web_api/
500
device not ready
=NETSPOC=NONE
=ERROR=
WARNING>>> status code: 500
ERROR>>> Devices unreachable: router
=OUTPUT=
--router.login
TESTSERVER/web_api/login
{"user":"admin","password":"xxx"}
500 Internal Server Error
=END=

############################################################
=TITLE=Device gives no valid answer
=SCENARIO=
POST /web_api/
EOF
=NETSPOC=NONE
=ERROR=
WARNING>>> Post "TESTSERVER/web_api/login": EOF
ERROR>>> Devices unreachable: router
=OUTPUT=
--router.login
TESTSERVER/web_api/login
{"user":"admin","password":"xxx"}
=END=

############################################################
=TITLE=Login fails
=SCENARIO=
POST /web_api/login
400
{
  "code" : "err_login_failed",
  "message" : "Authentication to server failed."
}
=NETSPOC=NONE
=ERROR=
WARNING>>> status code: 400
ERROR>>> Devices unreachable: router
=END=

############################################################
=TITLE=Only login succeeds
=SCENARIO=
[[standard]]
=NETSPOC=NONE
=ERROR=
ERROR>>> status code: 404, uri: /web_api/show-sessions
ERROR>>> 404 page not found
=END=

############################################################
=TITLE=No sessions to discard and empty config
=SCENARIO=
[[standard]]
POST /web_api
{}
=NETSPOC=NONE
=OUTPUT=
--router.login
TESTSERVER/web_api/login
{"user":"admin","password":"xxx"}
200 OK
{
  "sid": "xxx"
}

/web_api/show-sessions
{"details-level": "uid"}
/web_api/show-access-rulebase
{"details-level":"standard","limit":500,"name":"network","use-object-dictionary":false}
/web_api/show-networks
{"details-level":"full","limit":500}
/web_api/show-hosts
{"details-level":"full","limit":500}
/web_api/show-groups
{"dereference-group-members":true,"details-level":"full","limit":500}
/web_api/show-services-tcp
{"details-level":"full","limit":500}
/web_api/show-services-udp
{"details-level":"full","limit":500}
/web_api/show-services-icmp
{"details-level":"full","limit":500}
/web_api/show-services-icmp6
{"details-level":"full","limit":500}
/web_api/show-services-other
{"details-level":"full","limit":500}
/web_api/show-simple-gateways
{"details-level": "uid"}
/web_api/show-simple-clusters
{"details-level": "uid"}
=END=

############################################################
=TITLE=Discard session
=SCENARIO=
[[standard]]
POST /web_api/show-sessions
{ "objects": [ "id1" ] }
POST /web_api/show-session
{ "uid": "id1", "user-name": "admin", "application": "WEB_API" }
POST /web_api/discard
{}
=NETSPOC=NONE
=ERROR=
ERROR>>> While reading device: status code: 404, uri: /web_api/show-access-rulebase
ERROR>>> 404 page not found
=OUTPUT=
--router.login
TESTSERVER/web_api/login
{"user":"admin","password":"xxx"}
200 OK
{
  "sid": "xxx"
}

/web_api/show-sessions
{"details-level": "uid"}
/web_api/show-session
{"uid":"id1"}
{ "uid": "id1", "user-name": "admin", "application": "WEB_API" }

/web_api/discard
{"uid":"id1"}
{}

/web_api/show-access-rulebase
{"details-level":"standard","limit":500,"name":"network","use-object-dictionary":false}
404
404 page not found

=END=

############################################################
=TITLE=Show session fails
=SCENARIO=
[[standard]]
POST /web_api/show-sessions
{ "objects": [ "id1" ] }
=NETSPOC=NONE
=ERROR=
ERROR>>> status code: 404, uri: /web_api/show-session
ERROR>>> 404 page not found
=END=

############################################################
=TITLE=Ignore failure during discard
=SCENARIO=
[[standard]]
POST /web_api/show-sessions
{ "objects": [ "uid1" ] }
POST /web_api/show-session
{ "uid": "uid1", "user-name": "admin", "application": "WEB_API" }
=NETSPOC=NONE
=ERROR=
ERROR>>> While reading device: status code: 404, uri: /web_api/show-access-rulebase
ERROR>>> 404 page not found
=OUTPUT=
--router.login
TESTSERVER/web_api/login
{"user":"admin","password":"xxx"}
200 OK
{
  "sid": "xxx"
}

/web_api/show-sessions
{"details-level": "uid"}
/web_api/show-session
{"uid":"uid1"}
{ "uid": "uid1", "user-name": "admin", "application": "WEB_API" }

/web_api/discard
{"uid":"uid1"}
404
404 page not found


/web_api/show-access-rulebase
{"details-level":"standard","limit":500,"name":"network","use-object-dictionary":false}
404
404 page not found

=END=

############################################################
=TITLE=Invalid config in response
=SCENARIO=
[[standard]]
POST /web_api/show-access-rulebase
INVALID
POST /web_api/
{}
=NETSPOC=NONE
=ERROR=
ERROR>>> While reading device: invalid character 'I' looking for beginning of value
=END=

############################################################
=TITLE=Remove simple rule
=SCENARIO=
[[standard]]
POST /web_api/show-access-rulebase
{
  "from" : 1,
  "to" : 1,
  "total" : 1,
  "rulebase" : [ {
    "name" : "rule1",
    "source" : [ {
      "name" : "Any"
    } ],
    "destination" : [ {
      "name" : "Any"
    } ],
    "service" : [ {
      "name" : "icmp-proto"
    } ],
    "action" : {
      "name" : "Accept"
    },
    "install-on" : [ {
      "name" : "gw7"
    } ],
    "tags" : [ ]
  } ]
}
POST /web_api/
{}
=NETSPOC=
{}
=OUTPUT=
--router.login
TESTSERVER/web_api/login
{"user":"admin","password":"xxx"}
200 OK
{
  "sid": "xxx"
}

/web_api/show-sessions
{"details-level": "uid"}
/web_api/show-access-rulebase
{"details-level":"standard","limit":500,"name":"network","use-object-dictionary":false}
/web_api/show-networks
{"details-level":"full","limit":500}
/web_api/show-hosts
{"details-level":"full","limit":500}
/web_api/show-groups
{"dereference-group-members":true,"details-level":"full","limit":500}
/web_api/show-services-tcp
{"details-level":"full","limit":500}
/web_api/show-services-udp
{"details-level":"full","limit":500}
/web_api/show-services-icmp
{"details-level":"full","limit":500}
/web_api/show-services-icmp6
{"details-level":"full","limit":500}
/web_api/show-services-other
{"details-level":"full","limit":500}
/web_api/show-simple-gateways
{"details-level": "uid"}
/web_api/show-simple-clusters
{"details-level": "uid"}
--router.config
{"GatewayRoutes":{},"Groups":null,"Hosts":null,"ICMP":null,"ICMP6":null,"Networks":null,"Rules":[{"name":"rule1","source":[{"name":"Any"}],"destination":[{"name":"Any"}],"service":[{"name":"icmp-proto"}],"action":{"name":"Accept"},"install-on":[{"name":"gw7"}],"tags":[]}],"SvOther":null,"TCP":null,"UDP":null}
--router.change
/web_api/delete-access-rule
{"layer":"network","name":"rule1"}
{}

/web_api/publish
{}
{}

/web_api/show-task
{"task-id":""}
{
  "Tasks": [ {
    "status" : "succeeded",
    "task-name" : ""
  } ]
}

/web_api/install-policy
{"policy-package":"standard","targets":["gw7"]}
{}

/web_api/show-task
{"task-id":""}
{
  "Tasks": [ {
    "status" : "succeeded",
    "task-name" : ""
  } ]
}

=END=

############################################################
=TITLE=Add simple rule
=SCENARIO=
[[standard]]
POST /web_api/
{}
=NETSPOC=
{
  "Rules": [
   {
     "name": "rule1",
     "action": "Accept",
     "source": ["Any"],
     "destination": ["Any"],
     "service": ["https"],
     "install-on": ["test-fw"]
   }
  ]
}
=OUTPUT=
--router.config
{"GatewayRoutes":{},"Groups":null,"Hosts":null,"ICMP":null,"ICMP6":null,"Networks":null,"Rules":null,"SvOther":null,"TCP":null,"UDP":null}
--router.change
/web_api/add-access-rule
{"name":"rule1","layer":"network","action":"Accept","source":["Any"],"destination":["Any"],"service":["https"],"install-on":["test-fw"],"position":"bottom"}
{}

/web_api/publish
{}
{}

/web_api/show-task
{"task-id":""}
{
  "Tasks": [ {
    "status" : "succeeded",
    "task-name" : ""
  } ]
}

/web_api/install-policy
{"policy-package":"standard","targets":["test-fw"]}
{}

/web_api/show-task
{"task-id":""}
{
  "Tasks": [ {
    "status" : "succeeded",
    "task-name" : ""
  } ]
}

=END=

############################################################
=TITLE=Use gateway IP in GAIA API for changing static routes
=SCENARIO=
[[standard]]
POST /web_api/show-simple-gateways
{ "objects": [ "uid1" ] }
POST /web_api/show-simple-gateway
{ "name": "gw1", "ipv4-address": "10.1.1.1" }
POST /web_api/gaia-api/v1.7/show-static-routes
{ "response-message": { "objects" : [] } }
POST /web_api/show-simple-clusters
{ "objects": [ "uid2" ] }
POST /web_api/show-simple-cluster
{
 "name": "cluster1",
 "ipv4-address": "10.2.2.1",
 "cluster-members": [
  { "ip-address": "10.2.2.2" },
  { "ip-address": "10.2.2.3" } ]
}
POST /web_api/gaia-api/v1.7/show-static-routes
{ "response-message": { "objects" : [] } }
POST /web_api
{}
=NETSPOC=
{ "GatewayRoutes": {
 "gw1": [
 {
  "address": "10.11.0.0",
  "mask-length": 17,
  "type": "gateway",
  "next-hop" : [{ "gateway" : "10.11.1.12" }]
 }],
 "cluster1": [
 {
  "address": "10.1.2.0",
  "mask-length": 24,
  "type": "gateway",
  "next-hop" : [{ "gateway" : "10.1.2.2" }]
 }]
}}
=OUTPUT=
--router.change
/web_api/gaia_api/v1.7/set-static-route
{"address":"10.1.2.0","mask-length":24,"next-hop":[{"gateway":"10.1.2.2"}],"target":"10.2.2.2","type":"gateway"}
{}

/web_api/gaia_api/v1.7/set-static-route
{"address":"10.1.2.0","mask-length":24,"next-hop":[{"gateway":"10.1.2.2"}],"target":"10.2.2.3","type":"gateway"}
{}

/web_api/gaia_api/v1.7/set-static-route
{"address":"10.11.0.0","mask-length":17,"next-hop":[{"gateway":"10.11.1.12"}],"target":"10.1.1.1","type":"gateway"}
{}

=END=
