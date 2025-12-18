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
POST /web_api/show-packages
{
  "packages": [ {
    "name": "pkg1",
    "access": true,
    "comment": "Managed by NetSPoC",
    "access-layers": ["network"],
    "installation-targets": ["fw1"]
  }]
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
=TITLE=Login gives invalid JSON
=SCENARIO=
POST /web_api/login
200
INVALID
=NETSPOC=NONE
=ERROR=
WARNING>>> invalid character 'I' looking for beginning of value
ERROR>>> Devices unreachable: router
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
POST /web_api/
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
/web_api/show-packages
{"details-level": "full"}
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

/web_api/show-packages
{"details-level": "full"}
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


/web_api/show-packages
{"details-level": "full"}
/web_api/show-access-rulebase
{"details-level":"standard","limit":500,"name":"network","use-object-dictionary":false}
404
404 page not found

=END=

############################################################
=TITLE=EOF during discard
=SCENARIO=
[[standard]]
POST /web_api/show-sessions
EOF
=NETSPOC=NONE
=ERROR=
ERROR>>> Post "TESTSERVER/web_api/show-sessions": EOF
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
Post "TESTSERVER/web_api/show-sessions": EOF
=END=

############################################################
=TITLE=EOF while reading policy packages
=SCENARIO=
POST /web_api/
{}
POST /web_api/login
{
  "sid": "secret"
}
POST /web_api/show-packages
EOF
=NETSPOC=NONE
=ERROR=
ERROR>>> While reading device: Post "TESTSERVER/web_api/show-packages": EOF
=END=

############################################################
=TITLE=Invalid config in response
=SCENARIO=
[[standard]]
POST /web_api/
{}
=SUBST=/"packages"/INVALID/
=NETSPOC=NONE
=ERROR=
ERROR>>> While reading device: invalid character 'I' looking for beginning of object key string
=END=

############################################################
=TITLE=Not managed by NetSPoC
=SCENARIO=
[[standard]]
POST /web_api/
{}
=SUBST=/by NetSPoC/by admin/
=NETSPOC=
{ "TargetRules": {"fw1": []} }
=ERROR=
ERROR>>> Missing "NetSPoC" in comment of policy "pkg1"
=END=

############################################################
=TITLE=Multiple access layers
=SCENARIO=
[[standard]]
POST /web_api/
{}
=SUBST=/"network"/"L1","L2"/
=NETSPOC=NONE
=ERROR=
ERROR>>> While reading device: Policy package "pkg1" must use exactly one access-layer
=END=

############################################################
=TITLE=Multiple installation targets
=SCENARIO=
[[standard]]
POST /web_api/
{}
=SUBST=/"fw1"/"fw1","fw2"/
=NETSPOC=NONE
=ERROR=
ERROR>>> While reading device: Policy package "pkg1" must use exactly one installation-target
=END=

############################################################
=TITLE=EOF while reading rules
=SCENARIO=
[[standard]]
POST /web_api/show-access-rulebase
EOF
POST /web_api/
{}
=NETSPOC=NONE
=ERROR=
ERROR>>> While reading device: Post "TESTSERVER/web_api/show-access-rulebase": EOF
=END=

############################################################
=TITLE=Invalid list of rules
=SCENARIO=
[[standard]]
POST /web_api/show-access-rulebase
{
  "from" : 1,
  "to" : 1,
  "total" : 1,
  "rulebase" : 42
}
POST /web_api/
{}
=NETSPOC=NONE
=ERROR=
ERROR>>> While reading device: json: cannot unmarshal number into Go struct field .rulebase of type []json.RawMessage
=END=

############################################################
=TITLE=Invalid data in rule
=SCENARIO=
[[standard]]
POST /web_api/show-access-rulebase
{
  "from" : 1,
  "to" : 1,
  "total" : 1,
  "rulebase" : [42]
}
POST /web_api/
{}
=NETSPOC=NONE
=ERROR=
ERROR>>> While parsing device config: json: cannot unmarshal number into Go struct field chkpConfig.TargetRules of type checkpoint.chkpRule
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
    "uid": "id1",
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
      "name" : "Policy Targets"
    } ],
    "tags" : [ ]
  } ]
}
POST /web_api/
{}
=NETSPOC=
{ "TargetRules": {"fw1": []} }
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
/web_api/show-packages
{"details-level": "full"}
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
{"GatewayIPs":{},"GatewayRoutes":{},"Groups":null,"Hosts":null,"ICMP":null,"ICMP6":null,"Networks":null,"SvOther":null,"TCP":null,"TargetPolicy":{"fw1":{"Name":"pkg1","Layer":"network","Comment":"Managed by NetSPoC"}},"TargetRules":{"fw1":[{"name":"rule1","uid":"id1","source":[{"name":"Any"}],"destination":[{"name":"Any"}],"service":[{"name":"icmp-proto"}],"action":{"name":"Accept"},"install-on":[{"name":"Policy Targets"}],"tags":[]}]},"UDP":null}
--router.change
/web_api/delete-access-rule
{"layer":"network","uid":"id1"}
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
{"policy-package":"pkg1","targets":["fw1"]}
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
=TITLE=Add simple rule, show-task gives warning
=SCENARIO=
[[standard]]
POST /web_api/
{}
=SUBST=/"succeeded"/"succeeded with warnings"/
=NETSPOC=
{ "TargetRules": {"fw1": [
   {
     "name": "rule1",
     "action": "Accept",
     "source": ["Any"],
     "destination": ["Any"],
     "service": ["https"],
     "install-on": ["Policy Targets"]
   }
  ]}
}
=WARNING=
WARNING>>> task "" succeeded with warnings
WARNING>>> task "" succeeded with warnings
=OUTPUT=
--router.config
{"GatewayIPs":{},"GatewayRoutes":{},"Groups":null,"Hosts":null,"ICMP":null,"ICMP6":null,"Networks":null,"SvOther":null,"TCP":null,"TargetPolicy":{"fw1":{"Name":"pkg1","Layer":"network","Comment":"Managed by NetSPoC"}},"TargetRules":{"fw1":null},"UDP":null}
--router.change
/web_api/add-access-rule
{"name":"rule1","layer":"network","action":"Accept","source":["Any"],"destination":["Any"],"service":["https"],"install-on":["Policy Targets"],"position":"bottom"}
{}

/web_api/publish
{}
{}

/web_api/show-task
{"task-id":""}
{
  "Tasks": [ {
    "status" : "succeeded with warnings",
    "task-name" : ""
  } ]
}

/web_api/install-policy
{"policy-package":"pkg1","targets":["fw1"]}
{}

/web_api/show-task
{"task-id":""}
{
  "Tasks": [ {
    "status" : "succeeded with warnings",
    "task-name" : ""
  } ]
}

=END=

############################################################
=TITLE=Unchanged rule references changed object, publish fails
=SCENARIO=
[[standard]]
POST /web_api/show-access-rulebase
{
  "from" : 1,
  "to" : 1,
  "total" : 1,
  "rulebase" : [ {
    "name" : "rule1",
    "uid": "id1",
    "action" : "Accept",
    "source" : ["my-group"],
    "destination" : ["Any"],
    "service" : ["https"],
    "install-on" : ["Policy Targets"]
  } ]
}
POST /web_api/show-groups
{
  "from" : 1,
  "to" : 1,
  "total" : 1,
  "objects" : [ {
   "name": "my-group",
   "uid": "id-1",
   "members": ["my-net"]
  } ]
}
POST /web_api/show-networks
{
  "from" : 1,
  "to" : 1,
  "total" : 1,
  "objects" : [ {
   "name": "my-net",
   "uid": "my-net",
   "subnet4": "10.1.2.0",
   "mask-length4": 25
  } ]
}
POST /web_api/
{}
=SUBST=/"succeeded"/"failed"/
=NETSPOC=
{ "TargetRules": {"fw1": [
   {
     "name": "rule1",
     "action": "Accept",
     "source": ["my-group"],
     "destination": ["Any"],
     "service": ["https"],
     "install-on": ["Policy Targets"]
   }
  ]},
  "Groups": [{ "name": "my-group", "members": ["my-net"] }],
  "Networks": [{ "name": "my-net", "subnet4": "10.1.2.0", "mask-length4": 24 }]
}
=ERROR=
ERROR>>> Unexpected status of task "": "failed"
=OUTPUT=
--router.change
/web_api/set-network
{"uid":"my-net","subnet4":"10.1.2.0","mask-length4":24}
{}

/web_api/publish
{}
{}

/web_api/show-task
{"task-id":""}
{
  "Tasks": [ {
    "status" : "failed",
    "task-name" : ""
  } ]
}

=END=

############################################################
=TITLE=Collecting gateway IP fails
=SCENARIO=
[[standard]]
POST /web_api/show-simple-gateways
{ "objects": [ "uid1" ] }
POST /web_api/show-simple-gateway
ERROR
POST /web_api/
{}
=NETSPOC=NONE
=ERROR=
ERROR>>> While reading device: invalid character 'E' looking for beginning of value
=END=

############################################################
=TITLE=Use gateway IP in GAIA API for changing static routes
=SCENARIO=
[[standard]]
POST /web_api/show-simple-gateways
{ "objects": [ "uid1" ] }
POST /web_api/show-simple-gateway
{ "name": "gw1", "ipv4-address": "10.1.1.1" }
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
POST /web_api/gaia-api/v1.8/show-static-routes
{ "response-message": {
    "objects" : [
    {
     "address": "10.11.0.0",
     "mask-length": 17,
     "type": "gateway",
     "next-hop" : [{ "gateway" : "10.1.2.2" }]
    }
    ]
  }
}
POST /web_api/
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
--router.config
{"GatewayIPs":{"cluster1":["10.2.2.2","10.2.2.3"],"gw1":["10.1.1.1"]},"GatewayRoutes":{"cluster1":[{"address":"10.11.0.0","mask-length":17,"type":"gateway","next-hop":[{"gateway":"10.1.2.2"}]}],"gw1":[{"address":"10.11.0.0","mask-length":17,"type":"gateway","next-hop":[{"gateway":"10.1.2.2"}]}]},"Groups":null,"Hosts":null,"ICMP":null,"ICMP6":null,"Networks":null,"SvOther":null,"TCP":null,"TargetPolicy":{"fw1":{"Name":"pkg1","Layer":"network","Comment":"Managed by NetSPoC"}},"TargetRules":{"fw1":null},"UDP":null}
--router.change
/web_api/gaia-api/v1.8/delete-static-route
{"address":"10.11.0.0","mask-length":17,"target":"10.2.2.2"}
{}

/web_api/gaia-api/v1.8/set-static-route
{"address":"10.1.2.0","mask-length":24,"next-hop":[{"gateway":"10.1.2.2"}],"target":"10.2.2.2","type":"gateway"}
{}

/web_api/gaia-api/v1.8/delete-static-route
{"address":"10.11.0.0","mask-length":17,"target":"10.2.2.3"}
{}

/web_api/gaia-api/v1.8/set-static-route
{"address":"10.1.2.0","mask-length":24,"next-hop":[{"gateway":"10.1.2.2"}],"target":"10.2.2.3","type":"gateway"}
{}

/web_api/gaia-api/v1.8/set-static-route
{"address":"10.11.0.0","mask-length":17,"next-hop":[{"gateway":"10.11.1.12"}],"target":"10.1.1.1"}
{}

=END=

############################################################
=TITLE=Leave static routes unchanged if no routes from Netspoc
=SCENARIO=
[[standard]]
POST /web_api/show-simple-gateways
{ "objects": [ "uid1" ] }
POST /web_api/show-simple-gateway
{ "name": "gw1", "ipv4-address": "10.1.1.1" }
POST /web_api/gaia-api/v1.8/show-static-routes
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
POST /web_api/gaia-api/v1.8/show-static-routes
{ "response-message": { "objects" : [] } }
POST /web_api/
{}
=NETSPOC=
{ "GatewayRoutes": {} }
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
/web_api/show-packages
{"details-level": "full"}
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
/web_api/show-simple-gateway
{"uid":"uid1"}
/web_api/show-simple-clusters
{"details-level": "uid"}
/web_api/show-simple-cluster
{"uid":"uid2"}
--router.change
No changes applied
=END=