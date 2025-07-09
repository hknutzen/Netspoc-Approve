=TEMPL=route
{
 "address": "{{.ip}}",
 "mask-length": {{.len}},
 "type": "gateway",
 "next-hop" : [{ "gateway" : "{{.hop}}" }]
 }
=END=

############################################################
=TITLE=Add single route to empty gateway
=DEVICE=
{}
=NETSPOC=
{
  "GatewayRoutes": {
   "gw1": [
    [[route {ip: 10.11.0.0, len: 17, hop: 10.11.1.12} ]]
   ]
  }
}
=OUTPUT=
gaia_api/v1.7/set-static-route
{"address":"10.11.0.0",
 "mask-length":17,
 "next-hop":[{"gateway":"10.11.1.12"}],
 "target":"gw1",
 "type":"gateway"}
=END=

############################################################
=TITLE=Remove single route from gateway
=DEVICE=
{
  "GatewayRoutes": {
   "gw1": [
    [[route {ip: 10.1.1.0, len: 24, hop: 10.1.1.99} ]],
    [[route {ip: 10.11.0.0, len: 17, hop: 10.11.1.12} ]]
   ]
  }
}
=NETSPOC=
{
  "GatewayRoutes": {
   "gw1": [
    [[route {ip: 10.1.1.0, len: 24, hop: 10.1.1.99} ]]
   ]
  }
}
=OUTPUT=
gaia_api/v1.7/delete-static-route
{"address":"10.11.0.0","mask-length":17,"target":"gw1"}
=END=

############################################################
=TITLE=Leave gateway unchanged which is not known by Netspoc
=DEVICE=
{
  "GatewayRoutes": {
   "gw1": [
    [[route {ip: 10.1.1.0, len: 24, hop: 10.1.1.99} ]],
    [[route {ip: 10.11.0.0, len: 17, hop: 10.11.1.12} ]]
   ]
  }
}
=NETSPOC=
{
  "GatewayRoutes": {
  }
}
=OUTPUT=NONE

############################################################
=TITLE=Leave gateway unchanged if no routes from Netspoc
=DEVICE=
{
  "GatewayRoutes": {
   "gw1": [
    [[route {ip: 10.1.1.0, len: 24, hop: 10.1.1.99} ]],
    [[route {ip: 10.11.0.0, len: 17, hop: 10.11.1.12} ]]
   ]
  }
}
=NETSPOC=
{
  "GatewayRoutes": {
   "gw1": null
  }
}
=OUTPUT=NONE

############################################################
=TITLE=Change next hop of route
=DEVICE=
{
  "GatewayRoutes": {
   "gw1": [
    [[route {ip: 10.1.1.0, len: 24, hop: 10.1.1.99} ]]
   ]
  }
}
=NETSPOC=
{
  "GatewayRoutes": {
   "gw1": [
    [[route {ip: 10.1.1.0, len: 24, hop: 10.1.1.11} ]]
   ]
  }
}
=OUTPUT=
gaia_api/v1.7/set-static-route
{"address":"10.1.1.0","mask-length":24,
 "next-hop":[{"gateway":"10.1.1.11"}],
 "target":"gw1"}
=END=

############################################################
=TITLE=Change type of route
=DEVICE=
{
  "GatewayRoutes": {
   "gw1": [
{
 "address": "10.1.1.0",
 "mask-length": 24,
 "type": "reject"
}
   ]
  }
}
=NETSPOC=
{
  "GatewayRoutes": {
   "gw1": [
    [[route {ip: 10.1.1.0, len: 24, hop: 10.1.1.11} ]]
   ]
  }
}
=OUTPUT=
gaia_api/v1.7/set-static-route
{"address":"10.1.1.0","mask-length":24,
 "next-hop":[{"gateway":"10.1.1.11"}],
 "target":"gw1",
 "type":"gateway"}
=END=

############################################################
=TITLE=Equal routes with changed order
=DEVICE=
{
  "GatewayRoutes": {
   "gw1": [
    [[route {ip: 10.1.1.0, len: 24, hop: 10.1.1.11} ]],
    [[route {ip: 10.1.2.0, len: 23, hop: 10.1.1.22} ]],
    [[route {ip: 10.1.4.0, len: 24, hop: 10.1.1.44} ]],
    [[route {ip: 10.1.0.0, len: 16, hop: 10.1.0.99} ]]
   ]
  }
}
=NETSPOC=
{
  "GatewayRoutes": {
   "gw1": [
    [[route {ip: 10.1.0.0, len: 16, hop: 10.1.0.99} ]],
    [[route {ip: 10.1.2.0, len: 23, hop: 10.1.1.22} ]],
    [[route {ip: 10.1.1.0, len: 24, hop: 10.1.1.11} ]],
    [[route {ip: 10.1.4.0, len: 24, hop: 10.1.1.44} ]]
   ]
  }
}
=OUTPUT=NONE

############################################################
=TITLE=Add, delete and change route
=DEVICE=
{
  "GatewayRoutes": {
   "gw1": [
    [[route {ip: 10.1.1.0, len: 24, hop: 10.1.1.11} ]],
    [[route {ip: 10.1.2.0, len: 23, hop: 10.1.1.22} ]],
    [[route {ip: 10.1.0.0, len: 16, hop: 10.1.0.99} ]]
   ]
  }
}
=NETSPOC=
{
  "GatewayRoutes": {
   "gw1": [
    [[route {ip: 10.1.2.0, len: 23, hop: 10.1.1.22} ]],
    [[route {ip: 10.1.1.0, len: 24, hop: 10.1.1.111} ]],
    [[route {ip: 10.1.4.0, len: 24, hop: 10.1.1.44} ]]
   ]
  }
}
=OUTPUT=
gaia_api/v1.7/delete-static-route
{"address":"10.1.0.0","mask-length":16,"target":"gw1"}
gaia_api/v1.7/set-static-route
{"address":"10.1.1.0","mask-length":24,
 "next-hop":[{"gateway":"10.1.1.111"}],
 "target":"gw1"}
gaia_api/v1.7/set-static-route
{"address":"10.1.4.0","mask-length":24,
 "next-hop":[{"gateway":"10.1.1.44"}],
 "target":"gw1",
 "type":"gateway"}
=END=

############################################################
=TITLE=Handle multiple gateways
=DEVICE=
{
  "GatewayRoutes": {
   "gw1": [
    [[route {ip: 10.1.1.0, len: 24, hop: 10.1.1.11} ]],
    [[route {ip: 10.1.2.0, len: 23, hop: 10.1.1.22} ]],
    [[route {ip: 10.1.0.0, len: 16, hop: 10.1.0.99} ]]
   ],
   "other": [
    [[route {ip: 10.1.4.0, len: 24, hop: 10.1.1.44} ]]
   ]
  }
}
=NETSPOC=
{
  "GatewayRoutes": {
   "gw1": [
    [[route {ip: 10.1.2.0, len: 23, hop: 10.1.1.22} ]],
    [[route {ip: 10.1.0.0, len: 16, hop: 10.1.0.199} ]]
   ],
   "other": [
    [[route {ip: 10.1.1.0, len: 24, hop: 10.1.1.11} ]],
    [[route {ip: 10.1.4.0, len: 24, hop: 10.1.1.44} ]]
   ]
  }
}
=OUTPUT=
gaia_api/v1.7/set-static-route
{"address":"10.1.0.0","mask-length":16,
 "next-hop":[{"gateway":"10.1.0.199"}],"target":"gw1"}
gaia_api/v1.7/delete-static-route
{"address":"10.1.1.0","mask-length":24,"target":"gw1"}
gaia_api/v1.7/set-static-route
{"address":"10.1.1.0","mask-length":24,
 "next-hop":[{"gateway":"10.1.1.11"}],"target":"other","type":"gateway"}
=END=

############################################################
=TITLE=Merge routes from raw
=DEVICE=
{
  "GatewayRoutes": {
   "gw1": [
    [[route {ip: 10.1.1.0, len: 24, hop: 10.1.1.11} ]],
    [[route {ip: 10.1.2.0, len: 23, hop: 10.1.1.22} ]],
    [[route {ip: 10.1.0.0, len: 16, hop: 10.1.0.99} ]]
   ],
   "other": [
    [[route {ip: 10.1.4.0, len: 24, hop: 10.1.1.44} ]]
   ]
  }
}
=NETSPOC=
--router
{
  "GatewayRoutes": {
   "gw1": [
    [[route {ip: 10.1.0.0, len: 16, hop: 10.1.0.99} ]]
   ]
  }
}
--router.raw
{
  "GatewayRoutes": {
   "gw1": [
    [[route {ip: 10.1.1.0, len: 24, hop: 10.1.1.11} ]],
    [[route {ip: 10.1.2.0, len: 23, hop: 10.1.1.22} ]]
   ],
   "other": [
    [[route {ip: 10.1.4.0, len: 24, hop: 10.1.1.44} ]]
   ]
  }
}
=OUTPUT=NONE
