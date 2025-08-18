=TEMPL=rule
{
  "name": "{{.}}",
  "action": "Accept",
  "source": ["Any"],
  "destination": ["Any"],
  "service": ["{{.}}"],
  "install-on": ["test-fw"]
}
=END=

=TEMPL=idrule
{
  "name": "{{.}}",
  "uid": "id-{{.}}",
  "action": "Accept",
  "source": ["Any"],
  "destination": ["Any"],
  "service": ["{{.}}"],
  "install-on": ["test-fw"]
}
=END=

############################################################
=TITLE=Add simple rules to empty device
=DEVICE=
{}
=NETSPOC=
{
  "Rules": [
    [[rule http]],
    [[rule https]]
  ]
}
=OUTPUT=
add-access-rule
{
 "name":"http",
 "layer":"network",
 "action":"Accept",
 "source":["Any"],
 "destination":["Any"],
 "service":["http"],
 "install-on":["test-fw"],
 "position":"bottom"}
add-access-rule
{
 "name":"https",
 "layer":"network",
 "action":"Accept",
 "source":["Any"],
 "destination":["Any"],
 "service":["https"],
 "install-on":["test-fw"],
 "position":"bottom"}
=END=

############################################################
=TITLE=Remove simple rules from device
=DEVICE=
{
  "Rules": [
    [[idrule http]],
    [[idrule https]]
  ]
}
=NETSPOC=
{}
=OUTPUT=
delete-access-rule
{"layer":"network","uid":"id-http"}
delete-access-rule
{"layer":"network","uid":"id-https"}
=END=

############################################################
=TITLE=Replace simple rule
=DEVICE=
{
  "Rules": [
    [[idrule http]]
  ]
}
=NETSPOC=
{
  "Rules": [
    [[rule https]]
  ]
}
=OUTPUT=
delete-access-rule
{"layer":"network","uid":"id-http"}
add-access-rule
{
 "name":"https",
 "layer":"network",
 "action":"Accept",
 "source":["Any"],
 "destination":["Any"],
 "service":["https"],
 "install-on":["test-fw"],
 "position":"bottom"}
=END=

############################################################
=TITLE=Add rule and new objects
=DEVICE=
{}
=NETSPOC=
{
  "Rules": [
    {
      "name": "test rule",
      "action": "Accept",
      "source": ["n_10.1.1.0-24", "n_10.1.2.0-24"],
      "destination": ["h_10.1.8.1", "h_10.1.9.9"],
      "service": ["tcp_81", "udp_123"],
      "install-on": ["test-fw"]
    }
 ],
  "Networks": [
    {
      "name": "n_10.1.1.0-24",
      "subnet4": "10.1.1.0",
      "mask-length4": 24
    },
    {
      "name": "n_10.1.2.0-24",
      "subnet4": "10.1.2.0",
      "mask-length4": 24
    }
 ],
  "Hosts": [
    {
      "name": "h_10.1.8.1",
      "ipv4-address": "10.1.8.1"
    },
    {
      "name": "h_10.1.9.9",
      "ipv4-address": "10.1.9.9"
    }
 ],
  "TCP": [
    {
      "name": "tcp_81",
      "port": "81"
    }
 ],
  "UDP": [
    {
      "name": "udp_123",
      "port": "123"
    }
 ]
}
=OUTPUT=
add-network
{"name":"n_10.1.1.0-24","ignore-warnings":true,"subnet4":"10.1.1.0","mask-length4":24}
add-network
{"name":"n_10.1.2.0-24","ignore-warnings":true,"subnet4":"10.1.2.0","mask-length4":24}
add-host
{"name":"h_10.1.8.1","ignore-warnings":true,"ipv4-address":"10.1.8.1"}
add-host
{"name":"h_10.1.9.9","ignore-warnings":true,"ipv4-address":"10.1.9.9"}
add-service-tcp
{"name":"tcp_81","ignore-warnings":true,"port":"81"}
add-service-udp
{"name":"udp_123","ignore-warnings":true,"port":"123"}
add-access-rule
{"name":"test rule",
 "layer":"network",
 "action":"Accept",
 "source":["n_10.1.1.0-24","n_10.1.2.0-24"],
 "destination":["h_10.1.8.1","h_10.1.9.9"],
 "service":["tcp_81","udp_123"],
 "install-on":["test-fw"],
 "position":"bottom"}
=END=

############################################################
=TITLE=Delete rule and referenced objects
=DEVICE=
{
  "Rules": [
    {
      "name": "test rule",
      "uid": "id-test",
      "action": "Accept",
      "source": ["n_10.1.1.0-24", "n_10.1.2.0-24"],
      "destination": ["h_10.1.8.1", "h_10.1.9.9"],
      "service": ["tcp_81", "udp_123"],
      "install-on": ["test-fw"]
    }
 ],
  "Networks": [
    {
      "name": "n_10.1.1.0-24",
      "subnet4": "10.1.1.0",
      "mask-length4": 24
    },
    {
      "name": "n_10.1.2.0-24",
      "subnet4": "10.1.2.0",
      "mask-length4": 24
    }
 ],
  "Hosts": [
    {
      "name": "h_10.1.8.1",
      "ipv4-address": "10.1.8.1"
    },
    {
      "name": "h_10.1.9.9",
      "ipv4-address": "10.1.9.9"
    }
 ],
  "TCP": [
    {
      "name": "tcp_81",
      "port": "81"
    }
 ],
  "UDP": [
    {
      "name": "udp_123",
      "port": "123"
    }
 ]
}
=NETSPOC=
{}
=OUTPUT=
delete-access-rule
{"layer":"network",
 "uid":"id-test"}
delete-network
{"name":"n_10.1.1.0-24"}
delete-network
{"name":"n_10.1.2.0-24"}
delete-host
{"name":"h_10.1.8.1"}
delete-host
{"name":"h_10.1.9.9"}
delete-service-tcp
{"name":"tcp_81"}
delete-service-udp
{"name":"udp_123"}
=END=

############################################################
=TITLE=Change rule and referenced objects
=DEVICE=
{
  "Rules": [
    {
      "name": "test rule",
      "uid": "id-test",
      "action": "Accept",
      "source": ["n_10.1.1.0-24", "n_10.1.2.0-24"],
      "destination": ["h_10.1.8.1", "h_10.1.9.9"],
      "service": ["tcp_81", "udp_123"],
      "install-on": ["test-fw"]
    }
 ],
  "Networks": [
    {
      "name": "n_10.1.1.0-24",
      "subnet4": "10.1.1.0",
      "mask-length4": 24
    },
    {
      "name": "n_10.1.2.0-24",
      "subnet4": "10.1.2.0",
      "mask-length4": 24
    }
 ],
  "Hosts": [
    {
      "name": "h_10.1.8.1",
      "ipv4-address": "10.1.8.1"
    },
    {
      "name": "h_10.1.9.9",
      "ipv4-address": "10.1.9.9"
    }
 ],
  "TCP": [
    {
      "name": "tcp_81",
      "port": "81"
    }
 ],
  "UDP": [
    {
      "name": "udp_123",
      "port": "123"
    }
 ]
}
=NETSPOC=
{
  "Rules": [
    {
      "name": "test rule",
      "action": "Accept",
      "source": ["n_10.1.1.0-24", "n_10.1.2.0-24", "n_10.1.3.0-24"],
      "destination": ["h_10.1.8.1", "h_10.1.9.1"],
      "service": ["tcp_81"],
      "install-on": ["test-fw"]
    }
 ],
  "Networks": [
    {
      "name": "n_10.1.3.0-24",
      "subnet4": "10.1.3.0",
      "mask-length4": 24
    },
    {
      "name": "n_10.1.2.0-24",
      "subnet4": "10.1.2.0",
      "mask-length4": 24
    }
 ],
  "Hosts": [
    {
      "name": "h_10.1.8.1",
      "ipv4-address": "10.1.8.1"
    },
    {
      "name": "h_10.1.9.3",
      "ipv4-address": "10.1.9.3"
    }
 ]
}
=OUTPUT=
add-network
{"name":"n_10.1.3.0-24","ignore-warnings":true,"subnet4":"10.1.3.0","mask-length4":24}
add-host
{"name":"h_10.1.9.3","ignore-warnings":true,"ipv4-address":"10.1.9.3"}
set-access-rule
{"destination":{"add":["h_10.1.9.1"]},
 "layer":"network",
 "service":{"remove":["udp_123"]},
 "source":{"add":["n_10.1.3.0-24"]},
 "uid":"id-test"}
set-access-rule
{"destination":{"remove":["h_10.1.9.9"]},
 "layer":"network",
 "uid":"id-test"}
delete-host
{"name":"h_10.1.9.9"}
delete-service-udp
{"name":"udp_123"}
=END=

############################################################
=TITLE=Prepend rule at top
=DEVICE=
{
  "Rules": [
    [[rule http]]
    ]
}
=NETSPOC=
{
  "Rules": [
    [[rule https]],
    [[rule http]]
    ]
}
=OUTPUT=
add-access-rule
{
 "name":"https",
 "layer":"network",
 "action":"Accept",
 "source":["Any"],
 "destination":["Any"],
 "service":["https"],
 "install-on":["test-fw"],
 "position":{"above":"http"}}
=END=

############################################################
=TITLE=Append rule at bottom
=DEVICE=
{
  "Rules": [
    [[rule http]]
  ]
}
=NETSPOC=
{
  "Rules": [
    [[rule http]],
    [[rule https]]
  ]
}
=OUTPUT=
add-access-rule
{
 "name":"https",
 "layer":"network",
 "action":"Accept",
 "source":["Any"],
 "destination":["Any"],
 "service":["https"],
 "install-on":["test-fw"],
 "position":"bottom"}
=END=

############################################################
=TITLE=Replace rule between unchanged rules
=DEVICE=
{
  "Rules": [
    [[idrule http]],
    [[idrule https]],
    [[idrule ldap]]
  ]
}
=NETSPOC=
{
  "Rules": [
    [[rule http]],
    [[rule ssh]],
    [[rule ldap]]
  ]
}
=OUTPUT=
delete-access-rule
{"layer":"network","uid":"id-https"}
add-access-rule
{
 "name":"ssh",
 "layer":"network",
 "action":"Accept",
 "source":["Any"],
 "destination":["Any"],
 "service":["ssh"],
 "install-on":["test-fw"],
 "position":{"above":"ldap"}}
=END=

############################################################
=TITLE=Replace 2 by 3 rules after 1 unchanged
=DEVICE=
{
  "Rules": [
    [[idrule http]],
    [[idrule https]],
    [[idrule ldap]]
  ]
}
=NETSPOC=
{
  "Rules": [
    [[rule http]],
    [[rule ssh]],
    [[rule smtp]],
    [[rule pop-3]]
  ]
}
=OUTPUT=
delete-access-rule
{"layer":"network","uid":"id-https"}
delete-access-rule
{"layer":"network","uid":"id-ldap"}
add-access-rule
{
 "name":"ssh",
 "layer":"network",
 "action":"Accept",
 "source":["Any"],
 "destination":["Any"],
 "service":["ssh"],
 "install-on":["test-fw"],
 "position":"bottom"}
add-access-rule
{
 "name":"smtp",
 "layer":"network",
 "action":"Accept",
 "source":["Any"],
 "destination":["Any"],
 "service":["smtp"],
 "install-on":["test-fw"],
 "position":"bottom"}
add-access-rule
{
 "name":"pop-3",
 "layer":"network",
 "action":"Accept",
 "source":["Any"],
 "destination":["Any"],
 "service":["pop-3"],
 "install-on":["test-fw"],
 "position":"bottom"}
=END=

############################################################
=TITLE=Replace last rule
=DEVICE=
{
  "Rules": [
    [[idrule http]],
    [[idrule https]]
  ]
}
=NETSPOC=
{
  "Rules": [
    [[rule http]],
    [[rule ssh]]
  ]
}
=OUTPUT=
delete-access-rule
{"layer":"network","uid":"id-https"}
add-access-rule
{
 "name":"ssh",
 "layer":"network",
 "action":"Accept",
 "source":["Any"],
 "destination":["Any"],
 "service":["ssh"],
 "install-on":["test-fw"],
 "position":"bottom"}
=END=

############################################################
=TITLE=Change typically unused attributes
=DEVICE=
{
  "Rules": [
    {
      "name": "test",
      "uid": "id-test",
      "action": "Accept",
      "comments": "Some comment",
      "source-negate": true,
      "destination-negate": true,
      "service-negate": true,
      "enabled": false,
      "install-on": ["test-fw"]
    }
  ]
}
=NETSPOC=
{
  "Rules": [
    {
      "name": "test",
      "action": "Drop",
      "enabled": true,
      "install-on": ["test-fw"]
    }
  ]
}
=OUTPUT=
set-access-rule
{
 "action":"Drop",
 "comments":"",
 "destination-negate":false,
 "enabled":true,
 "layer":"network",
 "service-negate":false,
 "source-negate":false,
 "uid":"id-test"}
=END=

############################################################
=TITLE=Change attribute "install-on"
=DEVICE=
{
  "Rules": [
    {
      "name": "http",
      "uid": "id-http",
      "action": "Accept",
      "source": ["Any"],
      "destination": ["Any"],
      "service": ["http"],
      "install-on": ["test-fw"]
    }
  ]
}
=NETSPOC=
{
  "Rules": [
    {
      "name": "http",
      "action": "Accept",
      "source": ["Any"],
      "destination": ["Any"],
      "service": ["http"],
      "install-on": ["other-fw"]
    }
  ]
}
=OUTPUT=
delete-access-rule
{"layer":"network","uid":"id-http"}
add-access-rule
{
 "name":"http",
 "layer":"network",
 "action":"Accept",
 "source":["Any"],
 "destination":["Any"],
 "service":["http"],
 "install-on":["other-fw"],
 "position":"bottom"}
=END=

############################################################
=TITLE=Change attributes of referenced objects
=TEMPL=input
{
  "Rules": [
    {
      "name": "test rule",
      "uid": "id-test",
      "action": "Accept",
      "source": ["my-group"],
      "destination": ["my-host"],
      "service": ["my-srv"],
      "install-on": ["test-fw"]
    }
  ],
  "Groups": [{ "name": "my-group", "members": ["my-net"] }],
  "Networks": [{ "name": "my-net", "subnet4": "10.1.2.0", "mask-length4": 24 }],
  "Hosts": [{ "name": "my-host", "ipv4-address": "10.1.9.9" }],
  "TCP": [{ "name": "my-srv", "port": "81" }]
}
=DEVICE=
[[input]]
=NETSPOC=
[[input]]
=SUBST=/24/25/
=SUBST=/9.9/9.8/
=SUBST=/81/80/
=OUTPUT=
set-network
{"name":"my-net","subnet4":"10.1.2.0","mask-length4":25}
set-host
{"name":"my-host","ipv4-address":"10.1.9.8"}
set-service-tcp
{"name":"my-srv","port":"80"}
=END=
