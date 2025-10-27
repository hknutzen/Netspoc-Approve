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
=TITLE=Replace simple rule, ignore uid from Netspoc
=DEVICE=
{
  "Rules": [
    [[idrule http]],
    [[idrule smtp]]
  ]
}
=NETSPOC=
{
  "Rules": [
    [[idrule https]]
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
delete-access-rule
{"layer":"network","uid":"id-smtp"}
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
      "uid": "id-1-1",
      "subnet4": "10.1.1.0",
      "mask-length4": 24
    },
    {
      "name": "n_10.1.2.0-24",
      "uid": "id-1-2",
      "subnet4": "10.1.2.0",
      "mask-length4": 24
    }
 ],
  "Hosts": [
    {
      "name": "h_10.1.8.1",
      "uid": "id-1-8",
      "ipv4-address": "10.1.8.1"
    },
    {
      "name": "h_10.1.9.9",
      "uid": "id-1-9",
      "ipv4-address": "10.1.9.9"
    }
 ],
  "TCP": [
    {
      "name": "tcp_81",
      "uid": "id-81",
      "port": "81"
    }
 ],
  "UDP": [
    {
      "name": "udp_123",
      "uid": "id-123",
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
{"uid":"id-1-1"}
delete-network
{"uid":"id-1-2"}
delete-host
{"uid":"id-1-8"}
delete-host
{"uid":"id-1-9"}
delete-service-tcp
{"uid":"id-81"}
delete-service-udp
{"uid":"id-123"}
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
      "source": ["DöMINET", "n_10.1.2.0-24"],
      "destination": ["h_10.1.8.1", "h_10.1.9.9"],
      "service": ["tcp_81", "udp_123"],
      "install-on": ["test-fw"]
    }
 ],
  "Networks": [
    {
      "name": "DöMINET",
      "uid": "id-1-1",
      "subnet4": "10.1.1.0",
      "mask-length4": 24
    },
    {
      "name": "n_10.1.2.0-24",
      "uid": "id-1-2",
      "subnet4": "10.1.2.0",
      "mask-length4": 24
    }
 ],
  "Hosts": [
    {
      "name": "h_10.1.8.1",
      "uid": "id-1-8",
      "ipv4-address": "10.1.8.1"
    },
    {
      "name": "h_10.1.9.9",
      "uid": "id-1-9",
      "ipv4-address": "10.1.9.9"
    }
 ],
  "TCP": [
    {
      "name": "tcp_81",
      "uid": "id-81",
      "port": "81"
    }
 ],
  "UDP": [
    {
      "name": "udp_123",
      "uid": "id-123",
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
      "source": ["Döminet", "n_10.1.2.0-24", "n_10.1.3.0-24"],
      "destination": ["h_10.1.8.1", "h_10.1.9.1"],
      "service": ["tcp_81"],
      "install-on": ["test-fw"]
    }
 ],
  "Networks": [
    {
      "name": "Döminet",
      "subnet4": "10.1.1.0",
      "mask-length4": 24
    },
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
 "source":{"add":["n_10.1.3.0-24"]},
 "uid":"id-test"}
set-access-rule
{"destination":{"remove":["id-1-9"]},
 "layer":"network",
 "service":{"remove":["id-123"]},
 "uid":"id-test"}
delete-host
{"uid":"id-1-9"}
delete-service-udp
{"uid":"id-123"}
=END=

############################################################
=TITLE=Prepend rule at top
=DEVICE=
{
  "Rules": [
    [[idrule http]]
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
 "position":{"above":"id-http"}}
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
 "position":{"above":"id-ldap"}}
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
      "track" : {
        "type": "Log",
        "per-session": false,
        "per-connection": true,
        "accounting": false,
        "enable-firewall-session": false,
        "alert": "none"
      },
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
 "track":{"alert":"none","per-connection":true,"type":"Log"},
 "uid":"id-test"}
=END=

############################################################
=TITLE=Equal attribute track
=DEVICE=
{
  "Rules": [
    {
      "name": "test",
      "uid": "id-test",
      "action": "Accept",
      "track" : {
        "type": { "name": "Log" },
        "per-session": false,
        "per-connection": true,
        "accounting": false,
        "enable-firewall-session": false,
        "alert": "none"
      },
      "install-on": ["test-fw"]
    }
  ]
}
=NETSPOC=
{
  "Rules": [
    {
      "name": "test",
      "action": "Accept",
      "track":{"alert":"none","per-connection":true,"type":"Log"},
      "install-on": ["test-fw"]
    }
  ]
}
=OUTPUT=NONE

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
delete-access-rule
{"layer":"network","uid":"id-http"}
=END=

############################################################
=TITLE=Equal "install-on" with different order and different case
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
      "install-on": ["test-fw", "other-fw"]
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
      "install-on": ["other-fw", "TEST-FW"]
    }
  ]
}
=OUTPUT=NONE

############################################################
=TITLE=Delete, add rule with duplicate name and different install-on
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
    },
    {
      "name": "http",
      "uid": "id-http2",
      "action": "Accept",
      "source": ["Any"],
      "destination": ["Any"],
      "service": ["http"],
      "install-on": ["other-fw"]
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
    },
    {
      "name": "http",
      "action": "Accept",
      "source": ["Any"],
      "destination": ["Any"],
      "service": ["http"],
      "install-on": ["test-fw"]
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
 "install-on":["test-fw"],
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
  "Networks": [{ "name": "my-net", "uid": "my-net", "subnet4": "10.1.2.0", "mask-length4": 24 }],
  "Hosts": [{ "name": "my-host", "uid": "my-host", "ipv4-address": "10.1.9.9" }],
  "TCP": [{ "name": "my-srv", "uid": "my-srv", "port": "81" }]
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
{"uid":"my-net","subnet4":"10.1.2.0","mask-length4":25}
set-host
{"uid":"my-host","ipv4-address":"10.1.9.8"}
set-service-tcp
{"uid":"my-srv","port":"80"}
=END=

############################################################
=TITLE=Add, remove, change rule referencing predefined ICMP object
=DEVICE=
{
  "ICMP": [
    {
      "name": "echo-reply",
      "icmp-type": 0,
      "read-only": true
    },
    {
      "name": "dest-unreach",
      "icmp-type": 3,
      "read-only": true
    },
    {
      "name": "source-quench",
      "icmp-type": 4,
      "read-only": true
    }
  ],
  "Rules": [
    {
      "name": "echo-reply",
      "uid": "id-echo-reply",
      "action": "Accept",
      "source": ["Any"],
      "destination": ["Any"],
      "service": ["redirect"],
      "install-on": ["test-fw"]
    },
    [[idrule source-quench]]
  ]
}
=NETSPOC=
{
  "Rules": [
    [[rule echo-reply]],
    [[rule dest-unreach]]
  ]
}
=OUTPUT=
set-access-rule
{"layer":"network","service":{"add":["echo-reply"]},"uid":"id-echo-reply"}
set-access-rule
{"layer":"network","service":{"remove":["redirect"]},"uid":"id-echo-reply"}
delete-access-rule
{"layer":"network","uid":"id-source-quench"}
add-access-rule
{
 "name":"dest-unreach",
 "layer":"network",
 "action":"Accept",
 "source":["Any"],
 "destination":["Any"],
 "service":["dest-unreach"],
 "install-on":["test-fw"],
 "position":"bottom"}
=END=

############################################################
=TITLE=Add, remove, change user defined ICMP object
=DEVICE=
{
  "ICMP": [
    {
      "name": "icmp-2",
      "uid": "id-2",
      "icmp-type": 2
    },
    {
      "name": "icmp-2-0",
      "uid": "id-2-0",
      "icmp-type": 2,
      "icmp-code": 0
    },
    {
      "name": "icmp-3-1",
      "uid": "id-3-1",
      "icmp-type": 3,
      "icmp-code": 1
    }
  ],
  "Rules": [
    [[idrule icmp-2]]
  ]
}
=NETSPOC=
{
  "ICMP": [
    {
      "name": "icmp-2-0",
      "icmp-type": 2
    },
    {
      "name": "icmp-3-1",
      "icmp-type": 3,
      "icmp-code": 1
    },
    {
      "name": "icmp-3-0",
      "icmp-type": 3,
      "icmp-code": 0
    },
    {
      "name": "icmp-19",
      "icmp-type": 19
    }
  ]
}
=OUTPUT=
set-service-icmp
{"uid":"id-2-0","icmp-type":2}
add-service-icmp
{"name":"icmp-3-0","icmp-type":3,"icmp-code":0}
add-service-icmp
{"name":"icmp-19","icmp-type":19}
delete-access-rule
{"layer":"network","uid":"id-icmp-2"}
delete-service-icmp
{"uid":"id-2"}
=END=
