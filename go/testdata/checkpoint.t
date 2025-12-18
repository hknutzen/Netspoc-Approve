=TEMPL=rule
{
  "name": "{{.}}",
  "action": "Accept",
  "source": ["Any"],
  "destination": ["Any"],
  "service": ["{{.}}"],
  "install-on": ["Policy Targets"]
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
  "install-on": ["Policy Targets"]
}
=END=

############################################################
=TITLE=Add simple rules to empty device
=DEVICE=
{"TargetPolicy": {"fw1": {"Name": "standard", "Layer": "network"}}}
=NETSPOC=
{"TargetRules": {"fw1": [
    [[rule http]],
    [[rule https]]
  ]}
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
 "install-on":["Policy Targets"],
 "position":"bottom"}
add-access-rule
{
 "name":"https",
 "layer":"network",
 "action":"Accept",
 "source":["Any"],
 "destination":["Any"],
 "service":["https"],
 "install-on":["Policy Targets"],
 "position":"bottom"}
=END=

############################################################
=TITLE=Remove simple rules from device
=DEVICE=
{
  "TargetPolicy": {"fw1": {"Name": "standard", "Layer": "network"}},
  "TargetRules": {"fw1": [
    [[idrule http]],
    [[idrule https]]
  ]}
}
=NETSPOC=
{
  "TargetRules": { "fw1": []}
}
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
  "TargetPolicy": {"fw1": {"Name": "standard", "Layer": "network"}},
  "TargetRules": {"fw1": [
    [[idrule http]],
    [[idrule smtp]]
  ]}
}
=NETSPOC=
{
  "TargetRules": {"fw1": [
    [[idrule https]]
  ]}
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
 "install-on":["Policy Targets"],
 "position":"bottom"}
delete-access-rule
{"layer":"network","uid":"id-smtp"}
=END=

############################################################
=TITLE=Add rule and new objects
=DEVICE=
{"TargetPolicy": {"fw1": {"Name": "standard", "Layer": "network"}}}
=NETSPOC=
{
  "TargetRules": {"fw1": [
    {
      "name": "test rule",
      "action": "Accept",
      "source": ["n_10.1.1.0-24", "n_10.1.2.0-24"],
      "destination": ["h_10.1.8.1", "h_10.1.9.9"],
      "service": ["tcp_81", "udp_123"],
      "install-on": ["Policy Targets"]
    }
  ]},
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
 "install-on":["Policy Targets"],
 "position":"bottom"}
=END=

############################################################
=TITLE=Delete rule and referenced objects
=DEVICE=
{
  "TargetPolicy": {"fw1": {"Name": "standard", "Layer": "network"}},
  "TargetRules": {"fw1": [
    {
      "name": "test rule",
      "uid": "id-test",
      "action": "Accept",
      "source": ["n_10.1.1.0-24", "n_10.1.2.0-24"],
      "destination": ["h_10.1.8.1", "h_10.1.9.9"],
      "service": ["tcp_81", "udp_123"],
      "install-on": ["Policy Targets"]
    }
 ]},
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
{
  "TargetRules": {"fw1": []}
}
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
  "TargetPolicy": {"fw1": {"Name": "standard", "Layer": "network"}},
  "TargetRules": {"fw1": [
    {
      "name": "test rule",
      "uid": "id-test",
      "action": "Accept",
      "source": ["DöMINET", "n_10.1.2.0-24"],
      "destination": ["h_10.1.8.1", "h_10.1.9.9"],
      "service": ["tcp_81", "udp_123"],
      "install-on": ["Policy Targets"]
    }
 ]},
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
  "TargetRules": {"fw1": [
    {
      "name": "test rule",
      "action": "Accept",
      "source": ["Döminet", "n_10.1.2.0-24", "n_10.1.3.0-24"],
      "destination": ["h_10.1.8.1", "h_10.1.9.1"],
      "service": ["tcp_81"],
      "install-on": ["Policy Targets"]
    }
 ]},
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
  "TargetPolicy": {"fw1": {"Name": "standard", "Layer": "network"}},
  "TargetRules": {"fw1": [
    [[idrule http]]
  ]}
}
=NETSPOC=
{
  "TargetRules": {"fw1": [
    [[rule https]],
    [[rule http]]
  ]}
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
 "install-on":["Policy Targets"],
 "position":{"above":"id-http"}}
=END=

############################################################
=TITLE=Append rule at bottom
=DEVICE=
{
  "TargetPolicy": {"fw1": {"Name": "standard", "Layer": "network"}},
  "TargetRules": {"fw1": [
    [[rule http]]
  ]}
}
=NETSPOC=
{
  "TargetRules": {"fw1": [
    [[rule http]],
    [[rule https]]
  ]}
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
 "install-on":["Policy Targets"],
 "position":"bottom"}
=END=

############################################################
=TITLE=Replace rule between unchanged rules
=DEVICE=
{
  "TargetPolicy": {"fw1": {"Name": "standard", "Layer": "network"}},
  "TargetRules": {"fw1": [
    [[idrule http]],
    [[idrule https]],
    [[idrule ldap]]
  ]}
}
=NETSPOC=
{
  "TargetRules": {"fw1": [
    [[rule http]],
    [[rule ssh]],
    [[rule ldap]]
  ]}
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
 "install-on":["Policy Targets"],
 "position":{"above":"id-ldap"}}
=END=

############################################################
=TITLE=Replace 2 by 3 rules after 1 unchanged
=DEVICE=
{
  "TargetPolicy": {"fw1": {"Name": "standard", "Layer": "network"}},
  "TargetRules": {"fw1": [
    [[idrule http]],
    [[idrule https]],
    [[idrule ldap]]
  ]}
}
=NETSPOC=
{
  "TargetRules": {"fw1": [
    [[rule http]],
    [[rule ssh]],
    [[rule smtp]],
    [[rule pop-3]]
  ]}
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
 "install-on":["Policy Targets"],
 "position":"bottom"}
add-access-rule
{
 "name":"smtp",
 "layer":"network",
 "action":"Accept",
 "source":["Any"],
 "destination":["Any"],
 "service":["smtp"],
 "install-on":["Policy Targets"],
 "position":"bottom"}
add-access-rule
{
 "name":"pop-3",
 "layer":"network",
 "action":"Accept",
 "source":["Any"],
 "destination":["Any"],
 "service":["pop-3"],
 "install-on":["Policy Targets"],
 "position":"bottom"}
=END=

############################################################
=TITLE=Replace last rule
=DEVICE=
{
  "TargetPolicy": {"fw1": {"Name": "standard", "Layer": "network"}},
  "TargetRules": {"fw1": [
    [[idrule http]],
    [[idrule https]]
  ]}
}
=NETSPOC=
{
  "TargetRules": {"fw1": [
    [[rule http]],
    [[rule ssh]]
  ]}
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
 "install-on":["Policy Targets"],
 "position":"bottom"}
=END=

############################################################
=TITLE=Replace single rule
=DEVICE=
{
  "TargetPolicy": {"fw1": {"Name": "standard", "Layer": "network"}},
  "TargetRules": {"fw1": [
    [[idrule https]]
  ]}
}
=NETSPOC=
{
  "TargetRules": {"fw1": [
    [[rule ssh]]
  ]}
}
=OUTPUT=
add-access-rule
{
 "name":"ssh",
 "layer":"network",
 "action":"Accept",
 "source":["Any"],
 "destination":["Any"],
 "service":["ssh"],
 "install-on":["Policy Targets"],
 "position":"bottom"}
delete-access-rule
{"layer":"network","uid":"id-https"}
=END=

############################################################
=TITLE=Change typically unused attributes
=DEVICE=
{
  "TargetPolicy": {"fw1": {"Name": "standard", "Layer": "network"}},
  "TargetRules": {"fw1": [
    {
      "name": "test",
      "uid": "id-test",
      "action": "Accept",
      "comments": "Some comment",
      "source-negate": true,
      "destination-negate": true,
      "service-negate": true,
      "enabled": false,
      "install-on": ["Policy Targets"]
    }
  ]}
}
=NETSPOC=
{
  "TargetRules": {"fw1": [
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
      "install-on": ["Policy Targets"]
    }
  ]}
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
  "TargetPolicy": {"fw1": {"Name": "standard", "Layer": "network"}},
  "TargetRules": {"fw1": [
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
      "install-on": ["Policy Targets"]
    }
  ]}
}
=NETSPOC=
{
  "TargetRules": {"fw1": [
    {
      "name": "test",
      "action": "Accept",
      "track":{"alert":"none","per-connection":true,"type":"Log"},
      "install-on": ["Policy Targets"]
    }
  ]}
}
=OUTPUT=NONE

############################################################
=TITLE=Changed attribute track
=DEVICE=
{
  "TargetPolicy": {"fw1": {"Name": "standard", "Layer": "network"}},
  "TargetRules": {"fw1": [
    {
      "name": "test",
      "uid": "id-test",
      "action": "Accept",
      "track":{"alert":"none","per-connection":false,"type":"Log"},
      "install-on": ["Policy Targets"]
    }
  ]}
}
=NETSPOC=
{
  "TargetRules": {"fw1": [
    {
      "name": "test",
      "action": "Accept",
      "track":{"alert":"mail","per-connection":true,"type":"None"},
      "install-on": ["Policy Targets"]
    }
  ]}
}
=OUTPUT=
set-access-rule
{"layer":"network","track":{"alert":"mail","per-connection":true,"type":"None"},"uid":"id-test"}
=END=

############################################################
=TITLE=Invalid value in attribute "install-on"
=DEVICE=
{
  "TargetPolicy": {"fw1": {"Name": "standard", "Layer": "network"}},
  "TargetRules": {"fw1": [
    {
      "name": "http",
      "uid": "id-http",
      "action": "Accept",
      "source": ["Any"],
      "destination": ["Any"],
      "service": ["http"],
      "install-on": ["other-fw"]
    }
  ]}
}
=NETSPOC=
{"TargetRules": {"fw1": []}}
=ERROR=
ERROR>>> Must use "install-on": ["Policy Targets"] in rule "http" of "fw1"
=END=

############################################################
=TITLE=Too many values in attribute "install-on"
=DEVICE=
{
  "TargetPolicy": {"fw1": {"Name": "standard", "Layer": "network"}},
  "TargetRules": {"fw1": [
    {
      "name": "http",
      "uid": "id-http",
      "action": "Accept",
      "source": ["Any"],
      "destination": ["Any"],
      "service": ["http"],
      "install-on": ["Policy Targets", "other-fw"]
    }
  ]}
}
=NETSPOC=
{"TargetRules": {"fw1": []}}
=ERROR=
ERROR>>> Must use "install-on": ["Policy Targets"] in rule "http" of "fw1"
=END=

############################################################
=TITLE=Valid name used in attribute "install-on"
=DEVICE=
{
  "TargetPolicy": {"fw1": {"Name": "standard", "Layer": "network"}},
  "TargetRules": {"fw1": [
    {
      "name": "http",
      "uid": "id-http",
      "action": "Accept",
      "source": ["Any"],
      "destination": ["Any"],
      "service": ["http"],
      "install-on": ["fw1"]
    }
  ]}
}
=NETSPOC=
{"TargetRules": {"fw1": []}}
=OUTPUT=
delete-access-rule
{"layer":"network","uid":"id-http"}
=END=

############################################################
=TITLE=Missing policy package on device
=DEVICE=
{}
=NETSPOC=
{"TargetRules": {"fw1": []}}
=ERROR=
ERROR>>> Missing policy package for target "fw1"
=END=

############################################################
=TITLE=Identical rule name in different layers
=DEVICE=
{
  "TargetPolicy": {"fw1": {"Name": "p1", "Layer": "layer1"},
                   "fw2": {"Name": "p2", "Layer": "layer2"}},
  "TargetRules": {
    "fw1": [{
      "name": "http",
      "uid": "id-http",
      "action": "Accept",
      "source": ["Any"],
      "destination": ["Any"],
      "service": ["http"],
      "install-on": ["Policy Targets"]
    }],
    "fw2": [{
      "name": "http",
      "uid": "id-http2",
      "action": "Accept",
      "source": ["Any"],
      "destination": ["Any"],
      "service": ["http"],
      "install-on": ["Policy Targets"]
    }]
  }
}
=NETSPOC=
{
  "TargetRules": {
    "fw2": [{
      "name": "http",
      "action": "Accept",
      "source": ["Any"],
      "destination": ["Any"],
      "service": ["http"],
      "install-on": ["Policy Targets"]
    }],
    "fw1": [{
      "name": "http",
      "action": "Accept",
      "source": ["Any"],
      "destination": ["Any"],
      "service": ["http"],
      "install-on": ["Policy Targets"]
    }]
  }
}
=OUTPUT=NONE

############################################################
=TITLE=Change attributes of referenced objects
=TEMPL=input
{
  "TargetPolicy": {"fw1": {"Name": "standard", "Layer": "network"}},
  "TargetRules": {"fw1": [
    {
      "name": "test rule",
      "uid": "id-test",
      "action": "Accept",
      "source": ["my-group"],
      "destination": ["my-host"],
      "service": ["my-srv"],
      "install-on": ["Policy Targets"]
    }
  ]},
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
  "TargetPolicy": {"fw1": {"Name": "standard", "Layer": "network"}},
  "TargetRules": {"fw1": [
    {
      "name": "echo-reply",
      "uid": "id-echo-reply",
      "action": "Accept",
      "source": ["Any"],
      "destination": ["Any"],
      "service": ["redirect"],
      "install-on": ["Policy Targets"]
    },
    [[idrule source-quench]]
  ]}
}
=NETSPOC=
{
  "TargetRules": {"fw1": [
    [[rule echo-reply]],
    [[rule dest-unreach]]
  ]}
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
 "install-on":["Policy Targets"],
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
  "TargetPolicy": {"fw1": {"Name": "standard", "Layer": "network"}},
  "TargetRules": {"fw1": [
    [[idrule icmp-2]]
  ]}
}
=NETSPOC=
{
  "TargetRules": {"fw1": []},
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

############################################################
=TITLE=Add and delete user defined ICMP6 object
=DEVICE=
{
  "ICMP6": [
    {
      "name": "icmp-2",
      "uid": "id-2",
      "icmp-type": 2
    }
  ],
  "TargetPolicy": {"fw1": {"Name": "standard", "Layer": "network"}},
  "TargetRules": {"fw1": [
    [[idrule icmp-2]]
  ]}
}
=NETSPOC=
{
  "TargetRules": {"fw1": []},
  "ICMP6": [
    {
      "name": "icmp-19",
      "icmp-type": 19
    }
  ]
}
=OUTPUT=
add-service-icmp6
{"name":"icmp-19","icmp-type":19}
delete-access-rule
{"layer":"network","uid":"id-icmp-2"}
delete-service-icmp6
{"uid":"id-2"}
=END=

############################################################
=TITLE=Add and delete user defined service other
=DEVICE=
{
  "SvOther": [
    {
      "name": "New_Service_1",
      "uid": "id-1",
      "ip-protocol" : 51
    }
  ],
  "TargetPolicy": {"fw1": {"Name": "standard", "Layer": "network"}},
  "TargetRules": {"fw1": [
    [[idrule New_Service_1]]
  ]}
}
=NETSPOC=
{
  "TargetRules": {"fw1": []},
  "SvOther": [
    {
      "name": "New_Service_2",
      "ip-protocol" : 52
    }
  ]
}
=OUTPUT=
add-service-other
{"name":"New_Service_2","ip-protocol":52}
delete-access-rule
{"layer":"network","uid":"id-New_Service_1"}
delete-service-other
{"uid":"id-1"}
=END=
