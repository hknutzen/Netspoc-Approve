=TEMPL=simple
{
  "name": "{{.}}",
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
    [[simple http]],
    [[simple https]]
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
    [[simple http]],
    [[simple https]]
  ]
}
=NETSPOC=
{}
=OUTPUT=
delete-access-rule
{"layer":"network","name":"http"}
delete-access-rule
{"layer":"network","name":"https"}
=END=

############################################################
=TITLE=Replace simple rule
=DEVICE=
{
  "Rules": [
    [[simple http]]
  ]
}
=NETSPOC=
{
  "Rules": [
    [[simple https]]
  ]
}
=OUTPUT=
delete-access-rule
{"layer":"network","name":"http"}
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
{"name":"n_10.1.1.0-24","subnet4":"10.1.1.0","mask-length4":24}
add-network
{"name":"n_10.1.2.0-24","subnet4":"10.1.2.0","mask-length4":24}
add-host
{"name":"h_10.1.8.1","ipv4-address":"10.1.8.1"}
add-host
{"name":"h_10.1.9.9","ipv4-address":"10.1.9.9"}
add-service-tcp
{"name":"tcp_81","port":"81"}
add-service-udp
{"name":"udp_123","port":"123"}
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
 "name":"test rule"}
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
{"name":"n_10.1.3.0-24","subnet4":"10.1.3.0","mask-length4":24}
add-host
{"name":"h_10.1.9.3","ipv4-address":"10.1.9.3"}
set-access-rule
{"destination":["h_10.1.8.1","h_10.1.9.1"],
 "name":"test rule",
 "service":{"remove":["udp_123"]},
 "source":{"add":["n_10.1.3.0-24"]}}
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
    [[simple http]]
    ]
}
=NETSPOC=
{
  "Rules": [
    [[simple https]],
    [[simple http]]
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
    [[simple http]]
  ]
}
=NETSPOC=
{
  "Rules": [
    [[simple http]],
    [[simple https]]
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
    [[simple http]],
    [[simple https]],
    [[simple ldap]]
  ]
}
=NETSPOC=
{
  "Rules": [
    [[simple http]],
    [[simple ssh]],
    [[simple ldap]]
  ]
}
=OUTPUT=
delete-access-rule
{"layer":"network","name":"https"}
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
    [[simple http]],
    [[simple https]],
    [[simple ldap]]
  ]
}
=NETSPOC=
{
  "Rules": [
    [[simple http]],
    [[simple ssh]],
    [[simple smtp]],
    [[simple pop-3]]
  ]
}
=OUTPUT=
delete-access-rule
{"layer":"network","name":"https"}
delete-access-rule
{"layer":"network","name":"ldap"}
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
    [[simple http]],
    [[simple https]]
  ]
}
=NETSPOC=
{
  "Rules": [
    [[simple http]],
    [[simple ssh]]
  ]
}
=OUTPUT=
delete-access-rule
{"layer":"network","name":"https"}
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
=TITLE=Change attribute "install-on"
=DEVICE=
{
  "Rules": [
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
{"layer":"network","name":"http"}
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
