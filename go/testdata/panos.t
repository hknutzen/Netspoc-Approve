=TEMPL=prefix
<config><devices><entry name="localhost.localdomain"><vsys><entry name="{{.}}">
=TEMPL=postfix
</entry></vsys></entry></devices></config>
=END=

=TEMPL=rules
<rulebase><security><rules>
{{range .}}
<entry name="{{.name}}">
<action>{{or .action "allow"}}</action>
<from><member>{{or .from "z1"}}</member></from>
<to><member>{{or .to "z2"}}</member></to>
{{range .src}}<source><member>{{.}}</member></source>{{end}}
{{range .dst}}<destination><member>{{.}}</member></destination>{{end}}
{{range .srv}}<service><member>{{.}}</member></service>{{end}}
<application><member>any</member></application>
<rule-type>interzone</rule-type>
<log-start>yes</log-start>
<log-end>yes</log-end>
{{if .extra}}{{.extra}}{{end}}
</entry>
{{end}}
</rules></security></rulebase>
=END=

=TEMPL=groups
<address-group>
{{range .}}
<entry name="{{.name}}"><static>
{{range .members}}<member>{{.}}</member>{{end}}
</static></entry>
{{end}}
</address-group>
=END=

=TEMPL=addresses
<address>
{{range .}}
<entry name="{{.name}}"><ip-netmask>{{.ip}}</ip-netmask></entry>
{{end}}
</address>
=END=

=TEMPL=services
<service>
{{range .}}
<entry name="{{.proto}} {{.port}}"><protocol><{{.proto}}><port>{{.port}}</port></{{.proto}}></protocol></entry>
{{end}}
</service>

=TEMPL=input
[[prefix vsys2]]
[[rules
- name: r1
  src: [g0]
  dst: [NET_10.1.3.0_24, NET_10.1.2.0_24]
  srv: [udp 123, tcp 80]]]
[[groups
- {name: g0, members: [IP_10.1.1.20, IP_10.1.1.10]}
]]
[[addresses
- {name: IP_10.1.1.10, ip: 10.1.1.10/32}
- {name: IP_10.1.1.20, ip: 10.1.1.20/32}
- {name: NET_10.1.2.0_24, ip: 10.1.2.0/24}
- {name: NET_10.1.3.0_24, ip: 10.1.3.0/24}
]]
[[services
- {proto: tcp, port: 80}
- {proto: udp, port: 123}
]]
[[postfix]]
=END=

############################################################
=TITLE=No differences
=DEVICE=[[input]]
=NETSPOC=[[input]]
=OUTPUT=NONE

############################################################
=TITLE=Only group names differ
=DEVICE=[[input]]
=SUBST=/g0/g2/
=NETSPOC=[[input]]
=OUTPUT=NONE

############################################################
=TITLE=Change service
=DEVICE=[[input]]
=SUBST=|<member>udp 123</member>||
=NETSPOC=[[input]]
=SUBST=|<member>tcp 80</member>||
=SUBST=/g0/g2/
=OUTPUT=
action=delete&type=config&
 xpath=
  /config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/rulebase/security/rules/entry[@name='r1']
action=set&type=config&
 xpath=
  /config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/rulebase/security/rules/entry[@name='r1-1']&
 element=
  <action>allow</action>
  <from><member>z1</member></from>
  <to><member>z2</member></to>
  <source><member>g0</member></source>
  <destination>
   <member>NET_10.1.2.0_24</member>
   <member>NET_10.1.3.0_24</member>
  </destination>
  <service><member>udp 123</member></service>
  <application><member>any</member></application>
  <log-start>yes</log-start>
  <log-end>yes</log-end>
  <rule-type>interzone</rule-type>
action=delete&type=config&
 xpath=
  /config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/service/entry[@name='tcp 80']
=END=

############################################################
=TITLE=Add element to group
=DEVICE=[[input]]
=SUBST=|<member>IP_10.1.1.10</member>||
=NETSPOC=[[input]]
=OUTPUT=
action=set&type=config&
 xpath=
  /config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/address-group/entry[@name='g0']
  /static&
 element=
  <member>IP_10.1.1.10</member>
=END=

############################################################
=TITLE=Remove element from group
=DEVICE=[[input]]
=NETSPOC=[[input]]
=SUBST=|<member>IP_10.1.1.10</member>||
=OUTPUT=
action=delete&type=config&
 xpath=
  /config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/address-group/entry[@name='g0']
  /static/member[text()='IP_10.1.1.10']
action=delete&type=config&
 xpath=
  /config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/address/entry[@name='IP_10.1.1.10']
=END=

############################################################
=TITLE=Add element to destination
=DEVICE=[[input]]
=SUBST=|<member>NET_10.1.2.0_24</member>||
=NETSPOC=[[input]]
=OUTPUT=
action=set&type=config&
 xpath=
  /config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/rulebase/security/rules/entry[@name='r1']
  /destination&
 element=
  <member>NET_10.1.2.0_24</member>
=END=

############################################################
=TITLE=Remove element from destination
=DEVICE=[[input]]
=NETSPOC=[[input]]
=SUBST=|<member>NET_10.1.2.0_24</member>||
=OUTPUT=
action=delete&type=config&
 xpath=
  /config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/rulebase/security/rules/entry[@name='r1']
  /destination/member[text()='NET_10.1.2.0_24']
action=delete&type=config&
 xpath=
  /config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/address/entry[@name='NET_10.1.2.0_24']
=END=

############################################################
=TITLE=Add to empty device
=DEVICE=
[[prefix vsys2]]
[[postfix]]
=NETSPOC=
[[input]]
=OUTPUT=
action=set&type=config&
 xpath=
 /config/devices/entry[@name='localhost.localdomain']
 /vsys/entry[@name='vsys2']/address/entry[@name='IP_10.1.1.10']&
 element=
 <ip-netmask>10.1.1.10/32</ip-netmask>
action=set&type=config&
 xpath=/config/devices/entry[@name='localhost.localdomain']
 /vsys/entry[@name='vsys2']/address/entry[@name='IP_10.1.1.20']&
 element=
 <ip-netmask>10.1.1.20/32</ip-netmask>
action=set&type=config&
 xpath=
 /config/devices/entry[@name='localhost.localdomain']
 /vsys/entry[@name='vsys2']/address/entry[@name='NET_10.1.2.0_24']&
 element=
 <ip-netmask>10.1.2.0/24</ip-netmask>
action=set&type=config&
 xpath=
 /config/devices/entry[@name='localhost.localdomain']
 /vsys/entry[@name='vsys2']/address/entry[@name='NET_10.1.3.0_24']&
 element=
 <ip-netmask>10.1.3.0/24</ip-netmask>
action=set&type=config&
 xpath=
 /config/devices/entry[@name='localhost.localdomain']
 /vsys/entry[@name='vsys2']/address-group/entry[@name='g0']/static&
 element=
  <member>IP_10.1.1.10</member>
  <member>IP_10.1.1.20</member>
action=set&type=config&
 xpath=
 /config/devices/entry[@name='localhost.localdomain']
 /vsys/entry[@name='vsys2']/service/entry[@name='tcp 80']&
 element=
 <protocol>
  <tcp>
   <port>
    80
   </port>
  </tcp>
 </protocol>
action=set&type=config&
 xpath=
 /config/devices/entry[@name='localhost.localdomain']
 /vsys/entry[@name='vsys2']/service/entry[@name='udp 123']&
 element=
 <protocol><udp><port>123</port></udp></protocol>
action=set&type=config&
 xpath=
 /config/devices/entry[@name='localhost.localdomain']
 /vsys/entry[@name='vsys2']/rulebase/security/rules/entry[@name='r1']&
 element=
 <action>allow</action>
 <from><member>z1</member></from>
 <to><member>z2</member></to>
 <source><member>g0</member></source>
 <destination>
  <member>NET_10.1.2.0_24</member>
  <member>NET_10.1.3.0_24</member>
 </destination>
 <service>
  <member>tcp 80</member>
  <member>udp 123</member>
 </service>
 <application><member>any</member></application>
 <log-start>yes</log-start>
 <log-end>yes</log-end>
 <rule-type>interzone</rule-type>
=END=

############################################################
=TITLE=Remove all from device
=DEVICE=
[[input]]
=NETSPOC=
[[prefix vsys2]]
[[postfix]]
=OUTPUT=
action=delete&type=config&
 xpath=
  /config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/rulebase/security/rules/entry[@name='r1']
action=delete&type=config&
 xpath=
  /config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/address-group/entry[@name='g0']
action=delete&type=config&
 xpath=
  /config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/address/entry[@name='IP_10.1.1.10']
action=delete&type=config&
 xpath=
  /config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/address/entry[@name='IP_10.1.1.20']
action=delete&type=config&
 xpath=
  /config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/address/entry[@name='NET_10.1.2.0_24']
action=delete&type=config&
 xpath=
  /config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/address/entry[@name='NET_10.1.3.0_24']
action=delete&type=config&
 xpath=
  /config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/service/entry[@name='tcp 80']
action=delete&type=config&
 xpath=
  /config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/service/entry[@name='udp 123']
=END=

############################################################
=TITLE=Change group to elements
=DEVICE=[[input]]
=NETSPOC=[[input]]
=SUBST=|<member>g0</member>|<member>IP_10.1.1.10</member><member>IP_10.1.1.20</member>|
=OUTPUT=
action=delete&type=config&
 xpath=
  /config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/rulebase/security/rules/entry[@name='r1']
action=set&type=config&
 xpath=
  /config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/rulebase/security/rules/entry[@name='r1-1']&
  element=
  <action>allow</action>
  <from><member>z1</member></from>
  <to><member>z2</member></to>
  <source><member>IP_10.1.1.10</member><member>IP_10.1.1.20</member></source>
  <destination><member>NET_10.1.2.0_24</member><member>NET_10.1.3.0_24</member></destination>
  <service><member>tcp 80</member><member>udp 123</member></service>
  <application><member>any</member></application>
  <log-start>yes</log-start><log-end>yes</log-end>
  <rule-type>interzone</rule-type>
action=delete&type=config&
 xpath=
  /config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/address-group/entry[@name='g0']
=END=

############################################################
# Used for multiple tests
=TEMPL=identical
[[addresses
- {name: IP_10.1.1.10, ip: 10.1.1.10/32}
- {name: IP_10.1.1.20, ip: 10.1.1.20/32}
- {name: NET_10.1.2.0_24, ip: 10.1.2.0/24}
- {name: NET_10.1.3.0_24, ip: 10.1.3.0/24}
]]
[[services
- {proto: tcp, port: 80}
- {proto: udp, port: 123}
]]
[[postfix]]
=END=

############################################################
=TITLE=Merge two groups to one
=DEVICE=
[[prefix vsys2]]
[[rules
- {name: r1, src: [g0], dst: [NET_10.1.2.0_24], srv: [tcp 80]}
- {name: r2, src: [g1], dst: [NET_10.1.3.0_24], srv: [udp 123]}
]]
[[groups
- {name: g0, members: [IP_10.1.1.10]}
- {name: g1, members: [IP_10.1.1.20]}
]]
[[identical]]
=NETSPOC=
[[prefix vsys2]]
[[rules
- {name: r1, src: [g2], dst: [NET_10.1.2.0_24], srv: [tcp 80]}
- {name: r2, src: [g2], dst: [NET_10.1.3.0_24], srv: [udp 123]}
]]
[[groups
- {name: g2, members: [IP_10.1.1.10, IP_10.1.1.20]}
]]
[[identical]]
=OUTPUT=
action=set&type=config&
 xpath=
  /config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/address-group/entry[@name='g0']/static&
  element=
  <member>IP_10.1.1.20</member>
action=edit&type=config&
 xpath=
  /config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/rulebase/security/rules/entry[@name='r2']/source&
  element=
  <member>g0</member>
action=delete&type=config&
 xpath=
  /config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/address-group/entry[@name='g1']
=END=

############################################################
=TITLE=Split single group to different ones
=DEVICE=
[[prefix vsys2]]
[[rules
- {name: r1, src: [g0], dst: [NET_10.1.2.0_24], srv: [tcp 80]}
- {name: r2, src: [g0], dst: [NET_10.1.3.0_24], srv: [udp 123]}
]]
[[groups
- {name: g0, members: [IP_10.1.1.20, IP_10.1.1.10]}
]]
[[identical]]
=NETSPOC=
[[prefix vsys2]]
[[rules
- {name: r1, src: [g1], dst: [NET_10.1.2.0_24], srv: [tcp 80]}
- {name: r2, src: [g2], dst: [NET_10.1.3.0_24], srv: [udp 123]}
]]
[[groups
- {name: g1, members: [IP_10.1.1.20]}
- {name: g2, members: [IP_10.1.1.10]}
]]
[[identical]]
=OUTPUT=
action=set&type=config&
 xpath=
  /config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/address-group/entry[@name='g2']/static&
 element=
  <member>IP_10.1.1.10</member>
action=delete&type=config&
 xpath=
  /config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/address-group/entry[@name='g0']
  /static/member[text()='IP_10.1.1.10']
action=edit&type=config&
 xpath=
  /config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/rulebase/security/rules/entry[@name='r2']/source&
 element=
  <member>g2</member>
=END=

############################################################
# Changed for tests below
=TEMPL=identical
[[addresses
- {name: IP_10.1.1.10, ip: 10.1.1.10/32}
- {name: IP_10.1.1.20, ip: 10.1.1.20/32}
- {name: NET_10.1.2.0_24, ip: 10.1.2.0/24}
- {name: NET_10.1.3.0_24, ip: 10.1.3.0/24}
]]
[[services
- {proto: tcp, port: 80}
]]
[[postfix]]
=END=

############################################################
=TITLE=Add new elements to group in one go
=DEVICE=
[[prefix vsys2]]
[[rules
- {name: r1, src: [g1], dst: [NET_10.1.2.0_24], srv: [tcp 80]}
]]
[[groups
- {name: g1, members: [IP_10.1.1.20]}
]]
[[identical]]
=NETSPOC=
[[prefix vsys2]]
[[rules
- {name: r1, src: [g1], dst: [NET_10.1.2.0_24], srv: [tcp 80]}
]]
[[groups
- {name: g1, members: [IP_10.1.1.10, IP_10.1.1.20, NET_10.1.3.0_24]}
]]
[[identical]]
=OUTPUT=
action=set&type=config&
 xpath=
  /config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/address-group/entry[@name='g1']/static&
  element=
   <member>IP_10.1.1.10</member>
   <member>NET_10.1.3.0_24</member>
=END=

############################################################
# Changed for tests below
=TEMPL=identical
[[addresses
- {name: IP_10.1.1.1, ip: 10.1.1.1/32}
- {name: IP_10.1.1.2, ip: 10.1.1.2/32}
- {name: IP_10.1.1.3, ip: 10.1.1.3/32}
- {name: IP_10.1.1.4, ip: 10.1.1.4/32}
- {name: IP_10.1.1.5, ip: 10.1.1.5/32}
- {name: NET_10.1.2.0_24, ip: 10.1.2.0/24}
]]
[[services
- {proto: tcp, port: 80}
]]
[[postfix]]
=END=

############################################################
=TITLE=Create new group instead of deleting many elements
=DEVICE=
[[prefix vsys2]]
[[rules
- {name: r1, src: [g1], dst: [NET_10.1.2.0_24], srv: [tcp 80]}
]]
[[groups
- name: g1
  members: [IP_10.1.1.1, IP_10.1.1.2, IP_10.1.1.3, IP_10.1.1.4, IP_10.1.1.5]
]]
[[identical]]
=NETSPOC=
[[prefix vsys2]]
[[rules
- {name: r1, src: [g1], dst: [NET_10.1.2.0_24], srv: [tcp 80]}
]]
[[groups
- {name: g1, members: [IP_10.1.1.1, IP_10.1.1.2]}
]]
[[identical]]
=OUTPUT=
action=set&type=config&
 xpath=
  /config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/address-group/entry[@name='g1-1']/static&
  element=
   <member>IP_10.1.1.1</member>
   <member>IP_10.1.1.2</member>
action=edit&type=config&
 xpath=
  /config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/rulebase/security/rules/entry[@name='r1']/source&
  element=
   <member>g1-1</member>
action=delete&type=config&
 xpath=
  /config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/address-group/entry[@name='g1']
action=delete&type=config&
 xpath=
  /config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/address/entry[@name='IP_10.1.1.3']
action=delete&type=config&
 xpath=
  /config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/address/entry[@name='IP_10.1.1.4']
action=delete&type=config&
 xpath=
  /config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/address/entry[@name='IP_10.1.1.5']
=END=

############################################################
=TITLE=Transfer elements to rule instead of deleting and inserting
=DEVICE=
[[prefix vsys2]]
[[rules
- name: r1
  src: [IP_10.1.1.1, IP_10.1.1.2, IP_10.1.1.3, IP_10.1.1.4, IP_10.1.1.5]
  dst: [NET_10.1.2.0_24]
  srv: [tcp 80]
]]
[[identical]]
=NETSPOC=
[[prefix vsys2]]
[[rules
- name: r1
  src: [IP_10.1.1.1, IP_10.1.1.2]
  dst: [NET_10.1.2.0_24]
  srv: [tcp 80]
]]
[[identical]]
=OUTPUT=
action=edit&type=config&
 xpath=/config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/rulebase/security/rules/entry[@name='r1']/source&
 element=
   <member>IP_10.1.1.1</member>
   <member>IP_10.1.1.2</member>
action=delete&type=config&
 xpath=/config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/address/entry[@name='IP_10.1.1.3']
action=delete&type=config&
 xpath=/config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/address/entry[@name='IP_10.1.1.4']
action=delete&type=config&
 xpath=/config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/address/entry[@name='IP_10.1.1.5']
=END=

############################################################
=TITLE=Adapt elements in rule by deleting and inserting
=DEVICE=
[[prefix vsys2]]
[[rules
- name: r1
  src: [IP_10.1.1.2, IP_10.1.1.3, IP_10.1.1.4, IP_10.1.1.5]
  dst: [NET_10.1.2.0_24]
  srv: [tcp 80]
]]
[[identical]]
=NETSPOC=
[[prefix vsys2]]
[[rules
- name: r1
  src: [IP_10.1.1.1, IP_10.1.1.2, IP_10.1.1.4, IP_10.1.1.5]
  dst: [NET_10.1.2.0_24]
  srv: [tcp 80]
]]
[[identical]]
=OUTPUT=
action=delete&type=config&
 xpath=/config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/rulebase/security/rules/entry[@name='r1']
  /source/member[text()='IP_10.1.1.3']
action=set&type=config&
 xpath=/config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/rulebase/security/rules/entry[@name='r1']
  /source&element=<member>IP_10.1.1.1</member>
action=delete&type=config&
 xpath=/config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/address/entry[@name='IP_10.1.1.3']
=END=

############################################################
=TITLE=Delete multiple elements from rule
=DEVICE=
[[prefix vsys2]]
[[rules
- name: r1
  src: [IP_10.1.1.1, IP_10.1.1.2, IP_10.1.1.3, IP_10.1.1.4, IP_10.1.1.5]
  dst: [NET_10.1.2.0_24]
  srv: [tcp 80]
]]
[[identical]]
=NETSPOC=
[[prefix vsys2]]
[[rules
- name: r1
  src: [IP_10.1.1.1, IP_10.1.1.3, IP_10.1.1.5]
  dst: [NET_10.1.2.0_24]
  srv: [tcp 80]
]]
[[identical]]
=OUTPUT=
action=delete&type=config&
 xpath=/config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/rulebase/security/rules/entry[@name='r1']
  /source/member[text()='IP_10.1.1.2']
action=delete&type=config&
 xpath=/config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/rulebase/security/rules/entry[@name='r1']
  /source/member[text()='IP_10.1.1.4']
action=delete&type=config&
 xpath=/config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/address/entry[@name='IP_10.1.1.2']
action=delete&type=config&
 xpath=/config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/address/entry[@name='IP_10.1.1.4']
=END=

############################################################
# Changed for tests below
=TEMPL=identical
[[prefix vsys2]]
[[rules
- name: r1
  from: z1
  to:   z2
  src: [IP_10.1.1.1]
  dst: [NET_10.1.2.0_24]
  srv: [tcp 80]
- name: r2
  from: z1
  to:   z2
  action: drop
  src: [any]
  dst: [any]
  srv: [any]
- name: r3
  from: z2
  to:   z1
  src:  [NET_10.1.2.0_24]
  dst:  [IP_10.1.1.1]
  srv: [tcp 80]
- name: r4
  from: z2
  to:   z1
  action: drop
  src: [any]
  dst: [any]
  srv: [any]
]]
[[addresses
- {name: IP_10.1.1.1, ip: 10.1.1.1/32}
- {name: NET_10.1.2.0_24, ip: 10.1.2.0/24}
]]
[[services
- {proto: tcp, port: 80}
]]
=END=

=TEMPL=raw
[[rules
- name: raw1
  from: z1
  to:   z2
  src: [RANGE_10.1.1.3-7]
  dst: [NET_10.1.2.0_24]
  srv: [tcp 81]
- name: raw-log1
  from: z1
  to:   z2
  action: drop
  src: [any]
  dst: [any]
  srv: [any]
  extra: "<log-setting>TDC-Panorama</log-setting><APPEND/>"
- name: raw-log2
  from: z2
  to:   z1
  action: drop
  src: [any]
  dst: [any]
  srv: [any]
  extra: "<log-setting>TDC-Panorama</log-setting><APPEND/>"
]]
<address>
<entry name="RANGE_10.1.1.3-7"><ip-range>10.1.1.3-10.1.1.7</ip-range></entry>
</address>
[[services
- {proto: tcp, port: 81}
]]
=END=

############################################################
=TITLE=Add rules from raw
=DEVICE=
[[identical]]
[[postfix]]
=NETSPOC=
-- router
[[identical]]
[[postfix]]
-- router.raw
[[prefix vsys2]]
[[raw]]
[[postfix]]
=OUTPUT=
action=set&type=config&
 xpath=/config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/address/entry[@name='RANGE_10.1.1.3-7']&
 element=<ip-range>10.1.1.3-10.1.1.7</ip-range>
action=set&type=config&
 xpath=/config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/service/entry[@name='tcp 81']&
 element=<protocol><tcp><port>81</port></tcp></protocol>
action=set&type=config&
 xpath=/config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/rulebase/security/rules/entry[@name='raw1']&
 element=
  <action>allow</action>
  <from><member>z1</member></from>
  <to><member>z2</member></to>
  <source><member>RANGE_10.1.1.3-7</member></source>
  <destination><member>NET_10.1.2.0_24</member></destination>
  <service><member>tcp 81</member></service>
  <application><member>any</member></application>
  <log-start>yes</log-start>
  <log-end>yes</log-end>
  <rule-type>interzone</rule-type>
action=move&type=config&
 xpath=/config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/rulebase/security/rules/entry[@name='raw1']&
 where=before&dst=r1
action=set&type=config&
 xpath=/config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/rulebase/security/rules/entry[@name='raw-log1']&
 element=
  <action>drop</action>
  <from><member>z1</member></from>
  <to><member>z2</member></to>
  <source><member>any</member></source>
  <destination><member>any</member></destination>
  <service><member>any</member></service>
  <application><member>any</member></application>
  <log-start>yes</log-start>
  <log-end>yes</log-end>
  <log-setting>TDC-Panorama</log-setting>
  <rule-type>interzone</rule-type>
action=move&type=config&
 xpath=/config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/rulebase/security/rules/entry[@name='raw-log1']&
 where=before&dst=r2
action=set&type=config&
 xpath=/config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/rulebase/security/rules/entry[@name='raw-log2']&
 element=
  <action>drop</action>
  <from><member>z2</member></from>
  <to><member>z1</member></to>
  <source><member>any</member></source>
  <destination><member>any</member></destination>
  <service><member>any</member></service>
  <application><member>any</member></application>
  <log-start>yes</log-start>
  <log-end>yes</log-end>
  <log-setting>TDC-Panorama</log-setting>
  <rule-type>interzone</rule-type>
action=move&type=config&
 xpath=/config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/rulebase/security/rules/entry[@name='raw-log2']&
 where=before&dst=r4
=END=

############################################################
=TITLE=Recognize rules from raw already on device
=DEVICE=
[[prefix vsys2]]
[[rules
- name: raw1
  from: z1
  to:   z2
  src: [RANGE_10.1.1.3-7]
  dst: [NET_10.1.2.0_24]
  srv: [tcp 81]
- name: r1
  from: z1
  to:   z2
  src: [IP_10.1.1.1]
  dst: [NET_10.1.2.0_24]
  srv: [tcp 80]
- name: raw-log1
  from: z1
  to:   z2
  action: drop
  src: [any]
  dst: [any]
  srv: [any]
  extra: "<log-setting>TDC-Panorama</log-setting>"
- name: r2
  from: z1
  to:   z2
  action: drop
  src: [any]
  dst: [any]
  srv: [any]
- name: r3
  from: z2
  to:   z1
  src:  [NET_10.1.2.0_24]
  dst:  [IP_10.1.1.1]
  srv: [tcp 80]
- name: raw-log2
  from: z2
  to:   z1
  action: drop
  src: [any]
  dst: [any]
  srv: [any]
  extra: "<log-setting>TDC-Panorama</log-setting>"
- name: r4
  from: z2
  to:   z1
  action: drop
  src: [any]
  dst: [any]
  srv: [any]
]]
[[addresses
- {name: IP_10.1.1.1, ip: 10.1.1.1/32}
- {name: NET_10.1.2.0_24, ip: 10.1.2.0/24}
]]
[[services
- {proto: tcp, port: 80}
- {proto: tcp, port: 81}
]]
<address>
 <entry name="RANGE_10.1.1.3-7">
  <ip-range>10.1.1.3-10.1.1.7</ip-range>
 </entry>
</address>
[[postfix]]
=NETSPOC=
-- router
[[identical]]
[[postfix]]
-- router.raw
[[prefix vsys2]]
[[raw]]
[[postfix]]
=OUTPUT=NONE

############################################################
=TITLE=Append rule with multiple zones from raw
=DEVICE=
[[identical]]
[[postfix]]
=NETSPOC=
-- router
[[identical]]
[[postfix]]
-- router.raw
[[prefix vsys2]]
[[rules
- name: raw1
  from: "z0\"</member><member>\"z1"
  to: z2
  src: [any]
  dst: [NET_10.1.2.0_24]
  srv: [any]
  extra: "<APPEND/>"
]]
[[postfix]]
=ERROR=
Error: Must not use rule 'raw1' with multiple zones in From/To in raw
=END=

############################################################
=TITLE=Append to unknown from/to pair from raw
=DEVICE=
[[identical]]
[[postfix]]
=NETSPOC=
-- router
[[identical]]
[[postfix]]
-- router.raw
[[prefix vsys2]]
[[rules
- name: raw1
  from: z0
  to: z2
  src: [any]
  dst: [NET_10.1.2.0_24]
  srv: [any]
  extra: "<APPEND/>"
]]
[[postfix]]
=ERROR=
Error: Can't APPEND to unknown rule with From=z0, To=z2
=END=

############################################################
=TITLE=Prevent name clash of rule from raw
=DEVICE=
[[prefix vsys2]]
[[postfix]]
=NETSPOC=
-- router
[[prefix vsys2]]
[[postfix]]
-- router.raw
[[prefix vsys2]]
[[rules
- name: r3-2-1
  from: z0
  to: z2
  src: [any]
  dst: [NET_10.1.2.0_24]
  srv: [any]
]]
[[addresses
- {name: NET_10.1.2.0_24, ip: 10.1.2.0/24}
]]
[[postfix]]
=ERROR=
Error: Must not use rule name starting with 'r<NUM>' in raw: r3-2-1
=END=

############################################################
=TITLE=Ignore extra attributes with <member>any</member> in rule from device
=DEVICE=
[[prefix vsys2]]
[[rules
- name: r1
  from: z1
  to:   z2
  src: [IP_10.1.1.1]
  dst: [NET_10.1.2.0_24]
  srv: [any]
  extra: |
    <category>
     <member>any</member>
    </category>
    <destination-hip>
     <member>any</member>
    </destination-hip>
]]
[[addresses
- {name: IP_10.1.1.1, ip: 10.1.1.1/32}
- {name: NET_10.1.2.0_24, ip: 10.1.2.0/24}
]]
[[postfix]]
=NETSPOC=
[[prefix vsys2]]
[[rules
- name: r1
  from: z1
  to:   z2
  src: [IP_10.1.1.1]
  dst: [NET_10.1.2.0_24]
  srv: [any]
  extra: |
    <source-hip>
     <member>any</member>
    </source-hip>

    <source-user>
     <member>foo</member>
    </source-user>
]]
[[addresses
- {name: IP_10.1.1.1, ip: 10.1.1.1/32}
- {name: NET_10.1.2.0_24, ip: 10.1.2.0/24}
]]
[[postfix]]
=OUTPUT=
action=delete&type=config&
 xpath=/config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/rulebase/security/rules/entry[@name='r1']
action=set&type=config&
 xpath=/config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/rulebase/security/rules/entry[@name='r1-1']&
 element=
  <action>allow</action>
  <from><member>z1</member></from>
  <to><member>z2</member></to>
  <source><member>IP_10.1.1.1</member></source>
  <destination><member>NET_10.1.2.0_24</member></destination>
  <service><member>any</member></service>
  <application><member>any</member></application>
  <log-start>yes</log-start><log-end>yes</log-end>
  <rule-type>interzone</rule-type>
  <source-user><member>foo</member></source-user>
=END=

############################################################
=TITLE=Compare named service with any
=DEVICE=
[[prefix vsys2]]
[[rules
- name: r1
  from: z1
  to:   z2
  src: [any]
  dst: [any]
  srv: [tcp 80]
]]
[[services
- {proto: tcp, port: 80}
]]
[[postfix]]
=NETSPOC=
[[prefix vsys2]]
[[rules
- name: r1
  from: z1
  to:   z2
  src: [any]
  dst: [any]
  srv: [any]
]]
[[postfix]]
=OUTPUT=
action=delete&type=config&
 xpath=/config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/rulebase/security/rules/entry[@name='r1']
action=set&type=config&
 xpath=/config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/rulebase/security/rules/entry[@name='r1-1']&
 element=
  <action>allow</action>
  <from><member>z1</member></from>
  <to><member>z2</member></to>
  <source><member>any</member></source>
  <destination><member>any</member></destination>
  <service><member>any</member></service>
  <application><member>any</member></application>
  <log-start>yes</log-start><log-end>yes</log-end>
  <rule-type>interzone</rule-type>
action=delete&type=config&
 xpath=/config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/service/entry[@name='tcp 80']
=END=

############################################################
=TITLE=Change name of service
=DEVICE=
[[prefix vsys2]]
[[rules
- name: r1
  from: z1
  to:   z2
  src: [any]
  dst: [any]
  srv: [TCP 80 HTTP]
]]
<service>
 <entry name="TCP 80 HTTP">
  <protocol><tcp><port>80</port></tcp></protocol>
 </entry>
</service>
[[postfix]]
=NETSPOC=
[[prefix vsys2]]
[[rules
- name: r1
  from: z1
  to:   z2
  src: [any]
  dst: [any]
  srv: [tcp 80]
]]
[[services
- {proto: tcp, port: 80}
]]
[[postfix]]
=OUTPUT=
action=set&type=config&
 xpath=/config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/service/entry[@name='tcp 80']&
   element=<protocol><tcp><port>80</port></tcp></protocol>
action=edit&type=config&
 xpath=/config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/rulebase/security/rules/entry[@name='r1']/service&
 element=<member>tcp 80</member>
action=delete&type=config&
 xpath=/config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/service/entry[@name='TCP 80 HTTP']
=END=

############################################################
=TITLE=Extra attributes in service
=DEVICE=
[[prefix vsys2]]
[[rules
- name: r1
  from: z1
  to:   z2
  src: [IP_10.1.1.1]
  dst: [NET_10.1.2.0_24]
  srv: [TCP 80]
]]
[[addresses
- {name: IP_10.1.1.1, ip: 10.1.1.1/32}
- {name: NET_10.1.2.0_24, ip: 10.1.2.0/24}
]]
<service>
 <entry name="TCP 80">
   <protocol>
     <tcp>
       <port>80</port>
       <override>
         <no/>
       </override>
     </tcp>
   </protocol>
   <description>Hypertext Transfer Protocol (HTTP)</description>
 </entry>
</service>
[[postfix]]
=NETSPOC=
[[prefix vsys2]]
[[rules
- name: r1
  from: z1
  to:   z2
  src: [IP_10.1.1.1]
  dst: [NET_10.1.2.0_24]
  srv: [TCP 80]
]]
[[addresses
- {name: IP_10.1.1.1, ip: 10.1.1.1/32}
- {name: NET_10.1.2.0_24, ip: 10.1.2.0/24}
]]
<service>
 <entry name="TCP 80">
   <protocol>
     <tcp>
       <port>80</port>
     </tcp>
   </protocol>
   <description>Hypertext Transfer Protocol (HTTP)</description>
 </entry>
</service>
[[postfix]]
=OUTPUT=
action
=END=

############################################################
=TITLE=Delete and insert rules, replace deny rule at end
=DEVICE=
[[prefix vsys2]]
[[rules
- name: r1
  src: [IP_10.1.1.1]
  dst: [NET_10.1.2.0_24]
  srv: [tcp 80]
- name: r2
  action: drop
  src: [IP_10.1.1.1]
  dst: [NET_10.1.2.0_24]
  srv: [tcp 80]
- name: r3
  src: [IP_10.1.1.1]
  dst: [NET_10.1.2.0_24]
  srv: [udp 123]
- name: r4
  action: drop
  src: [any]
  dst: [NET_10.1.2.0_24]
  srv: [any]
- name: r5
  action: drop
  src: [any]
  dst: [any]
  srv: [any]
]]
[[addresses
- {name: IP_10.1.1.1, ip: 10.1.1.1/32}
- {name: NET_10.1.2.0_24, ip: 10.1.2.0/24}
]]
[[services
- {proto: tcp, port: 80}
- {proto: udp, port: 123}
]]
[[postfix]]
=NETSPOC=
[[prefix vsys2]]
[[rules
- name: r1
  src: [IP_10.1.1.1]
  dst: [NET_10.1.2.0_24]
  srv: [udp 123]
- name: r2
  action: drop
  src: [IP_10.1.1.1]
  dst: [NET_10.1.2.0_24]
  srv: [udp 123]
- name: r3
  src: [IP_10.1.1.1]
  dst: [NET_10.1.2.0_24]
  srv: [tcp 80]
- name: r4
  action: drop
  src: [any]
  dst: [NET_10.1.2.0_24]
  srv: [any]
- name: r5
  action: drop
  src: [any]
  dst: [any]
  srv: [application-default]
]]
[[addresses
- {name: IP_10.1.1.1, ip: 10.1.1.1/32}
- {name: NET_10.1.2.0_24, ip: 10.1.2.0/24}
]]
[[services
- {proto: tcp, port: 80}
- {proto: udp, port: 123}
]]
[[postfix]]
=OUTPUT=
action=delete&type=config&
 xpath=/config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/rulebase/security/rules/entry[@name='r1']
action=delete&type=config&
 xpath=/config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/rulebase/security/rules/entry[@name='r2']
action=set&type=config&
 xpath=/config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/rulebase/security/rules/entry[@name='r2-1']&
 element=
  <action>drop</action>
  <from><member>z1</member></from>
  <to><member>z2</member></to>
  <source><member>IP_10.1.1.1</member></source>
  <destination><member>NET_10.1.2.0_24</member></destination>
  <service><member>udp 123</member></service>
  <application><member>any</member></application>
  <log-start>yes</log-start>
  <log-end>yes</log-end>
  <rule-type>interzone</rule-type>
action=move&type=config&
 xpath=/config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/rulebase/security/rules/entry[@name='r2-1']&
 where=before&dst=r4
action=set&type=config&
 xpath=/config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/rulebase/security/rules/entry[@name='r3-1']&
 element=
  <action>allow</action>
  <from><member>z1</member></from>
  <to><member>z2</member></to>
  <source><member>IP_10.1.1.1</member></source>
  <destination><member>NET_10.1.2.0_24</member></destination>
  <service><member>tcp 80</member></service>
  <application><member>any</member></application>
  <log-start>yes</log-start>
  <log-end>yes</log-end>
  <rule-type>interzone</rule-type>
action=move&type=config&
 xpath=/config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/rulebase/security/rules/entry[@name='r3-1']&
 where=before&dst=r4
action=delete&type=config&
 xpath=/config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/rulebase/security/rules/entry[@name='r5']
action=set&type=config&
 xpath=/config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/rulebase/security/rules/entry[@name='r5-1']&
 element=
  <action>drop</action>
  <from><member>z1</member></from>
  <to><member>z2</member></to>
  <source><member>any</member></source>
  <destination><member>any</member></destination>
  <service><member>application-default</member></service>
  <application><member>any</member></application>
  <log-start>yes</log-start>
  <log-end>yes</log-end>
  <rule-type>interzone</rule-type>
=END=
