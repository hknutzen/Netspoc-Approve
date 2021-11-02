=TEMPL=prefix
<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys2">
=TEMPL=postfix
</entry></vsys></entry></devices></config>
=END=

=TEMPL=rules
<rulebase><security><rules>
{{range .}}
<entry name="{{.name}}">
<action>{{or .action "allow"}}</action>
<from><member>z1</member></from>
<to><member>z2</member></to>
{{range .src}}<source><member>{{.}}</member></source>{{end}}
{{range .dst}}<destination><member>{{.}}</member></destination>{{end}}
{{range .srv}}<service><member>{{.}}</member></service>{{end}}
<application><member>any</member></application>
<rule-type>interzone</rule-type>
<log-start>yes</log-start>
<log-end>yes</log-end>
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
[[prefix]]
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
[[prefix]]
[[postfix]]
=NETSPOC=
[[input]]
=OUTPUT=
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
=END=

############################################################
=TITLE=Remove all from device
=DEVICE=
[[input]]
=NETSPOC=
[[prefix]]
[[postfix]]
=OUTPUT=
action=delete&type=config&
 xpath=
  /config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/rulebase/security/rules/entry[@name='r1']
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
  /vsys/entry[@name='vsys2']/address-group/entry[@name='g0']
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

############################################################
=TITLE=Merge two groups to one
=DEVICE=
[[prefix]]
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
[[prefix]]
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
[[prefix]]
[[rules
- {name: r1, src: [g0], dst: [NET_10.1.2.0_24], srv: [tcp 80]}
- {name: r2, src: [g0], dst: [NET_10.1.3.0_24], srv: [udp 123]}
]]
[[groups
- {name: g0, members: [IP_10.1.1.20, IP_10.1.1.10]}
]]
[[identical]]
=NETSPOC=
[[prefix]]
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
action=set&type=config&
 xpath=
  /config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/address-group/entry[@name='g2']/static&
 element=
  <member>IP_10.1.1.10</member>
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
]]
[[postfix]]

############################################################
=TITLE=Add new elements in one go
=DEVICE=
[[prefix]]
[[rules
- {name: r1, src: [g1], dst: [NET_10.1.2.0_24], srv: [tcp 80]}
]]
[[groups
- {name: g1, members: [IP_10.1.1.20]}
]]
[[identical]]
=NETSPOC=
[[prefix]]
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

############################################################
=TITLE=Create new group instead of deleting many elements
=DEVICE=
[[prefix]]
[[rules
- {name: r1, src: [g1], dst: [NET_10.1.2.0_24], srv: [tcp 80]}
]]
[[groups
- name: g1
  members: [IP_10.1.1.1, IP_10.1.1.2, IP_10.1.1.3, IP_10.1.1.4, IP_10.1.1.5]
]]
[[identical]]
=NETSPOC=
[[prefix]]
[[rules
- {name: r1, src: [g1], dst: [NET_10.1.2.0_24], srv: [tcp 80]}
]]
[[groups
- {name: g1, members: [IP_10.1.1.1, IP_10.1.1.2]}
]]
[[identical]]
=OUTPUT=
action=edit&type=config&
 xpath=
  /config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/rulebase/security/rules/entry[@name='r1']/source&
  element=
   <member>g1-1</member>
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
action=delete&type=config&
 xpath=
  /config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/address-group/entry[@name='g1']
action=set&type=config&
 xpath=
  /config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/address-group/entry[@name='g1-1']/static&
  element=
   <member>IP_10.1.1.1</member>
   <member>IP_10.1.1.2</member>
=END=

############################################################
=TITLE=Transfer elements instead of deleting and inserting
=DEVICE=
[[prefix]]
[[rules
- name: r1
  src: [IP_10.1.1.1, IP_10.1.1.2, IP_10.1.1.3, IP_10.1.1.4, IP_10.1.1.5]
  dst: [NET_10.1.2.0_24]
  srv: [tcp 80]
]]
[[identical]]
=NETSPOC=
[[prefix]]
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
=TITLE=Adapt elements by deleting and inserting
=DEVICE=
[[prefix]]
[[rules
- name: r1
  src: [IP_10.1.1.2, IP_10.1.1.3, IP_10.1.1.4, IP_10.1.1.5]
  dst: [NET_10.1.2.0_24]
  srv: [tcp 80]
]]
[[identical]]
=NETSPOC=
[[prefix]]
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
=TITLE=Delete multiple elements
=DEVICE=
[[prefix]]
[[rules
- name: r1
  src: [IP_10.1.1.1, IP_10.1.1.2, IP_10.1.1.3, IP_10.1.1.4, IP_10.1.1.5]
  dst: [NET_10.1.2.0_24]
  srv: [tcp 80]
]]
[[identical]]
=NETSPOC=
[[prefix]]
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
