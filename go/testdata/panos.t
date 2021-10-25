=VAR=prefix
<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys2">
=VAR=postfix
</entry></vsys></entry></devices></config>
=END=

=VAR=input
${prefix}
<rulebase><security><rules>
<entry name="r1">
<action>allow</action>
<from><member>z1</member></from>
<to><member>z2</member></to>
<source><member>g0</member></source>
<destination>
 <member>NET_10.1.3.0_24</member>
 <member>NET_10.1.2.0_24</member>
</destination>
<service><member>udp 123</member><member>tcp</member></service>
<application><member>any</member></application>
<rule-type>interzone</rule-type>
<log-start>yes</log-start>
<log-end>yes</log-end>
</entry>
</rules></security></rulebase>
<address-group>
<entry name="g0"><static>
<member>IP_10.1.1.20</member>
<member>IP_10.1.1.10</member>
</static></entry>
</address-group>
<address>
<entry name="IP_10.1.1.10"><ip-netmask>10.1.1.10/32</ip-netmask></entry>
<entry name="IP_10.1.1.20"><ip-netmask>10.1.1.20/32</ip-netmask></entry>
<entry name="NET_10.1.2.0_24"><ip-netmask>10.1.2.0/24</ip-netmask></entry>
<entry name="NET_10.1.3.0_24"><ip-netmask>10.1.3.0/24</ip-netmask></entry>
</address>
<service>
<entry name="tcp"><protocol><tcp><port>1-65535</port></tcp></protocol></entry>
<entry name="udp 123"><protocol><udp><port>123</port></udp></protocol></entry>
</service>
${postfix}
=END=

############################################################
=TITLE=No differences
=DEVICE=${input}
=NETSPOC=${input}
=OUTPUT=NONE

############################################################
=TITLE=Only group names differ
=DEVICE=${input}
=SUBST=/g0/g2/
=NETSPOC=${input}
=OUTPUT=NONE

############################################################
=TITLE=Change service
=DEVICE=${input}
=SUBST=|<member>udp 123</member>||
=NETSPOC=${input}
=SUBST=|<member>tcp</member>||
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
  <log-start>yes</log-start>
  <log-end>yes</log-end>
  <rule-type>interzone</rule-type>
action=delete&type=config&
 xpath=
  /config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/service/entry[@name='tcp']
=END=

############################################################
=TITLE=Add element to group
=DEVICE=${input}
=SUBST=|<member>IP_10.1.1.10</member>||
=NETSPOC=${input}
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
=DEVICE=${input}
=NETSPOC=${input}
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
=DEVICE=${input}
=SUBST=|<member>NET_10.1.2.0_24</member>||
=NETSPOC=${input}
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
=DEVICE=${input}
=NETSPOC=${input}
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
${prefix}
${postfix}
=NETSPOC=
${input}
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
  <member>tcp</member>
  <member>udp 123</member>
 </service>
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
 /vsys/entry[@name='vsys2']/address-group/entry[@name='g0']&
 element=
 <static>
  <member>IP_10.1.1.10</member>
  <member>IP_10.1.1.20</member>
 </static>
action=set&type=config&
 xpath=
 /config/devices/entry[@name='localhost.localdomain']
 /vsys/entry[@name='vsys2']/service/entry[@name='tcp']&
 element=
 <protocol>
  <tcp>
   <port>
    1-65535
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
${input}
=NETSPOC=
${prefix}
${postfix}
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
  /vsys/entry[@name='vsys2']/service/entry[@name='tcp']
action=delete&type=config&
 xpath=
  /config/devices/entry[@name='localhost.localdomain']
  /vsys/entry[@name='vsys2']/service/entry[@name='udp 123']
=END=
