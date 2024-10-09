=TEMPL=apikey
GET /api?type=keygen
<response status = 'success'>
 <result><key>LUFRPT=</key></result>
</response>
=END=

=TEMPL=checkHA
[[apikey]]
GET /api/?type=op&cmd=<show><high-availability><state/></high-availability></show>
<response status = 'success'>
 <result>
  <enabled>yes</enabled>
  <group>
   <mode>Active-Passive</mode>
   <local-info>
    <ha2-port>hsci</ha2-port>
    <state>active</state>
   </local-info>
  </group>
 </result>
</response>
=END=

=TEMPL=empty_missing_vsys
GET /api/?type=config&action=get&xpath=/config/devices
<response status = 'success'>
 <result>
  <devices>
   <entry name="localhost.localdomain">
    <deviceconfig>
     <system>
      <hostname>router</hostname>
     </system>
    </deviceconfig>
   </entry>
  </devices>
 </result>
</response>
=END=

############################################################
=TITLE=Device gives no valid answer
=SCENARIO=
GET /api
500
device not ready
=NETSPOC=NONE
=ERROR=
WARNING>>> API key status code: 500
WARNING>>> device not ready
ERROR>>> Devices unreachable: router
=OUTPUT=
--router.login
TESTSERVER/api?password=xxx&type=keygen&user=admin
device not ready

=END=

############################################################
=TITLE=Login fails
=SCENARIO=
GET /api?type=keygen
<response status = 'failure'>
 <msg>User unknown</msg>
</response>
=NETSPOC=NONE
=ERROR=
WARNING>>> No success: User unknown
ERROR>>> Devices unreachable: router
=END=

############################################################
=TITLE=Only login succeeds
=SCENARIO=
[[apikey]]
=NETSPOC=NONE
=ERROR=
WARNING>>> not in active state: 10.1.13.33 (router)
ERROR>>> Devices unreachable: router
=OUTPUT=
--router.login
TESTSERVER/api?password=xxx&type=keygen&user=admin
<response status = 'success'>
 <result><key>xxx</key></result>
</response>

TESTSERVER/api/?key=xxx&type=op&cmd=<show><high-availability><state/></high-availability></show>
404 page not found

=END=

############################################################
=TITLE=Only HA check succeeds
=SCENARIO=
[[checkHA]]
=NETSPOC=NONE
=ERROR=
ERROR>>> status code: 404
ERROR>>> 404 page not found
=OUTPUT=
--router.login
TESTSERVER/api?password=xxx&type=keygen&user=admin
<response status = 'success'>
 <result><key>xxx</key></result>
</response>

TESTSERVER/api/?key=xxx&type=op&cmd=<show><high-availability><state/></high-availability></show>
<response status = 'success'>
 <result>
  <enabled>yes</enabled>
  <group>
   <mode>Active-Passive</mode>
   <local-info>
    <ha2-port>hsci</ha2-port>
    <state>active</state>
   </local-info>
  </group>
 </result>
</response>

--router.config
TESTSERVER/api/?key=xxx&type=config&action=get&xpath=/config/devices
404 page not found

=END=

############################################################
=TITLE=HA not enabled
=SCENARIO=
[[apikey]]
GET /api/?type=op&cmd=<show><high-availability><state/></high-availability></show>
<response status = 'success'>
 <result>
  <enabled>no</enabled>
 </result>
</response>
[[empty_missing_vsys]]
=NETSPOC=NONE
=OUTPUT=
--router.login
TESTSERVER/api?password=xxx&type=keygen&user=admin
<response status = 'success'>
 <result><key>xxx</key></result>
</response>

TESTSERVER/api/?key=xxx&type=op&cmd=<show><high-availability><state/></high-availability></show>
<response status = 'success'>
 <result>
  <enabled>no</enabled>
 </result>
</response>

=END=

############################################################
=TITLE=Invalid config in response
=SCENARIO=
[[checkHA]]
GET /api/?type=config&action=get&xpath=/config/devices
<INVALID>
=NETSPOC=NONE
=ERROR=
ERROR>>> While reading device: Parsing response: expected element type <response> but have <INVALID>
=END=

############################################################
=TITLE=Invalid config in result
=SCENARIO=
[[checkHA]]
GET /api/?type=config&action=get&xpath=/config/devices
<response status = 'success'>
 <result>
  <devices>
  <IN></VALID>
  </devices>
 </result>
</response>
=NETSPOC=NONE
=ERROR=
ERROR>>> While reading device: Parsing response: XML syntax error on line 4: element <IN> closed by </VALID>
=END=

############################################################
=TITLE=Empty config with missing device name
=SCENARIO=
[[checkHA]]
GET /api/?type=config&action=get&xpath=/config/devices
<response status = 'success'>
 <result>
  <devices>
   <entry name="localhost.localdomain">
   </entry>
  </devices>
 </result>
</response>
=NETSPOC=NONE
=ERROR=
ERROR>>> Wrong device name "", expected "router"
=END=

############################################################
=TITLE=Empty config from device
=SCENARIO=
[[checkHA]]
[[empty_missing_vsys]]
=NETSPOC=NONE
=WARNING=NONE

=TEMPL=minimal_netspoc
<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1">
<rulebase><security><rules>
<entry name="r1">
<action>allow</action>
<from><member>z1</member></from>
<to><member>z2</member></to>
<source><member>any</member></source>
<destination><member>any</member></destination>
<service><member>tcp 80</member></service>
<application><member>any</member></application>
<rule-type>interzone</rule-type>
</entry>
</rules></security></rulebase>
<service>
<entry name="tcp 80">
 <protocol>
 <tcp><port>80</port></tcp>
 </protocol>
</entry>
</service>
</entry></vsys></entry></devices></config>
=END=

############################################################
=TITLE=Empty config from device missing vsys
=SCENARIO=
[[checkHA]]
[[empty_missing_vsys]]
=NETSPOC=
[[minimal_netspoc]]
=ERROR=
ERROR>>> Unknown name 'vsys1' in VSYS of device configuration
=END=

############################################################
=TITLE=Add rule and service to empty device, commit change
=SCENARIO=
[[checkHA]]
GET /api/?type=config&action=get&xpath=/config/devices
<response status = 'success'>
 <result>
  <devices>
   <entry name="localhost.localdomain">
    <deviceconfig>
     <system>
      <hostname>router</hostname>
     </system>
    </deviceconfig>
    <vsys>
     <entry name="vsys1">
     <display-name>FW7-managed-by-Netspoc</display-name>
     </entry>
    </vsys>
   </entry>
  </devices>
 </result>
</response>
GET /api/?action=set&type=config
<response status="success" code="20"></response>
GET /api/?type=commit&action=partial
<response status="success" code="19"><result><job>6</job></result></response>
GET /api/?type=op&cmd=<show><jobs><id>6</id></jobs></show>
<response status="success"><result><job>
<result>OK</result>
</job></result></response>
=NETSPOC=
[[minimal_netspoc]]
=OUTPUT=
--router.change
TESTSERVER/api/?key=xxx&action=set&type=config&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/service/entry[@name='tcp 80']&element=<protocol><tcp><port>80</port></tcp></protocol>
<response status="success" code="20"></response>

TESTSERVER/api/?key=xxx&action=set&type=config&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules/entry[@name='r1']&element=<action>allow</action><from><member>z1</member></from><to><member>z2</member></to><source><member>any</member></source><destination><member>any</member></destination><service><member>tcp 80</member></service><application><member>any</member></application><rule-type>interzone</rule-type>
<response status="success" code="20"></response>

TESTSERVER/api/?key=xxx&type=commit&action=partial&cmd=<commit><partial><admin><member>admin</member></admin></partial></commit>
<response status="success" code="19"><result><job>6</job></result></response>

TESTSERVER/api/?key=xxx&type=op&cmd=<show><jobs><id>6</id></jobs></show>
<response status="success"><result><job>
<result>OK</result>
</job></result></response>

=END=
