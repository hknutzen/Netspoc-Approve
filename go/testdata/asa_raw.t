=TEMPL=crypto_ASA
interface Ethernet0/1
 nameif outside
=END=

############################################################
=TITLE=Only known command allowed in raw
=DEVICE=NONE
=NETSPOC=
--router
route inside 10.20.0.0 255.248.0.0 10.1.2.3
--router.raw
unexpected foo
=ERROR=
ERROR>>> While reading router.raw: Unexpected command:
>>unexpected foo<<
=END=

############################################################
=TITLE=Merge routing
=DEVICE=NONE
=NETSPOC=
--router
route inside 10.20.0.0 255.248.0.0 10.1.2.3
route inside 10.23.0.0 255.255.0.0 10.1.2.5
--router.raw
route inside 10.22.0.0 255.255.0.0 10.1.2.4
route inside 10.0.0.0 255.0.0.0 10.1.2.2
=OUTPUT=
route inside 10.22.0.0 255.255.0.0 10.1.2.4
route inside 10.23.0.0 255.255.0.0 10.1.2.5
route inside 10.20.0.0 255.248.0.0 10.1.2.3
route inside 10.0.0.0 255.0.0.0 10.1.2.2
=END=

############################################################
=TITLE=Different next hop
=DEVICE=NONE
=NETSPOC=
--router
route inside 10.20.0.0 255.255.0.0 10.1.2.3
--router.raw
route inside 10.20.0.0 255.255.0.0 10.1.2.4
=OUTPUT=
route inside 10.20.0.0 255.255.0.0 10.1.2.3
route inside 10.20.0.0 255.255.0.0 10.1.2.4
=END=

############################################################
=TITLE=Duplicate route from raw
=DEVICE=NONE
=NETSPOC=
--router
route inside 10.20.0.0 255.255.0.0 10.1.2.3
--router.raw
route inside 10.20.0.0 255.255.0.0 10.1.2.3
=OUTPUT=
route inside 10.20.0.0 255.255.0.0 10.1.2.3
=END=

############################################################
=TITLE=Routing in [APPEND] part ok
=DEVICE=NONE
=NETSPOC=
--router.raw
[APPEND]
route inside 10.22.0.0 255.255.0.0 10.1.2.4
=OUTPUT=
route inside 10.22.0.0 255.255.0.0 10.1.2.4
=END=

############################################################
=TITLE=Add ipv6 route from raw
=DEVICE=NONE
=NETSPOC=
--router
route inside 10.20.0.0 255.255.0.0 10.1.2.3
--router.raw
ipv6 route inside 10::3:0/120 10::2:2
=OUTPUT=
ipv6 route inside 10::3:0/120 10::2:2
route inside 10.20.0.0 255.255.0.0 10.1.2.3
=END=

############################################################
=TITLE=Merge ACL using [APPEND]
=DEVICE=
interface Ethernet0/1
 nameif inside
=NETSPOC=
--router
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
--router.raw
access-list inside_in extended permit udp 10.0.6.0 0.0.0.255 host 224.0.1.1 eq 123
[APPEND]
access-list inside_in extended deny ip any4 host 224.0.1.1 log
access-group inside_in in interface inside
=OUTPUT=
access-list inside_in-DRC-0 extended permit udp 10.0.6.0 0.0.0.255 host 224.0.1.1 eq 123
access-list inside_in-DRC-0 extended deny ip any4 host 224.0.1.1 log
access-list inside_in-DRC-0 extended deny ip any4 any4
access-group inside_in-DRC-0 in interface inside
=END=

############################################################
=TITLE=Merge ACL, duplicate access-group in raw
=DEVICE=
interface Ethernet0/1
 nameif inside
=NETSPOC=
--router
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
--router.raw
access-list inside_in extended permit udp 10.0.6.0 0.0.0.255 host 224.0.1.1 eq 123
access-group inside_in in interface inside
[APPEND]
access-list inside_in extended deny ip any4 host 224.0.1.1 log
access-group inside_in in interface inside
=ERROR=
ERROR>>> Must reference 'access-list inside_in' only once in raw
=END=

############################################################
=TITLE=Host written as IP MASK is recognized as host
=DEVICE=
interface Ethernet0/1
 nameif inside
access-list inside_in-DRC-0 extended permit udp host 10.0.6.1 host 224.0.1.1 eq 123
access-list inside_in-DRC-0 extended permit tcp host 1000::abcd:1:1 host 1000::abcd:2:1 range 80 90
access-list inside_in-DRC-0 extended permit udp host 10.0.6.1 host 10.0.1.11 eq 123
access-list inside_in-DRC-0 extended deny ip any4 any4
access-group inside_in-DRC-0 in interface inside
=NETSPOC=
--router
access-list inside_in extended permit udp host 10.0.6.1 host 10.0.1.11 eq 123
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
--router.raw
access-list inside_in extended permit udp 10.0.6.1 255.255.255.255 224.0.1.1 255.255.255.255 eq 123
access-list inside_in extended permit tcp 1000::abcd:1:1/128 1000::abcd:2:1/128 range 80 90
access-group inside_in in interface inside
=OUTPUT=NONE

############################################################
=TITLE=Recognize mask 0.0.0.0 as any4
=DEVICE=
interface Ethernet0/1
 nameif inside
access-list inside extended permit ip host 1.1.1.1 any4
access-group inside in interface inside
=NETSPOC=
--router.raw
access-list inside extended permit ip host 1.1.1.1 0.0.0.0 0.0.0.0
access-group inside in interface inside
=OUTPUT=NONE

############################################################
=TITLE=Recognize prefixlen /0 as any6
=DEVICE=
interface Ethernet0/1
 nameif inside
access-list inside extended permit ip host 1000::abcd:1:1 any6
access-group inside in interface inside
=NETSPOC=
--router.raw
access-list inside extended permit ip host 1000::abcd:1:1 0.0.0.0/0
access-group inside in interface inside
=OUTPUT=NONE

############################################################
=TITLE=Name clash with ACL
=DEVICE=NONE
=NETSPOC=
--router
access-list inside_in extended permit ip 10.0.6.0 0.0.0.255 host 10.0.1.11
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
--router.raw
access-list inside_in extended deny ip host 10.0.6.1 any4
access-group inside_in out interface inside
=ERROR=
ERROR>>> Name clash for 'access-list inside_in' from raw
=END=

############################################################
=TITLE=Must not bind same ACL multiple times (1)
=DEVICE=NONE
=NETSPOC=
--router.raw
access-list in_out extended permit ip any4 host 10.0.6.1
access-group in_out in interface inside
access-group in_out out interface inside
=ERROR=
ERROR>>> Name clash for 'access-list in_out' from raw
=END=

############################################################
=TITLE=Must not bind same ACL multiple times (2)
=DEVICE=NONE
=NETSPOC=
--router
access-list in extended permit ip any4 host 10.0.1.1
access-group in in interface inside
access-list out extended permit ip host 10.0.1.1 any4
access-group out out interface inside
--router.raw
access-list in_out extended permit ip any4 host 10.0.6.1
access-group in_out in interface inside
access-group in_out out interface inside
=ERROR=
ERROR>>> Must reference 'access-list in_out' only once in raw
=END=

############################################################
=TITLE=Unknown ACL in raw
=DEVICE=NONE
=NETSPOC=
--router
access-list inside_in extended permit ip 10.0.6.0 0.0.0.255 host 10.0.1.11
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
--router.raw
access-group inside_in in interface inside
=ERROR=
ERROR>>> While reading router.raw: 'access-group inside_in in interface inside' references unknown 'access-list inside_in'
=END=

############################################################
=TITLE=Unbound ACLs in raw
=DEVICE=
interface Ethernet0/1
 nameif inside
=NETSPOC=
--router
access-list inside_in extended permit ip 10.0.6.0 0.0.0.255 host 10.0.1.11
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
--router.raw
access-list inside_in extended deny ip host 10.0.6.1 any4
access-list outside_in extended deny ip host 10.0.6.0 any4
=WARNING=
WARNING>>> Ignoring unused 'access-list inside_in' in raw
WARNING>>> Ignoring unused 'access-list outside_in' in raw
=END=

############################################################
=TITLE=Name clash with object-group
=DEVICE=NONE
=NETSPOC=
--router
object-group network g1
 network-object host 2.2.2.2
access-list inside extended permit ip object-group g1 any4
access-group inside in interface inside
--router.raw
object-group network g1
 network-object host 1.1.1.1
access-list inside extended permit ip object-group g1 any4
access-group inside in interface inside
=ERROR=
ERROR>>> Name clash for 'object-group g1' from raw
=END=

############################################################
=TITLE=Add crypto
=DEVICE=[[crypto_ASA]]
=NETSPOC=
--router
crypto ipsec ikev1 transform-set abc esp-3des esp-sha-hmac
crypto dynamic-map outside_dyn_map 1 set pfs group19
crypto dynamic-map outside_dyn_map 1 set ikev1 transform-set abc
crypto map outside_map 2 ipsec-isakmp dynamic outside_dyn_map
crypto map outside_map interface outside
--router.raw
crypto ipsec ikev1 transform-set ESP-3DES-MD5 esp-3des esp-md5-hmac
crypto ipsec ikev1 transform-set ESP-AES-256-SHA esp-aes-256 esp-sha-hmac
crypto dynamic-map raw_dyn_map 1 set pfs group21
crypto dynamic-map raw_dyn_map 1 set ikev1 transform-set ESP-AES-256-SHA ESP-3DES-MD5
crypto dynamic-map raw_dyn_map 1 set reverse-route
crypto map outside_map 2 ipsec-isakmp dynamic raw_dyn_map
crypto map outside_map interface outside

group-policy DfltGrpPolicy attributes
 vpn-tunnel-protocol ikev1
 smartcard-removal-disconnect enable
 pfs enable
 ip-comp enable
=OUTPUT=
crypto dynamic-map outside_dyn_map 1 set pfs group19
crypto ipsec ikev1 transform-set abc-DRC-0 esp-3des esp-sha-hmac
crypto dynamic-map outside_dyn_map 1 set ikev1 transform-set abc-DRC-0
crypto map outside_map 2 ipsec-isakmp dynamic outside_dyn_map
crypto dynamic-map raw_dyn_map 1 set pfs group21
crypto ipsec ikev1 transform-set ESP-AES-256-SHA-DRC-0 esp-aes-256 esp-sha-hmac
crypto ipsec ikev1 transform-set ESP-3DES-MD5-DRC-0 esp-3des esp-md5-hmac
crypto dynamic-map raw_dyn_map 1 set ikev1 transform-set ESP-AES-256-SHA-DRC-0 ESP-3DES-MD5-DRC-0
crypto dynamic-map raw_dyn_map 1 set reverse-route
crypto map outside_map 65535 ipsec-isakmp dynamic raw_dyn_map
crypto map outside_map interface outside
group-policy DfltGrpPolicy attributes
vpn-tunnel-protocol ikev1
smartcard-removal-disconnect enable
pfs enable
ip-comp enable
=END=

############################################################
=TITLE=Add crypto to empty crypto
=DEVICE=[[crypto_ASA]]
=NETSPOC=
--router.raw
crypto map outside_map 2 set peer 1.2.3.4
crypto map outside_map 2 set pfs group21
crypto map outside_map interface outside
=OUTPUT=
crypto map outside_map 1 set peer 1.2.3.4
crypto map outside_map 1 set pfs group21
crypto map outside_map interface outside
=END=

############################################################
=TITLE=Merge crypto dynamic-map
=DEVICE=[[crypto_ASA]]
=NETSPOC=
--router
access-list crypto-vpn1@example.com extended permit ip any4 10.99.1.0 255.255.255.0
crypto ipsec ikev1 transform-set abc esp-3des esp-sha-hmac
crypto dynamic-map vpn1@example.com 1 set pfs group19
crypto dynamic-map vpn1@example.com 1 set ikev1 transform-set abc
crypto dynamic-map vpn1@example.com 1 match address crypto-vpn1@example.com
crypto map outside_map 1 ipsec-isakmp dynamic vpn1@example.com
crypto map outside_map interface outside
--router.raw
access-list extra extended permit ip any4 10.99.2.0 255.255.255.0
crypto ipsec ikev1 transform-set ESP-3DES-MD5 esp-3des esp-md5-hmac
crypto ipsec ikev1 transform-set ESP-AES-256-SHA esp-aes-256 esp-sha-hmac
crypto dynamic-map vpn1@example.com 2 set pfs group21
crypto dynamic-map vpn1@example.com 2 set ikev1 transform-set ESP-AES-256-SHA ESP-3DES-MD5
crypto dynamic-map vpn1@example.com 2 match address extra
crypto dynamic-map vpn1@example.com 2 set reverse-route
crypto map outside_map 2 ipsec-isakmp dynamic vpn1@example.com
crypto map outside_map interface outside
=OUTPUT=
crypto dynamic-map vpn1@example.com 1 set pfs group21
crypto ipsec ikev1 transform-set ESP-AES-256-SHA-DRC-0 esp-aes-256 esp-sha-hmac
crypto ipsec ikev1 transform-set ESP-3DES-MD5-DRC-0 esp-3des esp-md5-hmac
crypto dynamic-map vpn1@example.com 1 set ikev1 transform-set ESP-AES-256-SHA-DRC-0 ESP-3DES-MD5-DRC-0
access-list crypto-vpn1@example.com-DRC-0 extended permit ip any4 10.99.2.0 255.255.255.0
access-list crypto-vpn1@example.com-DRC-0 extended permit ip any4 10.99.1.0 255.255.255.0
crypto dynamic-map vpn1@example.com 1 match address crypto-vpn1@example.com-DRC-0
crypto dynamic-map vpn1@example.com 1 set reverse-route
crypto map outside_map 1 ipsec-isakmp dynamic vpn1@example.com
crypto map outside_map interface outside
=END=

############################################################
=TITLE=Prepend and append crypto filter ACL
=DEVICE=[[crypto_ASA]]
=NETSPOC=
--router
access-list crypto-1.2.3.4 extended permit ip host 10.1.1.10 10.1.2.0 255.255.255.240
crypto map crypto-outside 1 set peer 1.2.3.4
crypto map crypto-outside 1 match address crypto-1.2.3.4
crypto map crypto-outside interface outside
--router.raw
access-list acl extended permit ip host 10.1.1.10 10.1.7.0 255.255.255.240
[APPEND]
access-list acl extended deny ip any4 host 224.0.1.1 log
crypto map crypto-outside 1 set peer 1.2.3.4
crypto map crypto-outside 1 match address acl
crypto map crypto-outside interface outside
=OUTPUT=
crypto map crypto-outside 1 set peer 1.2.3.4
access-list crypto-1.2.3.4-DRC-0 extended permit ip host 10.1.1.10 10.1.7.0 255.255.255.240
access-list crypto-1.2.3.4-DRC-0 extended permit ip host 10.1.1.10 10.1.2.0 255.255.255.240
access-list crypto-1.2.3.4-DRC-0 extended deny ip any4 host 224.0.1.1 log
crypto map crypto-outside 1 match address crypto-1.2.3.4-DRC-0
crypto map crypto-outside interface outside
=END=

############################################################
=TITLE=Change crypto map attributes
=DEVICE=[[crypto_ASA]]
=NETSPOC=
--router
crypto ipsec ikev2 ipsec-proposal Trans2
 protocol esp encryption aes-256
 protocol esp integrity sha-384
access-list crypto-1.2.3.4 extended permit ip host 10.1.1.10 10.1.2.0 255.255.255.240
crypto map crypto-outside 9 set peer 1.2.3.4
crypto map crypto-outside 9 match address crypto-1.2.3.4
crypto map crypto-outside 9 set ikev2 ipsec-proposal Trans2
crypto map crypto-outside 9 set pfs group19
crypto map crypto-outside 9 set security-association lifetime seconds 3600
crypto map crypto-outside interface outside
tunnel-group 1.2.3.4 type ipsec-l2l
tunnel-group 1.2.3.4 ipsec-attributes
 peer-id-validate nocheck
--router.raw
crypto ipsec ikev2 ipsec-proposal Trans1
 protocol esp encryption 3des
 protocol esp integrity sha-1
crypto map crypto-outside 1 set peer 1.2.3.4
crypto map crypto-outside 1 set ikev2 ipsec-proposal Trans1
crypto map crypto-outside interface outside
=OUTPUT=
crypto map crypto-outside 9 set peer 1.2.3.4
access-list crypto-1.2.3.4-DRC-0 extended permit ip host 10.1.1.10 10.1.2.0 255.255.255.240
crypto map crypto-outside 9 match address crypto-1.2.3.4-DRC-0
crypto ipsec ikev2 ipsec-proposal Trans1-DRC-0
protocol esp encryption 3des
protocol esp integrity sha-1
crypto map crypto-outside 9 set ikev2 ipsec-proposal Trans1-DRC-0
crypto map crypto-outside 9 set pfs group19
crypto map crypto-outside 9 set security-association lifetime seconds 3600
crypto map crypto-outside interface outside
tunnel-group 1.2.3.4 type ipsec-l2l
tunnel-group 1.2.3.4 ipsec-attributes
peer-id-validate nocheck
=END=

############################################################
=TITLE=Add crypto map entry (1)
=DEVICE=[[crypto_ASA]]
=NETSPOC=
--router
crypto ipsec ikev2 ipsec-proposal Trans2
 protocol esp encryption aes-256
 protocol esp integrity sha-384
access-list crypto-1.2.3.4 extended permit ip host 10.1.1.14 10.1.2.0 255.255.255.240
crypto map crypto-outside 1 set peer 1.2.3.4
crypto map crypto-outside 1 match address crypto-1.2.3.4
crypto map crypto-outside 1 set ikev2 ipsec-proposal Trans2
crypto map crypto-outside 1 set pfs group19
crypto map crypto-outside 1 set security-association lifetime seconds 3600
tunnel-group 1.2.3.4 type ipsec-l2l
tunnel-group 1.2.3.4 ipsec-attributes
 peer-id-validate nocheck
crypto map crypto-outside 2 set peer 1.2.3.10
crypto map crypto-outside 2 set ikev2 ipsec-proposal Trans2
crypto map crypto-outside 2 set pfs group19
crypto map crypto-outside interface outside
tunnel-group 1.2.3.10 type ipsec-l2l
tunnel-group 1.2.3.10 ipsec-attributes
 peer-id-validate nocheck
--router.raw
crypto ipsec ikev2 ipsec-proposal Trans2x
 protocol esp encryption aes-256
 protocol esp integrity sha-384
access-list crypto-1.2.3.9 extended permit ip host 10.1.1.19 10.1.2.0 255.255.255.240
crypto map crypto-outside 1 set peer 1.2.3.9
crypto map crypto-outside 1 match address crypto-1.2.3.9
crypto map crypto-outside 1 set ikev2 ipsec-proposal Trans2x
crypto map crypto-outside 1 set pfs group19
crypto map crypto-outside 1 set security-association lifetime seconds 3600
access-list crypto-1.2.3.3 extended permit ip host 10.1.1.13 10.1.2.0 255.255.255.240
crypto map crypto-outside 2 set peer 1.2.3.3
crypto map crypto-outside 2 match address crypto-1.2.3.3
crypto map crypto-outside 2 set ikev2 ipsec-proposal Trans2x
crypto map crypto-outside interface outside
tunnel-group 1.2.3.9 type ipsec-l2l
tunnel-group 1.2.3.9 ipsec-attributes
 peer-id-validate nocheck
tunnel-group 1.2.3.3 type ipsec-l2l
tunnel-group 1.2.3.3 ipsec-attributes
 peer-id-validate nocheck
=OUTPUT=
crypto map crypto-outside 1 set peer 1.2.3.4
access-list crypto-1.2.3.4-DRC-0 extended permit ip host 10.1.1.14 10.1.2.0 255.255.255.240
crypto map crypto-outside 1 match address crypto-1.2.3.4-DRC-0
crypto ipsec ikev2 ipsec-proposal Trans2-DRC-0
protocol esp encryption aes-256
protocol esp integrity sha-384
crypto map crypto-outside 1 set ikev2 ipsec-proposal Trans2-DRC-0
crypto map crypto-outside 1 set pfs group19
crypto map crypto-outside 1 set security-association lifetime seconds 3600
crypto map crypto-outside 2 set peer 1.2.3.10
crypto map crypto-outside 2 set ikev2 ipsec-proposal Trans2-DRC-0
crypto map crypto-outside 2 set pfs group19
crypto map crypto-outside 3 set peer 1.2.3.9
access-list crypto-1.2.3.9-DRC-0 extended permit ip host 10.1.1.19 10.1.2.0 255.255.255.240
crypto map crypto-outside 3 match address crypto-1.2.3.9-DRC-0
crypto map crypto-outside 3 set ikev2 ipsec-proposal Trans2-DRC-0
crypto map crypto-outside 3 set pfs group19
crypto map crypto-outside 3 set security-association lifetime seconds 3600
crypto map crypto-outside 4 set peer 1.2.3.3
access-list crypto-1.2.3.3-DRC-0 extended permit ip host 10.1.1.13 10.1.2.0 255.255.255.240
crypto map crypto-outside 4 match address crypto-1.2.3.3-DRC-0
crypto map crypto-outside 4 set ikev2 ipsec-proposal Trans2-DRC-0
crypto map crypto-outside interface outside
tunnel-group 1.2.3.10 type ipsec-l2l
tunnel-group 1.2.3.10 ipsec-attributes
peer-id-validate nocheck
tunnel-group 1.2.3.3 type ipsec-l2l
tunnel-group 1.2.3.3 ipsec-attributes
peer-id-validate nocheck
tunnel-group 1.2.3.4 type ipsec-l2l
tunnel-group 1.2.3.4 ipsec-attributes
peer-id-validate nocheck
tunnel-group 1.2.3.9 type ipsec-l2l
tunnel-group 1.2.3.9 ipsec-attributes
peer-id-validate nocheck
=END=

############################################################
=TITLE=Add crypto map entry (2)
=DEVICE=[[crypto_ASA]]
=NETSPOC=
--router
crypto ipsec ikev2 ipsec-proposal Trans2
 protocol esp encryption aes-256
 protocol esp integrity sha-384
crypto map crypto-outside 1 set peer 1.2.3.4
crypto map crypto-outside 1 set ikev2 ipsec-proposal Trans2
tunnel-group 1.2.3.4 type ipsec-l2l
tunnel-group 1.2.3.4 ipsec-attributes
 peer-id-validate nocheck
crypto map crypto-outside 2 set peer 1.2.3.10
crypto map crypto-outside 2 set ikev2 ipsec-proposal Trans2
crypto map crypto-outside interface outside
tunnel-group 1.2.3.10 type ipsec-l2l
tunnel-group 1.2.3.10 ipsec-attributes
 peer-id-validate nocheck
--router.raw
crypto ipsec ikev2 ipsec-proposal Trans2
 protocol esp encryption aes-256
 protocol esp integrity sha-384
crypto map crypto-outside 1 set peer 1.2.3.9
crypto map crypto-outside 1 set ikev2 ipsec-proposal Trans2
crypto map crypto-outside interface outside
tunnel-group 1.2.3.9 type ipsec-l2l
tunnel-group 1.2.3.9 ipsec-attributes
 peer-id-validate nocheck
=OUTPUT=
crypto map crypto-outside 1 set peer 1.2.3.4
crypto ipsec ikev2 ipsec-proposal Trans2-DRC-0
protocol esp encryption aes-256
protocol esp integrity sha-384
crypto map crypto-outside 1 set ikev2 ipsec-proposal Trans2-DRC-0
crypto map crypto-outside 2 set peer 1.2.3.10
crypto map crypto-outside 2 set ikev2 ipsec-proposal Trans2-DRC-0
crypto map crypto-outside 3 set peer 1.2.3.9
crypto map crypto-outside 3 set ikev2 ipsec-proposal Trans2-DRC-0
crypto map crypto-outside interface outside
tunnel-group 1.2.3.10 type ipsec-l2l
tunnel-group 1.2.3.10 ipsec-attributes
peer-id-validate nocheck
tunnel-group 1.2.3.4 type ipsec-l2l
tunnel-group 1.2.3.4 ipsec-attributes
peer-id-validate nocheck
tunnel-group 1.2.3.9 type ipsec-l2l
tunnel-group 1.2.3.9 ipsec-attributes
peer-id-validate nocheck
=END=

############################################################
=TITLE=tunnel-group-map not supported in raw
=DEVICE=NONE
=NETSPOC=
--router.raw
crypto ca certificate map name1 10
 subject-name attr ea eq some-name
 extended-key-usage co 1.3.6.1.4.1.311.20.2.2
tunnel-group name2 type ipsec-l2l
tunnel-group name2 ipsec-attributes
 peer-id-validate nocheck
 ikev2 local-authentication certificate Trustpoint2
 ikev2 remote-authentication certificate
tunnel-group-map name1 10 name2
=ERROR=
ERROR>>> Command 'tunnel-group-map' not supported in raw file
=END=

############################################################
=TITLE=Ignore non referenced tunnel-group
=DEVICE=NONE
=NETSPOC=
--router.raw
tunnel-group name2 type ipsec-l2l
tunnel-group name2 ipsec-attributes
 peer-id-validate nocheck
 ikev2 local-authentication certificate Trustpoint2
 ikev2 remote-authentication certificate
=WARNING=
WARNING>>> Ignoring unused 'tunnel-group name2' in raw
=END=

############################################################
=TITLE=Add subcommands
=DEVICE=NONE
=NETSPOC=
--router
ip local pool pool 10.1.219.192-10.1.219.255 mask 0.0.0.63
access-list vpn-filter extended permit ip host 10.1.1.2 host 10.1.0.2
group-policy VPN-group1 internal
group-policy VPN-group1 attributes
 address-pools value pool
 vpn-filter value vpn-filter
tunnel-group 1.1.1.1 type ipsec-l2l
tunnel-group 1.1.1.1 general-attributes
 default-group-policy VPN-group1
--router.raw
ip local pool pool2 10.1.219.64-10.1.219.127 mask 0.0.0.63
access-list vpn-filter2 extended permit ip host 10.1.2.2 host 10.1.0.2
group-policy VPN-group2 internal
group-policy VPN-group2 attributes
 address-pools value pool2
 vpn-filter value vpn-filter2
tunnel-group 1.1.1.2 type ipsec-l2l
tunnel-group 1.1.1.2 general-attributes
 default-group-policy VPN-group2
=OUTPUT=
tunnel-group 1.1.1.1 type ipsec-l2l
group-policy VPN-group1-DRC-0 internal
ip local pool pool-DRC-0 10.1.219.192-10.1.219.255 mask 0.0.0.63
access-list vpn-filter-DRC-0 extended permit ip host 10.1.1.2 host 10.1.0.2
group-policy VPN-group1-DRC-0 attributes
address-pools value pool-DRC-0
vpn-filter value vpn-filter-DRC-0
tunnel-group 1.1.1.1 general-attributes
default-group-policy VPN-group1-DRC-0
tunnel-group 1.1.1.2 type ipsec-l2l
group-policy VPN-group2-DRC-0 internal
ip local pool pool2-DRC-0 10.1.219.64-10.1.219.127 mask 0.0.0.63
access-list vpn-filter2-DRC-0 extended permit ip host 10.1.2.2 host 10.1.0.2
group-policy VPN-group2-DRC-0 attributes
address-pools value pool2-DRC-0
vpn-filter value vpn-filter2-DRC-0
tunnel-group 1.1.1.2 general-attributes
default-group-policy VPN-group2-DRC-0
=END=

############################################################
=TITLE=Merge subcommands
=DEVICE=NONE
=NETSPOC=
--router
ip local pool pool 10.1.219.192-10.1.219.255 mask 0.0.0.63
group-policy VPN-group internal
group-policy VPN-group attributes
 address-pools value pool
tunnel-group 1.1.1.1 type ipsec-l2l
tunnel-group 1.1.1.1 general-attributes
 default-group-policy VPN-group
--router.raw
access-list raw-filter extended permit ip host 10.1.2.2 host 10.1.0.2
group-policy raw-group internal
group-policy raw-group attributes
 vpn-filter value raw-filter
tunnel-group 1.1.1.1 type ipsec-l2l
tunnel-group 1.1.1.1 general-attributes
 default-group-policy raw-group
=OUTPUT=
tunnel-group 1.1.1.1 type ipsec-l2l
group-policy VPN-group-DRC-0 internal
ip local pool pool-DRC-0 10.1.219.192-10.1.219.255 mask 0.0.0.63
access-list raw-filter-DRC-0 extended permit ip host 10.1.2.2 host 10.1.0.2
group-policy VPN-group-DRC-0 attributes
address-pools value pool-DRC-0
vpn-filter value raw-filter-DRC-0
tunnel-group 1.1.1.1 general-attributes
default-group-policy VPN-group-DRC-0
=END=

############################################################
=TITLE=Name clash in simple object
=DEVICE=NONE
=NETSPOC=
--router
ip local pool pool 10.1.219.192-10.1.219.255 mask 0.0.0.63
access-list vpn-filter extended permit ip host 10.1.1.2 host 10.1.0.2
group-policy VPN-group1 internal
group-policy VPN-group1 attributes
 address-pools value pool
 vpn-filter value vpn-filter
tunnel-group 1.1.1.1 type ipsec-l2l
tunnel-group 1.1.1.1 general-attributes
 default-group-policy VPN-group1
--router.raw
ip local pool pool 10.1.219.64-10.1.219.127 mask 0.0.0.63
access-list vpn-filter extended permit ip host 10.1.2.2 host 10.1.0.2
group-policy VPN-group2 internal
group-policy VPN-group2 attributes
 address-pools value pool
 vpn-filter value vpn-filter
tunnel-group 1.1.1.2 type ipsec-l2l
tunnel-group 1.1.1.2 general-attributes
 default-group-policy VPN-group2
=ERROR=
ERROR>>> Name clash for 'ip local pool pool' from raw
=END=

############################################################
=TITLE=Parse object as protocol
=DEVICE=
access-list inside_in extended permit object x any4 any4
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
=NETSPOC=
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
=OUTPUT=
no access-list inside_in line 1 extended permit object x any4 any4
=END=

############################################################
=TITLE=Handle protocol 1 as icmp
=DEVICE=
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
=NETSPOC=
--router
access-list inside_in extended permit tcp 10.1.1.0 255.255.255.252 10.9.9.0 255.255.255.0 range 80 90
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
--router.raw
access-list inside_in extended permit 1 any4 any4 3 6
access-group inside_in in interface inside
=OUTPUT=
access-list inside_in line 1 extended permit icmp any4 any4 3 6
access-list inside_in line 2 extended permit tcp 10.1.1.0 255.255.255.252 10.9.9.0 255.255.255.0 range 80 90
=END=

############################################################
=TITLE=Handle protocol 58 as icmp6
=DEVICE=
access-list inside_in extended deny ip any6 any6
access-group inside_in in interface inside
=NETSPOC=
--ipv6/router
access-list inside_in extended permit tcp host 1000::abcd:1:12 1000::abcd:9:0/112 range 80 90
access-list inside_in extended deny ip any6 any6
access-group inside_in in interface inside
--router.raw
access-list inside_in extended permit 58 any6 any6 128
access-group inside_in in interface inside
=OUTPUT=
access-list inside_in line 1 extended permit icmp6 any6 any6 128
access-list inside_in line 2 extended permit tcp host 1000::abcd:1:12 1000::abcd:9:0/112 range 80 90
=END=

############################################################
=TITLE=Leave port of non udp/tcp protocol unchanged
=DEVICE=
access-list inside_in extended permit sctp any4 any4 eq 1234
access-list inside_in extended permit sctp any4 any4 eq foo
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
=NETSPOC=
--router.raw
access-list inside_in extended permit 132 any4 any4 eq 1234
access-list inside_in extended deny ip any4 any4
access-group inside_in in interface inside
=OUTPUT=
no access-list inside_in line 2 extended permit sctp any4 any4 eq foo
=END=
