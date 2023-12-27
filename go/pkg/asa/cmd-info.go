package asa

// Description of commands that will be parsed.
// - $NAME matches name of command; only used in toplevel commands.
// - $SEQ matches a sequence number.
// - * matches one or more words at end of command.
// - " matches a string in douple quotes or a single word without double quotes.
// First word is used as prefix.
// This prefix may be referenced in other commands as $<prefix>.
// If multiple words are used as prefix, space is replaced by underscore.
//
// Special characters at beginning of line:
// <space>: Mark subcommands of previous command
// !: Matching command or subcommand will be ignored
// #: Comment that is ignored
var cmdInfo = `
# * may reference multiple $object-group, will be resolved later.
access-list $NAME standard *
access-list $NAME extended *
access-list $NAME remark *
object-group network $NAME
 *
object-group service $NAME *
 *
object-group service $NAME
 *
object-group protocol $NAME
 *
ip_local_pool $NAME *
crypto_ca_certificate_map $NAME $SEQ
 subject-name *
 extended-key-usage *
crypto_map $NAME $SEQ match address $access-list
crypto_map $NAME $SEQ ipsec-isakmp dynamic $crypto_dynamic-map
# * references one or more $crypto_ipsec_ikev1_transform-set
crypto_map $NAME $SEQ set ikev1 transform-set *
# * references one or more $crypto_ipsec_ikev2_ipsec-proposal
crypto_map $NAME $SEQ set ikev2 ipsec-proposal *
crypto_map $NAME $SEQ set nat-t-disable
crypto_map $NAME $SEQ set peer *
crypto_map $NAME $SEQ set pfs *
crypto_map $NAME $SEQ set pfs
crypto_map $NAME $SEQ set reverse-route
crypto_map $NAME $SEQ set security-association lifetime *
crypto_map $NAME $SEQ set trustpoint *
crypto_dynamic-map $NAME $SEQ match address $access-list
crypto_dynamic-map $NAME $SEQ ipsec-isakmp dynamic *
# * references one or more $crypto_ipsec_ikev1_transform-set
crypto_dynamic-map $NAME $SEQ set ikev1 transform-set *
# * references one or more $crypto_ipsec_ikev2_ipsec-proposal
crypto_dynamic-map $NAME $SEQ set ikev2 ipsec-proposal *
crypto_dynamic-map $NAME $SEQ set nat-t-disable
crypto_dynamic-map $NAME $SEQ set peer *
crypto_dynamic-map $NAME $SEQ set pfs *
# Default value 'group2' is not shown in config from device.
crypto_dynamic-map $NAME $SEQ set pfs
crypto_dynamic-map $NAME $SEQ set reverse-route
crypto_dynamic-map $NAME $SEQ set security-association lifetime *
crypto_ipsec_ikev1_transform-set $NAME *
crypto_ipsec_ikev2_ipsec-proposal $NAME
 protocol esp encryption *
 protocol esp integrity *
group-policy $NAME internal
group-policy $NAME attributes
 vpn-filter value $access-list
 split-tunnel-network-list value $access-list
 address-pools value $ip_local_pool
 !webvpn
 *

# Are transferred manually, but references must be followed.
aaa-server $NAME protocol ldap
# Value of * is different from Netspoc and device:
# Device: aaa-server NAME (inside) host 1.2.3.4
# Device: aaa-server NAME (inside) host 5.6.7.8
# Netspoc: aaa-server NAME host X
aaa-server $NAME *
 ldap-attribute-map $ldap_attribute-map
ldap_attribute-map $NAME
 map-name memberOf Group-Policy
 map-value memberOf " $group-policy

# Is anchor if $NAME is IP address
tunnel-group $NAME type *
tunnel-group $NAME general-attributes
 default-group-policy $group-policy
 authentication-server-group $aaa-server
 *
tunnel-group $NAME ipsec-attributes
 !ikev1 pre-shared-key *
 !ikev2 local-authentication pre-shared-key *
 !ikev2 remote-authentication pre-shared-key *
 !isakmp keepalive *
 *
tunnel-group $NAME webvpn-attributes
 *

# Anchors
access-group $access-list global
access-group $access-list in *
access-group $access-list out *
# Is stored in lookup with different prefix "cryto map interface"
crypto_map $crypto_map interface *
username $NAME nopassword
username $NAME attributes
 vpn-filter value $access-list
 vpn-group-policy $group-policy
 *
tunnel-group-map default-group $tunnel-group
tunnel-group-map $crypto_ca_certificate_map $SEQ $tunnel-group
webvpn
 certificate-group-map $crypto_ca_certificate_map $SEQ $tunnel-group

# Other anchors, not referencing any command
route *
ipv6_route *
interface *
 shutdown
 nameif *
no_sysopt_connection_permit-vpn
`
