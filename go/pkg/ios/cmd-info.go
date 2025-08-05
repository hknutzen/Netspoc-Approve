package ios

func (s *State) GetCmdInfo() string { return cmdInfo }

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
//
// Section header [NAME, ...] apply to following lines up to first blank line:
// - ANCHOR: Command is compared and may reference other commands.
// - FIXED_NAME: Name of object is left unchanged.
// - SIMPLE_OBJECT: Do not change but try to find matching command on device.
// - CAN_CLEAR_CONF: Command group is removed with "clear configure ..."
var cmdInfo = `
[ANCHOR]
ip_route *
ipv6_route *
interface *
 ip address *
 ip unnumbered *
 shutdown
 ip access-group $ip_access-list_extended in
 ip access-group $ip_access-list_extended out
 ip inspect *
 # 'vrf forwarding' is used if IPv6 is enabled.
 vrf forwarding *
 ip vrf forwarding *
 crypto map $crypto_map

ip_access-list_extended $NAME
 remark *
 permit *
 deny *
 $SEQ remark *
 $SEQ permit *
 $SEQ deny *

crypto_map $NAME $SEQ ipsec-isakmp
 set ip access-group $ip_access-list_extended in
 set ip access-group $ip_access-list_extended out
 set peer *
# match address $ip_access-list_extended # Currently configured manually
crypto_map $NAME $SEQ gdoi
`
