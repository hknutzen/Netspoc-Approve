package asa

import (
	"bytes"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/hknutzen/Netspoc-Approve/go/pkg/device"
	"golang.org/x/exp/slices"
)

type ASAConfig struct {
	// prefix -> name -> commands with same prefix and name
	lookup objLookup
}

type objLookup map[string]map[string][]*cmd

type cmdType struct {
	prefix   string   // e.g. "crypto map"
	template []string // e.g. ["$NAME", "$SEQ", "match", "address", "$REF"]
	ref      []string // Referenced prefixes, e.g. ["access-list"]
	ignore   bool     // Matching command is ignored.
	sub      []*cmdType
	// Nesting level of commands:
	// - Leaf nodes that don't reference any command have level -1,
	// - A command c1 referencing c2, ..., cn gets one less than
	//   the smallest level of referenced commands
	level int
	// Use "clear configure PREFIX NAME [SEQ]" to remove the complete
	// command
	canClearConf bool
	// Do not change object on device but try to find a matching
	// command on device.
	simpleObject bool
}

type cmd struct {
	typ       *cmdType
	ready     bool // cmd from Netspoc was found on or transferred to device
	needed    bool // cmd on device is referenced and must not be deleted
	toDelete  bool // Remove cmd on device if it is not needed
	fixedName bool

	orig string // e.g. "crypto map abc 10 match address xyz"
	// "*" and `"` of template are only used for matching,
	// but 'parsed' contains original value.
	parsed   string   // e.g. "crypto map $NAME $SEQ match address $REF"
	name     string   // Value of $NAME, e.g. "abc"
	seq      int      // Value of $SEQ,  e.g. 10
	ref      []string // Values of $REF, e.g. ["xyz"]
	sub      []*cmd
	subCmdOf *cmd
}

// Description of commands that will be parsed.
// $NAME matches name of command; only used in toplevel commands.
// First word is used as prefix.
// This prefix may be referenced in other commands as $<prefix>.
// If multiple words are used as prefix, space is replaced by underscore.
//
// Special characters at beginning of line:
// <space>: Mark subcommands of previous command
// !: Matching command or subcommand will be ignored
// #: Comment that is ignored
// '.': Attribute name, altering properties of following command
// Valid attributes:
var cmdInfo = `
# * may reference multiple $object-group, will be resolved later.
access-list $NAME standard *
access-list $NAME extended *
# ignoriere: object-group service|protocol
object-group network $NAME
 network-object *
 group-object *
 description *
ip_local_pool $NAME *
crypto_ca_certificate_map $NAME $SEQ
 subject-name attr *
 extended-key-usage *
crypto_dynamic-map $NAME $SEQ match address $access-list
crypto_dynamic-map $NAME $SEQ ipsec-isakmp dynamic *
# * references one or more $crypto_ipsec_ikev1_transform-set
crypto_dynamic-map $NAME $SEQ set ikev1 transform-set *
# * references one or more $crypto_ipsec_ikev2_ipsec-proposal
crypto_dynamic-map $NAME $SEQ set ikev2 ipsec-proposal *
crypto_dynamic-map $NAME $SEQ set nat-t-disable
crypto_dynamic-map $NAME $SEQ set peer *
crypto_dynamic-map $NAME $SEQ set pfs *
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
crypto_map $NAME $SEQ match address $access-list
crypto_map $NAME $SEQ ipsec-isakmp dynamic $crypto_dynamic-map
# * references one or more $crypto_ipsec_ikev1_transform-set
crypto_map $NAME $SEQ set ikev1 transform-set *
# * references one or more $crypto_ipsec_ikev2_ipsec-proposal
crypto_map $NAME $SEQ set ikev2 ipsec-proposal *
crypto_map $NAME $SEQ set nat-t-disable
crypto_map $NAME $SEQ set peer *
crypto_map $NAME $SEQ set pfs *
crypto_map $NAME $SEQ set reverse-route
crypto_map $NAME $SEQ set security-association lifetime *
crypto_map $NAME $SEQ set trustpoint *
username $NAME nopassword
username $NAME attributes
 vpn-filter value $access-list
 vpn-group-policy $group-policy
 *
tunnel-group-map enable rules
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

var canClearConf = []string{
	"crypto ca certificate map",
	"username",
	"tunnel-group",
	"group-policy",
}

var simpleObject = []string{
	"ip local pool",
	"crypto ipsec ikev1 transform-set",
	"crypto ipsec ikev2 ipsec-proposal",
}

func (s *State) ParseConfig(data []byte) (device.DeviceConfig, error) {
	// prefix -> name -> commands with same prefix and name
	lookup := make(objLookup)
	// Remember previous toplevel command where subcommands are added.
	var prev *cmd
	for len(data) > 0 {
		first, rest, _ := bytes.Cut(data, []byte("\n"))
		data = rest
		line := string(first)
		if line == "" || line[0] == '!' {
			continue
		}
		// Handle sub command.
		if line[0] == ' ' {
			line = line[1:]
			// Ignore sub command of ignored command.
			// Ignore sub-sub command.
			if prev == nil || line[0] == ' ' {
				continue
			}
			words := strings.Split(line, " ")
			if c := matchCmd("", words, prev.typ.sub); c != nil {
				prev.sub = append(prev.sub, c)
				c.subCmdOf = prev
			}
			continue
		}
		// Handle toplevel command.
		c := lookupCmd(line)
		prev = c // Set to next command or nil.
		if c != nil {
			p := c.typ.prefix
			m := lookup[p]
			if m == nil {
				m = make(map[string][]*cmd)
				lookup[p] = m
			}
			m[c.name] = append(m[c.name], c)
		}
	}
	postprocessParsed(lookup)
	err := checkReferences(lookup)
	return &ASAConfig{lookup: lookup}, err
}

func checkReferences(lookup objLookup) error {
	for _, m := range lookup {
		for _, cmdList := range m {
			check := func(c *cmd) error {
				for i, name := range c.ref {
					prefix := c.typ.ref[i]
					if _, found := lookup[prefix][name]; !found {
						if v, found := defaultObjects[[2]string{prefix, name}]; found {
							addDefaultObject(lookup, prefix, name, v)
						} else {
							return fmt.Errorf("'%s' references unknown '%s %s'",
								c.orig, prefix, name)
						}
					}
				}
				return nil
			}
			for _, c := range cmdList {
				if err := check(c); err != nil {
					return err
				}
				for _, sc := range c.sub {
					if err := check(sc); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

var defaultObjects = map[[2]string]string{
	[2]string{"group-policy", "DfltGrpPolicy"}:      "internal",
	[2]string{"tunnel-group", "DefaultL2LGroup"}:    "type ipsec-l2l",
	[2]string{"tunnel-group", "DefaultRAGroup"}:     "type remote-access",
	[2]string{"tunnel-group", "DefaultWEBVPNGroup"}: "type webvpn",
}

func addDefaultObject(lookup objLookup, prefix, name, typ string) {
	m := lookup[prefix]
	if m == nil {
		m = make(map[string][]*cmd)
		lookup[prefix] = m
	}
	c := lookupCmd(prefix + " " + name + " " + typ)
	c.fixedName = true
	l := m[name]
	// Do not add again, if already referenced previously.
	if len(l) > 0 && l[0].parsed == c.parsed {
		return
	}
	m[name] = append([]*cmd{c}, l...)
}

// Add definitions of default group-policy and default tunnel-groups.
func addDefaults(lookup objLookup) {
	for k, v := range defaultObjects {
		addDefaultObject(lookup, k[0], k[1], v)
	}
}

func init() {
	convertCmdInfo()
	setupLookup()
}

var cmdDescr []*cmdType

// Initialize cmdDescr from lines in cmdInfo.
func convertCmdInfo() {
	toParse := cmdInfo
	for toParse != "" {
		store := &cmdDescr
		line, rest, _ := strings.Cut(toParse, "\n")
		toParse = rest
		line = strings.TrimRight(line, " \t\r")
		if line == "" || line[0] == '#' {
			continue
		}
		isSubCmd := false
		if line[0] == ' ' {
			line = line[1:]
			if len(*store) == 0 {
				panic(fmt.Errorf("first line of cmdInfo must not be indented"))
			}
			if line[0] == ' ' {
				panic(fmt.Errorf(
					"only indentation with one space supported in cmdInfo"))
			}
			prev := (*store)[len(*store)-1]
			store = &prev.sub
			isSubCmd = true
		}
		ignore := false
		if line[0] == '!' {
			line = line[1:]
			ignore = true
			if line == "" {
				panic(fmt.Errorf("invalid line with only '!' in cmdInfo"))
			}
		}
		parts := strings.Fields(line)
		prefix := ""
		if !isSubCmd {
			prefix = strings.ReplaceAll(parts[0], "_", " ")
			parts = parts[1:]
		}
		template := parts
		ref := []string{}
		for i, val := range template {
			if val == "*" && i != len(template)-1 {
				panic(fmt.Errorf("* must only be used at end of line in cmdInfo"))
			}
			if !(val[0] == '$' && len(val) > 1) {
				continue
			}
			switch v := val[1:]; v {
			case "NAME", "SEQ", "STRING":
				break
			default:
				ref = append(ref, strings.ReplaceAll(v, "_", " "))
				template[i] = "$REF"
			}
		}
		descr := &cmdType{
			prefix:   prefix,
			template: template,
			ref:      ref,
			ignore:   ignore,
		}
		if slices.Contains(canClearConf, prefix) {
			descr.canClearConf = true
		}
		if slices.Contains(simpleObject, prefix) {
			descr.simpleObject = true
		}
		*store = append(*store, descr)
	}
}

type cmdLookup struct {
	prefixMap map[string]*cmdLookup
	descrList []*cmdType
}

var prefixMap = make(map[string]*cmdLookup)

// Fill prefixMap with commands from cmdDescr.
func setupLookup() {
	for _, descr := range cmdDescr {
		words := strings.Split(descr.prefix, " ")
		m := prefixMap
		for {
			w1 := words[0]
			words = words[1:]
			cl := m[w1]
			if cl == nil {
				cl = &cmdLookup{}
				m[w1] = cl
			}
			if len(words) == 0 {
				if cl.prefixMap != nil {
					panic(fmt.Errorf("inconsistent prefix in cmdInfo: %s", words))
				}
				cl.descrList = append(cl.descrList, descr)
				break
			}
			if cl.descrList != nil {
				panic(fmt.Errorf("inconsistent prefix in cmdInfo: %s", words))
			}
			if cl.prefixMap == nil {
				cl.prefixMap = make(map[string]*cmdLookup)
			}
			m = cl.prefixMap
		}
	}
}

func lookupCmd(line string) *cmd {
	words := strings.Split(line, " ")
	m := prefixMap
	for i, w1 := range words {
		cl := m[w1]
		if cl == nil {
			return nil
		}
		if l := cl.descrList; l != nil {
			prefix := strings.Join(words[:i+1], " ")
			args := words[i+1:]
			return matchCmd(prefix, args, l)
		}
		m = cl.prefixMap
	}
	return nil
}

func matchCmd(prefix string, words []string, l []*cmdType) *cmd {
DESCR:
	for _, descr := range l {
		args := words
		var parsed []string
		var name string
		var seq int
		var ref []string
	TEMPLATE:
		for _, token := range descr.template {
			if len(args) == 0 {
				continue DESCR
			}
			w := args[0]
			switch token {
			case "$NAME":
				name = w
				parsed = append(parsed, token)
			case "$SEQ":
				num, err := strconv.ParseUint(w, 10, 16)
				if err != nil {
					continue DESCR
				}
				seq = int(num)
				parsed = append(parsed, token)
			case "$REF":
				ref = append(ref, w)
				parsed = append(parsed, token)
			case `"`:
				strg := ""
				if w[0] == '"' {
					for j, w2 := range args {
						if strings.HasSuffix(w2, `"`) && !strings.HasSuffix(w2, `\"`) {
							strg = strings.Join(args[:j+1], " ")
							args = args[j:]
							break
						}
					}
				} else {
					strg = `"` + w + `"`
				}
				if strg == "" {
					panic(fmt.Errorf("Incomplete string in: %v", words))
				}
				parsed = append(parsed, strg)
			case "*":
				parsed = append(parsed, strings.Join(args, " "))
				args = nil
				break TEMPLATE
			default:
				if token != w {
					continue DESCR
				}
				parsed = append(parsed, w)
			}
			args = args[1:]
		}
		if len(args) > 0 {
			continue
		}
		if descr.ignore {
			return nil
		}
		if prefix != "" {
			words = append([]string{prefix}, words...)
			parsed = append([]string{prefix}, parsed...)
		}
		c := &cmd{
			typ:    descr,
			orig:   strings.Join(words, " "),
			parsed: strings.Join(parsed, " "),
			name:   name,
			seq:    seq,
			ref:    ref,
		}
		return c
	}
	return nil
}

func postprocessParsed(lookup objLookup) {
	// In access-list, replace "object-group NAME" by "$REF" in cmd.parsed
	// and add "NAME" to cmd.ref .
	for _, l := range lookup["access-list"] {
		for _, c := range l {
			postprocessACL(c)
			// access-list may reference up to five object-groups.
			c.typ.ref = []string{
				"object-group", "object-group", "object-group",
				"object-group", "object-group",
			}
		}
	}
	// NAME in commands
	// "crypto_dynamic-map $NAME $SEQ set ikev1 transform-set NAME ..." and
	// "crypto_map $NAME $SEQ set ikev1 transform-set NAME ..."
	// may reference up to 11 $crypto_ipsec_ikev1_transform-set
	// NAME in commands
	// "crypto_dynamic-map $NAME $SEQ set ikev2 ipsec-proposal NAME ..." and
	// "crypto_map $NAME $SEQ set ikev2 ipsec-proposal NAME ..."
	// may reference up to 11 $crypto_ipsec_ikev2_ipsec-proposal
	setTransRef := func(prefix, part string) {
		cmdPart := " set " + part + " "
		for _, l := range lookup[prefix] {
			for _, c := range l {
				if def, names, found := strings.Cut(c.parsed, cmdPart); found {
					nl := strings.Fields(names)
					c.ref = nl
					c.parsed =
						def + cmdPart + strings.Repeat("$REF ", len(nl)-1) + "$REF"
					def := "crypto ipsec " + part
					c.typ.ref =
						[]string{def, def, def, def, def, def, def, def, def, def, def}
				}
			}
		}
	}
	setTransRef("crypto map", "ikev1 transform-set")
	setTransRef("crypto map", "ikev2 ipsec-proposal")
	setTransRef("crypto dynamic-map", "ikev1 transform-set")
	setTransRef("crypto dynamic-map", "ikev2 ipsec-proposal")

	// Normalize lines
	// aaa-server NAME [(interface-name)] host {IP|NAME} [key] [timeout SECONDS]
	// - strip (interface-name), key, timeout
	// - substitute {IP|NAME} by "x"
	// - check that multiple occurrences with same name but different host
	//   all use the same ldap-attribute-map
	// - replace multiple occurrences of this line by one line
	for name, l := range lookup["aaa-server"] {
		ldapMap := " " // invalid name
		if !strings.HasSuffix(l[0].parsed, "protocol ldap") {
			continue
		}
		for _, c := range l[1:] {
			words := strings.Split(c.parsed, " ")
			// Strip (interface-name)
			if words[2][0] == '(' {
				copy(words[2:], words[3:])
			}
			if words[2] == "host" {
				words[3] = "x"    // Change to value generated by Netspoc.
				words = words[:4] // Strip key, timeout
				ref := ""
				if len(c.sub) != 0 {
					ref = c.sub[0].ref[0]
				}
				if ldapMap != " " && ldapMap != ref {
					device.Abort("aaa-server %s must not use different values"+
						" in 'ldap-attribute-map'",
						name)
				}
				ldapMap = ref
				c.parsed = strings.Join(words, " ")
			}
		}
		lookup["aaa-server"][name] = l[0:2]
	}
	// Normalize subcommand "subject-name attr *"
	// of "crypto ca certificate map" to lowercase for comparison with device,
	// because it gets stored in lowercase on device.
	idMap := make(map[string]string)
	for name, l := range lookup["crypto ca certificate map"] {
		for _, c := range l {
			for _, sc := range c.sub {
				if strings.HasPrefix(sc.parsed, "subject-name") {
					sc.parsed = strings.ToLower(sc.parsed)
				}
				if other, found := idMap[sc.parsed]; found {
					if other > name {
						other, name = name, other
					}
					device.Abort(
						"Two ca cert map items use identical subject-name: '%s', '%s'",
						other, name)
				}
				idMap[sc.parsed] = name
			}
		}
	}
	// Mark commands having fixed name.
	for _, prefix := range []string{
		"crypto map", "username", "crypto dynamic-map", "aaa-server",
		"ldap attribute-map", "tunnel-group",
	} {
		for name, l := range lookup[prefix] {
			if prefix == "tunnel-group" {
				if _, err := netip.ParseAddr(name); err != nil {
					continue
				}
			}
			for _, c := range l {
				c.fixedName = true
			}
		}
	}
}

var protoNames = map[string]int{
	"ah":     51,
	"eigrp":  88,
	"esp":    50,
	"gre":    47,
	"igmp":   2,
	"igrp":   9,
	"ipinip": 4,
	"ipsec":  50,
	"nos":    94,
	"ospf":   89,
	"pcp":    108,
	"pim":    103,
	"pptp":   47,
	"sctp":   132,
	"snp":    109,
}

var protoNonNumeric = map[string]string{
	"1":  "icmp",
	"58": "icmp6",
	"6":  "tcp",
	"17": "udp",
}
var tcpNames = map[string]int{
	"aol":             5190,
	"bgp":             179,
	"chargen":         19,
	"cifs":            3020,
	"citrix-ica":      1494,
	"cmd":             514,
	"ctiqbe":          2748,
	"daytime":         13,
	"discard":         9,
	"domain":          53,
	"echo":            7,
	"exec":            512,
	"finger":          79,
	"ftp":             21,
	"ftp-data":        20,
	"gopher":          70,
	"h323":            1720,
	"hostname":        101,
	"http":            80,
	"https":           443,
	"ident":           113,
	"imap4":           143,
	"irc":             194,
	"kerberos":        750,
	"klogin":          543,
	"kshell":          544,
	"ldap":            389,
	"ldaps":           636,
	"login":           513,
	"lotusnotes":      1352,
	"lpd":             515,
	"netbios-ssn":     139,
	"nfs":             2049,
	"nntp":            119,
	"pcanywhere-data": 5631,
	"pim-auto-rp":     496,
	"pop2":            109,
	"pop3":            110,
	"pptp":            1723,
	"rsh":             514,
	"rtsp":            554,
	"sip":             5060,
	"smtp":            25,
	"sqlnet":          1521,
	"ssh":             22,
	"sunrpc":          111,
	"tacacs":          49,
	"talk":            517,
	"telnet":          23,
	"uucp":            540,
	"whois":           43,
	"www":             80,
}

var udpNames = map[string]int{
	"biff":              512,
	"bootpc":            68,
	"bootps":            67,
	"cifs":              3020,
	"discard":           9,
	"dnsix":             195,
	"domain":            53,
	"echo":              9,
	"http":              80,
	"isakmp":            500,
	"kerberos":          750,
	"mobile-ip":         434,
	"nameserver":        42,
	"netbios-dgm":       138,
	"netbios-ns":        137,
	"nfs":               2049,
	"ntp":               123,
	"pcanywhere-status": 5632,
	"pim-auto-rp":       496,
	"radius":            1645,
	"radius-acct":       1646,
	"rip":               520,
	"secureid-udp":      5510,
	"sip":               5060,
	"snmp":              161,
	"snmptrap":          162,
	"sunrpc":            111,
	"syslog":            514,
	"tacacs":            49,
	"talk":              517,
	"tftp":              69,
	"time":              37,
	"vxlan":             4789,
	"who":               513,
	"www":               80,
	"xdmcp":             177,
}

var icmpTypes = map[string]int{
	"alternate-address":    6,
	"conversion-error":     31,
	"echo":                 8,
	"echo-reply":           0,
	"information-reply":    16,
	"information-request":  15,
	"mask-reply":           18,
	"mask-request":         17,
	"mobile-redirect":      32,
	"parameter-problem":    12,
	"redirect":             5,
	"router-advertisement": 9,
	"router-solicitation":  10,
	"source-quench":        4,
	"time-exceeded":        11,
	"timestamp-reply":      14,
	"timestamp-request":    13,
	"traceroute":           30,
	"unreachable":          3,
}

var icmp6Types = map[string]int{
	"echo":                   128,
	"echo-reply":             129,
	"membership-query":       130,
	"membership-reduction":   132,
	"membership-report":      131,
	"neighbor-advertisement": 136,
	"neighbor-redirect":      137,
	"neighbor-solicitation":  135,
	"packet-too-big":         2,
	"parameter-problem":      4,
	"router-advertisement":   134,
	"router-renumbering":     138,
	"router-solicitation":    133,
	"time-exceeded":          3,
	"unreachable":            1,
}

// Postprocess command
// access-list $NAME extended deny|permit PROTO SRC [PORT] DST [PORT]
// - Replace named numbers by number
// - Replace reference to object-group by $REF
func postprocessACL(c *cmd) {
	tokens := strings.Fields(c.parsed)
	if tokens[2] == "standard" {
		return
	}
	// Skip "access-list $NAME extended deny|permit"
	parts := tokens[4:]
	proto := ""

	convNamed := func(m map[string]int) {
		if num, found := m[parts[0]]; found {
			parts[0] = strconv.Itoa(num)
		}
		parts = parts[1:]
	}
	convNamedPort := func() {
		switch proto {
		case "tcp":
			convNamed(tcpNames)
		case "udp":
			convNamed(udpNames)
		default:
			parts = parts[1:]
		}
	}
	convObjectGroup := func() {
		name := parts[1]
		parts[1] = "$REF"
		c.ref = append(c.ref, name)
		parts = parts[2:]
	}
	convProto := func() {
		proto = parts[0]
		switch proto {
		case "object-group":
			convObjectGroup()
		case "object":
			parts = parts[2:]
		default:
			if name, found := protoNonNumeric[parts[0]]; found {
				parts[0] = name
			}
			convNamed(protoNames)
		}
	}
	convObject := func() {
		if len(parts) > 0 {
			switch parts[0] {
			case "object-group":
				convObjectGroup()
			case "host", "object", "object-group-security", "object-group-user",
				"security-group", "user", "user-group":
				parts = parts[2:]
			case "any", "any4", "any6", "interface":
				parts = parts[1:]
			default:
				if strings.Contains(parts[0], "/") {
					parts = parts[1:]
				} else {
					parts = parts[2:]
				}
			}
		}
	}
	convPort := func() {
		if len(parts) > 0 {
			switch parts[0] {
			case "object-group":
				convObjectGroup()
			case "eq", "gt", "lt", "neq":
				parts = parts[1:]
				convNamedPort()
			case "range":
				parts = parts[1:]
				convNamedPort()
				convNamedPort()
			}
		}
	}
	convICMP := func() {
		if len(parts) > 0 {
			switch proto {
			case "icmp":
				convNamed(icmpTypes)
			case "icmp6":
				convNamed(icmp6Types)
			}
		}
	}

	convProto()
	convObject()
	switch proto {
	case "tcp", "udp":
		convPort()
		convObject()
		convPort()
	case "icmp", "icmp6":
		convObject()
		convICMP()
	}
	c.parsed = strings.Join(tokens, " ")
}
