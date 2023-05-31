package asa

import (
	"bytes"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/hknutzen/Netspoc-Approve/go/pkg/device"
	"golang.org/x/exp/slices"
)

type ASAConfig struct {
	// prefix -> name -> commands with same prefix and name
	lookup map[string]map[string][]*cmd
}

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
}

type cmd struct {
	typ       *cmdType
	ready     bool // cmd from Netspoc was found on or transferred to device
	needed    bool // cmd on device is referenced and must not be deleted
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

func (s *State) ParseConfig(data []byte) (device.DeviceConfig, error) {
	// prefix -> name -> commands with same prefix and name
	lookup := make(map[string]map[string][]*cmd)
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

func checkReferences(lookup map[string]map[string][]*cmd) error {
	for _, m := range lookup {
		for _, cmdList := range m {
			check := func(c *cmd) error {
				for i, name := range c.ref {
					prefix := c.typ.ref[i]
					if _, found := lookup[prefix][name]; !found {
						return fmt.Errorf("Referencing unknown '%s %s' from '%s'",
							prefix, name, c.orig)
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

var objGroupRegex = regexp.MustCompile(`\bobject-group (\S+)\b`)

func postprocessParsed(lookup map[string]map[string][]*cmd) {
	// In access-list, replace "object-group NAME" by "$REF" in cmd.parsed
	// and add "NAME" to cmd.ref .
	for _, l := range lookup["access-list"] {
		for _, c := range l {
			c.parsed =
				objGroupRegex.ReplaceAllStringFunc(c.parsed, func(s string) string {
					_, name, _ := strings.Cut(s, " ")
					c.ref = append(c.ref, name)
					return "object-group $REF"
				})
			// access-list may reference up to three object-groups.
			c.typ.ref = []string{"object-group", "object-group", "object-group"}
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

func addDefaults(lookup map[string]map[string][]*cmd) {
	getPrefixMap := func(p string) map[string][]*cmd {
		m := lookup[p]
		if m == nil {
			m = make(map[string][]*cmd)
			lookup[p] = m
		}
		return m
	}
	// Add definition of default group-policy
	m := getPrefixMap("group-policy")
	name := "DfltGrpPolicy"
	c := lookupCmd("group-policy " + name + " internal")
	c.fixedName = true
	m[name] = append([]*cmd{c}, m[name]...)
	// Add definition of default tunnel-groups.
	name2typ := map[string]string{
		"DefaultL2LGroup":    "ipsec-l2l",
		"DefaultRAGroup":     "remote-access",
		"DefaultWEBVPNGroup": "webvpn",
	}
	m = getPrefixMap("tunnel-group")
	for name, typ := range name2typ {
		c := lookupCmd("tunnel-group " + name + " type " + typ)
		c.fixedName = true
		m[name] = append([]*cmd{c}, m[name]...)
	}
}
