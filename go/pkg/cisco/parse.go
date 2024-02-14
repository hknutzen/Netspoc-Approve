package cisco

import (
	"bytes"
	"fmt"
	"net/netip"
	"path"
	"strconv"
	"strings"
	"unicode"

	"github.com/hknutzen/Netspoc-Approve/go/pkg/device"
	"golang.org/x/exp/slices"
)

type Config struct {
	// prefix -> name -> commands with same prefix and name
	lookup objLookup
	isRaw  bool
}

type objLookup map[string]map[string][]*cmd

type cmdType struct {
	prefix   string   // e.g. "crypto map"
	template []string // e.g. ["$NAME", "$SEQ", "match", "address", "$REF"]
	ref      []string // Referenced prefixes, e.g. ["access-list"]
	ignore   bool     // Matching command is ignored.
	sub      []*cmdType
	// Use "clear configure PREFIX NAME [SEQ]" to remove the complete
	// command
	clearConf bool
	// Do not change object on device but try to find a matching
	// command on device.
	simpleObj bool
	anchor    bool
	fixedName bool
}

type cmd struct {
	typ   *cmdType
	ready bool // cmd from Netspoc was found on or transferred to device
	// cmd on device is referenced and must not be deleted
	// or is marked as already deleted.
	needed    bool
	toDelete  bool // Remove cmd on device if it is not needed
	anchor    bool
	fixedName bool
	append    bool // Command was found after [APPEND] marker in raw file

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

type parser struct {
	cmdDescr  []*cmdType
	prefixMap map[string]*cmdLookup
}

func (s *State) SetupParser(cmdInfo string) {
	p := &parser{}
	p.setupCmdDescr(cmdInfo)
	p.setupLookup()
	s.parser = p
}

func (p *parser) ParseConfig(data []byte, fName string) (
	device.DeviceConfig, error) {

	// prefix -> name -> commands with same prefix and name
	lookup := make(objLookup)
	// Remember previous toplevel command where subcommands are added.
	var prev *cmd
	// Allow uncommon indentation only at first subcommand.
	isFirstSubCmd := false
	// Indentation count of subcommand.
	indent := 1
	// Mark commands found after [APPEND] marker.
	isAppend := false
	isRaw := path.Ext(fName) == ".raw"
	for len(data) > 0 {
		first, rest, _ := bytes.Cut(data, []byte("\n"))
		data = rest
		line := string(first)
		// Remove whitespace at end of line in manually created raw file.
		line = strings.TrimRightFunc(line, unicode.IsSpace)
		if line == "" || line[0] == '!' {
			continue
		}
		if line == "[APPEND]" {
			isAppend = true
			continue
		}
		if line[0] != ' ' {
			// Handle toplevel command.
			c := p.lookupCmd(line)
			prev = c // Set to next command or nil.
			isFirstSubCmd = true
			if c == nil {
				if isRaw {
					return nil, fmt.Errorf("Unexpected command:\n>>%s<<", line)
				}
			} else {
				p := c.typ.prefix
				m := lookup[p]
				if m == nil {
					m = make(map[string][]*cmd)
					lookup[p] = m
				}
				c.append = isAppend
				m[c.name] = append(m[c.name], c)
			}
		} else if prev != nil {
			// Handle sub command of non ignored command.
			getIndent := func() int {
				return strings.IndexFunc(line, func(c rune) bool { return c != ' ' })
			}
			if isFirstSubCmd {
				// Allow higher indentation at first subcommand.
				// This applies to following subcommands as well.
				isFirstSubCmd = false
				indent = getIndent()
			} else {
				if getIndent() < indent {
					return nil,
						fmt.Errorf("Bad indentation in subcommands:\n"+
							">>%s<<\n>>%s<<",
							strings.Repeat(" ", indent)+prev.sub[0].parsed, line)
				}
			}
			line = line[indent:]
			// Ignore sub-sub command.
			if line[0] == ' ' {
				continue
			}
			// Get arguments.  Use strings.Fields, not strings.Split to
			// remove extra indentation between arguments.
			// Example:  "map-name  memberOf ..."
			words := strings.Fields(line)
			if c := matchCmd("", words, prev.typ.sub); c != nil {
				prev.sub = append(prev.sub, c)
				c.subCmdOf = prev
				c.append = isAppend
			}
		}
	}
	postprocessParsed(lookup)
	err := p.checkReferences(lookup)
	return &Config{lookup: lookup, isRaw: isRaw}, err
}

func (p *parser) checkReferences(lookup objLookup) error {
	for _, m := range lookup {
		for _, cmdList := range m {
			check := func(c *cmd) error {
				for i, name := range c.ref {
					prefix := c.typ.ref[i]
					if _, found := lookup[prefix][name]; !found {
						if vl, found := defaultObjects[[2]string{prefix, name}]; found {

							p.addDefaultObject(lookup, prefix, name, vl)
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

var defaultObjects = map[[2]string][]string{
	{"group-policy", "DfltGrpPolicy"}: {"internal"},
	{"tunnel-group", "DefaultL2LGroup"}: {
		"type ipsec-l2l", "general-attributes"},
	{"tunnel-group", "DefaultRAGroup"}: {
		"type remote-access", "general-attributes"},
	{"tunnel-group", "DefaultWEBVPNGroup"}: {"type webvpn", "general-attributes"},
}

func (p *parser) addDefaultObject(lookup objLookup, prefix, name string, vl []string) {
	m := lookup[prefix]
	if m == nil {
		m = make(map[string][]*cmd)
		lookup[prefix] = m
	}
OBJ:
	for _, arg := range vl {
		c := p.lookupCmd(prefix + " " + name + " " + arg)
		l := m[name]
		// Do only add, if not already parsed previously.
		for _, c2 := range l {
			if c2.parsed == c.parsed {
				c2.fixedName = true
				c2.anchor = true
				continue OBJ
			}
		}
		c.fixedName = true
		c.anchor = true
		l = append([]*cmd{c}, l...)
		m[name] = l
	}
}

// Add definitions of default group-policy and default tunnel-groups.
func (p *parser) addDefaults(cf *Config) {
	lookup := cf.lookup
	for k, vl := range defaultObjects {
		prefix, name := k[0], k[1]
		if p.prefixMap[prefix] != nil { // Ignore ASA defaults for IOS.
			p.addDefaultObject(lookup, prefix, name, vl)
		}
	}
}

type header struct {
	anchor    bool
	fixedName bool
	clearConf bool
	simpleObj bool
}

// Initialize cmdDescr from lines in cmdInfo.
func (p *parser) setupCmdDescr(info string) {
	toParse := info
	sectHead := header{}
	for toParse != "" {
		store := &p.cmdDescr
		line, rest, _ := strings.Cut(toParse, "\n")
		toParse = rest
		line = strings.TrimRight(line, " \t\r")
		if line == "" {
			sectHead = header{}
			continue
		}
		isSubCmd := false
		ignore := false
		switch line[0] {
		case '#':
			continue
		case '[':
			sectHead = parseHeader(line)
			continue
		case ' ':
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
			case "NAME", "SEQ":
				continue
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
		if sectHead.anchor {
			descr.anchor = true
		}
		if sectHead.fixedName {
			descr.fixedName = true
		}
		if sectHead.clearConf {
			descr.clearConf = true
		}
		if sectHead.simpleObj {
			descr.simpleObj = true
		}
		*store = append(*store, descr)
	}
}

func parseHeader(line string) header {
	h := header{}
	line = strings.Trim(line, "[]")
	for _, w := range strings.Split(line, ",") {
		w = strings.TrimSpace(w)
		switch w {
		case "ANCHOR":
			h.anchor = true
		case "FIXED_NAME":
			h.fixedName = true
		case "SIMPLE_OBJ":
			h.simpleObj = true
		case "CLEAR_CONF":
			h.clearConf = true
		default:
			panic(fmt.Errorf("Invalid token %q in section header of cmdInfo", w))
		}
	}
	return h
}

type cmdLookup struct {
	prefixMap map[string]*cmdLookup
	descrList []*cmdType
}

// Fill prefixMap with commands from cmdDescr.
func (p *parser) setupLookup() {
	p.prefixMap = make(map[string]*cmdLookup)
	for _, descr := range p.cmdDescr {
		words := strings.Split(descr.prefix, " ")
		m := p.prefixMap
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

func (p *parser) lookupCmd(line string) *cmd {
	words := strings.Split(line, " ")
	m := p.prefixMap
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
				num, err := strconv.ParseUint(w, 10, 0)
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
			postprocessASAACL(c)
			// access-list may reference up to five object-groups.
			c.typ.ref = []string{
				"object-group", "object-group", "object-group",
				"object-group", "object-group",
			}
		}
	}
	for _, l := range lookup["ip access-list extended"] {
		for _, c := range l[0].sub {
			postprocessIOSACL(c)
		}
	}
	// Move crypto map interface commands to different prefix for
	// easier subsequent processing.
	if l := lookup["crypto map"][""]; l != nil {
		lookup["crypto map interface"] = map[string][]*cmd{"": l}
		delete(lookup["crypto map"], "")
	}
	// NAME in commands
	// - "crypto_dynamic-map $NAME $SEQ set ikev1 transform-set NAME ..." and
	// - "crypto_map $NAME $SEQ set ikev1 transform-set NAME ..."
	// may reference up to 11 $crypto_ipsec_ikev1_transform-set
	// NAME in commands
	// - "crypto_dynamic-map $NAME $SEQ set ikev2 ipsec-proposal NAME ..." and
	// - "crypto_map $NAME $SEQ set ikev2 ipsec-proposal NAME ..."
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

	// Strip default value 'group2' from "crypto [dynamic-]map set pfs group2"
	stripPFSDefault := func(prefix string) {
		for _, l := range lookup[prefix] {
			for _, c := range l {
				if strings.HasSuffix(c.parsed, "$NAME $SEQ set pfs group2") {
					c.parsed = strings.TrimSuffix(c.parsed, " group2")
				}
			}
		}
	}
	stripPFSDefault("crypto map")
	stripPFSDefault("crypto dynamic-map")

	// Normalize routes:
	// Strip trailing [metric] in
	// - "route if_name ip_address netmask gateway_ip [metric]"
	// - "ipv6 route if_name destination next_hop_ipv6_addr [metric]"
	stripMetric := func(prefix string) {
		for _, l := range lookup[prefix] {
			for _, c := range l {
				tokens := strings.Split(c.parsed, " ")
				if len(tokens) == 6 {
					c.parsed = strings.Join(tokens[:5], " ")
				}
			}
		}
	}
	stripMetric("route")
	stripMetric("ipv6 route")

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
		if len(l) > 1 {
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
	}
	// Normalize subcommand "subject-name *"
	// of "crypto ca certificate map" to lowercase for comparison with device,
	// because it gets stored in lowercase on device.
	for _, l := range lookup["crypto ca certificate map"] {
		for _, c := range l {
			for _, sc := range c.sub {
				if strings.HasPrefix(sc.parsed, "subject-name") {
					sc.parsed = strings.ToLower(sc.parsed)
				}
			}
		}
	}
	// Mark tunnel-group having IP address as name.
	for name, l := range lookup["tunnel-group"] {
		if _, err := netip.ParseAddr(name); err == nil {
			for _, c := range l {
				c.fixedName = true
				c.anchor = true
			}
		}
	}
}

var protoNames = map[string]int{
	"ah":     51,
	"ahp":    51,
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
	"aol":                 5190,
	"bgp":                 179,
	"chargen":             19,
	"cifs":                3020,
	"citrix-ica":          1494,
	"cmd":                 514,
	"connectedapps-plain": 15001,
	"connectedapps-tls":   15002,
	"ctiqbe":              2748,
	"daytime":             13,
	"discard":             9,
	"domain":              53,
	"echo":                7,
	"exec":                512,
	"finger":              79,
	"ftp":                 21,
	"ftp-data":            20,
	"gopher":              70,
	"h323":                1720,
	"hostname":            101,
	"http":                80,
	"https":               443,
	"ident":               113,
	"imap4":               143,
	"irc":                 194,
	"kerberos":            750,
	"klogin":              543,
	"kshell":              544,
	"ldap":                389,
	"ldaps":               636,
	"login":               513,
	"lotusnotes":          1352,
	"lpd":                 515,
	"msrpc":               135,
	"netbios-ssn":         139,
	"nfs":                 2049,
	"nntp":                119,
	"pcanywhere-data":     5631,
	"pim-auto-rp":         496,
	"pop2":                109,
	"pop3":                110,
	"pptp":                1723,
	"rsh":                 514,
	"rtsp":                554,
	"sip":                 5060,
	"smtp":                25,
	"sqlnet":              1521,
	"ssh":                 22,
	"sunrpc":              111,
	"tacacs":              49,
	"tacacs-ds":           65,
	"talk":                517,
	"telnet":              23,
	"uucp":                540,
	"whois":               43,
	"www":                 80,
}

var udpNames = map[string]int{
	"biff":              512,
	"bootpc":            68,
	"bootps":            67,
	"cifs":              3020,
	"discard":           9,
	"dns":               53,
	"dnsix":             195,
	"domain":            53,
	"echo":              7,
	"http":              80,
	"isakmp":            500,
	"kerberos":          750,
	"mobile-ip":         434,
	"nameserver":        42,
	"netbios-dgm":       138,
	"netbios-ns":        137,
	"netbios-ss":        139,
	"nfs":               2049,
	"non500-isakmp":     4500,
	"ntp":               123,
	"pcanywhere-status": 5632,
	"pim-auto-rp":       496,
	"radius":            1645,
	"radius-acct":       1646,
	"rip":               520,
	"ripng":             521,
	"ripv6":             521,
	"secureid-udp":      5510,
	"sip":               5060,
	"snmp":              161,
	"snmptrap":          162,
	"sunrpc":            111,
	"syslog":            514,
	"tacacs":            49,
	"tacacs-ds":         65,
	"talk":              517,
	"tftp":              69,
	"time":              37,
	"vxlan":             4789,
	"who":               513,
	"www":               80,
	"xdmcp":             177,
}

var icmpTypeCodes = map[string]string{
	"administratively-prohibited": "3 13",
	"alternate-address":           "6",
	"conversion-error":            "31",
	"dod-host-prohibited":         "3 10",
	"dod-net-prohibited":          "3 9",
	"echo":                        "8",
	"echo-reply":                  "0",
	"general-parameter-problem":   "12 0",
	"host-isolated":               "3 8",
	"host-precedence-unreachable": "3 14",
	"host-redirect":               "5 1",
	"host-tos-redirect":           "5 3",
	"host-tos-unreachable":        "3 12",
	"host-unknown":                "3 7",
	"host-unreachable":            "3 1",
	"information-reply":           "16",
	"information-request":         "15",
	"mask-reply":                  "18",
	"mask-request":                "17",
	"mobile-redirect":             "32",
	"net-redirect":                "5 0",
	"net-tos-redirect":            "5 2",
	"net-tos-unreachable":         "3 11",
	"net-unreachable":             "3 0",
	"network-unknown":             "3 6",
	"no-room-for-option":          "12 2",
	"option-missing":              "12 1",
	"packet-too-big":              "3 4",
	"parameter-problem":           "12",
	"port-unreachable":            "3 3",
	"precedence-unreachable":      "3 15",
	"protocol-unreachable":        "3 2",
	"reassembly-timeout":          "11",
	"redirect":                    "5",
	"router-advertisement":        "9",
	"router-solicitation":         "10",
	"source-quench":               "4",
	"source-route-failed":         "3 5",
	"time-exceeded":               "11",
	"timestamp-reply":             "14",
	"timestamp-request":           "13",
	"traceroute":                  "30",
	"ttl-exceeded":                "11 0",
	"unreachable":                 "3",
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

var logNames = map[string]int{
	"emergencies":   0,
	"alerts":        1,
	"critical":      2,
	"errors":        3,
	"warnings":      4,
	"notifications": 5,
	"informational": 6,
	"debugging":     7,
}

func postprocessIOSACL(c *cmd) {
	tokens := strings.Fields(c.parsed)
	// Remove sequence number shown since IOS-XE 16.12.
	if tokens[0] == "$SEQ" {
		tokens = tokens[1:]
		c.parsed = strings.Join(tokens, " ")
		_, c.orig, _ = strings.Cut(c.orig, " ")
	}
	if tokens[0] == "remark" {
		return
	}
	// Skip "deny|permit"
	parts := tokens[1:]
	// Variables 'tokens' and 'parts' use same backing store.
	postprocessACLParts(c, parts)
	tokens = slices.DeleteFunc(tokens, func(w string) bool { return w == "" })
	c.parsed = strings.Join(tokens, " ")
}

// Postprocess command
// access-list $NAME extended deny|permit PROTO SRC [PORT] DST [PORT]
// - Replace named TCP, UDP ports and ICMP type by number
// - Replace named log level by number
// - Replace reference to object-group by $REF
// - Replace network with host mask by host
func postprocessASAACL(c *cmd) {
	tokens := strings.Fields(c.parsed)
	if tokens[2] != "extended" {
		return
	}
	// Skip "access-list $NAME extended deny|permit"
	parts := tokens[4:]
	// Variables 'tokens' and 'parts' use same backing store.
	postprocessACLParts(c, parts)
	tokens = slices.DeleteFunc(tokens, func(w string) bool { return w == "" })
	c.parsed = strings.Join(tokens, " ")
}

func postprocessACLParts(c *cmd, parts []string) {
	proto := ""

	convNamed := func(m map[string]int) {
		if len(parts) > 0 {
			if num, found := m[parts[0]]; found {
				parts[0] = strconv.Itoa(num)
			}
			parts = parts[1:]
		}
	}
	convNamedPort := func() {
		switch proto {
		case "tcp":
			convNamed(tcpNames)
		case "udp":
			convNamed(udpNames)
		}
	}
	convObjectGroup := func() {
		name := parts[1]
		parts[1] = "$REF"
		c.ref = append(c.ref, name)
		parts = parts[2:]
	}
	convProto := func() {
		switch parts[0] {
		case "object-group":
			convObjectGroup()
		case "object":
			parts = parts[2:]
		default:
			if name, found := protoNonNumeric[parts[0]]; found {
				parts[0] = name
			}
			proto = parts[0]
			convNamed(protoNames)
		}
	}
	convObject := func() {
		if len(parts) > 0 {
			switch parts[0] {
			case "object-group":
				convObjectGroup()
			case "log", "log-input":
				parts = parts[1:]
				if len(parts) > 0 {
					if num, found := logNames[parts[0]]; found {
						parts[0] = strconv.Itoa(num)
					}
					if parts[0] == "6" {
						parts[0] = ""
					}
					parts = parts[1:]
				}
				convNamed(logNames)
			case "host", "object", "object-group-security", "object-group-user",
				"security-group", "user", "user-group":
				parts = parts[2:]
			case "any", "any4", "any6", "interface":
				parts = parts[1:]
			default:
				if ip, bits, found := strings.Cut(parts[0], "/"); found {
					switch bits {
					case "0":
						parts[0] = "any6"
					case "128":
						parts[0] = "host " + ip
					}
					parts = parts[1:]
				} else if len(parts) >= 2 {
					switch parts[1] {
					case "0.0.0.0":
						parts[0], parts[1] = "any4", ""
					case "255.255.255.255":
						parts[0], parts[1] = "host", parts[0]
					}
					parts = parts[2:]
				}
			}
		}
	}
	convPortOrObject := func() {
		if len(parts) > 0 {
			switch parts[0] {
			case "eq", "gt", "lt", "neq":
				parts = parts[1:]
				convNamedPort()
			case "range":
				parts = parts[1:]
				convNamedPort()
				convNamedPort()
			default:
				convObject()
			}
		}
	}
	convICMP := func() {
		if len(parts) > 0 {
			switch proto {
			case "icmp":
				if replace, found := icmpTypeCodes[parts[0]]; found {
					parts[0] = replace
					parts = parts[1:]
				}
			case "icmp6":
				convNamed(icmp6Types)
			}
		}
	}
	skipNumber := func() {
		if len(parts) > 0 {
			if _, err := strconv.ParseUint(parts[0], 10, 8); err == nil {
				parts = parts[1:]
			}
		}
	}

	convProto()
	convObject()
	switch proto {
	case "tcp", "udp":
		convPortOrObject()
		convPortOrObject()
		convPortOrObject()
	case "icmp", "icmp6":
		convObject()
		convICMP()
		skipNumber()
	default:
		convObject()
	}
	convObject()
}

// Postprocess subcommands of object-groups:
// - replace named TCP, UDP ports and ICMP type by number
// - replace network with host mask by host
// port-object eq NAME
// port-object range NAME1 NAME2
// icmp-object NAME
// service-object { protocol |{ tcp | udp |tcp-udp | sctp }
//                  [ source operator number ]
//                  [ destination operator number ]|
//                { icmp | icmp6 }[ icmp_type [ icmp_code ]]
//
// Not implemented, since Netspoc currently not generates object-groups
// of services.
