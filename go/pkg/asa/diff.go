package asa

import (
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/hknutzen/Netspoc-Approve/go/pkg/device"
	"github.com/pkg/diff/myers"
	"golang.org/x/exp/maps"
)

var anchors = []string{
	"access-group", "crypto map", "username", "tunnel-group-map",
}

func (s *State) diffConfig() {
	s.generateNamesForTransfer()
	s.diffUnnamedCmds("route", getParsed)
	s.diffUnnamedCmds("ipv6 route", getParsed)
	s.diffUnnamedCmds("no sysopt connection permit-vpn", getParsed)
	// Use parsed command "access-group $REF interface <NAME>",
	// effectively using name of interface as key.
	s.diffUnnamedCmds("access-group", getParsed)
	// Use "subject-name" of referenced "crypto ca certificate map" as key.
	certMapKey := func(conf *ASAConfig, c *cmd) string {
		name := c.ref[0]
		prefix := c.typ.ref[0]
		l := conf.lookup[prefix][name]
		if l == nil {
			return ""
		}
		for _, sc := range l[0].sub {
			if strings.HasPrefix(sc.parsed, "subject-name attr") {
				return sc.parsed
			}
		}
		return ""
	}
	s.diffUnnamedCmds("tunnel-group-map", certMapKey)
	s.diffSubCmds("webvpn", certMapKey)
	s.diffNamedCmds("username")
	s.diffNamedCmds("crypto map")
	s.diffTunnelGroup()
	s.diffPredefined("group-policy", "DfltGrpPolicy")
	s.diffPredefined("tunnel-group", "ipsec-l2l")
	s.diffPredefined("tunnel-group", "remote-access")
	s.diffPredefined("tunnel-group", "webvpn")
	s.deleteUnused()
}

func getParsed(_ *ASAConfig, c *cmd) string {
	key := c.parsed
	// Must not change this command, which may be referenced from
	// different places.
	if c.typ.prefix == "crypto ipsec ikev2 ipsec-proposal" {
		for _, sc := range c.sub {
			key += " " + sc.parsed
		}
	}
	return key
}

func (s *State) diffUnnamedCmds(prefix string, key keyFunc) {
	s.sortDiffCmds(func(c *ASAConfig) []*cmd { return c.lookup[prefix][""] }, key)
}

func (s *State) diffSubCmds(prefix string, key keyFunc) {
	al := s.a.lookup[prefix][""]
	bl := s.b.lookup[prefix][""]
	if al == nil {
		if bl == nil {
			return
		}
		s.addCmds(bl)
	} else if bl == nil {
		s.delCmds(al)
	} else {
		s.sortDiffCmds(func(c *ASAConfig) []*cmd {
			if l := c.lookup[prefix][""]; l != nil {
				return l[0].sub
			}
			return nil
		},
			key,
		)
	}
}

func (s *State) diffNamedCmds(prefix string) {
	aMap := s.a.lookup[prefix]
	bMap := s.b.lookup[prefix]
	aNames := maps.Keys(aMap)
	bNames := maps.Keys(bMap)
	sort.Strings(aNames)
	sort.Strings(bNames)
	s.diffNamedCmds2(aMap, bMap, aNames, bNames)
}

// tunnel-group command is anchor, if name is IP address.
func (s *State) diffTunnelGroup() {
	aMap := s.a.lookup["tunnel-group"]
	bMap := s.b.lookup["tunnel-group"]
	getIPNames := func(m map[string][]*cmd) []string {
		var result []string
		for name := range m {
			if _, err := netip.ParseAddr(name); err == nil {
				result = append(result, name)
			}
		}
		sort.Strings(result)
		return result
	}
	aNames := getIPNames(aMap)
	bNames := getIPNames(bMap)
	s.diffNamedCmds2(aMap, bMap, aNames, bNames)
}

func (s *State) diffNamedCmds2(
	aMap, bMap map[string][]*cmd, aNames, bNames []string) {

	for _, aName := range aNames {
		s.diffSeqCmds(aMap[aName], bMap[aName], getParsed, noRef)
	}
	for _, bName := range bNames {
		if _, found := aMap[bName]; !found {
			s.diffSeqCmds(nil, bMap[bName], getParsed, noRef)
		}
	}
}

func (s *State) diffPredefined(prefix, name string) {
	aMap := s.a.lookup[prefix]
	bMap := s.b.lookup[prefix]
	if al, found := aMap[name]; found {
		if bl, found := bMap[name]; found {
			s.makeEqual(al, bl)
		} else {
			for _, aCmd := range al {
				aCmd.needed = true
			}
		}
	} else if bl, found := bMap[name]; found {
		s.addCmds(bl)
	}
}

func (s *State) diffSeqCmds(al, bl []*cmd, key keyFunc, isRef refCmd) {
	mapBySeq := func(l []*cmd) map[int][]*cmd {
		m := make(map[int][]*cmd)
		for _, c := range l {
			m[c.seq] = append(m[c.seq], c)
		}
		return m
	}
	aSeqMap := mapBySeq(al)
	bSeqMap := mapBySeq(bl)
	var prefix string
	if len(al) > 0 {
		prefix = al[0].typ.prefix
	} else {
		prefix = bl[0].typ.prefix
	}
	if prefix == "crypto map" {
		s.diffCryptoMap(aSeqMap, bSeqMap, key, isRef)
	} else {
		if len(aSeqMap) > 1 || len(bSeqMap) > 1 {
			device.Abort("Only one sequence nummber supported with '%s'", prefix)
		}
		var al, bl []*cmd
		for _, al = range aSeqMap {
			break
		}
		for _, bl = range bSeqMap {
			break
		}
		s.diffCmds(al, bl, key, isRef)
	}
}

func (s *State) diffCryptoMap(
	aSeqMap, bSeqMap map[int][]*cmd, key keyFunc, isRef refCmd) {

	mapByPeer := func(seqMap map[int][]*cmd) map[string][]*cmd {
		m := make(map[string][]*cmd)
		for _, l := range seqMap {
			peer := ""
			for _, c := range l {
				if _, p, found := strings.Cut(c.parsed, " set peer "); found {
					peer = p
					break
				}
				if strings.Contains(c.parsed, " ipsec-isakmp dynamic ") {
					peer = c.ref[0]
					break
				}
			}
			if peer == "" {
				device.Abort("Missing peer or dynamic in crypto map %s %s",
					l[0].name, l[0].seq)
			}
			if _, found := m[peer]; found {
				device.Abort(
					"Duplicate peer or dynamic peer %s in crypto map %s %s",
					peer, l[0].name, l[0].seq)
			}
			m[peer] = l
		}
		return m
	}
	aPeerMap := mapByPeer(aSeqMap)
	bPeerMap := mapByPeer(bSeqMap)
	aPeers := maps.Keys(aPeerMap)
	bPeers := maps.Keys(bPeerMap)
	sort.Strings(aPeers)
	sort.Strings(bPeers)
	for _, aPeer := range aPeers {
		s.diffCmds(aPeerMap[aPeer], bPeerMap[aPeer], getParsed, isRef)
	}
	// Use fresh sequence number per peer for added commands from Netspoc.
	seq := 1
	for _, bPeer := range bPeers {
		if _, found := aPeerMap[bPeer]; !found {
			bl := bPeerMap[bPeer]
			for {
				if _, found := aSeqMap[seq]; !found {
					break
				}
				seq++
			}
			for _, bCmd := range bl {
				bCmd.seq = seq
			}
			s.diffCmds(nil, bl, getParsed, isRef)
			seq++
		}
	}
}

type keyFunc func(*ASAConfig, *cmd) string

type cmdsPair struct {
	a, b         *ASAConfig
	aCmds, bCmds []*cmd
	key          keyFunc
}

func (ab *cmdsPair) LenA() int { return len(ab.aCmds) }
func (ab *cmdsPair) LenB() int { return len(ab.bCmds) }

func (ab *cmdsPair) Equal(ai, bi int) bool {
	return ab.key(ab.a, ab.aCmds[ai]) == ab.key(ab.b, ab.bCmds[bi])
}

func (s *State) sortDiffCmds(lookup func(*ASAConfig) []*cmd, key keyFunc) {
	sorted := func(c *ASAConfig) []*cmd {
		l := lookup(c)
		sort.Slice(l, func(i, j int) bool { return key(c, l[i]) < key(c, l[j]) })
		return l
	}
	s.diffCmds(sorted(s.a), sorted(s.b), key, noRef)
}

type refCmd bool

const (
	noRef refCmd = false
	isRef refCmd = true
)

// Compare list of commands having equal prefix.
// Return name of existing command, if it is unchanged or modified
// or return name of new command, if it replaces old command.
func (s *State) diffCmds(al, bl []*cmd, key keyFunc, isRef refCmd) string {
	// Command on device was already equalized with other command from Netspoc.
	if len(al) > 0 && al[0].needed {
		if len(bl) > 0 {
			s.addCmds(bl)
			return bl[0].name
		}
		return ""
	}
	// Command from Netspoc already was transferred or was found on device.
	if len(bl) > 0 {
		c := bl[0]
		if c.ready {
			return c.name
		}
	}
	ab := &cmdsPair{
		a:     s.a,
		b:     s.b,
		aCmds: al,
		bCmds: bl,
		key:   key,
	}
	diff := myers.Diff(nil, ab).Ranges
	// If some command modifies existing command on device with name N,
	// then also use name N in other added commands (having same prefix).
	nameN := ""
FINDEQ:
	for _, r := range diff {
		if r.IsEqual() {
			for _, aCmd := range al[r.LowA:r.HighA] {
				nameN = aCmd.name
				break FINDEQ
			}
		}
	}
	for _, r := range diff {
		if r.IsDelete() {
			if !isRef {
				s.delCmds(al[r.LowA:r.HighA])
			}
		} else if r.IsInsert() {
			l := bl[r.LowB:r.HighB]
			for _, bCmd := range l {
				if nameN != "" {
					bCmd.name = nameN
				}
			}
			s.addCmds(l)
		} else {
			s.makeEqual(al[r.LowA:r.HighA], bl[r.LowB:r.HighB])
		}
	}
	if nameN != "" {
		return nameN
	}
	if len(bl) > 0 {
		return bl[0].name
	}
	return ""
}

// al and bl are lists of commands, known to be equal, but names may differ.
// Equalize subcommands and referenced commands.
// Overwrite command
func (s *State) makeEqual(al, bl []*cmd) {
	for i, a := range al {
		b := bl[i]
		//fmt.Fprintf(os.Stderr, "a: %s\n", a)
		//fmt.Fprintf(os.Stderr, "b: %s\n", b)
		a.needed = true
		b.name = a.name
		b.seq = a.seq
		b.ready = true
		s.diffCmds(a.sub, b.sub, getParsed, noRef)
		changedRef := false
		for i, aName := range a.ref {
			prefix := a.typ.ref[i]
			bName := b.ref[i]
			if prefix == "aaa-server" && aName != bName {
				changedRef = true
				s.addCmds(s.b.lookup[prefix][bName])
				continue
			}
			refName := s.diffCmds(
				s.a.lookup[prefix][aName],
				s.b.lookup[prefix][bName],
				getParsed, isRef)
			//fmt.Fprintf(os.Stderr, "refName: %s, aName: %s, bName: %s\n",
			//	refName, aName, bName)
			if refName != aName {
				changedRef = true
			}
			b.ref[i] = refName
		}
		if changedRef {
			s.addCmd(b)
		}
	}
}

// Recursively transfer commands referenced from command and subcommands.
// Then transfer command and its subcommands.
// Mark transferred commands.
// Transfer each command only once.
func (s *State) addCmds(l []*cmd) {
	var add func(l []*cmd) string
	follow := func(c *cmd) {
		for i, name := range c.ref {
			prefix := c.typ.ref[i]
			if s.b.lookup[prefix][name][0].fixedName {
				if al, found := s.a.lookup[prefix][name]; found {
					s.diffCmds(al, s.b.lookup[prefix][name], getParsed, isRef)
					continue
				}
				switch prefix {
				case "aaa-server", "ldap attribute-map":
					device.Abort("'%s %s' must be transferred manually", prefix, name)
				}
			}
			c.ref[i] = add(s.b.lookup[prefix][name])
		}
	}
	add = func(l []*cmd) string {
		for _, c := range l {
			if !c.ready {
				c.ready = true
				follow(c)
				for _, sc := range c.sub {
					follow(sc)
				}
				s.addCmd(c)
			}
		}
		return l[0].name
	}
	add(l)
}

func (s *State) addCmd(c *cmd) {
	switch c.typ.prefix {
	case "aaa-server", "ldap attribute-map":
		return
	}
	s.setSuperCmd(c)
	s.changes.push(c.String())
	for _, sc := range c.sub {
		s.changes.push(sc.String())
	}
}

func (s *State) delCmds(l []*cmd) {
	for _, c := range l {
		if c.needed {
			continue
		}
		c.deleted = true
		s.setSuperCmd(c)
		if c2 := strings.TrimPrefix(c.orig, "no "); c.orig != c2 {
			s.changes.push(c2)
		} else {
			s.changes.push("no " + c.orig)
		}
	}
}

// Delete unused toplevel commands from device.
func (s *State) deleteUnused() {
	prefixes := maps.Keys(s.a.lookup)
	sort.Strings(prefixes)
	for _, prefix := range prefixes {
		m := s.a.lookup[prefix]
		names := maps.Keys(m)
		sort.Strings(names)
		for _, name := range names {
			if name != "" {
				for _, c := range m[name] {
					switch c.typ.prefix {
					case "aaa-server", "ldap attribute-map":
						continue
					}
					if !c.needed && !c.deleted {
						c.deleted = true
						s.changes.push("no " + c.orig)
					}
				}
			}
		}
	}
}

func (c *cmd) String() string {
	s := c.parsed
	s = strings.Replace(s, "$NAME", c.name, 1)
	s = strings.Replace(s, "$SEQ", strconv.Itoa(c.seq), 1)
	for _, r := range c.ref {
		s = strings.Replace(s, "$REF", r, 1)
	}
	return s
}

func (s *State) setSuperCmd(c *cmd) {
	if c.subCmdOf == nil {
		s.subCmdOf = c
	} else {
		if s.subCmdOf == nil || s.subCmdOf.orig != c.subCmdOf.orig {
			s.changes.push(c.subCmdOf.String())
			s.subCmdOf = c.subCmdOf
		}
	}
}

// Generate new names for objects from Netspoc: <spoc-name>-DRC-<index>
func (s *State) generateNamesForTransfer() {
	set := func(c *cmd, devNames map[string][]*cmd) {
		prefix := c.name + "-DRC-"
		index := 0
		for {
			newName := prefix + strconv.Itoa(index)
			if _, found := devNames[newName]; !found {
				//fmt.Fprintf(os.Stderr, "%s -> %s\n", c.name, newName)
				c.name = newName
				break
			}
			index++
		}
	}
	for prefix, m := range s.b.lookup {
		fixed := false
		switch prefix {
		case "crypto map", "username", // Anchors
			"crypto dynamic-map",               // Has certificate as name.
			"aaa-server", "ldap attribute-map": // Has fixed name.
			fixed = true
		}
		for name, bl := range m {
			switch name {
			case "":
				continue
			case "DfltGrpPolicy":
				if prefix == "group-policy" {
					fixed = true
				}
			}
			if prefix == "tunnel-group" {
				if _, err := netip.ParseAddr(name); err == nil {
					fixed = true
				}
			}
			for _, c := range bl {
				if fixed {
					c.fixedName = true
				} else {
					set(c, s.a.lookup[prefix])
				}
			}
		}
	}
}
