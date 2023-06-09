package asa

import (
	"sort"
	"strconv"
	"strings"

	"github.com/hknutzen/Netspoc-Approve/go/pkg/device"
	"github.com/pkg/diff/myers"
	"golang.org/x/exp/constraints"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
)

var anchors = []string{
	"access-group", "crypto map", "username", "tunnel-group-map",
}

func (s *State) diffConfig() {
	addDefaults(s.a.lookup)
	addDefaults(s.b.lookup)
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
	s.diffFixedNames("group-policy")
	s.diffFixedNames("tunnel-group")
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
	} else if bl != nil {
		for _, aCmd := range al {
			aCmd.needed = true
		}
		s.sortDiffCmds(
			func(c *ASAConfig) []*cmd {
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
	aNames := sortedKeys(aMap)
	bNames := sortedKeys(bMap)
	s.diffNamedCmds2(aMap, bMap, aNames, bNames)
}

func (s *State) diffFixedNames(prefix string) {
	aMap := s.a.lookup[prefix]
	bMap := s.b.lookup[prefix]
	getFixedNames := func(m map[string][]*cmd) []string {
		var result []string
		for name, l := range m {
			if l[0].fixedName {
				result = append(result, name)
			}
		}
		sort.Strings(result)
		return result
	}
	aNames := getFixedNames(aMap)
	bNames := getFixedNames(bMap)
	s.diffNamedCmds2(aMap, bMap, aNames, bNames)
}

func (s *State) diffNamedCmds2(
	aMap, bMap map[string][]*cmd, aNames, bNames []string) {

	for _, aName := range aNames {
		s.diffSeqCmds(aMap[aName], bMap[aName], getParsed)
	}
	for _, bName := range bNames {
		if _, found := aMap[bName]; !found {
			s.diffSeqCmds(nil, bMap[bName], getParsed)
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

func (s *State) diffSeqCmds(al, bl []*cmd, key keyFunc) {
	aSeqMap := mapBySeq(al)
	bSeqMap := mapBySeq(bl)
	var prefix string
	if len(al) > 0 {
		prefix = al[0].typ.prefix
	} else {
		prefix = bl[0].typ.prefix
	}
	if prefix == "crypto map" {
		s.diffCryptoMap(aSeqMap, bSeqMap, key)
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
		s.diffCmds(al, bl, key)
	}
}

func (s *State) diffCryptoMap(aSeqMap, bSeqMap map[int][]*cmd, key keyFunc) {
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
	aPeers := sortedKeys(aPeerMap)
	bPeers := sortedKeys(bPeerMap)
	for _, aPeer := range aPeers {
		s.diffCmds(aPeerMap[aPeer], bPeerMap[aPeer], getParsed)
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
			s.diffCmds(nil, bl, getParsed)
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
	s.diffCmds(sorted(s.a), sorted(s.b), key)
}

// Compare list of commands having equal prefix.
// Return name of existing command, if it is unchanged or modified
// or return name of new command, if it replaces old command.
func (s *State) diffCmds(al, bl []*cmd, key keyFunc) string {
	if len(al) == 0 && len(bl) == 0 {
		return ""
	}
	// Command on device was already equalized with other command from Netspoc.
	if len(al) > 0 && al[0].needed {
		if len(bl) > 0 {
			s.addCmds(bl)
			return bl[0].name
		}
		return ""
	}
	if len(bl) > 0 {
		c := bl[0]
		// Command from Netspoc already was transferred or was found on device.
		if c.ready {
			return c.name
		}
		// Find equal simple object on device or transfer.
		if c.typ.simpleObject {
			return s.equalizeSimpleObject(al, bl)
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
	for _, r := range diff {
		if r.IsEqual() {
			nameN = al[0].name
			break
		}
	}
	// Delete commands before adding new ones
	// But must not delete complete toplevel command, because currently
	// it is not known, if it is referenced by some other command.
	for _, r := range diff {
		if r.IsDelete() {
			if nameN != "" || r.HighA > r.LowA && al[r.LowA].subCmdOf != nil {
				s.delCmds(al[r.LowA:r.HighA])
			}
			s.markDeleted(al[r.LowA:r.HighA])
		}
	}
	for _, r := range diff {
		if r.IsInsert() {
			l := bl[r.LowB:r.HighB]
			for _, bCmd := range l {
				if nameN != "" {
					bCmd.name = nameN
				}
			}
			s.addCmds(l)
		} else if r.IsEqual() {
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
		s.diffCmds(a.sub, b.sub, getParsed)
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
				getParsed)
			//fmt.Fprintf(os.Stderr, "refName: %s, aName: %s, bName: %s\n",
			//	refName, aName, bName)
			if refName != aName {
				changedRef = true
			}
			//b.ref[i] = refName
		}
		if changedRef {
			if strings.Contains(b.parsed, "$NAME $SEQ set ikev") {
				s.changes.push("no " + a.orig)
			}
			s.addCmd(b)
		}
	}
}

func (s *State) equalizeSimpleObject(al, bl []*cmd) string {
	if !simpleObjEqual(al, bl) {
		s.markDeleted(al)
		al = s.findSimpleObjOnDevice(bl)
	}
	if al != nil {
		al[0].needed = true
		bl[0].ready = true
		bl[0].name = al[0].name
		return al[0].name
	}
	s.addCmds(bl)
	return bl[0].name
}

func (s *State) findSimpleObjOnDevice(bl []*cmd) []*cmd {
	prefix := bl[0].typ.prefix
	m := s.a.lookup[prefix]
	names := sortedKeys(m)
	for _, name := range names {
		al := m[name]
		if simpleObjEqual(al, bl) {
			return al
		}
	}
	return nil
}

func simpleObjEqual(al, bl []*cmd) bool {
	if len(al) != len(bl) {
		return false
	}
	ac, bc := al[0], bl[0]
	sortedSub := func(c *cmd) []string {
		l := make([]string, len(c.sub))
		for i, s := range c.sub {
			l[i] = s.parsed
		}
		sort.Strings(l)
		return l
	}
	return ac.parsed == bc.parsed && slices.Equal(sortedSub(ac), sortedSub(bc))
}

// Recursively transfer commands referenced from command and subcommands.
// Then transfer command and its subcommands.
// Mark transferred commands.
// Transfer each command only once.
func (s *State) addCmds(l []*cmd) {
	var add func(l []*cmd)
	follow := func(c *cmd) {
		for i, name := range c.ref {
			prefix := c.typ.ref[i]
			if s.b.lookup[prefix][name][0].fixedName {
				if al, found := s.a.lookup[prefix][name]; found {
					s.diffCmds(al, s.b.lookup[prefix][name], getParsed)
					continue
				}
				switch prefix {
				case "aaa-server", "ldap attribute-map":
					device.Abort("'%s %s' must be transferred manually", prefix, name)
				}
			}
			add(s.b.lookup[prefix][name])
		}
	}
	add = func(bl []*cmd) {
		if bl[0].ready {
			return
		}
		bl[0].ready = true
		if bl[0].typ.simpleObject {
			if al := s.findSimpleObjOnDevice(bl); al != nil {
				al[0].needed = true
				bl[0].name = al[0].name
				return
			}
		}
		for _, c := range bl {
			follow(c)
			for _, sc := range c.sub {
				follow(sc)
			}
			s.addCmd(c)
		}
		return
	}
	add(l)
}

func (s *State) addCmd(c *cmd) {
	switch c.typ.prefix {
	case "aaa-server", "ldap attribute-map":
		return
	}
	pr := s.printNetspocCmd(c)
	// If current command is subcommand of some command x
	// then write x and remember that x has been written,
	// so that it isn't written again if another subcommand of x is modified.
	if sup := c.subCmdOf; sup != nil {
		pr2 := s.printNetspocCmd(sup)
		if s.subCmdOf != pr2 {
			s.changes.push(pr2)
			s.subCmdOf = pr2
		}
	} else {
		s.subCmdOf = pr
	}
	s.changes.push(pr)
	for _, sub := range c.sub {
		s.changes.push(s.printNetspocCmd(sub))
	}
}

// Delete subcommands and parts of multi line command.
func (s *State) delCmds(l []*cmd) {
	for _, c := range l {
		if sup := c.subCmdOf; sup != nil && s.subCmdOf != sup.orig {
			s.changes.push(sup.orig)
			s.subCmdOf = sup.orig
		}
		c.needed = true // Don't delete again later.
		s.changes.push("no " + c.orig)
	}
}

// Mark command on device and referenced commands as deleted.
func (s *State) markDeleted(al []*cmd) {
	var del func(al []*cmd)
	follow := func(c *cmd) {
		for i, name := range c.ref {
			prefix := c.typ.ref[i]
			del(s.a.lookup[prefix][name])
		}
	}
	del = func(al []*cmd) {
		for _, c := range al {
			if !c.toDelete {
				c.toDelete = true
				follow(c)
				for _, sc := range c.sub {
					follow(sc)
				}
			}
		}
	}
	del(al)
}

// Delete unused toplevel command from device
// - that was previously referenced by command generated from Netspoc or
// - that was generated by Netspoc, but was accidently not deleted in last run.
func (s *State) deleteUnused() {
	deleteable := func(c *cmd) bool {
		return !c.needed && (c.toDelete) // || strings.Contains(c.name, "-DRC-"))
	}
	prefixes := maps.Keys(s.a.lookup)
	s.sortByNestedFirst(prefixes)
	for _, prefix := range prefixes {
		switch prefix {
		case "aaa-server", "ldap attribute-map", "interface":
			continue
		}
		m := s.a.lookup[prefix]
		names := sortedKeys(m)
		for _, name := range names {
			l := m[name]
			deleteAll := true
			for _, c := range l {
				if !deleteable(c) {
					deleteAll = false
				}
			}
			c0 := l[0]
			if t := c0.typ; deleteAll && t.canClearConf {
				clear := "clear configure " + prefix + " " + name
				s.changes.push(clear)
			} else {
				for _, c := range l {
					if deleteable(c) {
						if c2 := strings.TrimPrefix(c.orig, "no "); c.orig != c2 {
							s.changes.push(c2)
						} else {
							s.changes.push("no " + c.orig)
						}
					}
				}
			}
		}
	}
}

func (s *State) printNetspocCmd(c *cmd) string {
	p := c.parsed
	p = strings.Replace(p, "$NAME", c.name, 1)
	p = strings.Replace(p, "$SEQ", strconv.Itoa(c.seq), 1)
	for i, r := range c.ref {
		prefix := c.typ.ref[i]
		name := s.b.lookup[prefix][r][0].name
		p = strings.Replace(p, "$REF", name, 1)
	}
	return p
}

func (s *State) sortByNestedFirst(prefixes []string) {
	setLevels := func() {
		// Build map from prefix to cmdType.
		m := make(map[string][]*cmdType)
		for _, t := range cmdDescr {
			m[t.prefix] = append(m[t.prefix], t)
		}
		// Mark nodes that reference some marked node.
		// If some marked node is found, set new level as smallest level - 1.
		for ready := false; !ready; ready = true {
			for _, t := range cmdDescr {
				lv := 0
				follow := func(t *cmdType) {
					for _, prefix := range t.ref {
						for _, t2 := range m[prefix] {
							if lv2 := t2.level; lv2 < lv {
								//fmt.Fprintf(os.Stdout, "%v -> %v %v\n",
								//	t.prefix, t2.prefix, lv2)
								lv = lv2
							}
						}
					}
				}
				follow(t)
				for _, t2 := range t.sub {
					follow(t2)
				}
				lv--
				if lv < t.level {
					t.level = lv
					//fmt.Fprintf(os.Stdout, "%s %v\n", t.prefix, lv)
					ready = false

				}
			}
		}
		// For multiple commands with same name and prefix take smallest value.
		for _, l := range m {
			lv := 0
			for _, t := range l {
				if t.level < lv {
					lv = t.level
				}
			}
			l[0].level = lv
		}
	}
	getLevel := func(prefix string) int {
		return maps.Values(s.a.lookup[prefix])[0][0].typ.level
	}
	setLevels()
	sort.Strings(prefixes)
	sort.SliceStable(prefixes, func(i, j int) bool {
		return getLevel(prefixes[i]) < getLevel(prefixes[j])
	})
}

// Generate new names for objects from Netspoc: <spoc-name>-DRC-<index>
func (s *State) generateNamesForTransfer() {
	setName := func(c *cmd, devNames map[string][]*cmd) {
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
		for _, bl := range m {
			for _, c := range bl {
				if !c.fixedName {
					setName(c, s.a.lookup[prefix])
				}
			}
		}
	}
}

func mapBySeq(l []*cmd) map[int][]*cmd {
	m := make(map[int][]*cmd)
	for _, c := range l {
		m[c.seq] = append(m[c.seq], c)
	}
	return m
}

func sortedKeys[M ~map[K]V, K constraints.Ordered, V any](m M) []K {
	keys := maps.Keys(m)
	slices.Sort(keys)
	return keys
}
