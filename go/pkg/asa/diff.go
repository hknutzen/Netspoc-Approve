package asa

import (
	"net/netip"
	"sort"
	"strings"

	"github.com/pkg/diff/myers"
	"golang.org/x/exp/maps"
)

var anchors = []string{
	"access-group", "crypto map", "username", "tunnel-group-map",
}

func (s *State) diffConfig() {
	s.diffUnnamedCmds("route", getParsed)
	s.diffUnnamedCmds("ipv6 route", getParsed)
	s.diffUnnamedCmds("no sysopt connection permit-vpn", getParsed)
	// Use parsed command "access-group $REF interface <NAME>",
	// effectively using name of interface as key.
	s.diffUnnamedCmds("access-group", getParsed)
	// Use list of subcommands of referenced crypto_ca_certificate_map as key.
	certMapKey := func(conf *ASAConfig, c *cmd) string {
		name := c.ref[0]
		prefix := c.typ.ref[0]
		l := conf.lookup[prefix][name]
		if l == nil {
			return ""
		}
		var result []string
		for _, s := range l[0].sub {
			result = append(result, s.parsed)
		}
		return strings.Join(result, "\n")
	}
	s.diffTunnelGroup()
	s.diffUnnamedCmds("tunnel-group-map", certMapKey)
	s.diffSubCmds("webvpn", certMapKey)
	s.diffNamedCmds("username")
	s.deleteUnused()
}

func getParsed(_ *ASAConfig, c *cmd) string {
	return c.parsed
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

func (s *State) diffCmds(al, bl []*cmd, key keyFunc, isRef refCmd) {
	ab := &cmdsPair{
		a:     s.a,
		b:     s.b,
		aCmds: al,
		bCmds: bl,
		key:   key,
	}
	for _, r := range myers.Diff(nil, ab).Ranges {
		if r.IsDelete() {
			if !isRef {
				s.delCmds(ab.aCmds[r.LowA:r.HighA])
			}
		} else if r.IsInsert() {
			s.addCmds(ab.bCmds[r.LowB:r.HighB])
		} else {
			al := ab.aCmds[r.LowA:r.HighA]
			bl := ab.bCmds[r.LowB:r.HighB]
			s.makeEqual(al, bl)
		}
	}
}

// tunnel-group command is anchor, if name is IP address.
func (s *State) diffTunnelGroup() {
	aMap := s.a.lookup["tunnel-group"]
	bMap := s.b.lookup["tunnel-group"]
	getNames := func(m map[string][]*cmd) []string {
		var result []string
		for name := range m {
			if _, err := netip.ParseAddr(name); err == nil {
				result = append(result, name)
			}
		}
		sort.Strings(result)
		return result
	}
	aNames := getNames(aMap)
	bNames := getNames(bMap)
	s.diffNamedCmds2(aMap, bMap, aNames, bNames)
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

func (s *State) diffNamedCmds2(
	aMap, bMap map[string][]*cmd, aNames, bNames []string) {

	for _, aName := range aNames {
		al := aMap[aName]
		if bl, found := bMap[aName]; found {
			s.makeEqual(al, bl)
		} else {
			s.delCmds(al)
		}
	}
	for _, bName := range bNames {
		if _, found := aMap[bName]; !found {
			s.addCmds(bMap[bName])
		}
	}
}

func (s *State) delCmds(l []*cmd) {
	for _, c := range l {
		c.deleted = true
		s.setSuperCmd(c)
		s.changes.push("no " + c.orig)
	}
}

// Recursively transfer commands referenced from command and subcommands.
// Then transfer command and its subcommands.
// Mark transferred commands as transferred.
// Transfer each command only once.
func (s *State) addCmds(l []*cmd) {
	var add func(l []*cmd)
	add = func(l []*cmd) {
		for _, c := range l {
			if c.transferred {
				continue
			}
			c.transferred = true
			withRefCmdsDo(s.b, c, add)
			s.addCmd(c)
		}
	}
	add(l)
}

func (s *State) addCmd(c *cmd) {
	s.setSuperCmd(c)
	s.changes.push(c.orig)
	for _, sc := range c.sub {
		s.changes.push(sc.orig)
	}
}

func (s *State) setSuperCmd(c *cmd) {
	if c.subCmdOf == nil {
		s.subCmdOf = c
	} else {
		if s.subCmdOf == nil || s.subCmdOf.orig != c.subCmdOf.orig {
			s.changes.push(c.subCmdOf.orig)
			s.subCmdOf = c.subCmdOf
		}
	}
}

func withRefCmdsDo(cnf *ASAConfig, c *cmd, do func([]*cmd)) {
	follow := func(c *cmd) {
		for i, name := range c.ref {
			prefix := c.typ.ref[i]
			l := cnf.lookup[prefix][name]
			do(l)
		}
	}
	follow(c)
	for _, sc := range c.sub {
		follow(sc)
	}
}

// al and bl are lists of commands, known to be equal.
// Equalize subcommands and referenced commands.
func (s *State) makeEqual(al, bl []*cmd) {
	for i, a := range al {
		a.needed = true
		b := bl[i]
		s.diffCmds(a.sub, b.sub, getParsed, noRef)
		for i, name := range a.ref {
			prefix := a.typ.ref[i]
			s.diffCmds(s.a.lookup[prefix][name], s.b.lookup[prefix][name],
				getParsed, isRef)
		}
	}
}

// Delete unused toplevel commands from device.
func (s *State) deleteUnused() {
	for _, m := range s.a.lookup {
		for name, l := range m {
			if name != "" {
				for _, c := range l {
					if !c.needed && !c.deleted {
						c.deleted = true
						s.changes.push("no " + c.orig)
					}
				}
			}
		}
	}
}
