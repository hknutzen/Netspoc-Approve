package cisco

import (
	"cmp"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/hknutzen/Netspoc-Approve/go/pkg/device"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/sorted"
	"github.com/pkg/diff/edit"
	"github.com/pkg/diff/myers"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
)

type State struct {
	*parser
	a        *Config
	b        *Config
	Changes  []string
	Model    string
	subCmdOf string
}

func (s *State) addChange(chg string) {
	s.Changes = append(s.Changes, chg)
}

func (s *State) GetChanges(c1, c2 device.DeviceConfig) error {
	s.a = c1.(*Config)
	s.b = c2.(*Config)
	s.alignVRFs()
	if err := s.checkInterfaces(); err != nil {
		return err
	}
	s.ignoreCryptoGDOI()
	s.diffConfig()
	return nil
}

func (s *State) HasChanges() bool {
	return len(s.Changes) != 0
}

func (s *State) ShowChanges() string {
	var collect strings.Builder
	for _, chg := range s.Changes {
		chg = strings.Replace(chg, "\n", "\\N ", 1)
		fmt.Fprintln(&collect, chg)
	}
	return collect.String()
}

func (s *State) diffConfig() {
	s.addDefaults(s.a)
	s.addDefaults(s.b)
	sortGroups(s.a)
	sortGroups(s.b)
	sortRoutes(s.a)
	sortRoutes(s.b)
	s.generateNamesForTransfer()
	comb := make(objLookup)
	maps.Copy(comb, s.a.lookup)
	maps.Copy(comb, s.b.lookup)
	for _, prefix := range sorted.Keys(comb) {
		if prefix == "tunnel-group-map" {
			s.diffTunnelGroupMap()
		} else if prefix == "webvpn" {
			s.diffWebVPN()
		} else {
			var anchor bool
			for _, l := range comb[prefix] {
				anchor = l[0].typ.anchor
				break
			}
			if anchor {
				s.diffAnchors(prefix)
			} else {
				s.diffSomeAnchors(prefix)
			}
		}
	}
	s.deleteUnused()
}

func byParsedCmd(_ *Config, c *cmd) string {
	return c.parsed
}

func (s *State) diffAnchors(prefix string) {
	aMap := s.a.lookup[prefix]
	bMap := s.b.lookup[prefix]
	aNames := sorted.Keys(aMap)
	bNames := sorted.Keys(bMap)
	s.diffNamedCmds2(aMap, bMap, aNames, bNames)
}

func (s *State) diffSomeAnchors(prefix string) {
	aMap := s.a.lookup[prefix]
	bMap := s.b.lookup[prefix]
	onlyAnchorNames := func(m map[string][]*cmd) []string {
		var result []string
		for name, l := range m {
			if l[0].anchor {
				result = append(result, name)
			}
		}
		sort.Strings(result)
		return result
	}
	aNames := onlyAnchorNames(aMap)
	bNames := onlyAnchorNames(bMap)
	s.diffNamedCmds2(aMap, bMap, aNames, bNames)
}

func (s *State) diffNamedCmds2(
	aMap, bMap map[string][]*cmd, aNames, bNames []string) {

	for _, aName := range aNames {
		s.diffCmds(aMap[aName], bMap[aName], byParsedCmd)
	}
	for _, bName := range bNames {
		if _, found := aMap[bName]; !found {
			s.diffCmds(nil, bMap[bName], byParsedCmd)
		}
	}
}

// Use "subject-name" of referenced "crypto ca certificate map" as key.
func byCertMapKey(cf *Config, c *cmd) string {
	if len(c.ref) == 1 {
		// tunnel-group-map default-group $tunnel-group
		return "default-group"
	}
	name := c.ref[0]
	prefix := c.typ.ref[0]
	l := cf.lookup[prefix][name]
	for _, sc := range l[0].sub {
		if strings.HasPrefix(sc.parsed, "subject-name attr") {
			return sc.parsed
		}
	}
	return ""
}

func (s *State) diffTunnelGroupMap() {
	prefix := "tunnel-group-map"
	al := s.a.lookup[prefix][""]
	bl := s.b.lookup[prefix][""]
	s.diffCmds(al, bl, byCertMapKey)
}

func (s *State) diffWebVPN() {
	prefix := "webvpn"
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
		s.diffCmds(al[0].sub, bl[0].sub, byCertMapKey)
	} else {
		s.delCmds(al[0].sub)
	}
}

type keyFunc func(*Config, *cmd) string

type cmdsPair struct {
	a, b         *Config
	aCmds, bCmds []*cmd
	key          keyFunc
}

func (ab *cmdsPair) LenA() int { return len(ab.aCmds) }
func (ab *cmdsPair) LenB() int { return len(ab.bCmds) }

func (ab *cmdsPair) Equal(ai, bi int) bool {
	return ab.key(ab.a, ab.aCmds[ai]) == ab.key(ab.b, ab.bCmds[bi])
}

// Compare list of commands
// - toplevel commands having equal prefix and to be compared names or
// - subcommands of otherwise equal toplevel command.
// Return name of existing command, if it is unchanged or modified
// or return name of new command, if it replaces old command.
func (s *State) diffCmds(al, bl []*cmd, key keyFunc) string {
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
		if c.typ.simpleObj {
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
	hasEq := false
	isEq := true
	diff := diffCmdLists(ab)
	for _, r := range diff {
		if r.IsEqual() {
			hasEq = true
		} else {
			isEq = false
		}
	}
	if len(al) > 0 {
		if p := al[0].typ.prefix; p == "route" ||
			p == "ip route" || p == "ipv6 route" {

			s.diffRoutes(al, bl, diff)
			return ""
		}
	}
	// Standard ACL can't be changed incrementally.
	// Ignore "access-list $NAME remark " in first line.
	if !isEq {
		for _, c := range al {
			if strings.HasPrefix(c.parsed, "access-list $NAME extended ") {
				break
			}
			if strings.HasPrefix(c.parsed, "access-list $NAME standard ") {
				hasEq = false
				break
			}
		}
	}
	// No parts are equal, hence remove all from device and add all from Netspoc.
	if !hasEq {
		if len(al) > 0 {
			// Must not delete complete toplevel command, because at this time
			// it is not known, if it is referenced by some other command.
			if al[0].subCmdOf == nil {
				s.markDeleted(al)
			} else {
				s.delCmds(al)
			}
		}
		if len(bl) > 0 {
			s.addCmds(bl)
			return bl[0].name
		}
		return ""
	}
	// Commands modify existing command on device.
	// Use name of existing command in added commands.
	for _, r := range diff {
		if r.IsInsert() {
			for _, bCmd := range bl[r.LowB:r.HighB] {
				bCmd.name = al[0].name
			}
		}
	}

	if al[0].typ.prefix == "access-list" {
		s.diffASAACLs(al, bl, diff)
		return al[0].name
	}
	if c := al[0].subCmdOf; c != nil &&
		c.typ.prefix == "ip access-list extended" {

		s.diffIOSACLs(al, bl, diff)
		return al[0].name
	}
	// Delete commands before adding new ones
	for _, r := range diff {
		if r.IsDelete() {
			s.delCmds(al[r.LowA:r.HighA])
		}
	}
	for _, r := range diff {
		if r.IsInsert() {
			s.addCmds(bl[r.LowB:r.HighB])
		} else if r.IsEqual() {
			s.makeEqual(al[r.LowA:r.HighA], bl[r.LowB:r.HighB])
		}
	}
	return al[0].name
}

// al and bl are lists of commands, known to be equal, but names may differ.
// Equalize subcommands and referenced commands.
// Overwrite command
func (s *State) makeEqual(al, bl []*cmd) {
	for i, a := range al {
		b := bl[i]
		a.needed = true
		b.name = a.name
		b.seq = a.seq
		b.ready = true
		s.diffCmds(a.sub, b.sub, byParsedCmd)
		changedRef := false
		for i, aName := range a.ref {
			prefix := a.typ.ref[i]
			bName := b.ref[i]
			aRef := s.a.lookup[prefix][aName]
			bRef := s.b.lookup[prefix][bName]
			var refName string
			if prefix == "aaa-server" && aName != bName {
				refName = bName
				s.addCmds(bRef)
			} else if prefix == "crypto map" {
				refName = s.diffCryptoMap(aRef, bRef)
			} else {
				refName = s.diffCmds(aRef, bRef, byParsedCmd)
			}
			if refName != aName {
				changedRef = true
			}
		}
		if changedRef {
			if strings.Contains(b.parsed, "$NAME $SEQ set ikev") {
				s.addChange("no " + a.orig)
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
	return findSimpleObject(bl, s.a)
}

func findSimpleObject(bl []*cmd, a *Config) []*cmd {
	prefix := bl[0].typ.prefix
	m := a.lookup[prefix]
	names := sorted.Keys(m)
	for _, name := range names {
		al := m[name]
		if simpleObjEqual(al, bl) {
			return al
		}
	}
	return nil
}

func simpleObjEqual(al, bl []*cmd) bool {
	// Simple objects are known to have exactly one toplevel command.
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

func (s *State) diffIOSACLs(al, bl []*cmd, diff []edit.Range) {
	aclName := al[0].subCmdOf.name
	// Position where to add or delete a command.
	pos := make(map[*cmd]int)
	s.addChange("ip access-list resequence " + aclName + " 10000 10000")
	chgLen := len(s.Changes)
	// ACL lines have been sorted; take original position from c.seq
	for _, c := range al {
		pos[c] = (c.seq + 1) * 10000
	}
	// Collect to be added and to be deleted entries.
	var add, del []*cmd
	addACL := func(b *cmd) {
		b.parsed = strconv.Itoa(pos[b]) + " " + b.parsed
		s.addCmds([]*cmd{b})
	}
	delACL := func(a *cmd) {
		a.orig = strconv.Itoa(pos[a])
		s.delCmds([]*cmd{a})
	}

	// Generate move command which sends add and delete command together
	// as a single command.
	moveACL := func(a, b *cmd) {
		delACL(a)
		i := len(s.Changes) - 1
		addACL(b)
		top := len(s.Changes) - 1
		del := s.Changes[i]
		add := s.Changes[top]
		s.Changes = s.Changes[:top]
		s.Changes[top-1] = del + "\n" + add
	}

	// Check if insert position is between first and last line
	// of a block of permit rules (or deny rules).
	// Checks both, current and original position.
	// Returns action and position or empty action, if at border of block.
	insideBlock := func(pos int) string {
		var lowAct, highAct string
		for i := pos - 1; i >= 0; i-- {
			if a := getIOSAction(al[i]); a != "remark" {
				lowAct = a
				break
			}
		}
		for i := pos; i < len(al); i++ {
			if a := getIOSAction(al[i]); a != "remark" {
				highAct = a
				break
			}
		}
		if lowAct == highAct {
			return lowAct
		}
		return ""
	}
	// Restore a sorted block of lines to its original order.
	unsortBlock := func(pos int) {
		a := getIOSAction(al[pos])
		var low int
		for i := pos - 1; i >= 0; i-- {
			switch getIOSAction(al[i]) {
			case "remark":
			case a:
				low = i
			default:
				break
			}
		}
		high := pos
		for i := pos + 1; i < len(al); i++ {
			switch getIOSAction(al[i]) {
			case "remark":
			case a:
				high = i
			default:
				break
			}
		}
		l := al[low : high+1]
		slices.SortFunc(l, func(a, b *cmd) int {
			return cmp.Compare(a.seq, b.seq)
		})
	}

	// Check for dangerous case, where block must not be sorted:
	// A deny rule is inserted into a block of permit rules or
	// a permit rule is inserted into a block of deny rules.
	renewDiff := false
	for _, r := range diff {
		if r.IsInsert() {
			if action := insideBlock(r.LowA); action != "" {
				for _, c := range bl[r.LowB:r.HighB] {
					if action != getIOSAction(c) {
						unsortBlock(r.LowA)
						renewDiff = true
						break
					}
				}
			}
		}
	}
	if renewDiff {
		ab := &cmdsPair{
			a:     s.a,
			b:     s.b,
			aCmds: al,
			bCmds: bl,
			key:   byParsedCmd,
		}
		diff = myers.Diff(nil, ab).Ranges
	}
	for _, r := range diff {
		if r.IsInsert() {
			if r.HighB-r.LowB >= 10000 {
				device.Abort("Can't insert more than 9999 ACL lines at once")
			}
			for i, c := range bl[r.LowB:r.HighB] {
				pos[c] = r.LowA*10000 + i + 1
			}
			add = append(add, bl[r.LowB:r.HighB]...)
		} else if r.IsDelete() {
			del = append(del, al[r.LowA:r.HighA]...)
		}
	}
	// An ACL line which is already present on device can't be added again.
	// Therefore we need add, delete and move operations.
	//
	// Two ACL lines which differ only in 'log' attribute,
	// can't both be present on a device.
	// [ log | log-input ]
	// Hence we must remove one line before we can add the other one.
	//
	// Find move operations from commands in 'add' and 'del'.
	// A command is moved if the same command is deleted and added.
	// Two commands are equal if they
	// - have same attribute .parsed,
	//   but attribute 'log' is ignored during compare.
	delMap := make(map[string]*cmd)
	rx := regexp.MustCompile(` log(?:-input)?`)
	for _, a := range del {
		p := getPrintableCmd(a, s.a)
		p = rx.ReplaceAllLiteralString(p, "")
		delMap[p] = a
	}
	for _, b := range add {
		p := s.printNetspocCmd(b)
		p = rx.ReplaceAllLiteralString(p, "")
		if a := delMap[p]; a != nil {
			moveACL(a, b)
			continue
		}
		addACL(b)
	}
	// Delete lines on device.
	// Work from bottom to top. Otherwise we would permit too much
	// traffic for a short time range.
	slices.Reverse(del)
	for _, a := range del {
		// Must not delete cmd again, if it already was moved.
		if !a.needed {
			delACL(a)
		}
	}
	if len(s.Changes) == chgLen {
		// No changes found; remove initial resequence command.
		s.Changes = s.Changes[:chgLen-1]
	} else {
		s.addChange("ip access-list resequence " + aclName + " 10 10")
	}
}

func (s *State) diffASAACLs(al, bl []*cmd, diff []edit.Range) {
	// Collect to be added and to be deleted entries.
	var add, del []*cmd
	// Position where to add or delete a command.
	pos := make(map[*cmd]int)

	// access-list NAME ...
	// ==>
	// access-list NAME line N ...
	insertLineNr := func(s string, pos int) string {
		nr := strconv.Itoa(pos + 1)
		l := len("access-list ")
		i := strings.Index(s[l:], " ")
		return s[:l+i] + " line " + nr + s[l+i:]
	}
	addACL := func(b *cmd) {
		b.parsed = insertLineNr(b.parsed, pos[b])
		s.addCmds([]*cmd{b})
		i := pos[b]
		for cmd, p := range pos {
			if p >= i {
				pos[cmd] = p + 1
			}
		}
	}
	delACL := func(a *cmd) {
		a.orig = insertLineNr(a.orig, pos[a])
		s.delCmds([]*cmd{a})
		i := pos[a]
		for cmd, p := range pos {
			if p > i {
				pos[cmd] = p - 1
			}
		}
	}

	// Generate move command which sends add and delete command together
	// as a single command.
	//
	// First append delete and add command to s.changes:
	// i  : no access-list ...
	// i+1: object-group g1 ...
	// ...: object-group gN ...
	// top: access-list ...
	//
	// Then
	// - move commands between 'i' and 'top' to position 'i',
	// - join commands at 'i' and at 'top' into a single command at position 'top'-1
	// i  : object-group g1 ...
	// ...: object-group gN ...
	// top-1: no access-list ...\n access-list
	moveACL := func(a, b *cmd) {
		delACL(a)
		i := len(s.Changes) - 1
		addACL(b)
		top := len(s.Changes) - 1
		del := s.Changes[i]
		add := s.Changes[top]
		copy(s.Changes[i:], s.Changes[i+1:])
		s.Changes = s.Changes[:top]
		s.Changes[top-1] = del + "\n" + add
	}

	// al and bl are list of access-list commands known to be equal,
	// assuming object-groups as equal.
	// Equalize corresponding object-groups.
	// Also add commands to change access-list that need to be changed on
	// device, because name of referenced object-group has changed.
	equalizeACLs := func(al, bl []*cmd, lowA int) {
		for i, a := range al {
			b := bl[i]
			b.name = a.name
			pos[a] = lowA + i
			pos[b] = lowA + i
			changedRef := false
			for i, aName := range a.ref {
				bName := b.ref[i]
				if !s.equalizedGroups(aName, bName) {
					changedRef = true
				}
			}
			if changedRef {
				add = append(add, b)
				del = append(del, a)
			} else {
				a.needed = true
				b.ready = true
			}
		}
	}
	// Check for identical groups early and equalize groups later.
	for _, r := range diff {
		if r.IsInsert() {
			for _, c := range bl[r.LowB:r.HighB] {
				for _, bName := range c.ref {
					s.findGroupOnDevice(bName)
				}
			}
		}
	}
	for _, r := range diff {
		if r.IsInsert() {
			for _, c := range bl[r.LowB:r.HighB] {
				pos[c] = r.LowA
			}
			add = append(add, bl[r.LowB:r.HighB]...)
		} else if r.IsDelete() {
			for i, c := range al[r.LowA:r.HighA] {
				pos[c] = i + r.LowA
			}
			del = append(del, al[r.LowA:r.HighA]...)
		} else if r.IsEqual() {
			equalizeACLs(al[r.LowA:r.HighA], bl[r.LowB:r.HighB], r.LowA)
		}
	}
	// An ACL line which is already present on device can't be added again.
	// Therefore we need add, delete and move operations.
	//
	// Two ACL lines which differ only in 'log' attribute,
	// can't both be present on a device.
	// [ log [ [ level ] interval secs ] | disable | default ] ]
	// [ time-range time_range_name ] [ inactive ]
	// Hence we must remove one line before we can add the other one.
	//
	// Find move operations from commands in 'add' and 'del'.
	// A command is moved if the same command is deleted and added.
	// Two commands are equal if they
	// - have same attribute .parsed,
	//   but attribute 'log' is ignored during compare,
	// - reference the same object-groups. Here we must compare
	//   object-groups from Netspoc with object-groups on device.
	delMap := make(map[string]*cmd)
	rx := regexp.MustCompile(
		` log( ((\w+ )?interval \d+|\w+|disable|default))?\b`)
	for _, a := range del {
		p := getPrintableCmd(a, s.a)
		p = rx.ReplaceAllLiteralString(p, "")
		delMap[p] = a
	}
	for _, b := range add {
		p := s.printNetspocCmd(b)
		p = rx.ReplaceAllLiteralString(p, "")
		if a := delMap[p]; a != nil {
			moveACL(a, b)
			continue
		}
		addACL(b)
	}
	// Delete lines on device.
	// Work from bottom to top. Otherwise we would permit too much
	// traffic for a short time range.
	slices.Reverse(del)
	for _, a := range del {
		// Must not delete cmd again, if it already was moved.
		if !a.needed {
			delACL(a)
		}
	}
}

// ga and gb are object-group commands that need to be equal.
// Try to transform subcommands of ga to subcommands of gb if viable.
// Return true if transformation succeeded.
func (s *State) equalizedGroups(aName, bName string) bool {
	ga := s.a.lookup["object-group"][aName][0]
	gb := s.b.lookup["object-group"][bName][0]
	if ga.parsed != gb.parsed {
		// Type of object-group differs.
		return false
	}
	if ga.needed {
		if gb.ready {
			return ga.name == gb.name
		}
		s.findGroupOnDevice(bName)
		return false
	}
	la := ga.sub
	lb := gb.sub
	byOrig := func(_ *Config, c *cmd) string { return c.orig }
	ab := &cmdsPair{aCmds: la, bCmds: lb, key: byOrig}
	script := myers.Diff(nil, ab)
	if !script.IsIdentity() {
		s.findGroupOnDevice(bName)
		if gb.ready {
			return aName == gb.name
		}
	}
	ins, del := script.Stat()
	if ins+del > len(lb) {
		return false
	}
	ga.needed = true
	gb.name = ga.name
	for _, r := range script.Ranges {
		if r.IsDelete() {
			s.delCmds(la[r.LowA:r.HighA])
		} else if r.IsInsert() {
			s.addCmds(lb[r.LowB:r.HighB])
		}
	}
	gb.ready = true
	return true
}

type routeDst struct {
	vrf string
	dst netip.Prefix
}

func (s *State) diffRoutes(al, bl []*cmd, diff []edit.Range) {
	chgVRF := make(map[string]bool)
	for _, c := range bl {
		chgVRF[dstOfRoute(c).vrf] = true
	}
	delDst := make(map[routeDst]*cmd)
	for _, r := range diff {
		if r.IsDelete() {
			for _, c := range al[r.LowA:r.HighA] {
				delDst[dstOfRoute(c)] = c
			}
		}
	}
	for _, r := range diff {
		if r.IsInsert() {
			for _, c := range bl[r.LowB:r.HighB] {
				add := s.printNetspocCmd(c)
				c.ready = true
				if del, found := delDst[dstOfRoute(c)]; found {
					// ASA doesn't allow two routes to identical
					// destination. Remove and add routes in one transaction.
					s.addChange("no " + del.orig + "\n" + add)
					del.needed = true
				} else {
					s.addChange(add)
				}
			}
		}
	}
	seenVRF := make(map[string]bool)
	for _, r := range diff {
		if r.IsDelete() {
			for _, c := range al[r.LowA:r.HighA] {
				ipv := "IPv4"
				if strings.Contains(c.parsed, "ipv6") {
					ipv = "ipv6"
				}
				if vrf := dstOfRoute(c).vrf; chgVRF[vrf] {
					s.delCmds([]*cmd{c})
				} else if !seenVRF[ipv+vrf] {
					seenVRF[ipv+vrf] = true
					forVRF := ""
					if vrf != "" {
						forVRF = " for VRF " + vrf
					}
					device.Info("No %s routing specified%s, leaving untouched",
						ipv, forVRF)
				}
			}
		}
	}
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
			bl := s.b.lookup[prefix][name]
			if bl[0].typ.fixedName || bl[0].fixedName {
				if al, found := s.a.lookup[prefix][name]; found {
					if prefix == "crypto map" {
						s.diffCryptoMap(al, bl)
					} else {
						s.diffCmds(al, bl, byParsedCmd)
					}
					continue
				}
			}
			add(bl)
		}
	}
	add = func(bl []*cmd) {
		b0 := bl[0]
		if b0.ready {
			return
		}
		b0.ready = true
		if b0.typ.simpleObj {
			if al := s.findSimpleObjOnDevice(bl); al != nil {
				al[0].needed = true
				b0.name = al[0].name
				return
			}
		}
		if b0.typ.fixedName || b0.fixedName {
			prefix := b0.typ.prefix
			name := b0.name
			if _, found := s.a.lookup[prefix][name]; !found {
				switch prefix {
				case "aaa-server", "ldap attribute-map":
					device.Abort("'%s %s' must be transferred manually", prefix, name)
				}
			}
		}
		for _, c := range bl {
			follow(c)
			for _, sc := range c.sub {
				follow(sc)
			}
			s.addCmd(c)
		}
	}
	add(l)
}

func (s *State) addCmd(c *cmd) {
	switch c.typ.prefix {
	case "aaa-server", "ldap attribute-map", "interface":
		return
	}
	pr := s.printNetspocCmd(c)
	// If current command is subcommand of some command x
	// then write x and remember that x has been written,
	// so that it isn't written again if another subcommand of x is modified.
	if sup := c.subCmdOf; sup != nil {
		pr2 := s.printNetspocCmd(sup)
		s.setCmdConfMode(pr2)
	} else if c.typ.sub != nil {
		s.subCmdOf = pr
	} else {
		s.subCmdOf = ""
	}
	s.addChange(pr)
	for _, sub := range c.sub {
		s.addChange(s.printNetspocCmd(sub))
	}
}

func (s *State) setCmdConfMode(printedSup string) {
	if s.subCmdOf != printedSup {
		// Prevent toplevel command "webvpn" be given
		// in mode (config-group-policy)
		// since this mode also has a subcommand "webvpn"
		if s.subCmdOf != "" {
			s.addChange("exit")
		}
		s.addChange(printedSup)
		s.subCmdOf = printedSup
	}
}

// Delete subcommands and parts of multi line command.
func (s *State) delCmds(l []*cmd) {
	switch l[0].typ.prefix {
	// Leave these commands unchanged on device:
	case "interface":
		return
	}
	for _, c := range l {
		if c.needed {
			continue
		}
		if sup := c.subCmdOf; sup != nil {
			s.setCmdConfMode(sup.orig)
		} else {
			s.subCmdOf = ""
		}
		c.needed = true // Don't delete again later.
		s.addChange("no " + c.orig)
	}
	// Mark referenced commands as deleted.
	s.markDeleted(l)
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
		switch al[0].typ.prefix {
		// Leave these commands unchanged on device:
		case "aaa-server", "ldap attribute-map", "interface":
			return
		}
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
	// Collect to be deleted commands.
	type pair [2]string
	toDelete := make(map[pair][]*cmd)
	for prefix, m := range s.a.lookup {
		for name, l := range m {
			var del []*cmd
			for _, c := range l {
				if !c.needed && (c.toDelete || strings.Contains(c.name, "-DRC-")) {
					del = append(del, c)
				}
			}
			if del != nil {
				toDelete[pair{prefix, name}] = del
			}
		}
	}
	if len(toDelete) > 0 && s.subCmdOf != "" {
		s.addChange("exit")
	}
	for len(toDelete) > 0 {
		// Mark commands that are still referenced by other to be
		// deleted commands.
		isReferenced := make(map[pair]bool)
		follow := func(c *cmd) {
			for i, name := range c.ref {
				prefix := c.typ.ref[i]
				isReferenced[pair{prefix, name}] = true
			}
		}
		for _, l := range toDelete {
			for _, c := range l {
				follow(c)
				for _, sc := range c.sub {
					follow(sc)
				}
			}
		}
		// Delete commands not referenced any longer.
		pairs := maps.Keys(toDelete)
		sort.Slice(pairs, func(i, j int) bool {
			return pairs[i][0] < pairs[j][0] ||
				pairs[i][0] == pairs[j][0] && pairs[i][1] < pairs[j][1]
		})
		for _, pair := range pairs {
			if isReferenced[pair] {
				continue
			}
			prefix := pair[0]
			l := toDelete[pair]
			delete(toDelete, pair)
			if l[0].typ.clearConf {
				name := pair[1]
				s.addChange("clear configure " + prefix + " " + name)
			} else {
				for _, c := range l {
					if c2, found := strings.CutPrefix(c.orig, "no "); found {
						s.addChange(c2)
					} else {
						s.addChange("no " + c.orig)
					}
				}
			}
		}
	}
}

func (s *State) printNetspocCmd(c *cmd) string {
	return getPrintableCmd(c, s.b)
}

func getPrintableCmd(c *cmd, cf *Config) string {
	p := c.parsed
	p = strings.Replace(p, "$NAME", c.name, 1)
	p = strings.Replace(p, "$SEQ", strconv.Itoa(c.seq), 1)
	for i, r := range c.ref {
		prefix := c.typ.ref[i]
		name := cf.lookup[prefix][r][0].name
		p = strings.Replace(p, "$REF", name, 1)
	}
	return p
}

// Generate new names for objects from Netspoc: <spoc-name>-DRC-<index>
func (s *State) generateNamesForTransfer() {
	setName := func(c *cmd, devNames map[string][]*cmd) {
		prefix := c.name + "-DRC-"
		index := 0
		for {
			newName := prefix + strconv.Itoa(index)
			if _, found := devNames[newName]; !found {
				c.name = newName
				break
			}
			index++
		}
	}
	for prefix, m := range s.b.lookup {
		for _, bl := range m {
			for _, c := range bl {
				if !(c.typ.fixedName || c.fixedName) {
					setName(c, s.a.lookup[prefix])
				}
			}
		}
	}
}

// Sort elements of object-groups for findGroupOnDevice to work.
func sortGroups(cf *Config) {
	for _, gl := range cf.lookup["object-group"] {
		l := gl[0].sub
		sort.Slice(l, func(i, j int) bool { return l[i].parsed < l[j].parsed })
	}
}

func (s *State) findGroupOnDevice(name string) {
	gb := s.b.lookup["object-group"][name][0]
	if gb.ready {
		return
	}
GROUP:
	for _, l := range s.a.lookup["object-group"] {
		ga := l[0]
		if ga.parsed != gb.parsed {
			// Type of object-group differs.
			continue
		}
		// Group ga was already changed to elements of some group from
		// Netspoc or it is equal to some group from Netspoc.
		if ga.needed {
			continue
		}
		if len(ga.sub) != len(gb.sub) {
			continue
		}
		for i, n := range gb.sub {
			if n.orig != ga.sub[i].orig {
				continue GROUP
			}
		}
		ga.needed = true
		gb.ready = true
		gb.name = ga.name
		break
	}
}

func (s *State) diffCryptoMap(al, bl []*cmd) string {
	matchCryptoMap(al, bl, func(aSeqL, bSeqL []*cmd) {
		s.diffCmds(aSeqL, bSeqL, byParsedCmd)
	})
	return al[0].name
}

func matchCryptoMap(al, bl []*cmd, f func([]*cmd, []*cmd)) {
	mapBySeq := func(l []*cmd) map[int][]*cmd {
		m := make(map[int][]*cmd)
		for _, c := range l {
			m[c.seq] = append(m[c.seq], c)
		}
		return m
	}
	getPeer := func(l []*cmd) string {
		name, seq := l[0].name, l[0].seq
		// For IOS look into subcommands.
		if len(l) == 1 && l[0].sub != nil {
			l = l[0].sub
		}
		peer := ""
		for _, c := range l {
			if _, p, found := strings.Cut(c.parsed, "set peer "); found {
				peer = "peer " + p
				break
			}
			if strings.Contains(c.parsed, "ipsec-isakmp dynamic ") {
				peer = c.ref[0]
				break
			}
		}
		if peer == "" {
			device.Abort("Missing peer or dynamic in crypto map %s %d", name, seq)
		}
		return peer
	}
	mapPeerToSeq := func(seqMap map[int][]*cmd) map[string]int {
		m := make(map[string]int)
		for seq, l := range seqMap {
			m[getPeer(l)] = seq
		}
		return m
	}

	aSeqMap := mapBySeq(al)
	bSeqMap := mapBySeq(bl)
	bPeer2Seq := mapPeerToSeq(bSeqMap)
	// Match commands having same peer.
	for _, aSeq := range sorted.Keys(aSeqMap) {
		aSeqL := aSeqMap[aSeq]
		aPeer := getPeer(aSeqL)
		if bSeq, found := bPeer2Seq[aPeer]; found {
			f(aSeqL, bSeqMap[bSeq])
			delete(bSeqMap, bSeq) // Mark as already processed.
		} else {
			f(aSeqL, nil)
		}
	}
	// Use fresh sequence numbers for added commands.
	static := 1
	dynamic := 65535
	for _, bSeq := range sorted.Keys(bSeqMap) {
		bSeqL := bSeqMap[bSeq]
		seq := &dynamic
		incr := -1
		if strings.HasPrefix(getPeer(bSeqL), "peer ") {
			seq = &static
			incr = 1
		}
		// Get next free seq num.
		for ; aSeqMap[*seq] != nil; *seq += incr {
		}
		for _, bCmd := range bSeqL {
			bCmd.seq = *seq
			// Use name of existing crypto map.
			if len(al) > 0 {
				bCmd.name = al[0].name
			}
		}
		f(nil, bSeqL)
		*seq += incr
	}
}

// Add routes with long mask first. If we switch the default
// route, this ensures, that we have the new routes available
// before deleting the old default route.
func sortRoutes(cf *Config) {
	for _, prefix := range []string{"route", "ip route", "ipv6 route"} {
		l := cf.lookup[prefix][""]
		sort.Slice(l, func(i, j int) bool {
			return byMoreSpecificRoute(l[i]) < byMoreSpecificRoute(l[j])
		})
	}
}

func byMoreSpecificRoute(c *cmd) string {
	// .Bits() has result -1, if .dst is invalid.
	b := 128 - byte(dstOfRoute(c).dst.Bits())
	return string([]byte{b}) + c.parsed
}

func dstOfRoute(c *cmd) routeDst {
	vrf := ""
	var ipp netip.Prefix
	l := strings.Split(c.parsed, " ")
	if c.typ.prefix == "ipv6 route" {
		// ASA: ipv6 route intf ip/len gw
		// IOS: ipv6 route [vrf NAME] ip/len gw
		i := slices.IndexFunc(l, func(e string) bool { return strings.Contains(e, "/") })
		ipp, _ = netip.ParsePrefix(l[i])
		if len(l) >= 6 && l[2] == "vrf" {
			vrf = l[3]
		}
	} else {
		// ASA: route intf ip mask gw
		// IOS: ip route [vrf NAME] ip mask gw
		i := 2
		if l[0] == "ip" && l[2] == "vrf" {
			vrf = l[3]
			i = 4
		}
		ip, err1 := netip.ParseAddr(l[i])
		mask, err2 := netip.ParseAddr(l[i+1])
		if err1 == nil && err2 == nil {
			size, _ := net.IPMask(mask.AsSlice()).Size()
			ipp = netip.PrefixFrom(ip, size)
		}
	}
	return routeDst{vrf, ipp}
}

func diffCmdLists(ab *cmdsPair) []edit.Range {
	al := ab.aCmds
	if len(al) > 0 {
		if al[0].typ.prefix == "access-list" {
			return myers.Diff(nil, ab).Ranges
		} else {
			s := al[0].subCmdOf
			if s != nil && s.typ.prefix == "ip access-list extended" {
				sortIOSPermitDenyBlocks(al)
				sortIOSPermitDenyBlocks(ab.bCmds)
				return myers.Diff(nil, ab).Ranges
			}
		}
	}
	return diffUnordered(ab)
}

func diffUnordered(ab *cmdsPair) []edit.Range {
	var result []edit.Range
	prev := &edit.Range{LowA: -1, HighA: -1, LowB: -1, HighB: -1}
	m := make(map[string]int)
	for i, bCmd := range ab.bCmds {
		m[ab.key(ab.b, bCmd)] = i
	}
	for i, aCmd := range ab.aCmds {
		k := ab.key(ab.a, aCmd)
		if j, found := m[k]; found && j != -1 {
			if prev.IsEqual() && prev.HighA == i && prev.HighB == j {
				prev.HighA = i + 1
				prev.HighB = j + 1
			} else {
				result = append(result,
					edit.Range{LowA: i, HighA: i + 1, LowB: j, HighB: j + 1})
				prev = &result[len(result)-1]
			}
			m[k] = -1
		} else {
			if prev.IsDelete() && prev.HighA == i {
				prev.HighA = i + 1
			} else {
				result = append(result,
					edit.Range{LowA: i, HighA: i + 1, LowB: 0, HighB: 0})
				prev = &result[len(result)-1]
			}
		}
	}
	for j, bCmd := range ab.bCmds {
		if m[ab.key(ab.b, bCmd)] != -1 {
			if prev.IsInsert() && prev.HighB == j {
				prev.HighB = j + 1
			} else {
				l := len(ab.aCmds)
				result = append(result,
					edit.Range{LowA: l, HighA: l, LowB: j, HighB: j + 1})
				prev = &result[len(result)-1]
			}
		}
	}
	return result
}

func getIOSAction(c *cmd) string {
	action, _, _ := strings.Cut(c.parsed, " ")
	return action
}

// Sort rules inside blocks of successive rules with identical action,
// because order doesn't matter in this case.
// This allows to find rules as unchanged if only the order has changed.
//
// Traffic from Netspoc is filtered by some rule.
// It is crucial to never move this rule, because this would lockout
// Netspoc from device. This is safeguarded by sorting rules before comparing.
//
// Original position for each rule c is stored in c.seq.
func sortIOSPermitDenyBlocks(l []*cmd) {
	sortBlock := func(i, j int) {
		block := l[i:j]
		sort.SliceStable(block, func(i, j int) bool {
			pi := block[i].parsed
			pj := block[j].parsed
			// Leave order of remark lines unchanged.
			if strings.HasPrefix(pi, "remark") || strings.HasPrefix(pj, "remark") {
				return false
			}
			return pi < pj
		})
	}
	i0 := 0
	action := "permit"
	for i, c := range l {
		c.seq = i
		a := getIOSAction(c)
		switch a {
		case action, "remark":
		default:
			sortBlock(i0, i)
			action = a
			i0 = i
		}
	}
	sortBlock(i0, len(l))
}

func (s *State) checkInterfaces() error {
	if s.Model == "IOS" {
		return s.checkIOSInterfaces()
	}
	return s.checkASAInterfaces()
}

func (s *State) checkASAInterfaces() error {
	// For ASA collect implicit interfaces from Netspoc.
	// These are defined by commands
	// - "access-group $access-list in|out interface INTF".
	// - "crypto map $crypto_map interface INTF"
	// Ignore "access-group $access-list global".
	getImplicitInterfaces := func(cfg *Config) map[string]bool {
		m := make(map[string]bool)
		for _, c := range cfg.lookup["access-group"][""] {
			tokens := strings.Fields(c.parsed)
			if len(tokens) == 5 {
				m[tokens[4]] = true
			}
		}
		for _, c := range cfg.lookup["crypto map interface"][""] {
			tokens := strings.Fields(c.parsed)
			m[tokens[4]] = true
		}
		return m
	}
	bIntf := getImplicitInterfaces(s.b)

	// Collect and check named interfaces from device.
	// Add implicit interfaces when comparing two Netspoc generated configs.
	aIntf := getImplicitInterfaces(s.a)
INTF:
	for _, c := range s.a.lookup["interface"][""] {
		name := ""
		for _, sc := range c.sub {
			tokens := strings.Fields(sc.parsed)
			switch tokens[0] {
			case "shutdown":
				continue INTF
			case "nameif":
				name = tokens[1]
			}
		}
		if name != "" {
			aIntf[name] = true
			if !bIntf[name] {
				device.Warning(
					"Interface '%s' on device is not known by Netspoc", name)
			}
		}
	}

	// Check interfaces from Netspoc
	for _, name := range sorted.Keys(bIntf) {
		if !aIntf[name] {
			return fmt.Errorf(
				"Interface '%s' from Netspoc not known on device", name)
		}
	}
	return nil
}

func (s *State) checkIOSInterfaces() error {
	type intfInfo struct {
		shut    bool
		addr    string
		inspect string
		vrf     string
	}
	// Read and remove sub commands from interface, that must not be
	// compared later.
	extractIntfInfo := func(c *cmd) *intfInfo {
		info := &intfInfo{
			shut:    false,
			addr:    "",
			inspect: "disabled",
			vrf:     "<global>",
		}
		addrList := []string{}
		l := c.sub
		j := 0
		for _, sc := range l {
			p := sc.parsed
			if p == "shutdown" {
				info.shut = true
			} else if ip, ok := strings.CutPrefix(p, "ip address "); ok {
				ip = strings.TrimSuffix(ip, " secondary")
				addrList = append(addrList, ip)
			} else if p == "unnumbered" {
				addrList = append(addrList, p)
			} else if _, v, ok := strings.Cut(p, "vrf forwarding "); ok {
				info.vrf = v
			} else if strings.HasPrefix(p, "ip inspect") {
				info.inspect = "enabled"
			} else {
				// Only leave other commands as sub command.
				l[j] = sc
				j++
			}
		}
		c.sub = l[:j]
		sort.Strings(addrList)
		info.addr = strings.Join(addrList, ",")
		return info
	}
	aKnown := make(map[string]bool)
	bIntf := make(map[string]*intfInfo)
	for _, c := range s.b.lookup["interface"][""] {
		name := strings.Fields(c.parsed)[1]
		bIntf[name] = extractIntfInfo(c)
	}
	// If config from Netspoc has no interface definitions, it is probably
	// of type "managed=routing_only", and Netspoc won't change any
	// interface config.
	if len(bIntf) == 0 {
		return nil
	}
	for _, c := range s.a.lookup["interface"][""] {
		name := strings.Fields(c.parsed)[1]
		aInfo := extractIntfInfo(c)
		aKnown[name] = true
		if aInfo.shut {
			continue
		}
		if bInfo := bIntf[name]; bInfo != nil {
			if aInfo.addr != bInfo.addr && bInfo.addr != "negotiated" {
				device.Warning(
					"Different address defined for interface %s:"+
						" Device: %q, Netspoc: %q", name, aInfo.addr, bInfo.addr)
			}
			if aInfo.inspect != bInfo.inspect {
				return fmt.Errorf(
					"Different 'ip inspect' defined for interface %s:"+
						" Device: %s, Netspoc: %s",
					name, aInfo.inspect, bInfo.inspect)
			}
			if aInfo.vrf != bInfo.vrf {
				return fmt.Errorf(
					"Different VRFs defined for interface %s:"+
						" Device: %s, Netspoc: %s", name, aInfo.vrf, bInfo.vrf)
			}
		} else if aInfo.addr != "" {
			device.Warning(
				"Interface '%s' on device is not known by Netspoc", name)
		}
	}
	for _, c := range s.b.lookup["interface"][""] {
		name := strings.Fields(c.parsed)[1]
		if !aKnown[name] {
			return fmt.Errorf(
				"Interface '%s' from Netspoc not known on device", name)
		}
	}
	return nil
}

func (s *State) alignVRFs() {
	interfaceVRF := func(c *cmd) string {
		for _, s := range c.sub {
			if _, v, found := strings.Cut(s.orig, "vrf forwarding "); found {
				return v
			}
		}
		return ""
	}
	routeVRF := func(c *cmd) string {
		tokens := strings.Fields(c.parsed)
		if tokens[2] == "vrf" {
			return tokens[3]
		}
		return ""
	}
	pairs := []struct {
		name string
		get  func(c *cmd) string
	}{
		{"interface", interfaceVRF},
		{"ip route", routeVRF},
	}
	// Find VRFs used in Netspoc configuration.
	bVRF := make(map[string]bool)
	for _, p := range pairs {
		for _, c := range s.b.lookup[p.name][""] {
			bVRF[p.get(c)] = true
		}
	}
	// Leave device config unchanged if approve is run with empty
	// Netspoc config for testing.
	if len(bVRF) == 0 {
		return
	}
	// Remove VRFs from device configuration that are not handled by Netspoc.
	removed := make(map[string]bool)
	for _, p := range pairs {
		if l := s.a.lookup[p.name][""]; l != nil {
			j := 0
			for _, c := range l {
				vrf := p.get(c)
				if bVRF[vrf] {
					l[j] = c
					j++
				} else {
					removed[vrf] = true
				}
			}
			l = l[:j]
			if len(l) != 0 {
				s.a.lookup[p.name][""] = l
			} else {
				delete(s.a.lookup[p.name], "")
			}
		}
	}
	for _, vrf := range sorted.Keys(removed) {
		if vrf == "" {
			vrf = "<global>"
		}
		device.Info("Leaving VRF %s untouched", vrf)
	}
}

// 'crypto map gdoi' is currently not supported by Netspoc.
// That commands must be left unchanged on device.
func (s *State) ignoreCryptoGDOI() {
	rm := make(map[string]bool)
	for _, c := range s.a.lookup["interface"][""] {
		l := c.sub
		j := 0
		for _, sc := range l {
			if sc.parsed == "crypto map $REF" {
				name := sc.ref[0]
				l2 := s.a.lookup["crypto map"][name]
				if l2[0].parsed == "crypto map $NAME $SEQ gdoi" {
					rm[name] = true
					continue
				}
			}
			l[j] = sc
			j++
		}
		c.sub = l[:j]
	}
	for name := range rm {
		delete(s.a.lookup["crypto map"], name)
	}
}
