package panos

import (
	"fmt"
	"sort"

	"github.com/pkg/diff/myers"
)

func diffConfig(a, b *panVsys, vsysPath string) []string {
	sortMembers(a)
	sortMembers(b)
	ab := rulesPairFrom(a, b)
	ab.markObjects(b.Rules)
	ab.genUniqRuleNames()
	ab.genUniqGroupNames()
	ruleCmds := ab.diffRules(vsysPath)
	result := append(ab.transferNeededObjects(vsysPath), ruleCmds...)
	result = append(result, ab.removeUnneededObjects(vsysPath)...)
	return result
}

type vsysInfo struct {
	vsys      *panVsys
	rules     []*panRule
	addresses map[string]*panAddress
	groups    map[string]*panAddressGroup
	services  map[string]*panService
	sGroups   map[string]*panServiceGroup
}

type rulesPair struct {
	a vsysInfo
	b vsysInfo
}

func rulesPairFrom(a, b *panVsys) *rulesPair {
	return &rulesPair{
		vsysInfo{
			vsys:      a,
			rules:     a.Rules,
			addresses: addressMap(a),
			groups:    groupMap(a),
			sGroups:   sGroupMap(a),
			services:  serviceMap(a),
		},
		vsysInfo{
			vsys:      b,
			rules:     b.Rules,
			addresses: addressMap(b),
			groups:    groupMap(b),
			sGroups:   sGroupMap(b),
			services:  serviceMap(b),
		},
	}
}

func addressMap(v *panVsys) map[string]*panAddress {
	m := make(map[string]*panAddress)
	for _, o := range v.Addresses {
		m[o.Name] = o
	}
	return m
}

func groupMap(v *panVsys) map[string]*panAddressGroup {
	m := make(map[string]*panAddressGroup)
	for _, o := range v.AddressGroups {
		m[o.Name] = o
	}
	return m
}

func serviceMap(v *panVsys) map[string]*panService {
	m := make(map[string]*panService)
	for _, o := range v.Services {
		m[o.Name] = o
	}
	return m
}

func sGroupMap(v *panVsys) map[string]*panServiceGroup {
	m := make(map[string]*panServiceGroup)
	for _, o := range v.ServiceGroups {
		m[o.Name] = o
	}
	return m
}

func (ab *rulesPair) LenA() int { return len(ab.a.rules) }
func (ab *rulesPair) LenB() int { return len(ab.b.rules) }

func (ab *rulesPair) Equal(ai, bi int) bool {
	a := ab.a.rules[ai]
	b := ab.b.rules[bi]
	return a.Action == b.Action &&
		stringsEq(a.From, b.From) &&
		stringsEq(a.To, b.To) &&
		ab.objectsTypeEq(a.Source, b.Source) &&
		ab.objectsTypeEq(a.Destination, b.Destination) &&
		ab.servicesEq(a.Service, b.Service) &&
		stringsEq(a.Application, b.Application) &&
		a.LogStart == b.LogStart &&
		a.LogEnd == b.LogEnd &&
		a.LogSetting == b.LogSetting &&
		a.RuleType == b.RuleType &&
		unknownEq(a.Unknown, b.Unknown)

}

func (ab *rulesPair) diffRules(vsysPath string) []string {
	rulesPath := vsysPath + "/rulebase/security/rules/entry"
	cmd0 := "type=config&xpath=" + rulesPath
	s := myers.Diff(nil, ab)
	var result []string
	aRules := ab.a.rules
	bRules := ab.b.rules
	delIdx := -1 // Next index after deleted rule(s).
	type insRules struct {
		move  string
		rules []*panRule
	}
	var insert []insRules
	for _, r := range s.Ranges {
		if r.IsDelete() {
			delIdx = r.HighA
			for _, ru := range aRules[r.LowA:r.HighA] {
				name := nameAttr(ru.Name)
				cmd := "action=delete&" + cmd0 + name
				result = append(result, cmd)
			}
		} else if r.IsInsert() {
			aPos := r.LowA
			// Adapt position to next available rule if this rule has
			// just been deleted.
			if aPos < delIdx {
				aPos = delIdx
			}
			// New rule is initially appended as last element.
			// Move to given position where required.
			moveTo := ""
			if aPos < len(aRules) {
				aName := aRules[aPos].Name
				moveTo = "&where=before&dst=" + aName
			}
			// Add command later, when names of groups have been determined.
			insert = append(insert, insRules{
				move:  moveTo,
				rules: bRules[r.LowB:r.HighB]})
		} else {
			offset := r.LowB - r.LowA
			for i := r.LowA; i < r.HighA; i++ {
				rA := aRules[i]
				rB := bRules[i+offset]
				result = append(result, ab.equalize(rA, rB, vsysPath)...)
			}
		}
	}
	for _, ins := range insert {
		for _, ru := range ins.rules {
			ab.adaptGroups(ru.Source)
			ab.adaptGroups(ru.Destination)
			name := nameAttr(ru.Name)
			elem := "&element=" + printXMLValue(ru)
			cmd1 := "action=set&" + cmd0 + name + elem
			result = append(result, cmd1)
			if ins.move != "" {
				cmd2 := "action=move&" + cmd0 + name + ins.move
				result = append(result, cmd2)
			}
		}
	}
	return result
}

func stringsEq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i, s := range a {
		if s != b[i] {
			return false
		}
	}
	return true
}

func (ab *rulesPair) objectsTypeEq(a, b []string) bool {
	t1 := getObjListType(a, ab.a)
	t2 := getObjListType(b, ab.b)
	return t1 == t2
}

func (ab *rulesPair) servicesEq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i, aName := range a {
		bName := b[i]
		if aName == bName {
			// any | application-default
			// or two defined services or service-groups
			// with equal name and possibly different definitions.
			// In this case, definition will be edited later.
			continue
		}
		sA := ab.a.services[aName]
		sB := ab.b.services[bName]
		if sA == nil || sB == nil || !serviceEq(sA, sB) {
			return false
		}
	}
	return true
}

type objListType int

const (
	unknownT = iota
	listT
	groupT
	anyT
)

func getObjListType(l []string, v vsysInfo) objListType {
	if len(l) == 1 {
		e := l[0]
		if e == "any" {
			return anyT
		}
		if g := v.groups[e]; g != nil {
			if getObjListType(g.Members, v) == listT {
				return groupT
			}
			// Nested groups are not supported.
			return unknownT
		}
	}
	for _, e := range l {
		if v.addresses[e] == nil {
			return unknownT
		}
	}
	return listT
}

func (ab *rulesPair) markObjects(l []*panRule) {
	for _, ru := range l {
		ab.markAddresses(ru.Source)
		ab.markAddresses(ru.Destination)
		ab.markServices(ru.Service)
	}
}

func (ab *rulesPair) markAddresses(l []string) {
	for _, name := range l {
		if g := ab.b.groups[name]; g != nil {
			// Preliminary mark group from Netspoc as needed.  Mark will
			// be moved to group on device later if an equivalent group
			// is found.
			g.needed = true
			ab.markAddresses(g.Members)
			continue
		}
		aB := ab.b.addresses[name]
		if aB == nil {
			// Ignore "any" or address, address-group defined in <shared>
			// and referenced from raw.
			continue
		}
		if aA := ab.a.addresses[name]; aA != nil {
			aA.needed = true
			if !addressEq(aA, aB) {
				aB.edit = true
			}
		} else {
			aB.needed = true
		}
	}
}

func addressEq(a, b *panAddress) bool {
	return a.IpNetmask == b.IpNetmask && unknownEq(a.Unknown, b.Unknown)
}

func unknownEq(a, b []AnyHolder) bool {
	if len(a) != len(b) {
		return false
	}
	for i, uA := range a {
		uB := b[i]
		if uA.XMLName != uB.XMLName || uA.XML != uB.XML {
			return false
		}
	}
	return true
}

func (ab *rulesPair) markServices(l []string) {
	for _, name := range l {
		if g := ab.b.sGroups[name]; g != nil {
			g.needed = true
			ab.markServices(g.Members)
			if sA := ab.a.sGroups[name]; sA != nil {
				sA.needed = true
				if ab.servicesEq(g.Members, sA.Members) {
					g.needed = false
				}
			}
			continue
		}
		sB := ab.b.services[name]
		if sB == nil {
			// Ignore "any", "application-default" or service,
			// service-group defined in <shared> and referenced from raw.
			continue
		}
		if sA := ab.a.services[name]; sA != nil {
			sA.needed = true
			if !serviceEq(sA, sB) {
				sB.edit = true
			}
		} else {
			sB.needed = true
		}
	}
}

func serviceEq(a, b *panService) bool {
	return protocolEq(a.Protocol, b.Protocol) && unknownEq(a.Unknown, b.Unknown)
}

func protocolEq(a, b panProtocol) bool {
	return portEq(a.TCP, b.TCP) && portEq(a.UDP, b.UDP) &&
		unknownEq(a.Unknown, b.Unknown)
}

func portEq(a, b *panPort) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Port == b.Port && unknownEq(a.Unknown, b.Unknown)
}

// Transfer objects from b, that are needed in a
// or if object with same name exists in a and b, only change attributes.
func (ab *rulesPair) transferNeededObjects(vsysPath string) []string {
	var result []string
	addressPath := vsysPath + "/address/entry"
	cmd0 := "type=config&xpath=" + addressPath
	for _, o := range ab.b.vsys.Addresses {
		if o.needed || o.edit {
			action := ""
			elem := "&element="
			if o.edit {
				action = "edit"
				elem += printXML(o)
			} else {
				action = "set"
				elem += printXMLValue(o)
			}
			name := nameAttr(o.Name)
			cmd := "action=" + action + "&" + cmd0 + name + elem
			result = append(result, cmd)
		}
	}
	groupPath := vsysPath + "/address-group/entry"
	cmd0 = "type=config&xpath=" + groupPath
	for _, o := range ab.b.vsys.AddressGroups {
		if o.needed {
			name := nameAttr(o.Name)
			object := &panMembers{Member: o.Members}
			elem := "&element=" + printXMLValue(object)
			cmd := "action=set&" + cmd0 + name + "/static" + elem
			result = append(result, cmd)
		}
	}
	servicePath := vsysPath + "/service/entry"
	cmd0 = "type=config&xpath=" + servicePath
	for _, o := range ab.b.vsys.Services {
		if o.needed || o.edit {
			action := ""
			elem := "&element="
			if o.edit {
				action = "edit"
				elem += printXML(o)
			} else {
				action = "set"
				elem += printXMLValue(o)
			}
			name := nameAttr(o.Name)
			cmd := "action=" + action + "&" + cmd0 + name + elem
			result = append(result, cmd)
		}
	}
	sGroupPath := vsysPath + "/service-group/entry"
	cmd0 = "type=config&xpath=" + sGroupPath
	for _, o := range ab.b.vsys.ServiceGroups {
		if o.needed {
			name := nameAttr(o.Name)
			object := &panMembers{Member: o.Members}
			elem := "&element=" + printXMLValue(object)
			cmd := "action=set&" + cmd0 + name + "/members" + elem
			result = append(result, cmd)
		}
	}
	return result
}

// Remove objects from a, that are no longer needed.
func (ab *rulesPair) removeUnneededObjects(vsysPath string) []string {
	var result []string
	var cmd0 string
	delete := func(name string) {
		cmd := "action=delete&" + cmd0 + nameAttr(name)
		result = append(result, cmd)
	}
	groupPath := vsysPath + "/address-group/entry"
	cmd0 = "type=config&xpath=" + groupPath
	for _, o := range ab.a.vsys.AddressGroups {
		if !o.needed {
			delete(o.Name)
		}
	}
	addressPath := vsysPath + "/address/entry"
	cmd0 = "type=config&xpath=" + addressPath
	for _, o := range ab.a.vsys.Addresses {
		if !o.needed {
			delete(o.Name)
		}
	}
	sGroupPath := vsysPath + "/service-group/entry"
	cmd0 = "type=config&xpath=" + sGroupPath
	for _, o := range ab.a.vsys.ServiceGroups {
		if !o.needed {
			delete(o.Name)
		}
	}
	servicePath := vsysPath + "/service/entry"
	cmd0 = "type=config&xpath=" + servicePath
	for _, o := range ab.a.vsys.Services {
		if !o.needed {
			delete(o.Name)
		}
	}
	return result
}

type addrListPair struct {
	a     []string
	b     []string
	rPair *rulesPair
}

func (ab *addrListPair) LenA() int { return len(ab.a) }
func (ab *addrListPair) LenB() int { return len(ab.b) }

func (ab *addrListPair) Equal(ai, bi int) bool {
	a := ab.a[ai]
	b := ab.b[bi]
	// Always assume that addressgroups are equal.
	if ab.rPair.a.groups[a] != nil {
		return ab.rPair.b.groups[b] != nil
	}
	if gb := ab.rPair.b.groups[b]; gb != nil {
		return false
	}
	// Addresses of same name are known to be equal.
	return a == b
}

func (ab *rulesPair) equalize(a, b *panRule, vsysPath string) []string {
	rulePath := vsysPath + "/rulebase/security/rules/entry" + nameAttr(a.Name)
	groupPath := vsysPath + "/address-group/entry"
	var result []string
	cmd0 := "type=config&xpath="
	var hasEqualizedGroups func(ga, gb *panAddressGroup) bool
	hasEqualizedLists := func(la, lb []string, path string) bool {
		ab := &addrListPair{a: la, b: lb, rPair: ab}
		s := myers.Diff(nil, ab)
		// Check if an incremental change is viable.
		// Be
		// - D the number of deleted elements
		// - I the number of inserted elements
		// - N the new number of elements
		// - O the old number of elements
		// - U the number of elements that stay unchanged
		// N = O - D + I
		// U = O - D
		// Delete operations are expensive,
		// because we need a single call for each deletion.
		// But if U is large, it would be also be expensive
		// to transfer all elements again.
		// Heuristic:
		// If D > U/2 then don't change incrementally but transfer all elements.
		o := len(la)
		d := 0
		for _, r := range s.Ranges {
			if r.IsDelete() {
				d += r.HighA - r.LowA
			}
		}
		u := o - d
		if 2*d > u+1 { // +1: allow some deletes in small group
			return false
		}
		insert := ""
		for _, r := range s.Ranges {
			if r.IsDelete() {
				for _, adr := range la[r.LowA:r.HighA] {
					text := textAttr(adr)
					cmd := "action=delete&" + cmd0 + path + "/member" + text
					result = append(result, cmd)
				}
			} else if r.IsInsert() {
				object := &panMembers{Member: lb[r.LowB:r.HighB]}
				insert += printXMLValue(object)
			} else {
				// Check that addressgroups are equal or can be made equal.
				offset := r.LowB - r.LowA
				for i := r.LowA; i < r.HighA; i++ {
					adrA := la[i]
					adrB := lb[i+offset]
					if ga := ab.rPair.a.groups[adrA]; ga != nil {
						gb := ab.rPair.b.groups[adrB]
						if !hasEqualizedGroups(ga, gb) {
							return false
						}
					}
				}
			}
		}
		if insert != "" {
			elem := "&element=" + insert
			cmd := "action=set&" + cmd0 + path + elem
			result = append(result, cmd)
		}
		return true
	}
	hasEqualizedGroups = func(ga, gb *panAddressGroup) bool {
		if gb.nameOnDevice != "" {
			// Current group from netspoc is already available on device.
			// No need to transfer the group.
			// But rule must be changed in this situation:
			// conf  spoc
			// g2    g1
			// g3    g1
			return gb.nameOnDevice == ga.Name
		}
		if ga.needed {
			// Current group on device has already been marked as needed.
			// conf  spoc
			// g3    g1
			// g3    g2
			// Don't change group on device twice.
			// Instead change occurrence of group in second rule on device.
			return false
		}
		path := groupPath + nameAttr(ga.Name) + "/static"
		if hasEqualizedLists(ga.Members, gb.Members, path) {
			ga.needed = true
			gb.needed = false
			gb.nameOnDevice = ga.Name
			return true
		}
		return false
	}
	equalizeList := func(a, b panList, path string) {
		la := a.getList()
		lb := b.getList()
		if hasEqualizedLists(la, lb, path) {
			return
		}
		// Replace current members by new members.
		ab.adaptGroups(lb)
		elem := "&element=" + printXMLValue(b)
		cmd := "action=edit&" + cmd0 + path + elem
		result = append(result, cmd)
	}
	equalizeList(a.panRuleSrc, b.panRuleSrc, rulePath+"/source")
	equalizeList(a.panRuleDst, b.panRuleDst, rulePath+"/destination")
	if !stringsEq(a.Service, b.Service) {
		elem := "&element=" + printXMLValue(b.panRuleSrv)
		cmd := "action=edit&" + cmd0 + rulePath + "/service" + elem
		result = append(result, cmd)
	}
	return result
}

func (ab *rulesPair) findGroupOnDevice(gb *panAddressGroup) string {
GROUP:
	for _, ga := range ab.a.vsys.AddressGroups {
		// Group ga was already changed to elements of group gb from Netspoc or
		// it is equal to group gb from Netspoc.
		// In both cases gb.nameOnDevice is already linked to some ga
		// and will never be searched again.
		if ga.needed {
			continue
		}
		if len(ga.Members) != len(gb.Members) {
			continue
		}
		for i, n := range gb.Members {
			if n != ga.Members[i] {
				continue GROUP
			}
		}
		ga.needed = true
		gb.needed = false
		gb.nameOnDevice = ga.Name
		return ga.Name
	}
	return ""
}

func (ab *rulesPair) adaptGroups(lb []string) {
	for i, adr := range lb {
		if gb := ab.b.groups[adr]; gb != nil {
			if name := gb.nameOnDevice; name != "" {
				lb[i] = name
			} else if name := ab.findGroupOnDevice(gb); name != "" {
				lb[i] = name
			} else {
				// Name may have been changed before, to prevent name clashes.
				lb[i] = gb.Name
			}
		}
	}
}

// Rename rules in b such that names are unique in respect to rules in a.
func (ab *rulesPair) genUniqRuleNames() {
	aNames := make(map[string]bool)
	for _, ru := range ab.a.rules {
		aNames[ru.Name] = true
	}
	for _, ru := range ab.b.rules {
		name := ru.Name
		if !aNames[name] {
			continue
		}
		for i := 1; ; i++ {
			new := fmt.Sprintf("%s-%d", name, i)
			if !aNames[new] {
				ru.Name = new
				break
			}
		}
	}
}

// Rename groups in b such that names are unique in respect to groups in a.
func (ab *rulesPair) genUniqGroupNames() {
	aGroups := ab.a.groups
	for _, g := range ab.b.vsys.AddressGroups {
		name := g.Name
		if aGroups[name] == nil {
			continue
		}
		for i := 1; ; i++ {
			new := fmt.Sprintf("%s-%d", name, i)
			if aGroups[new] == nil {
				g.Name = new
				break
			}
		}
	}
}

func sortMembers(v *panVsys) {
	for _, ru := range v.Rules {
		sort.Strings(ru.Source)
		sort.Strings(ru.Destination)
		sort.Strings(ru.Service)
	}
	for _, g := range v.AddressGroups {
		sort.Strings(g.Members)
	}
}
