package panos

import (
	"fmt"
	"github.com/pkg/diff/myers"
)

func diffConfig(a, b *panVsys, vsysPath string) []string {
	ab := rulesPairFrom(a, b)
	ab.markObjects(b.Rules)
	result := ab.diffRules(vsysPath)
	result = append(result, ab.transferNeededObjects(vsysPath)...)
	result = append(result, ab.removeUnneededObjects(vsysPath)...)
	return result
}

type vsysInfo struct {
	vsys      *panVsys
	rules     []*panRule
	addresses map[string]*panAddress
	groups    map[string]*panAddressGroup
	services  map[string]*panService
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
			services:  serviceMap(a),
		},
		vsysInfo{
			vsys:      b,
			rules:     b.Rules,
			addresses: addressMap(b),
			groups:    groupMap(b),
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

func (ab *rulesPair) LenA() int { return len(ab.a.rules) }
func (ab *rulesPair) LenB() int { return len(ab.b.rules) }

func (ab *rulesPair) Equal(ai, bi int) bool {
	a := ab.a.rules[ai]
	b := ab.b.rules[bi]
	return a.Action == b.Action &&
		stringsEq(a.From, b.From) &&
		stringsEq(a.To, b.To) &&
		ab.objectsEq(a.Source, b.Source) &&
		ab.objectsEq(a.Destination, b.Destination) &&
		stringsEq(a.Service, b.Service) &&
		a.LogStart == b.LogStart &&
		a.LogEnd == b.LogEnd &&
		a.RuleType == b.RuleType

}

func (ab *rulesPair) diffRules(vsysPath string) []string {
	ab.genUniqRuleNames()
	rulesPath := vsysPath + "/rulebase/security/rules/entry"
	cmd0 := "type=config&xpath=" + rulesPath
	s := myers.Diff(nil, ab)
	var result []string
	aRules := ab.a.rules
	bRules := ab.b.rules
	delIdx := -1 // Next index after deleted rule(s).
	for _, r := range s.Ranges {
		if r.IsDelete() {
			delIdx = r.HighA
			for _, ru := range aRules[r.LowA:r.HighA] {
				name := nameAttr(ru.Name)
				// No longer referenced objects are deleted later.
				cmd := "action=delete&" + cmd0 + name
				result = append(result, cmd)
			}
		} else if r.IsInsert() {
			moveTo := ""
			aPos := r.LowA
			// Adapt position to next available rule if this rule has
			// just been deleted.
			if aPos < delIdx {
				aPos = delIdx
			}
			// New rule is initially appended as last element.
			// Move to given position where required.
			if aPos < len(aRules) {
				aName := aRules[aPos].Name
				moveTo = "&where=before&dst=" + aName
			}
			for _, ru := range bRules[r.LowB:r.HighB] {
				name := nameAttr(ru.Name)
				elem := "&element=" + printXMLValue(ru)
				cmd1 := "action=set&" + cmd0 + name + elem
				result = append(result, cmd1)
				if moveTo != "" {
					cmd2 := "action=move&" + cmd0 + name + moveTo
					result = append(result, cmd2)
				}
			}
		} else {
			offset := r.LowB - r.LowA
			for i := r.LowA; i < r.HighA; i++ {
				rA := aRules[i]
				rB := bRules[i+offset]
				result = append(result, ab.equalize(rA, rB, rulesPath)...)
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

func (ab *rulesPair) objectsEq(a, b []string) bool {
	t1 := getObjListType(a, ab.a)
	t2 := getObjListType(b, ab.b)
	return t1 == t2 && t1 != otherT
}

type objListType int

const (
	otherT = iota
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
			return otherT
		}
	}
	if len(l) == 0 {
		return otherT
	}
	for _, e := range l {
		if v.addresses[e] == nil {
			return otherT
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
		} else if a := ab.a.addresses[name]; a != nil {
			a.needed = true
		} else if a := ab.b.addresses[name]; a != nil {
			a.needed = true
		}
	}
}

func (ab *rulesPair) markServices(l []string) {
	for _, name := range l {
		if s := ab.a.services[name]; s != nil {
			s.needed = true
		} else if s := ab.b.services[name]; s != nil {
			s.needed = true
		}
	}
}

// Transfer objects from b, that are needed in a.
func (ab *rulesPair) transferNeededObjects(vsysPath string) []string {
	var result []string
	addressPath := vsysPath + "/address/entry"
	cmd0 := "type=config&xpath=" + addressPath
	for _, o := range ab.b.vsys.Addresses {
		if o.needed {
			name := nameAttr(o.Name)
			elem := "&element=" + printXMLValue(o)
			cmd := "action=set&" + cmd0 + name + elem
			result = append(result, cmd)
		}
	}
	groupPath := vsysPath + "/address-group/entry"
	cmd0 = "type=config&xpath=" + groupPath
	for _, o := range ab.b.vsys.AddressGroups {
		if o.needed {
			name := nameAttr(o.Name)
			elem := "&element=" + printXMLValue(o)
			cmd := "action=set&" + cmd0 + name + elem
			result = append(result, cmd)
		}
	}
	servicePath := vsysPath + "/service/entry"
	cmd0 = "type=config&xpath=" + servicePath
	for _, o := range ab.b.vsys.Services {
		if o.needed {
			name := nameAttr(o.Name)
			elem := "&element=" + printXMLValue(o)
			cmd := "action=set&" + cmd0 + name + elem
			result = append(result, cmd)
		}
	}
	return result
}

// Remove objects from a, that are no longer needed.
func (ab *rulesPair) removeUnneededObjects(vsysPath string) []string {
	var result []string
	addressPath := vsysPath + "/address/entry"
	cmd0 := "type=config&xpath=" + addressPath
	delete := func(name string) {
		cmd := "action=delete&" + cmd0 + nameAttr(name)
		result = append(result, cmd)
	}
	for _, o := range ab.a.vsys.Addresses {
		if !o.needed {
			delete(o.Name)
		}
	}
	groupPath := vsysPath + "/address-group/entry"
	cmd0 = "type=config&xpath=" + groupPath
	for _, o := range ab.a.vsys.AddressGroups {
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
	a []string
	b []string
}

func (ab *addrListPair) LenA() int { return len(ab.a) }
func (ab *addrListPair) LenB() int { return len(ab.b) }

func (ab *addrListPair) Equal(ai, bi int) bool {
	return ab.a[ai] == ab.b[bi]
}

func (ab *rulesPair) equalize(a, b *panRule, rulesPath string) []string {
	var result []string
	cmd0 := "type=config&xpath=" + rulesPath + nameAttr(a.Name)
	equalizeAddresses := func(la, lb []string, where string) bool {
		ab := &addrListPair{a: la, b: lb}
		s := myers.Diff(nil, ab)
		for _, r := range s.Ranges {
			if r.IsDelete() {
				for _, adr := range la[r.LowA:r.HighA] {
					text := textAttr(adr)
					cmd := "action=delete&" + cmd0 + "/" + where + "/member" + text
					result = append(result, cmd)
				}
			} else if r.IsInsert() {
				object := &panMembers{Member: lb[r.LowB:r.HighB]}
				elem := "&element=" + printXMLValue(object)
				cmd := "action=set&" + cmd0 + "/" + where + elem
				result = append(result, cmd)
			}
		}
		return true
	}
	equalizeGroups := func(la, lb []string) bool {
		ga := ab.a.groups[la[0]]
		gb := ab.b.groups[lb[0]]
		// ToDo:
		// - Check, if groups has already been equalized.
		// Group uses static>member, not member as XML elements.
		if equalizeAddresses(ga.Members, gb.Members, ga.Name) {
			ga.needed = true
			gb.needed = false
			return true
		}
		return false
	}
	equalizeList := func(la, lb []string, where string) {
		t1 := getObjListType(la, ab.a)
		t2 := getObjListType(lb, ab.b)
		if t1 == t2 && t1 != otherT {
			switch t1 {
			case anyT:
				return
			case groupT:
				if equalizeGroups(la, lb) {
					return
				}
			case listT:
				if equalizeAddresses(la, lb, where) {
					return
				}
			}
		}
		// Replace current members by new members.
		object := &panMembers{Member: lb}
		elem := "&element=" + printXMLValue(object)
		cmd := "action=edit&" + cmd0 + "/" + where + elem
		result = append(result, cmd)
	}
	equalizeList(a.Source, b.Source, "source")
	equalizeList(a.Destination, b.Destination, "destination")
	if !stringsEq(a.Service, b.Service) {
		elem := "&element=" + printXMLValue(b.Service)
		cmd := cmd0 + "/service" + elem
		result = append(result, cmd)
	}
	return result
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
