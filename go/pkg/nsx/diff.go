package nsx

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/pkg/diff/myers"
)

type rulesPair struct {
	a      *nsxInfo
	b      *nsxInfo
	policy *nsxPolicy
}

type nsxInfo struct {
	rules    []*nsxRule
	groups   map[string]*nsxGroup
	services map[string]*nsxService
}

func diffConfig(a, b *NsxConfig) ([]change, error) {
	sortGroups(a.Groups)
	sortGroups(b.Groups)

	var changes []change
	addNewServices :=
		func() {
			m := serviceMap(a.Services)
			method := "PUT"
			for _, sb := range b.Services {
				if sa := m[sb.Id]; sa != nil {
					sa.needed = true
					ja, _ := json.Marshal(sa)
					jb, _ := json.Marshal(sb)
					if bytes.Compare(ja, jb) == 0 {
						continue
					}
					method = "PATCH"
				}
				url := "/policy/api/v1/infra/services/" + sb.Id
				sb.Id = "" // Don't send Id twice.
				postData, _ := json.Marshal(sb)
				changes = append(changes, change{method, url, postData})
			}
		}
	addNewServices()

	getPolicyMap :=
		func(c *NsxConfig) map[string]*nsxPolicy {
			m := make(map[string]*nsxPolicy)
			for _, p := range c.Policies {
				m[p.Id] = p
			}
			return m
		}
	pm := getPolicyMap(b)
	for _, p1 := range a.Policies {
		p2 := pm[p1.Id]
		l := diffPolicies(p1, p2, a.Groups, b.Groups)
		changes = append(changes, l...)
	}
	pm = getPolicyMap(a)
	for _, p2 := range b.Policies {
		if pm[p2.Id] == nil {
			l := diffPolicies(nil, p2, a.Groups, b.Groups)
			changes = append(changes, l...)
		}
	}

	removeUnusedServices :=
		func() {
			for _, sa := range a.Services {
				if !sa.needed {
					url := "/policy/api/v1/infra/services/" + sa.Id
					changes = append(changes, change{"DELETE", url, nil})
				}
			}
		}

	removeUnusedServices()
	return changes, nil
}

func sortGroups(groups []*nsxGroup) {
	for _, group := range groups {
		sort.Strings(group.Expression[0].IPAddresses)
	}
}

func diffPolicies(a, b *nsxPolicy, ga, gb []*nsxGroup) []change {
	if b == nil {
		return deletePolicy(a)
	}
	var chgs []change
	//TODO: Regeln nicht einzeln anlegen, wenn policy neu angelegt wird.
	createPolicy :=
		func() {
			cp := *b
			cp.Rules = nil
			url := fmt.Sprintf("/policy/api/v1/infra/domains/default/gateway-policies/%s", cp.Id)
			postData, _ := json.Marshal(&cp)
			a = &cp
			chgs = append(chgs, change{"PUT", url, postData})
		}
	if a == nil {
		createPolicy()
	}
	genUniqRuleNames(a.Rules, b.Rules)
	aStart := 0
	bStart := 0
	var aEnd, bEnd int
	ab := &rulesPair{policy: a, a: &nsxInfo{}, b: &nsxInfo{}}
	ab.a.groups = groupMap(ga)
	ab.b.groups = groupMap(gb)
	sortRules(a.Rules, ab.a.groups)
	sortRules(b.Rules, ab.b.groups)
	for aStart < len(a.Rules) {
		r1 := a.Rules[aStart]
		dir := r1.Direction
		seq := r1.SequenceNumber
		// Preliminary assume that all rules have equal values for dir and seq.
		aEnd = len(a.Rules)
		for i, r2 := range a.Rules[aStart+1:] {
			if r2.Direction != dir || r2.SequenceNumber != seq {
				aEnd = i + aStart + 1
				break
			}
		}
		// Assume there is no matching rule in b.
		bEnd = bStart
		for _, r2 := range b.Rules[bStart:] {
			if r2.Direction != dir || r2.SequenceNumber != seq {
				break
			}
			bEnd++
		}
		ab.a.rules = a.Rules[aStart:aEnd]
		ab.b.rules = b.Rules[bStart:bEnd]
		chgs = append(chgs, ab.diffRules()...)
		aStart = aEnd
		bStart = bEnd
	}
	if bStart < len(b.Rules) {
		ab.a.rules = nil
		ab.b.rules = b.Rules[bStart:]
		chgs = append(chgs, ab.diffRules()...)
	}
	chgs = append(chgs, ab.removeUnusedGroups()...)
	return chgs
}

func groupMap(g []*nsxGroup) map[string]*nsxGroup {
	m := make(map[string]*nsxGroup)
	for _, o := range g {
		m[o.Id] = o
	}
	return m
}

func serviceMap(s []*nsxService) map[string]*nsxService {
	m := make(map[string]*nsxService)
	for _, o := range s {
		m[o.Id] = o
	}
	return m
}

func deletePolicy(a *nsxPolicy) []change {
	url := fmt.Sprintf("/policy/api/v1/infra/domains/default/gateway-policies/%s", a.Id)
	return []change{{"DELETE", url, nil}}
}

func (ab *rulesPair) LenA() int { return len(ab.a.rules) }
func (ab *rulesPair) LenB() int { return len(ab.b.rules) }

func (ab *rulesPair) Equal(ai, bi int) bool {
	a := ab.a.rules[ai]
	b := ab.b.rules[bi]

	objEqual := func(a, b string) bool {
		if strings.HasPrefix(a, "/infra/domains/default/groups/") {
			return strings.HasPrefix(b, "/infra/domains/default/groups/")
		}
		return a == b
	}

	return a.Action == b.Action &&
		a.Services[0] == b.Services[0] &&
		objEqual(a.SourceGroups[0], b.SourceGroups[0]) &&
		objEqual(a.DestinationGroups[0], b.DestinationGroups[0])
}

func (ab *rulesPair) diffRules() []change {
	a := ab.a
	b := ab.b
	s := myers.Diff(nil, ab)
	var result []change
	del :=
		func(l []*nsxRule) {
			for _, ru := range l {
				url := fmt.Sprintf("/policy/api/v1/infra/domains/default/gateway-policies/%s/rules/%s",
					ab.policy.Id, ru.Id)
				result = append(result, change{"DELETE", url, nil})
			}
		}
	ins :=
		func(l []*nsxRule) {
			adaptGroup :=
				func(l []string) {
					if gb := getGroup(l[0], b.groups); gb != nil {
						if gb.nameOnDevice != "" {
							l[0] = "/infra/domains/default/groups/" + gb.nameOnDevice
						} else if ga := findGroupOnDevice(gb, a.groups); ga != nil {
							ga.needed = true
							gb.nameOnDevice = ga.Id
							l[0] = "/infra/domains/default/groups/" + ga.Id
						} else {
							result = append(result, addGroup(gb)...)
						}
					}
				}
			for _, ru := range l {
				adaptGroup(ru.SourceGroups)
				adaptGroup(ru.DestinationGroups)
				result = append(result, ab.writeRule(ru))
			}
		}
	for _, r := range s.Ranges {
		if r.IsDelete() {
			del(a.rules[r.LowA:r.HighA])
		} else if r.IsInsert() {
			ins(b.rules[r.LowB:r.HighB])
		} else {
			for i, ra := range a.rules[r.LowA:r.HighA] {
				rb := b.rules[r.LowB+i]
				result = append(result, ab.equalizeGroups(ra, rb)...)
			}
		}
	}
	return result
}

func (ab *rulesPair) writeRule(r *nsxRule) change {
	url := fmt.Sprintf("/policy/api/v1/infra/domains/default/gateway-policies/%s/rules/%s",
		ab.policy.Id, r.Id)
	r.Id = "" // Don't send Id twice.
	postData, _ := json.Marshal(r)
	return change{"PUT", url, postData}
}

func getGroup(s string, m map[string]*nsxGroup) *nsxGroup {
	if g := strings.TrimPrefix(s, "/infra/domains/default/groups/"); g != s {
		return m[g]
	}
	return nil
}

func addGroup(g *nsxGroup) []change {
	if g.nameOnDevice != "" {
		return nil
	}
	url := "/policy/api/v1/infra/domains/default/groups/" + g.Id
	g.nameOnDevice = g.Id
	g.Id = ""
	postData, _ := json.Marshal(g)
	return []change{{"PUT", url, postData}}
}

func findGroupOnDevice(gb *nsxGroup, ma map[string]*nsxGroup) *nsxGroup {
	bAddr := gb.Expression[0].IPAddresses
GROUP:
	for _, ga := range ma {
		aAddr := ga.Expression[0].IPAddresses
		// Check if group already referenced by other group.
		if ga.needed {
			continue
		}
		if len(aAddr) != len(bAddr) {
			continue
		}
		for i, n := range bAddr {
			if n != aAddr[i] {
				continue GROUP
			}
		}
		return ga
	}
	return nil
}

type groupPair struct {
	a *nsxGroup
	b *nsxGroup
}

func (g groupPair) LenA() int {
	return len(g.a.Expression[0].IPAddresses)
}

func (g groupPair) LenB() int {
	return len(g.b.Expression[0].IPAddresses)
}

func (g groupPair) Equal(ai, bi int) bool {
	return g.a.Expression[0].IPAddresses[ai] == g.b.Expression[0].IPAddresses[bi]
}

func (ab *rulesPair) equalizeGroups(ra, rb *nsxRule) []change {
	var result []change
	var changedRuleA bool
	equalize := func(la, lb []string) {
		ga := getGroup(la[0], ab.a.groups)
		if ga == nil {
			return
		}
		gb := getGroup(lb[0], ab.b.groups)
		// Don't change ga on device but adapt rule to name of group to be transferred to
		// device or already found on device.
		if ga.needed || gb.nameOnDevice != "" {
			if gb.nameOnDevice == "" {
				result = append(result, addGroup(gb)...)
			}
			la[0] = "/infra/domains/default/groups/" + gb.nameOnDevice
			changedRuleA = true
			return
		}
		ga.needed = true
		gb.nameOnDevice = ga.Id
		gab := &groupPair{
			ga, gb,
		}
		var toAdd, toRemove []string
		s := myers.Diff(nil, gab)
		for _, r := range s.Ranges {
			if r.IsDelete() {
				toRemove = append(toRemove, ga.Expression[0].IPAddresses[r.LowA:r.HighA]...)
			} else if r.IsInsert() {
				toAdd = append(toAdd, gb.Expression[0].IPAddresses[r.LowB:r.HighB]...)
			}
		}
		addChange := func(action string, addresses []string) {
			if addresses != nil {
				var data struct {
					IpAddresses []string `json:"ip_addresses"`
				}
				url := fmt.Sprintf("/policy/api/v1/infra/domains/default/groups/%s/ip-address-expressions/%s?action=%s",
					ga.Id, ga.Expression[0].Id, action)
				data.IpAddresses = addresses
				postData, _ := json.Marshal(data)
				result = append(result, change{"POST", url, postData})
			}
		}
		addChange("remove", toRemove)
		addChange("add", toAdd)
	}

	equalize(ra.SourceGroups, rb.SourceGroups)
	equalize(ra.DestinationGroups, rb.DestinationGroups)
	if changedRuleA {
		result = append(result, ab.writeRule(ra))
	}
	return result
}

func (ab *rulesPair) removeUnusedGroups() []change {
	var result []change
	for _, ga := range ab.a.groups {
		if !ga.needed {
			url := "/policy/api/v1/infra/domains/default/groups/" + ga.Id
			result = append(result, change{"DELETE", url, nil})
		}
	}
	return result
}

func sortRules(l []*nsxRule, m map[string]*nsxGroup) {
	elementLess := func(ei, ej string) bool {
		gi := getGroup(ei, m)
		gj := getGroup(ej, m)
		if gi != nil {
			if gj != nil {
				return gi.Expression[0].IPAddresses[0] < gj.Expression[0].IPAddresses[0]
			}
			return true
		}
		if gj != nil {
			return false
		}
		return ei < ej
	}
	sort.Slice(l, func(i, j int) bool {
		if l[i].Direction != l[j].Direction {
			return l[i].Direction < l[j].Direction
		}
		if l[i].SequenceNumber != l[j].SequenceNumber {
			return l[i].SequenceNumber < l[j].SequenceNumber
		}
		if l[i].Action != l[j].Action {
			return l[i].Action < l[j].Action
		}
		//Assume length of all following is only 1
		if l[i].Services[0] != l[j].Services[0] {
			return l[i].Services[0] < l[j].Services[0]
		}
		if l[i].SourceGroups[0] != l[j].SourceGroups[0] {
			return elementLess(l[i].SourceGroups[0], l[j].SourceGroups[0])
		}
		if l[i].DestinationGroups[0] != l[j].DestinationGroups[0] {
			return elementLess(l[i].DestinationGroups[0], l[j].DestinationGroups[0])
		}
		return false
	})
}

// Rename rules in b such that names are unique in respect to rules in a.
func genUniqRuleNames(a, b []*nsxRule) {
	aIds := make(map[string]bool)
	for _, ru := range a {
		aIds[ru.Id] = true
	}
	for _, ru := range b {
		id := ru.Id
		if !aIds[id] {
			continue
		}
		for i := 1; ; i++ {
			newId := fmt.Sprintf("%s-%d", id, i)
			if !aIds[newId] {
				ru.Id = newId
				break
			}
		}
	}
}
