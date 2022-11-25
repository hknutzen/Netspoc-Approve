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
	rules  []*nsxRule
	groups map[string]*nsxGroup
}

func diffConfig(a, b *NsxConfig) []change {
	sortGroups(a.Groups)
	sortGroups(b.Groups)

	var changes []change
	addNewServices := func() {
		m := serviceMap(a.Services)
		for _, sb := range b.Services {
			method := "PUT"
			if sa := m[sb.Id]; sa != nil {
				sa.needed = true
				ja, _ := json.Marshal(sa)
				jb, _ := json.Marshal(sb)
				if bytes.Equal(ja, jb) {
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

	getPolicyMap := func(c *NsxConfig) map[string]*nsxPolicy {
		m := make(map[string]*nsxPolicy)
		for _, p := range c.Policies {
			m[p.Id] = p
		}
		return m
	}
	ab := &rulesPair{policy: nil, a: &nsxInfo{}, b: &nsxInfo{}}
	ab.a.groups = groupMap(a.Groups)
	ab.b.groups = groupMap(b.Groups)
	genUniqGroupNames(ab.a.groups, b.Groups)
	pm := getPolicyMap(b)
	for _, p1 := range a.Policies {
		p2 := pm[p1.Id]
		l := diffPolicies(p1, p2, ab)
		changes = append(changes, l...)
	}
	pm = getPolicyMap(a)
	for _, p2 := range b.Policies {
		if pm[p2.Id] == nil {
			l := diffPolicies(nil, p2, ab)
			changes = append(changes, l...)
		}
	}

	removeUnusedServices := func() {
		for _, sa := range a.Services {
			if !sa.needed {
				url := "/policy/api/v1/infra/services/" + sa.Id
				changes = append(changes, change{"DELETE", url, nil})
			}
		}
	}

	removeUnusedGroups := func() {
		for _, ga := range ab.a.groups {
			if !ga.needed {
				url := "/policy/api/v1/infra/domains/default/groups/" + ga.Id
				changes = append(changes, change{"DELETE", url, nil})
			}
		}
	}

	removeUnusedServices()
	removeUnusedGroups()
	return changes
}

func sortGroups(groups []*nsxGroup) {
	for _, group := range groups {
		sort.Strings(group.Expression[0].IPAddresses)
	}
}

func diffPolicies(a, b *nsxPolicy, ab *rulesPair) []change {
	if b == nil {
		return deletePolicy(a)
	}
	var chgs []change
	createPolicy := func() {
		for _, ru := range b.Rules {
			chgs = append(chgs, ab.adaptGroup(ru.SourceGroups)...)
			chgs = append(chgs, ab.adaptGroup(ru.DestinationGroups)...)
		}
		url := fmt.Sprintf(
			"/policy/api/v1/infra/domains/default/gateway-policies/%s", b.Id)
		postData, _ := json.Marshal(b)
		chgs = append(chgs, change{"PUT", url, postData})
	}
	if a == nil {
		createPolicy()
		return chgs
	}
	ab.policy = a
	genUniqRuleNames(a.Rules, b.Rules)
	sortRules(a.Rules, ab.a.groups)
	sortRules(b.Rules, ab.b.groups)
	ab.a.rules = a.Rules
	ab.b.rules = b.Rules
	chgs = append(chgs, ab.diffRules()...)
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
	stringsEq := func(a, b []string) bool {
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

	return a.Direction == b.Direction &&
		a.SequenceNumber == b.SequenceNumber &&
		a.Action == b.Action &&
		a.Logged == b.Logged &&
		a.Disabled == b.Disabled &&
		a.DestinationsExcluded == b.DestinationsExcluded &&
		a.SourcesExcluded == b.SourcesExcluded &&
		bytes.Equal(a.ServiceEntries, b.ServiceEntries) &&
		stringsEq(a.Profiles, b.Profiles) &&
		stringsEq(a.Scope, b.Scope) &&
		a.Services[0] == b.Services[0] &&
		objEqual(a.SourceGroups[0], b.SourceGroups[0]) &&
		objEqual(a.DestinationGroups[0], b.DestinationGroups[0])
	// TODO: IPProtocol (v4 & v6) separat prüfen
}

func (ab *rulesPair) diffRules() []change {
	a := ab.a
	b := ab.b
	s := myers.Diff(nil, ab)
	var result []change
	del := func(l []*nsxRule) {
		for _, ru := range l {
			url := fmt.Sprintf("/policy/api/v1/infra/domains/default/gateway-policies/%s/rules/%s",
				ab.policy.Id, ru.Id)
			result = append(result, change{"DELETE", url, nil})
		}
	}
	ins := func(l []*nsxRule) {
		for _, ru := range l {
			result = append(result, ab.adaptGroup(ru.SourceGroups)...)
			result = append(result, ab.adaptGroup(ru.DestinationGroups)...)
			result = append(result, ab.writeRule("PUT", ru))
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

func (ab *rulesPair) adaptGroup(lb []string) []change {
	if gb := getGroup(lb[0], ab.b.groups); gb != nil {
		if gb.nameOnDevice != "" {
			lb[0] = "/infra/domains/default/groups/" + gb.nameOnDevice
		} else if ga := findGroupOnDevice(gb, ab.a.groups); ga != nil {
			ga.needed = true
			gb.nameOnDevice = ga.Id
			lb[0] = "/infra/domains/default/groups/" + ga.Id
		} else {
			// Name may have been changed before, to prevent name clashes.
			lb[0] = "/infra/domains/default/groups/" + gb.Id
			return addGroup(gb)
		}
	}
	return nil
}

func (ab *rulesPair) writeRule(method string, r *nsxRule) change {
	url := fmt.Sprintf("/policy/api/v1/infra/domains/default/gateway-policies/%s/rules/%s",
		ab.policy.Id, r.Id)
	r.Id = "" // Don't send Id twice.
	postData, _ := json.Marshal(r)
	return change{method, url, postData}
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
		if ga.needed ||
			gb.nameOnDevice != "" {
			if gb.nameOnDevice == "" {
				result = append(result, addGroup(gb)...)
			}
			// No need to change name of group in rule from ga to gb
			// if gb is known to have values of ga.
			if gb.nameOnDevice != ga.Id {
				la[0] = "/infra/domains/default/groups/" + gb.nameOnDevice
				changedRuleA = true
			}
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
		result = append(result, ab.writeRule("PATCH", ra))
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

// Rename groups in b such that names are unique in respect to groups in a.
func genUniqGroupNames(a map[string]*nsxGroup, b []*nsxGroup) {
	for _, g := range b {
		id := g.Id
		if a[id] == nil {
			continue
		}
		for i := 1; ; i++ {
			newId := fmt.Sprintf("%s-%d", id, i)
			if a[newId] == nil {
				g.Id = newId
				break
			}
		}
	}
}
