package nsx

import (
	"bytes"
	"cmp"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/pkg/diff/myers"
	"golang.org/x/exp/slices"
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
		ma := serviceMap(a.Services)
		// To ignore duplicate defined services from IPv4 and IPv6 input
		mb := make(map[string]bool)
		for _, sb := range b.Services {
			if mb[sb.Id] {
				continue
			}
			mb[sb.Id] = true
			method := "PUT"
			if sa := ma[sb.Id]; sa != nil {
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
		for _, ga := range a.Groups {
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
	ra := ab.a.rules[ai]
	rb := ab.b.rules[bi]

	groupEq := func(a, b string) bool {
		if getGroup(a, ab.a.groups) == nil || getGroup(b, ab.b.groups) == nil {
			return a == b
		}
		return true
	}

	return ra.Direction == rb.Direction &&
		ra.SequenceNumber == rb.SequenceNumber &&
		ra.Action == rb.Action &&
		ra.Logged == rb.Logged &&
		ra.Tag == rb.Tag &&
		ra.Disabled == rb.Disabled &&
		ra.DestinationsExcluded == rb.DestinationsExcluded &&
		ra.SourcesExcluded == rb.SourcesExcluded &&
		bytes.Equal(ra.ServiceEntries, rb.ServiceEntries) &&
		ra.IPProtocol == rb.IPProtocol &&
		slices.Equal(ra.Profiles, rb.Profiles) &&
		slices.Equal(ra.Scope, rb.Scope) &&
		ra.Services[0] == rb.Services[0] &&
		groupEq(ra.SourceGroups[0], rb.SourceGroups[0]) &&
		groupEq(ra.DestinationGroups[0], rb.DestinationGroups[0])
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
	if g, found := strings.CutPrefix(s, "/infra/domains/default/groups/"); found {
		return m[g]
	}
	return nil
}

func addGroup(g *nsxGroup) []change {
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
		// No need to change name of group in rule from ga to gb
		// if gb is known to have values of ga.
		if gb.nameOnDevice == ga.Id {
			return
		}
		// Don't change ga on device but adapt rule to name of group to be transferred to
		// device or already found on device.
		if ga.needed ||
			gb.nameOnDevice != "" {
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
		// Check if an incremental change is viable.
		// Be
		// - D the number of deleted elements
		// - I the number of inserted elements
		// - O the old number of elements
		// - N the new number of elements
		// N = O - D + I
		// If number to delete exeeds number of remaining elements send complete list instead
		d := len(toRemove)
		i := len(toAdd)
		o := len(ga.Expression[0].IPAddresses)
		n := o - d + i
		if n < d {
			url := fmt.Sprintf("/policy/api/v1/infra/domains/default/groups/%s/ip-address-expressions/%s",
				ga.Id, ga.Expression[0].Id)
			gb.Expression[0].Id = ""
			postData, _ := json.Marshal(gb.Expression[0])
			result = append(result, change{"PATCH", url, postData})

		} else {
			addChange("remove", toRemove)
			addChange("add", toAdd)
		}
	}

	equalize(ra.SourceGroups, rb.SourceGroups)
	equalize(ra.DestinationGroups, rb.DestinationGroups)
	if changedRuleA {
		result = append(result, ab.writeRule("PATCH", ra))
	}
	return result
}

func sortRules(l []*nsxRule, m map[string]*nsxGroup) {
	elementCmp := func(ei, ej string) int {
		gi := getGroup(ei, m)
		gj := getGroup(ej, m)
		if gi != nil {
			if gj != nil {
				return cmp.Compare(gi.Expression[0].IPAddresses[0], gj.Expression[0].IPAddresses[0])
			}
			return -1
		}
		// Length of group > single IP
		if gj != nil {
			return 1
		}
		return cmp.Compare(ei, ej)
	}
	boolCmp := func(a, b bool) int {
		if a == b {
			return 0
		}
		if a {
			return -1
		}
		return 1
	}

	slices.SortFunc(l, func(a, b *nsxRule) int {
		if n := cmp.Compare(a.Direction, b.Direction); n != 0 {
			return n
		}
		if n := cmp.Compare(a.SequenceNumber, b.SequenceNumber); n != 0 {
			return n
		}
		if n := cmp.Compare(a.Action, b.Action); n != 0 {
			return n
		}
		if n := boolCmp(a.Logged, b.Logged); n != 0 {
			return n
		}
		if n := cmp.Compare(a.Tag, b.Tag); n != 0 {
			return n
		}
		if n := boolCmp(a.Disabled, b.Disabled); n != 0 {
			return n
		}
		if n := boolCmp(a.DestinationsExcluded, b.DestinationsExcluded); n != 0 {
			return n
		}
		if n := boolCmp(a.SourcesExcluded, b.SourcesExcluded); n != 0 {
			return n
		}
		if n := bytes.Compare(a.ServiceEntries, b.ServiceEntries); n != 0 {
			return n
		}
		if n := cmp.Compare(a.IPProtocol, b.IPProtocol); n != 0 {
			return n
		}
		if n := slices.Compare(a.Profiles, b.Profiles); n != 0 {
			return n
		}
		if n := slices.Compare(a.Scope, b.Scope); n != 0 {
			return n
		}
		//Assume length of all following is only 1
		if n := cmp.Compare(a.Services[0], b.Services[0]); n != 0 {
			return n
		}
		if n := elementCmp(a.SourceGroups[0], b.SourceGroups[0]); n != 0 {
			return n
		}
		return elementCmp(a.DestinationGroups[0], b.DestinationGroups[0])
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
