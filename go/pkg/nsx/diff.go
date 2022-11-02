package nsx

import (
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

func diffConfig(a, b *NsxConfig) ([]change, error) {
	getPolicyMap :=
		func(c *NsxConfig) map[string]*nsxPolicy {
			m := make(map[string]*nsxPolicy)
			for _, p := range c.Policies {
				m[p.Id] = p
			}
			return m
		}
	var changes []change
	m := getPolicyMap(b)
	sortGroups(a.Groups)
	sortGroups(b.Groups)
	for _, p1 := range a.Policies {
		p2 := m[p1.Id]
		l := diffPolicies(p1, p2, a.Groups, b.Groups)
		changes = append(changes, l...)
	}
	m = getPolicyMap(a)
	for _, p2 := range b.Policies {
		if m[p2.Id] == nil {
			l := diffPolicies(nil, p2, a.Groups, b.Groups)
			changes = append(changes, l...)
		}
	}
	return changes, nil
}

func sortGroups(groups []*nsxGroup) {
	for _, group := range groups {
		sort.Strings(group.Expression[0].IPAddresses)
	}
}

func diffPolicies(a, b *nsxPolicy, ga, gb []*nsxGroup) []change {
	if a == nil {
		return createPolicy(b)
	}
	if b == nil {
		return deletePolicy(a)
	}
	sortRules(a.Rules)
	sortRules(b.Rules)
	genUniqRuleNames(a.Rules, b.Rules)
	aStart := 0
	bStart := 0
	var aEnd, bEnd int
	var chgs []change
	ab := &rulesPair{policy: a, a: &nsxInfo{}, b: &nsxInfo{}}
	ab.a.groups = groupMap(ga)
	ab.b.groups = groupMap(gb)
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
		ab.a = nil
		ab.b.rules = b.Rules[bStart:]
		chgs = append(chgs, ab.diffRules()...)
	}
	return chgs
}

func groupMap(g []*nsxGroup) map[string]*nsxGroup {
	m := make(map[string]*nsxGroup)
	for _, o := range g {
		m[o.Id] = o
	}
	return m
}

func createPolicy(a *nsxPolicy) []change {
	url := fmt.Sprintf("/policy/api/v1/infra/domains/default/gateway-policies/%s", a.Id)
	postData, _ := json.Marshal(a)
	return []change{{"PUT", url, postData}}
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
			for _, ru := range l {
				url := fmt.Sprintf("/policy/api/v1/infra/domains/default/gateway-policies/%s/rules/%s",
					ab.policy.Id, ru.Id)
				ru.Id = "" // Don't send Id twice.
				postData, _ := json.Marshal(ru)
				result = append(result, change{"PUT", url, postData})
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

func getGroup(s string, m map[string]*nsxGroup) *nsxGroup {
	if g := strings.TrimPrefix(s, "/infra/domains/default/groups/"); g != s {
		return m[g]
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
	equalize := func(ga, gb *nsxGroup) {
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
		addRequest := func(action string, addresses []string) {
			if addresses != nil {
				var data struct {
					IpAddresses []string `json:"ip_addresses"`
				}
				url := fmt.Sprintf("/policy/api/v1/infra/domains/default/groups/%s/ip-address-expressions/%s?action=%s", ga.Id, ga.Expression[0].Id, action)
				data.IpAddresses = addresses
				postData, _ := json.Marshal(data)
				result = append(result, change{"POST", url, postData})
			}
		}
		addRequest("remove", toRemove)
		addRequest("add", toAdd)
	}
	if ga := getGroup(ra.SourceGroups[0], ab.a.groups); ga != nil {
		gb := getGroup(rb.SourceGroups[0], ab.b.groups)
		equalize(ga, gb)
	}
	if ga := getGroup(ra.DestinationGroups[0], ab.a.groups); ga != nil {
		gb := getGroup(rb.DestinationGroups[0], ab.b.groups)
		equalize(ga, gb)
	}
	return result
}

func sortRules(l []*nsxRule) {
	sort.Slice(l, func(i, j int) bool {
		return l[i].Direction < l[j].Direction ||
			l[i].Direction == l[j].Direction &&
				(l[i].SequenceNumber < l[j].SequenceNumber ||
					l[i].SequenceNumber == l[j].SequenceNumber &&
						(l[i].Action < l[j].Action ||
							l[i].Action == l[j].Action &&
								//Assume length of all following is only 1
								(l[i].Services[0] < l[j].Services[0] ||
									l[i].Services[0] == l[j].Services[0] &&
										(l[i].SourceGroups[0] < l[j].SourceGroups[0] ||
											l[i].SourceGroups[0] == l[j].SourceGroups[0] &&
												(l[i].DestinationGroups[0] < l[j].DestinationGroups[0] ||
													l[i].DestinationGroups[0] == l[j].DestinationGroups[0])))))
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
