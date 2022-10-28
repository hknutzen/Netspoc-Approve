package nsx

import (
	"encoding/json"
	"fmt"
	"github.com/pkg/diff/myers"
	"sort"
)

type rulesPair struct {
	a      []*nsxRule
	b      []*nsxRule
	policy *nsxPolicy
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
	for _, p1 := range a.Policies {
		p2 := m[p1.Id]
		l := diffPolicies(p1, p2)
		changes = append(changes, l...)
	}
	m = getPolicyMap(a)
	for _, p2 := range b.Policies {
		if m[p2.Id] == nil {
			l := diffPolicies(nil, p2)
			changes = append(changes, l...)
		}
	}
	return changes, nil
}

func diffPolicies(a, b *nsxPolicy) []change {
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
	ab := &rulesPair{policy: a}
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
		ab.a = a.Rules[aStart:aEnd]
		ab.b = b.Rules[bStart:bEnd]
		chgs = append(chgs, ab.diffRules()...)
		aStart = aEnd
		bStart = bEnd
	}
	if bStart < len(b.Rules) {
		ab.a = nil
		ab.b = b.Rules[bStart:]
		chgs = append(chgs, ab.diffRules()...)
	}
	return chgs
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

func (ab *rulesPair) LenA() int { return len(ab.a) }
func (ab *rulesPair) LenB() int { return len(ab.b) }

func (ab *rulesPair) Equal(ai, bi int) bool {
	a := ab.a[ai]
	b := ab.b[bi]
	return a.Action == b.Action &&
		a.Services[0] == b.Services[0] &&
		//TODO check for contents of named groups
		a.SourceGroups[0] == b.SourceGroups[0] &&
		a.DestinationGroups[0] == b.DestinationGroups[0]
}

func (ab *rulesPair) diffRules() []change {
	a := ab.a
	b := ab.b
	s := myers.Diff(nil, ab)
	var result []change
	delete :=
		func(l []*nsxRule) {
			for _, ru := range l {
				url := fmt.Sprintf("/policy/api/v1/infra/domains/default/gateway-policies/%s/rules/%s",
					ab.policy.Id, ru.Id)
				result = append(result, change{"DELETE", url, nil})
			}
		}
	insert :=
		func(l []*nsxRule) {
			for _, ru := range l {
				url := fmt.Sprintf("/policy/api/v1/infra/domains/default/gateway-policies/%s/rules/%s",
					ab.policy.Id, ru.Id)
				postData, _ := json.Marshal(ru)
				result = append(result, change{"PUT", url, postData})
			}
		}
	for _, r := range s.Ranges {
		if r.IsDelete() {
			delete(a[r.LowA:r.HighA])
		} else if r.IsInsert() {
			insert(b[r.LowB:r.HighB])
		} //else: IsEqual
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
			new := fmt.Sprintf("%s-%d", id, i)
			if !aIds[new] {
				ru.Id = new
				break
			}
		}
	}
}
