package nsx

import "sort"

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
	processPolicyPairs :=
		func(c1, c2 *NsxConfig) error {
			m := getPolicyMap(c2)
			for _, p1 := range c1.Policies {
				p2 := m[p1.Id]
				l := diffPolicies(p1, p2)
				changes = append(changes, l...)
			}
			return nil
		}
	err := processPolicyPairs(a, b)
	if err != nil {
		return nil, err
	}
	err = processPolicyPairs(b, a)
	if err != nil {
		return nil, err
	}
	return changes, nil
}

func diffPolicies(a, b *nsxPolicy) []change {
	sortRules(a.Rules)
	sortRules(b.Rules)
	aStart := 0
	bStart := 0
	var aEnd, bEnd int
	var chgs []change
	for aStart < len(a.Rules) {
		r1 := a.Rules[aStart]
		dir := r1.Direction
		seq := r1.SequenceNumber
		// Preliminary assume that all rules have equal values for dir and seq.
		aEnd = len(a.Rules)
		for i, r2 := range a.Rules[aStart+1:] {
			if r2.Direction != dir || r2.SequenceNumber != seq {
				aEnd = i
				break
			}
		}
		bEnd = len(b.Rules)
		for i, r2 := range b.Rules[bStart:] {
			if r2.Direction != dir || r2.SequenceNumber != seq {
				bEnd = i
				break
			}
		}
		chgs = append(chgs, diffRules(a.Rules[aStart:aEnd], b.Rules[bStart:bEnd])...)
		aStart = aEnd
		bStart = bEnd
	}
	if bStart < len(b.Rules) {
		chgs = append(chgs, diffRules(nil, b.Rules[bStart:])...)
	}
	return chgs
}

func diffRules(a, b []*nsxRule) []change {

	return nil
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
