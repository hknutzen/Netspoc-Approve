package checkpoint

import (
	"encoding/json"
	"maps"
	"slices"
	"strings"

	"github.com/google/go-cmp/cmp"
	"github.com/pkg/diff/myers"
)

type rulesPair struct {
	aRules, bRules []*chkpRule
}

func (ab *rulesPair) LenA() int { return len(ab.aRules) }
func (ab *rulesPair) LenB() int { return len(ab.bRules) }

func (ab *rulesPair) Equal(ai, bi int) bool {
	// Checkpoint compares ASCII-case-insensitively.
	return equalFold(ab.aRules[ai].Name, ab.bRules[bi].Name) &&
		// We may have different rules with identical name on different devices,
		// because rule names are generated from service names in Netspoc.
		// Reason is, that the same service may expand to different rules
		// on different firewalls.
		slices.Equal(ab.aRules[ai].InstallOn, ab.bRules[bi].InstallOn)
}

type namesPair struct {
	aNames, bNames []chkpName
}

func (ab *namesPair) LenA() int { return len(ab.aNames) }
func (ab *namesPair) LenB() int { return len(ab.bNames) }

func (ab *namesPair) Equal(ai, bi int) bool {
	// Checkpoint compares ASCII-case-insensitively.
	return equalFold(string(ab.aNames[ai]), string(ab.bNames[bi]))
}

func diffConfig(a, b *chkpConfig) ([]change, []string) {
	var changes []change
	addChange := func(e string, d any) {
		changes = append(changes, change{endpoint: e, postData: d})
	}
	installMap := make(map[string]bool)
	setInstallOn := func(r *chkpRule) {
		for _, name := range r.InstallOn {
			installMap[string(name)] = true
		}
	}
	aObjects := getObjList(a)
	aObjMap := make(map[string]object)
	for _, o := range aObjects {
		aObjMap[toLower(o.getName())] = o
	}
	lookup := func(n string) (object, bool) {
		obj, found := aObjMap[toLower(n)]
		return obj, found
	}
	markDeletable := func(n chkpName) {
		// Predefined objects like "Any" won't be found.
		if aObj, found := lookup(string(n)); found {
			aObj.setDeletable()
		}
	}
	// Compare objects referenced by src/dst/srv of rule or by members of group.
	compareObjects := func(attr string, chg1, chg2 jsonMap, aL, bL []chkpName) {
		cmpFold := func(a, b chkpName) int {
			return strings.Compare(toLower(string(a)), toLower(string(b)))
		}
		slices.SortFunc(aL, cmpFold)
		slices.SortFunc(bL, cmpFold)
		ab := &namesPair{aNames: aL, bNames: bL}
		var add []chkpName
		var remove []string
		diff := myers.Diff(nil, ab).Ranges
		for _, r := range diff {
			if r.IsDelete() {
				for _, aName := range aL[r.LowA:r.HighA] {
					id := string(aName)
					if aObj, found := lookup(string(aName)); found {
						id = aObj.getUID()
					}
					remove = append(remove, id)
					markDeletable(aName)
				}
			} else if r.IsInsert() {
				add = append(add, bL[r.LowB:r.HighB]...)
			}
		}
		if add != nil {
			chg1[attr] = map[string][]chkpName{"add": add}
		}
		if remove != nil {
			chg2[attr] = map[string][]string{"remove": remove}
		}
	}
	// Compare objects defined from Netspoc with objects from device.
	for _, bObj := range getObjList(b) {
		name := bObj.getName()
		if aObj, found := lookup(name); found {
			// Object is found on device and marked as needed.
			aObj.setNeeded()
			// Compare members of groups or attributes of other objects.
			switch aObj.(type) {
			case *chkpGroup:
				aGrp := aObj.(*chkpGroup)
				bGrp := bObj.(*chkpGroup)
				chg1 := make(jsonMap)
				chg2 := make(jsonMap)
				compareObjects("members", chg1, chg2, aGrp.Members, bGrp.Members)
				if len(chg1) > 0 {
					chg1["uid"] = aGrp.UID
					addChange("set-group", chg1)
				}
				if len(chg2) > 0 {
					chg2["uid"] = aGrp.UID
					addChange("set-group", chg2)
				}
			default:
				uid := aObj.getUID()
				bObj.setUID(uid)
				aObj.clearName()
				bObj.clearName()
				ja, _ := json.Marshal(aObj)
				jb, _ := json.Marshal(bObj)
				if d := cmp.Diff(ja, jb); d != "" {
					// Modify existing object on device.
					addChange("set-"+bObj.getAPIObject(), bObj)
				}
			}
		} else {
			// Add definition of new object to device.
			switch bObj.(type) {
			case *chkpNetwork, *chkpHost, *chkpTCP, *chkpUDP:
				// Ignore warnings
				// - "More than one network has the same IP ..."
				// - "The port is already used by another service."
				//   This occurs if destination ports are equal,
				//   but source ports are different.
				bObj.setIgnoreWarnings()
			}
			bObj.setUID("")
			addChange("add-"+bObj.getAPIObject(), bObj)
		}
	}
	// Compare rules.
	ab := &rulesPair{
		aRules: a.Rules,
		bRules: b.Rules,
	}
	diff := myers.Diff(nil, ab).Ranges
	// Fix result of myers.Diff.
	// Insert position is set to 0,0 if edit script is a full replace.
	// But we need to insert behind deleted rules.
	if len(diff) == 2 {
		if diff[0].IsDelete() && diff[0].Len() == len(a.Rules) &&
			diff[1].IsInsert() && diff[1].Len() == len(b.Rules) {
			diff[1].LowA = len(a.Rules)
			diff[1].HighA = len(a.Rules)
			// Deleting all rules before inserting new rules
			// would result in this error:
			//  Action cannot be executed on object:
			//  Cleanup rule due to: Layer ('Network') has only one rule.
			// Hence
			// - delete rules up to the last but one rule,
			// - then insert new rules,
			// - then delete last rule.
			if len(a.Rules) == 1 {
				diff[0], diff[1] = diff[1], diff[0]
			} else {
				last := diff[0]
				diff[0].HighA--
				last.LowA = diff[0].HighA
				diff = append(diff, last)
			}
		}
	}
	for _, r := range diff {
		if r.IsDelete() {
			// Remove unneeded rules from device.
			for _, aRule := range a.Rules[r.LowA:r.HighA] {
				setInstallOn(aRule)
				setDeletable := func(l []chkpName) {
					for _, n := range l {
						markDeletable(n)
					}
				}
				setDeletable(aRule.Source)
				setDeletable(aRule.Destination)
				setDeletable(aRule.Service)
				addChange("delete-access-rule",
					jsonMap{"uid": aRule.UID, "layer": "network"})
			}
		} else if r.IsInsert() {
			// Add rules from Netspoc
			// - add before exiting rule on device or
			// - add at bottom of ruleset.
			var pos any
			if r.LowA < len(a.Rules) {
				pos = jsonMap{"above": a.Rules[r.LowA].UID}
			} else {
				pos = "bottom"
			}
			for _, bRule := range b.Rules[r.LowB:r.HighB] {
				setInstallOn(bRule)
				bRule.Position = pos
				// Original UID must not be applied to device.
				// This occurs if original config was read from file.
				bRule.UID = ""
				addChange("add-access-rule", bRule)
			}
		} else if r.IsEqual() {
			// Change attributes of rules remaining at same position.
			for i, aRule := range a.Rules[r.LowA:r.HighA] {
				bRule := b.Rules[r.LowB:r.HighB][i]
				aRule.needed = true
				chg1 := make(jsonMap)
				chg2 := make(jsonMap)
				if aRule.Comments != bRule.Comments {
					chg1["comments"] = bRule.Comments
				}
				if aRule.Action != bRule.Action {
					chg1["action"] = bRule.Action
				}
				if aRule.SourceNegate != bRule.SourceNegate {
					chg1["source-negate"] = bRule.SourceNegate
				}
				if aRule.DestinationNegate != bRule.DestinationNegate {
					chg1["destination-negate"] = bRule.DestinationNegate
				}
				if aRule.ServiceNegate != bRule.ServiceNegate {
					chg1["service-negate"] = bRule.ServiceNegate
				}
				if aRule.Disabled != bRule.Disabled {
					chg1["enabled"] = !bRule.Disabled
				}
				compareObjects("source", chg1, chg2, aRule.Source, bRule.Source)
				compareObjects("destination", chg1, chg2,
					aRule.Destination, bRule.Destination)
				compareObjects("service", chg1, chg2, aRule.Service, bRule.Service)
				compareObjects("install-on", chg1, chg2,
					aRule.InstallOn, bRule.InstallOn)
				add := func(chg jsonMap) {
					if len(chg) > 0 {
						setInstallOn(bRule)
						chg["uid"] = aRule.UID
						chg["layer"] = "network"
						addChange("set-access-rule", chg)
					}
				}
				add(chg1)
				add(chg2)
			}
		}
	}
	willDelete := func(obj object) bool {
		return !obj.getNeeded() && !obj.getReadOnly() &&
			(obj.getDeletable() ||
				strings.Contains(strings.ToLower(obj.getComments()), "netspoc"))
	}
	// Mark members of to be deleted group.
	// Delete group, but only after all references have been deleted.
	var markAndDelete func(*chkpGroup)
	markAndDelete = func(group *chkpGroup) {
		if willDelete(group) {
			for _, name := range group.Members {
				if obj, found := lookup(string(name)); found {
					if !obj.getDeletable() {
						obj.setDeletable()
						if g2, ok := obj.(*chkpGroup); ok {
							markAndDelete(g2)
						}
					}
				}
			}
			addChange("delete-group", jsonMap{"uid": group.UID})
		}
	}
	for _, g := range a.Groups {
		markAndDelete(g)
	}
	// Remove unneeded objects from device.
	for _, aObj := range aObjects {
		if _, ok := aObj.(*chkpGroup); !ok && willDelete(aObj) {
			addChange("delete-"+aObj.getAPIObject(),
				jsonMap{"uid": aObj.getUID()})
		}
	}
	return changes, slices.Sorted(maps.Keys(installMap))
}

func getObjList(cf *chkpConfig) []object {
	var result []object
	for _, o := range cf.Networks {
		result = append(result, o)
	}
	for _, o := range cf.Hosts {
		result = append(result, o)
	}
	for _, o := range cf.Groups {
		result = append(result, o)
	}
	for _, o := range cf.TCP {
		result = append(result, o)
	}
	for _, o := range cf.UDP {
		result = append(result, o)
	}
	for _, o := range cf.ICMP {
		result = append(result, o)
	}
	for _, o := range cf.ICMP6 {
		result = append(result, o)
	}
	for _, o := range cf.SvOther {
		result = append(result, o)
	}
	return result
}

// Copied from go/src/net/http/internal/ascii/print.go

// equalFold is [strings.EqualFold], ASCII only. It reports whether s and t
// are equal, ASCII-case-insensitively.
func equalFold(s, t string) bool {
	if len(s) != len(t) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if lower(s[i]) != lower(t[i]) {
			return false
		}
	}
	return true
}

// lower returns the ASCII lowercase version of b.
func lower(b byte) byte {
	if 'A' <= b && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

// tolower converts uppercase ASCII characters in s to lowercase.
func toLower(s string) string {
	l := make([]rune, 0, len(s))
	for _, r := range s {
		if 'A' <= r && r <= 'Z' {
			r += ('a' - 'A')
		}
		l = append(l, r)
	}
	return string(l)
}
