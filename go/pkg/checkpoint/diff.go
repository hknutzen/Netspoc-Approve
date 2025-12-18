package checkpoint

import (
	"encoding/json"
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
	aRule := ab.aRules[ai]
	bRule := ab.bRules[bi]
	// Checkpoint compares ASCII-case-insensitively.
	return equalFold(aRule.Name, bRule.Name)
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
	var installTargets []string
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
	hasChange := func(aL []chkpName) bool {
		for _, name := range aL {
			if aObj, found := lookup(string(name)); found && aObj.getChanged() {
				return true
			}
		}
		return false
	}
	// Compare objects defined from Netspoc with objects from device
	// and mark changed objects.
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
				add := func(chg jsonMap) {
					if len(chg) > 0 {
						chg["uid"] = aGrp.UID
						addChange("set-group", chg)
						aGrp.changed = true
					}
				}
				add(chg1)
				add(chg2)
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
					aObj.setChanged()
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
	// Mark groups as changed, that reference changed objects.
	var markChanged func(*chkpGroup)
	markChanged = func(group *chkpGroup) {
		for _, name := range group.Members {
			if obj, found := lookup(string(name)); found {
				if g2, ok := obj.(*chkpGroup); ok {
					markChanged(g2)
				}
				if obj.getChanged() {
					group.changed = true
					break
				}
			}
		}
	}
	for _, g := range a.Groups {
		markChanged(g)
	}
	// Compare rules.
	for target, bRules := range b.TargetRules {
		layer := a.TargetPolicy[target].Layer
		aRules := a.TargetRules[target]
		needInstall := false
		ab := &rulesPair{
			aRules: aRules,
			bRules: bRules,
		}
		diff := myers.Diff(nil, ab).Ranges
		// Fix result of myers.Diff.
		// Insert position is set to 0,0 if edit script is a full replace.
		// But we need to insert behind deleted rules.
		if len(diff) == 2 {
			if diff[0].IsDelete() && diff[0].Len() == len(aRules) &&
				diff[1].IsInsert() && diff[1].Len() == len(bRules) {
				diff[1].LowA = len(aRules)
				diff[1].HighA = len(aRules)
				// Deleting all rules before inserting new rules
				// would result in this error:
				//  Action cannot be executed on object:
				//  Cleanup rule due to: Layer ('Network') has only one rule.
				// Hence
				// - delete rules up to the last but one rule,
				// - then insert new rules,
				// - then delete last rule.
				if len(aRules) == 1 {
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
				needInstall = true
				// Remove unneeded rules from device.
				for _, aRule := range aRules[r.LowA:r.HighA] {
					setDeletable := func(l []chkpName) {
						for _, n := range l {
							markDeletable(n)
						}
					}
					setDeletable(aRule.Source)
					setDeletable(aRule.Destination)
					setDeletable(aRule.Service)
					addChange("delete-access-rule",
						jsonMap{"uid": aRule.UID, "layer": layer})
				}
			} else if r.IsInsert() {
				needInstall = true
				// Add rules from Netspoc
				// - add before exiting rule on device or
				// - add at bottom of ruleset.
				var pos any
				if r.LowA < len(aRules) {
					pos = jsonMap{"above": aRules[r.LowA].UID}
				} else {
					pos = "bottom"
				}
				for _, bRule := range bRules[r.LowB:r.HighB] {
					bRule.Layer = layer
					bRule.Position = pos
					// Original UID must not be applied to device.
					// This occurs if original config was read from file.
					bRule.UID = ""
					addChange("add-access-rule", bRule)
				}
			} else if r.IsEqual() {
				// Change attributes of rules remaining at same position.
				for i, aRule := range aRules[r.LowA:r.HighA] {
					bRule := bRules[r.LowB:r.HighB][i]
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
					if t1, t2 := aRule.Track, bRule.Track; t1 == nil || t2 == nil {
						if t1 != t2 {
							chg1["track"] = bRule.Track
						}
					} else if *t1 != *t2 {
						chg1["track"] = bRule.Track
					}
					compareObjects("source", chg1, chg2, aRule.Source, bRule.Source)
					compareObjects("destination", chg1, chg2,
						aRule.Destination, bRule.Destination)
					compareObjects("service", chg1, chg2,
						aRule.Service, bRule.Service)
					add := func(chg jsonMap) {
						if len(chg) > 0 {
							needInstall = true
							chg["uid"] = aRule.UID
							chg["layer"] = layer
							addChange("set-access-rule", chg)
						}
					}
					if len(chg1) != 0 || len(chg2) != 0 {
						add(chg1)
						add(chg2)
					} else if !needInstall &&
						(hasChange(aRule.Source) ||
							hasChange(aRule.Destination) ||
							hasChange(aRule.Service)) {
						needInstall = true
					}
				}
			}
		}
		if needInstall {
			installTargets = append(installTargets, target)
		}
	}
	willDelete := func(obj object) bool {
		return !obj.getNeeded() && !obj.getReadOnly() &&
			(obj.getDeletable() ||
				strings.Contains(strings.ToLower(obj.getComments()), "netspoc"))
	}
	// Mark members of to be deleted group.
	// Delete group, but only after all references have been deleted.
	isDeleted := make(map[*chkpGroup]bool)
	var markAndDelete func(*chkpGroup)
	markAndDelete = func(group *chkpGroup) {
		if willDelete(group) && !isDeleted[group] {
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
			isDeleted[group] = true
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
	return changes, installTargets
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

func cmpFold(a, b chkpName) int {
	return strings.Compare(toLower(string(a)), toLower(string(b)))
}
