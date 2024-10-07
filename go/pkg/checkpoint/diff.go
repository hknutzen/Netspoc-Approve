package checkpoint

import (
	"encoding/json"
	"maps"
	"slices"
	"strings"

	"github.com/google/go-cmp/cmp"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/errlog"
	"github.com/pkg/diff/myers"
)

type rulesPair struct {
	aRules, bRules []*chkpRule
}

func (ab *rulesPair) LenA() int { return len(ab.aRules) }
func (ab *rulesPair) LenB() int { return len(ab.bRules) }

func (ab *rulesPair) Equal(ai, bi int) bool {
	return ab.aRules[ai].Name == ab.bRules[bi].Name &&
		slices.Equal(ab.aRules[ai].InstallOn, ab.bRules[bi].InstallOn)
}

func diffConfig(a, b *chkpConfig) ([]change, []string) {
	var changes []change
	addChange := func(e string, d interface{}) {
		changes = append(changes, change{endpoint: e, postData: d})
	}
	installMap := make(map[string]bool)
	setInstallOn := func(r *chkpRule) {
		for _, name := range r.InstallOn {
			installMap[string(name)] = true
		}
	}
	aObjects := getObjList(a)
	aObjMap := getObjMap(aObjects)
	for _, bObj := range getObjList(b) {
		name := bObj.getName()
		jb, _ := json.Marshal(bObj)
		if aObj, found := aObjMap[string(name)]; found {
			// Object is found on device and marked as needed.
			aObj.setNeeded()
			ja, _ := json.Marshal(aObj)
			if d := cmp.Diff(ja, jb); d != "" {
				errlog.Abort("Values of %q differ between device and Netspoc.\n"+
					"Please modify manually.\n%s",
					name, d)
			}
		} else {
			// Add definition of new object to device.
			addChange("add-"+bObj.getAPIObject(), bObj)
		}
	}
	markDeletable := func(n string) {
		if aObj, found := aObjMap[n]; found {
			aObj.setDeletable()
		}
	}
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
		}
	}
	for _, r := range diff {
		if r.IsDelete() {
			// Remove unneeded rules from device.
			for _, aRule := range a.Rules[r.LowA:r.HighA] {
				setInstallOn(aRule)
				setDeletable := func(l []chkpName) {
					for _, n := range l {
						markDeletable(string(n))
					}
				}
				setDeletable(aRule.Source)
				setDeletable(aRule.Destination)
				setDeletable(aRule.Service)
				addChange("delete-access-rule",
					jsonMap{"name": aRule.Name, "layer": "network"})
			}
		} else if r.IsInsert() {
			// Add rules from Netspoc
			// - add before exiting rule on device or
			// - add at bottom of ruleset.
			var pos interface{}
			if r.LowA < len(a.Rules) {
				pos = jsonMap{"above": a.Rules[r.LowA].Name}
			} else {
				pos = "bottom"
			}
			for _, bRule := range b.Rules[r.LowB:r.HighB] {
				setInstallOn(bRule)
				bRule.Position = pos
				addChange("add-access-rule", bRule)
			}
		} else if r.IsEqual() {
			// Change attributes of rules remaining at same position.
			for i, aRule := range a.Rules[r.LowA:r.HighA] {
				bRule := b.Rules[r.LowB:r.HighB][i]
				aRule.needed = true
				changed := make(jsonMap)
				getNameMap := func(l []chkpName) map[chkpName]bool {
					m := make(map[chkpName]bool)
					for _, n := range l {
						m[n] = true
					}
					return m
				}
				compareObjects := func(attr string, aL, bL []chkpName) {
					aMap := getNameMap(aL)
					bMap := getNameMap(bL)
					var add []chkpName
					var remove []chkpName
					for _, aName := range aL {
						if !bMap[aName] {
							remove = append(remove, aName)
							markDeletable(string(aName))
						}
					}
					for _, bName := range bL {
						if !aMap[bName] {
							add = append(add, bName)
						}
					}
					if add != nil && remove != nil {
						// Replace all if elements are both added and removed.
						changed[attr] = bL
					} else if add != nil {
						changed[attr] = map[string][]chkpName{"add": add}
					} else if remove != nil {
						changed[attr] = map[string][]chkpName{"remove": remove}
					}
				}
				if aRule.Comments != bRule.Comments {
					changed["comments"] = bRule.Comments
				}
				if aRule.Action != bRule.Action {
					changed["action"] = bRule.Action
				}
				compareObjects("source", aRule.Source, bRule.Source)
				compareObjects("destination", aRule.Destination, bRule.Destination)
				compareObjects("service", aRule.Service, bRule.Service)
				if len(changed) > 0 {
					setInstallOn(bRule)
					changed["name"] = bRule.Name
					addChange("set-access-rule", changed)
				}
			}
		}
	}
	// Remove unneeded objects from device.
	for _, aObj := range aObjects {
		if !aObj.getNeeded() && !aObj.getReadOnly() &&
			(aObj.getDeletable() ||
				strings.Contains(strings.ToLower(aObj.getComments()), "netspoc")) {
			addChange("delete-"+aObj.getAPIObject(),
				jsonMap{"name": aObj.getName()})
		}
	}
	return changes, slices.Sorted(maps.Keys(installMap))
}

func getObjMap(l []object) map[string]object {
	m := make(map[string]object)
	for _, o := range l {
		m[o.getName()] = o
	}
	return m
}

func getObjList(cf *chkpConfig) []object {
	var result []object
	for _, o := range cf.Networks {
		result = append(result, o)
	}
	for _, o := range cf.Hosts {
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
