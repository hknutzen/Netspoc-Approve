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
	markDeletable := func(n string) {
		if aObj, found := aObjMap[n]; found {
			aObj.setDeletable()
		}
	}
	// Compare objects referenced by src/dst of rule or by members of group.
	compareObjects := func(attr string, chg1, chg2 jsonMap, aL, bL []chkpName) {
		getNameMap := func(l []chkpName) map[chkpName]bool {
			m := make(map[chkpName]bool)
			for _, n := range l {
				m[n] = true
			}
			return m
		}
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
		if add != nil {
			chg1[attr] = map[string][]chkpName{"add": add}
			// It is currently not allowed to both, add and remove in one change.
			if remove != nil {
				chg2[attr] = map[string][]chkpName{"remove": remove}
			}
		} else if remove != nil {
			chg1[attr] = map[string][]chkpName{"remove": remove}
		}
	}

	for _, bObj := range getObjList(b) {
		name := bObj.getName()
		jb, _ := json.Marshal(bObj)
		if aObj, found := aObjMap[string(name)]; found {
			// Object is found on device and marked as needed.
			aObj.setNeeded()
			// Compare members of groups or attributes of other objects.
			switch aReal := aObj.(type) {
			case *chkpGroup:
				bReal := bObj.(*chkpGroup)
				chg1 := make(jsonMap)
				chg2 := make(jsonMap)
				compareObjects("members", chg1, chg2, aReal.Members, bReal.Members)
				if len(chg1) > 0 {
					chg1["name"] = name
					addChange("set-group", chg1)
				}
				if len(chg2) > 0 {
					chg2["name"] = name
					addChange("set-group", chg2)
				}
			default:
				ja, _ := json.Marshal(aObj)
				if d := cmp.Diff(ja, jb); d != "" {
					errlog.Abort("Values of %q differ between device and Netspoc.\n"+
						"Please modify manually.\n%s",
						name, d)
				}
			}
		} else {
			// Add definition of new object to device.
			addChange("add-"+bObj.getAPIObject(), bObj)
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
				chg1 := make(jsonMap)
				chg2 := make(jsonMap)
				if aRule.Comments != bRule.Comments {
					chg1["comments"] = bRule.Comments
				}
				if aRule.Action != bRule.Action {
					chg1["action"] = bRule.Action
				}
				compareObjects("source", chg1, chg2, aRule.Source, bRule.Source)
				compareObjects("destination", chg1, chg2,
					aRule.Destination, bRule.Destination)
				compareObjects("service", chg1, chg2, aRule.Service, bRule.Service)
				add := func(chg jsonMap) {
					if len(chg) > 0 {
						setInstallOn(bRule)
						chg["name"] = bRule.Name
						addChange("set-access-rule", chg)
					}
				}
				add(chg1)
				add(chg2)
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
	for _, o := range cf.SvOther {
		result = append(result, o)
	}
	return result
}