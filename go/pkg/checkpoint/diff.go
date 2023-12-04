package checkpoint

import (
	"encoding/json"
	"strings"

	"github.com/google/go-cmp/cmp"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/device"
	"github.com/pkg/diff/myers"
	"golang.org/x/exp/slices"
)

type jsonMap map[string]interface{}

type rulesPair struct {
	aRules, bRules []*chkpRule
}

func (ab *rulesPair) LenA() int { return len(ab.aRules) }
func (ab *rulesPair) LenB() int { return len(ab.bRules) }

func (ab *rulesPair) Equal(ai, bi int) bool {
	return ab.aRules[ai].Name == ab.bRules[bi].Name
}

func diffConfig(a, b *chkpConfig) []change {
	var changes []change
	aObjects := getObjList(a)
	aObjMap := getObjMap(aObjects)
	for _, bObj := range getObjList(b) {
		name := bObj.getName()
		jb, _ := json.Marshal(bObj)
		if aObj, found := aObjMap[name]; found {
			// Object is found on device and marked as needed.
			aObj.setNeeded()
			ja, _ := json.Marshal(aObj)
			if d := cmp.Diff(ja, jb); d != "" {
				device.Abort("Values of %q differ between device and Netspoc.\n"+
					"Please modify manually.\n%s",
					name, d)
			}
		} else {
			// Add definition of new object to device.
			changes = append(changes,
				change{
					endpoint: "add-" + bObj.getAPIObject(),
					postData: jb,
				})
		}
	}
	markDeletable := func(n chkpName) {
		if aObj, found := aObjMap[n]; found {
			aObj.setDeletable()
		}
	}
	ab := &rulesPair{
		aRules: a.Rules,
		bRules: b.Rules,
	}
	diff := myers.Diff(nil, ab).Ranges
	for _, r := range diff {
		if r.IsDelete() {
			// Remove unneeded rules from device.
			for _, aRule := range a.Rules[r.LowA:r.HighA] {
				setDeletable := func(l []chkpName) {
					for _, n := range l {
						markDeletable(n)
					}
				}
				setDeletable(aRule.Source)
				setDeletable(aRule.Destination)
				setDeletable(aRule.Service)
				data, _ := json.Marshal(
					chkpRuleID{Name: aRule.Name, Layer: "network"})
				changes = append(changes,
					change{
						endpoint: "delete-access-rule",
						postData: data,
					})
			}
		} else if r.IsInsert() {
			// Add rules from Netspoc
			// - add before exiting rule on device or
			// - add at bottom of ruleset.
			var pos interface{}
			if r.LowA < len(a.Rules) {
				pos = jsonMap{"before": a.Rules[r.LowA].Name}
			} else {
				pos = "bottom"
			}
			for _, bRule := range b.Rules[r.LowB:r.HighB] {
				bRule.Position = pos
				data, _ := json.Marshal(bRule)
				changes = append(changes,
					change{
						endpoint: "add-access-rule",
						postData: data,
					})
			}
		} else if r.IsEqual() {
			// Change attributes of rule remaining at same position.
			for i, aRule := range a.Rules[r.LowA:r.HighA] {
				bRule := b.Rules[r.LowB:r.HighB][i]
				aRule.needed = true
				changed := make(jsonMap)
				compareObjects := func(attr string, aL, bL []chkpName) {
					aMap := getNameMap(aL)
					bMap := getNameMap(bL)
					var add []chkpName
					var remove []chkpName
					for _, aName := range aL {
						if !bMap[aName] {
							remove = append(remove, aName)
							markDeletable(aName)
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
				if !slices.Equal(aRule.InstallOn, bRule.InstallOn) {
					changed["install-on"] = bRule.InstallOn
				}
				if len(changed) > 0 {
					changed["name"] = bRule.Name
					changed["layer"] = bRule.Layer
					data, _ := json.Marshal(changed)
					changes = append(changes,
						change{
							endpoint: "set-access-rule",
							postData: data,
						})
				}
			}
		}
	}
	// Remove unneeded objects from device.
	for _, aObj := range aObjects {
		if !aObj.getNeeded() && !aObj.getReadOnly() &&
			(aObj.getDeletable() ||
				strings.Contains(strings.ToLower(aObj.getComments()), "netspoc")) {
			changes = append(changes,
				change{
					endpoint: "delete-" + aObj.getAPIObject(),
					postData: []byte(`{"name": "` + aObj.getName() + `"}`),
				})
		}
	}
	return changes
}

func getObjMap(l []object) map[chkpName]object {
	m := make(map[chkpName]object)
	for _, o := range l {
		m[o.getName()] = o
	}
	return m
}

func getNameMap(l []chkpName) map[chkpName]bool {
	m := make(map[chkpName]bool)
	for _, n := range l {
		m[n] = true
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
