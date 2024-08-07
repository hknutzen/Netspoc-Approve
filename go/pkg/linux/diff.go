package linux

import (
	"cmp"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/hknutzen/Netspoc-Approve/go/pkg/device"
	"github.com/hknutzen/Netspoc-Approve/go/pkg/sorted"
)

func diffConfig(a, b *config) change {
	return change{
		newConfig: b,
		routes:    diffRoutes(a.routes, b.routes),
		iptables:  diffIPTables(a.iptables, b.iptables),
	}
}

// ip route add 10.1.1.1 via 10.9.1.1
// ip route add 10.1.1.0/28 via 10.9.1.2
func diffRoutes(a, b []string) []string {
	type dst struct {
		ip     string
		prefix int
	}
	type route struct {
		dst
		orig string
	}
	parse := func(l []string) []route {
		var result []route
		for _, line := range l {
			if rest, found := strings.CutPrefix(line, "ip route add "); found {
				words := strings.Fields(rest)
				if len(words) >= 3 && words[1] == "via" {
					ip := words[0]
					prefix := 32
					if _, prefix2, found := strings.Cut(ip, "/"); found {
						prefix, _ = strconv.Atoi(prefix2)
					} else if ip == "default" {
						prefix = 0
					}
					result = append(result,
						route{dst: dst{ip: ip, prefix: prefix}, orig: line})
					continue
				}
			}
			device.Abort("Invalid route: %s", line)
		}
		return result
	}
	printAdd := func(r route) string {
		return r.orig
	}
	printDel := func(r route) string {
		cmd := r.orig
		return strings.Replace(cmd, "ip route add ", "ip route del ", 1)
	}
	aRoutes := parse(a)
	bRoutes := parse(b)
	// Add routes with long mask first. If we switch the default
	// route, this ensures, that we have the new routes available
	// before deleting the old default route.
	slices.SortFunc(bRoutes, func(r1, r2 route) int {
		return cmp.Compare(r2.prefix, r1.prefix)
	})
	aMap := make(map[route]bool)
	aDstMap := make(map[dst]route)
	for _, r := range aRoutes {
		aMap[r] = true
		aDstMap[r.dst] = r
	}
	var result []string
	for _, r := range bRoutes {
		if aMap[r] {
			delete(aMap, r)
			continue
		}
		cmd := printAdd(r)
		// Prevent two routes to identical destination to be both active.
		// Remove and add routes in one transaction.
		if r2, found := aDstMap[r.dst]; found {
			if aMap[r2] {
				cmd = printDel(r2) + "\n" + cmd
				delete(aMap, r2)
			}
		}
		result = append(result, cmd)
	}
	for _, r := range aRoutes {
		if aMap[r] {
			result = append(result, printDel(r))
		}
	}
	return result
}

func diffIPTables(a, b tables) string {
	if extra := checkExtra(a, b); extra != "" {
		return fmt.Sprintf("iptables differs at [tables: %s]", extra)
	}
	for _, tName := range sorted.Keys(a) {
		aChains := a[tName]
		bChains := b[tName]
		if extra := checkExtra(aChains, bChains); extra != "" {
			return fmt.Sprintf("iptables differs at %s: [chains: %s]",
				tName, extra)
		}
		for _, cName := range sorted.Keys(aChains) {
			aChain := aChains[cName]
			bChain := bChains[cName]
			if aChain.policy != bChain.policy {
				return fmt.Sprintf(
					"iptables differs at %s:%s:POLICY:[%s<->%s]",
					tName, cName, aChain.policy, bChain.policy)
			}
			aRules := aChain.rules
			bRules := bChain.rules
			if len(aRules) != len(bRules) {
				return fmt.Sprintf(
					"iptables differs at %s:%s:RULES:[size: %d<->%d]",
					tName, cName, len(aRules), len(bRules))
			}
			for i, aRule := range aRules {
				bRule := bRules[i]
				aPairs := aRule.pairs
				bPairs := bRule.pairs
				if extra := checkExtra(aPairs, bPairs); extra != "" {
					return fmt.Sprintf(
						"iptables differs at %s:%s:RULES:%d:[options: %s]",
						tName, cName, i, extra)
				}
				for k, v := range aPairs {
					if v2 := bPairs[k]; v2 != v {
						return fmt.Sprintf(
							"iptables differs at %s:%s:RULES:%d:%s:[%s<->%s]",
							tName, cName, i, k, v, v2)
					}
				}
			}
		}
	}
	return ""
}

func checkExtra[T any](a, b map[string]T) string {
	getExtra := func(a, b map[string]T) string {
		var extra []string
		for _, name := range sorted.Keys(a) {
			if _, found := b[name]; !found {
				extra = append(extra, name)
			}
		}
		return strings.Join(extra, ",")
	}
	aExtra := getExtra(a, b)
	bExtra := getExtra(b, a)
	if aExtra != "" || bExtra != "" {
		return fmt.Sprintf("%s<->%s", aExtra, bExtra)
	}
	return ""
}
