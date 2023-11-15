package asa

import (
	"fmt"
	"sort"
	"strings"

	"github.com/hknutzen/Netspoc-Approve/go/pkg/device"
)

func (cf *ASAConfig) CheckRulesFromRaw() error { return nil }

// Check that non anchor commands from raw file are referenced by some
// anchor and are referenced only once.
var isReferenced map[*cmd]bool

func (a *ASAConfig) MergeSpoc(d device.DeviceConfig) device.DeviceConfig {
	b := d.(*ASAConfig)
	lookup := a.lookup
	if lookup == nil {
		lookup = make(objLookup)
		a.lookup = lookup
	}
	for prefix := range b.lookup {
		if lookup[prefix] == nil {
			lookup[prefix] = make(map[string][]*cmd)
		}
	}
	isReferenced = make(map[*cmd]bool)
	for prefix, bMap := range b.lookup {
		aMap := lookup[prefix]
		for name, bl := range bMap {
			bCmd := bl[0]
			// Select anchor commands.
			// Collect non anchor commands.
			switch prefix {
			case "tunnel-group-map", "webvpn":
				device.Abort("Command '%s' not supported in raw file", prefix)
			case "access-group":
				if b.isRaw {
					// Duplicate lines from raw are a leftover from previous version,
					// where access-group is given in prepend and append part.
					m := make(map[string]bool)
					j := 0
					for _, c := range bl {
						if !m[c.parsed] {
							bl[j] = c
							j++
							m[c.parsed] = true
						}
					}
					bl = bl[:j]
					bMap[name] = bl
				}
			case "route", "ipv6 route", "username", "crypto map interface":
			case "group-policy", "tunnel-group":
				if bCmd.fixedName {
					break
				}
				if _, found := defaultObjects[[2]string{prefix, name}]; found {
					break
				}
				fallthrough
			default:
				if _, found := isReferenced[bCmd]; !found {
					isReferenced[bCmd] = false
				}
				continue
			}
			al := aMap[name]
			ab := &cmdsPair{
				a:     a,
				b:     b,
				aCmds: al,
				bCmds: bl,
			}
			mergeCmds(ab, name, prefix)
		}
	}
	if b.isRaw {
		var warnings []string
		for c, used := range isReferenced {
			if !used {
				warnings = append(warnings,
					fmt.Sprintf("Ignoring unused '%s %s' in raw",
						c.typ.prefix, c.name))
			}
		}
		sort.Strings(warnings)
		for _, w := range warnings {
			device.Warning(w)
		}
	}
	return a
}

func mergeCmds(ab *cmdsPair, name, prefix string) {
	switch prefix {
	case "crypto map":
		mergeCryptoMap(ab, name, prefix)
		return
	case "crypto dynamic-map":
		mergeCryptoDynMap(ab, name, prefix)
		return
	case "access-list":
		mergeACLs(ab, name, prefix)
		return
	}
	al := ab.aCmds
	bl := ab.bCmds
	m := make(map[string]*cmd)
	for _, a := range al {
		m[a.parsed] = a
	}
	for _, b := range bl {
		if a, found := m[b.parsed]; found {
			mergeSubCmds(ab, a, b)
			mergeRefs(ab, a, b)
		} else {
			for _, bs := range b.sub {
				mergeRefs(ab, nil, bs)
			}
			mergeRefs(ab, nil, b)
			al = append(al, b)
		}
	}
	ab.a.lookup[prefix][name] = al
}

func mergeSubCmds(ab *cmdsPair, a, b *cmd) {
	m := make(map[string]*cmd)
	for _, as := range a.sub {
		m[as.parsed] = as
	}
	for _, bs := range b.sub {
		as := m[bs.parsed]
		mergeRefs(ab, as, bs)
		if as == nil {
			a.sub = append(a.sub, bs)
		}
	}
}

func mergeRefs(ab *cmdsPair, a, b *cmd) {
	for i, bName := range b.ref {
		prefix := b.typ.ref[i]
		bl := ab.b.lookup[prefix][bName]
		refCmd := bl[0]
		if refCmd.typ.simpleObject {
			isReferenced[refCmd] = true
			al := findSimpleObject(bl, ab.a)
			if al == nil {
				if _, found := ab.a.lookup[prefix][bName]; found && ab.b.isRaw {
					device.Abort("Name clash for '%s %s' from raw", prefix, bName)
				}
				ab.a.lookup[prefix][bName] = bl
				al = bl
			}
			objName := al[0].name
			if a != nil {
				a.ref[i] = objName
			} else {
				b.ref[i] = objName
			}
			continue
		}
		var al []*cmd = nil
		storeName := bName
		if a != nil {
			if isReferenced[refCmd] {
				device.Abort("Must reference '%s %s' only once in raw",
					prefix, bName)
			}
			storeName = a.ref[i]
			al = ab.a.lookup[prefix][storeName]
			for _, b := range bl {
				b.name = storeName
			}
		} else if _, found := ab.a.lookup[prefix][bName]; found && ab.b.isRaw {
			device.Abort("Name clash for '%s %s' from raw", prefix, bName)
		}
		isReferenced[refCmd] = true
		refPair := *ab
		refPair.aCmds = al
		refPair.bCmds = bl
		mergeCmds(&refPair, storeName, prefix)
	}
}

func mergeACLs(ab *cmdsPair, name, prefix string) {
	acl := ab.aCmds
	var prependACL, appendACL []*cmd
	for _, b := range ab.bCmds {
		if b.append {
			appendACL = append(appendACL, b)
		} else {
			prependACL = append(prependACL, b)
		}
		// Add, not merge referenced object-groups.
		mergeRefs(ab, nil, b)
	}
	if len(prependACL) > 0 {
		// By default prepend ACL lines, but append
		// terminating 'deny ip any6 any6' line when merging v4 and v6 config.
		i := len(prependACL) - 1
		if prependACL[i].parsed == "access-list $NAME extended deny ip any6 any6" {
			acl = append(acl, prependACL[i])
			prependACL = prependACL[:i]
		}
		acl = append(prependACL, acl...)
	}
	if len(appendACL) > 0 {
		// Add ACL lines marked with [APPEND] behind last permit line.
		// Find last permit line within entries from Netspoc.
		i := len(acl) - 1
		for ; i >= 0; i-- {
			if strings.Contains(acl[i].parsed, "$NAME extended permit") {
				i++
				break
			}
		}
		acl = append(acl[:i], append(appendACL, acl[i:]...)...)
	}
	// Store changed ACL.
	ab.a.lookup[prefix][name] = acl
}

func mergeCryptoMap(ab *cmdsPair, name, prefix string) {
	al := ab.aCmds
	matchCryptoMap(al, ab.bCmds, func(aSeqL, bSeqL []*cmd) {
		add := mergeCryptoCommon(ab, aSeqL, bSeqL)
		al = append(al, add...)
	})
	ab.a.lookup[prefix][name] = al
}

func mergeCryptoDynMap(ab *cmdsPair, name, prefix string) {
	add := mergeCryptoCommon(ab, ab.aCmds, ab.bCmds)
	ab.a.lookup[prefix][name] = append(ab.aCmds, add...)
}

// When comparing commands, take 5. and 6. word as key.
// Command from raw with equal key replaces command from Netspoc
// or extends ACL.
//
// crypto map $NAME $SEQ match address $access-list
// crypto map $NAME $SEQ ipsec-isakmp dynamic $crypto_dynamic-map
// crypto map $NAME $SEQ set ikev1 transform-set *
// crypto map $NAME $SEQ set ikev2 ipsec-proposal *
// crypto map $NAME $SEQ set nat-t-disable
// crypto map $NAME $SEQ set peer *
// crypto map $NAME $SEQ set pfs *
// crypto map $NAME $SEQ set reverse-route
// crypto map $NAME $SEQ set security-association lifetime *
// crypto map $NAME $SEQ set trustpoint *
//
// crypto dynamic-map $NAME $SEQ match address $access-list
// crypto dynamic-map $NAME $SEQ ipsec-isakmp dynamic *
// crypto dynamic-map $NAME $SEQ set ikev1 transform-set *
// crypto dynamic-map $NAME $SEQ set ikev2 ipsec-proposal *
// crypto dynamic-map $NAME $SEQ set nat-t-disable
// crypto dynamic-map $NAME $SEQ set peer *
// crypto dynamic-map $NAME $SEQ set pfs *
// crypto dynamic-map $NAME $SEQ set reverse-route
//	crypto dynamic-map $NAME $SEQ set security-association lifetime *

func mergeCryptoCommon(ab *cmdsPair, al, bl []*cmd) []*cmd {
	key := func(c *cmd) [2]string {
		tokens := strings.Split(c.parsed, " ")
		return [2]string(tokens[4:6])
	}
	var add []*cmd
	m := make(map[[2]string]*cmd)
	for _, aCmd := range al {
		m[key(aCmd)] = aCmd
	}
	for _, bCmd := range bl {
		if aCmd, found := m[key(bCmd)]; found {
			if aCmd.parsed == bCmd.parsed {
				mergeRefs(ab, aCmd, bCmd)
			} else {
				mergeRefs(ab, nil, bCmd)
				aCmd.parsed = bCmd.parsed
				aCmd.ref = bCmd.ref
			}
		} else {
			if len(al) > 0 {
				bCmd.seq = al[0].seq
			}
			add = append(add, bCmd)
			mergeRefs(ab, nil, bCmd)
		}
	}
	return add
}
