package checkpoint

import (
	"cmp"
	"maps"
	"slices"

	"github.com/pkg/diff/myers"
)

type routesPair struct {
	aRoutes, bRoutes []*chkpRoute
}

func (ab *routesPair) LenA() int { return len(ab.aRoutes) }
func (ab *routesPair) LenB() int { return len(ab.bRoutes) }

func (ab *routesPair) Equal(ai, bi int) bool {
	return ab.aRoutes[ai].Address == ab.bRoutes[bi].Address &&
		ab.aRoutes[ai].MaskLength == ab.bRoutes[bi].MaskLength
}

func sortRoutes(l []*chkpRoute) {
	slices.SortFunc(l, func(a, b *chkpRoute) int {
		return cmp.Or(cmp.Compare(a.Address, b.Address),
			cmp.Compare(a.MaskLength, b.MaskLength))
	})
}

func diffRoutes(a, b *chkpConfig) []change {
	var changes []change
	addChange := func(e string, d interface{}) {
		changes = append(changes, change{endpoint: e, postData: d})
	}
	for _, gw := range slices.Sorted(maps.Keys(b.GatewayRoutes)) {
		aRoutes := a.GatewayRoutes[gw]
		bRoutes := b.GatewayRoutes[gw]
		sortRoutes(aRoutes)
		sortRoutes(bRoutes)
		ab := &routesPair{
			aRoutes: aRoutes,
			bRoutes: bRoutes,
		}
		target := gw
		// Workaroud for bug in Checkpoint version R81.20
		// which only accepts IP as target.
		if ip := a.GatewayIP[gw]; ip != "" {
			target = ip
		}

		diff := myers.Diff(nil, ab).Ranges
		for _, r := range diff {
			if r.IsDelete() {
				// Remove route from device.
				for _, aRoute := range aRoutes[r.LowA:r.HighA] {
					addChange("gaia_api/v1.7/delete-static-route", jsonMap{
						"target":      target,
						"address":     aRoute.Address,
						"mask-length": aRoute.MaskLength,
					})
				}
			} else if r.IsInsert() {
				// Add route from Netspoc.
				for _, bRoute := range bRoutes[r.LowB:r.HighB] {
					addChange("gaia_api/v1.7/set-static-route", jsonMap{
						"target":      target,
						"address":     bRoute.Address,
						"mask-length": bRoute.MaskLength,
						"type":        bRoute.Type,
						"next-hop":    bRoute.NextHop,
					})
				}
			} else if r.IsEqual() {
				// Change type or hops of route.
				for i, aRoute := range aRoutes[r.LowA:r.HighA] {
					bRoute := bRoutes[r.LowB:r.HighB][i]
					changed := make(jsonMap)
					if aRoute.Type != bRoute.Type {
						changed["type"] = bRoute.Type
					}
					if !slices.Equal(aRoute.NextHop, bRoute.NextHop) {
						changed["next-hop"] = bRoute.NextHop
					}
					if len(changed) > 0 {
						changed["target"] = target
						changed["address"] = bRoute.Address
						changed["mask-length"] = bRoute.MaskLength
						addChange("gaia_api/v1.7/set-static-route", changed)
					}
				}
			}
		}
	}
	return changes
}
