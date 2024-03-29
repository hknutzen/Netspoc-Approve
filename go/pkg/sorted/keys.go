package sorted

import (
	"golang.org/x/exp/constraints"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
)

func Keys[M ~map[K]V, K constraints.Ordered, V any](m M) []K {
	keys := maps.Keys(m)
	slices.Sort(keys)
	return keys
}
