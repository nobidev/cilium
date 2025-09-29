// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package reconcilerv2

import (
	"net/netip"
	"slices"

	"github.com/cilium/cilium/enterprise/pkg/rib"
	"github.com/cilium/cilium/pkg/container/bitlpm"
)

func ribOwnerName(instanceName string) string {
	return "bgp-" + instanceName
}

func reconcileRIB(r *rib.RIB, desired, current map[uint32]*bitlpm.CIDRTrie[*rib.Route]) {
	toUpsert, toDelete := calculateRouteDiffs(desired, current)

	for vrfID, routes := range toUpsert {
		routes.ForEach(func(_ netip.Prefix, route *rib.Route) bool {
			r.UpsertRoute(vrfID, *route)
			return true
		})
	}

	for vrfID, routes := range toDelete {
		routes.ForEach(func(_ netip.Prefix, route *rib.Route) bool {
			r.DeleteRoute(vrfID, *route)
			return true
		})
	}
}

func rtMatches(pathRTs []string, vrfRTs []string) bool {
	for _, pathRT := range pathRTs {
		if slices.Contains(vrfRTs, pathRT) {
			return true
		}
	}
	return false
}

func calculateRouteDiffs(desired, current map[uint32]*bitlpm.CIDRTrie[*rib.Route]) (
	map[uint32]*bitlpm.CIDRTrie[*rib.Route],
	map[uint32]*bitlpm.CIDRTrie[*rib.Route],
) {
	toUpsert := map[uint32]*bitlpm.CIDRTrie[*rib.Route]{}
	toDelete := map[uint32]*bitlpm.CIDRTrie[*rib.Route]{}

	for vrfID, desiredRoutes := range desired {
		if currentRoutes, found := current[vrfID]; found {
			trie := bitlpm.NewCIDRTrie[*rib.Route]()
			desiredRoutes.ForEach(func(prefix netip.Prefix, desiredRoute *rib.Route) bool {
				currentRoute, found := currentRoutes.ExactLookup(prefix)
				if !found || !desiredRoute.Equal(currentRoute) {
					trie.Upsert(prefix, desiredRoute)
				}
				return true
			})
			if trie.Len() > 0 {
				toUpsert[vrfID] = trie
			}
		} else {
			toUpsert[vrfID] = desiredRoutes
		}
	}

	for vrfID, currentRoutes := range current {
		if desiredRoutes, found := desired[vrfID]; found {
			trie := bitlpm.NewCIDRTrie[*rib.Route]()
			currentRoutes.ForEach(func(prefix netip.Prefix, route *rib.Route) bool {
				if _, found := desiredRoutes.ExactLookup(prefix); !found {
					trie.Upsert(prefix, route)
				}
				return true
			})
			if trie.Len() > 0 {
				toDelete[vrfID] = trie
			}
		} else {
			toDelete[vrfID] = currentRoutes
		}
	}

	return toUpsert, toDelete
}
