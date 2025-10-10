//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package rib

import (
	"context"
	"iter"
	"net/netip"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/pkg/container/bitlpm"
)

type ops struct {
	rib   *RIB
	owner string
}

func NewOps(rib *RIB, owner string) reconciler.Operations[VRFRoute] {
	return &ops{
		rib:   rib,
		owner: owner,
	}
}

func (o *ops) Update(_ context.Context, _ statedb.ReadTxn, _ statedb.Revision, vr VRFRoute) error {
	if vr.Route.Owner != o.owner {
		// Ignore routes with a different owner
		return nil
	}
	o.rib.UpsertRoute(vr.VRFID, vr.Route)
	return nil
}

func (o *ops) Delete(_ context.Context, _ statedb.ReadTxn, _ statedb.Revision, vr VRFRoute) error {
	if vr.Route.Owner != o.owner {
		// Ignore routes with a different owner
		return nil
	}
	o.rib.DeleteRoute(vr.VRFID, vr.Route)
	return nil
}

func (o *ops) Prune(_ context.Context, _ statedb.ReadTxn, vrs iter.Seq2[VRFRoute, statedb.Revision]) error {
	currentRoutes := o.rib.ListRoutes(o.owner)

	desiredRoutes := map[uint32]*bitlpm.CIDRTrie[*Route]{}
	for vr := range vrs {
		if vr.Route.Owner != o.owner {
			// Ignore routes with a different owner
			continue
		}
		trie, found := desiredRoutes[vr.VRFID]
		if !found {
			trie = bitlpm.NewCIDRTrie[*Route]()
		}
		route := vr.Route
		trie.Upsert(vr.Route.Prefix, &route)
		desiredRoutes[vr.VRFID] = trie
	}

	toDelete := []VRFRoute{}
	for currentVRF, currentTrie := range currentRoutes {
		desiredTrie, found := desiredRoutes[currentVRF]
		if !found {
			// VRF no longer exists, delete all routes
			currentTrie.ForEach(func(p netip.Prefix, currentRoute *Route) bool {
				toDelete = append(toDelete, VRFRoute{
					VRFID: currentVRF,
					Route: *currentRoute,
				})
				return true
			})
			continue
		}
		currentTrie.ForEach(func(p netip.Prefix, currentRoute *Route) bool {
			desiredRoute, found := desiredTrie.ExactLookup(p)
			if !found || !desiredRoute.Equal(currentRoute) {
				toDelete = append(toDelete, VRFRoute{
					VRFID: currentVRF,
					Route: *currentRoute,
				})
			}
			return true
		})
	}

	for _, vr := range toDelete {
		o.rib.DeleteRoute(vr.VRFID, vr.Route)
	}

	return nil
}
