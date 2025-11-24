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
	"context"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"sort"

	"github.com/cilium/cilium/enterprise/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/bgp/manager/reconciler"
	ossTypes "github.com/cilium/cilium/pkg/bgp/types"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// ResourceRoutePolicyMap holds the route policies per resource.
type ResourceRoutePolicyMap map[resource.Key]RoutePolicyMap

// RoutePolicyMap holds routing policies configured by the policy reconciler keyed by policy name.
type RoutePolicyMap map[string]*types.ExtendedRoutePolicy

type ReconcileRoutePoliciesParams struct {
	Logger          *slog.Logger
	Ctx             context.Context
	Router          types.EnterpriseRouter
	DesiredPolicies RoutePolicyMap
	CurrentPolicies RoutePolicyMap
}

type resetDirections struct {
	in  bool
	out bool
}

func (rd *resetDirections) Update(dir ossTypes.RoutePolicyType) {
	switch dir {
	case ossTypes.RoutePolicyTypeExport:
		rd.out = true
	case ossTypes.RoutePolicyTypeImport:
		rd.in = true
	}
}

func (rd *resetDirections) SoftResetDirection() ossTypes.SoftResetDirection {
	if rd.in && rd.out {
		return ossTypes.SoftResetDirectionBoth
	} else if rd.in {
		return ossTypes.SoftResetDirectionIn
	} else if rd.out {
		return ossTypes.SoftResetDirectionOut
	}
	return ossTypes.SoftResetDirectionNone
}

// ReconcileRoutePolicies reconciles routing policies between the desired and the current state.
// It returns the updated routing policies and an error if the reconciliation fails.
func ReconcileRoutePolicies(rp *ReconcileRoutePoliciesParams) (RoutePolicyMap, error) {
	runningPolicies := make(RoutePolicyMap)
	maps.Copy(runningPolicies, rp.CurrentPolicies)

	var toAdd, toRemove, toUpdate []*types.ExtendedRoutePolicy

	// Tracks which peers have to be reset which direction because of policy change
	resetPeers := map[netip.Addr]*resetDirections{}
	allResetDirs := &resetDirections{}

	upsertResetPeers := func(p *types.ExtendedRoutePolicy) {
		addrs, allPeers := peerAddressesFromPolicy(p)
		if allPeers {
			allResetDirs.Update(p.Type)
			return
		}
		for _, peer := range addrs {
			dirs, found := resetPeers[peer]
			if !found {
				dirs = &resetDirections{}
			}
			dirs.Update(p.Type)
			resetPeers[peer] = dirs
		}
	}

	for _, desired := range rp.DesiredPolicies {
		if current, found := rp.CurrentPolicies[desired.Name]; found {
			if !current.DeepEqual(desired) {
				toUpdate = append(toUpdate, desired)

				// This can be optimized further by checking whether the update
				// is only for the list of neighbors. In that case, the peers in
				// the old policy would not need a reset. At this point, we
				// blindly reset all peers in the old policy for simplicity.
				upsertResetPeers(desired)
				upsertResetPeers(current)
			}
		} else {
			toAdd = append(toAdd, desired)
			upsertResetPeers(desired)
		}
	}
	for _, current := range rp.CurrentPolicies {
		if _, found := rp.DesiredPolicies[current.Name]; !found {
			toRemove = append(toRemove, current)
			upsertResetPeers(current)
		}
	}

	// add missing policies
	for _, p := range toAdd {
		rp.Logger.Debug(
			"Adding route policy",
			ossTypes.PolicyLogField, p.Name,
		)

		err := rp.Router.AddRoutePolicyExtended(rp.Ctx, types.RoutePolicyExtendedRequest{
			DefaultExportAction: ossTypes.RoutePolicyActionReject, // do not advertise routes by default
			Policy:              p,
		})
		if err != nil {
			return runningPolicies, err
		}

		runningPolicies[p.Name] = p
	}

	// update modified policies
	for _, p := range toUpdate {
		// As proper implementation of an update operation for complex policies would be quite involved,
		// we resort to recreating the policies that need an update here.
		rp.Logger.Debug(
			"Updating (re-creating) route policy",
			ossTypes.PolicyLogField, p.Name,
		)

		existing := rp.CurrentPolicies[p.Name]
		err := rp.Router.RemoveRoutePolicyExtended(rp.Ctx, types.RoutePolicyExtendedRequest{Policy: existing})
		if err != nil {
			return runningPolicies, err
		}
		delete(runningPolicies, existing.Name)

		err = rp.Router.AddRoutePolicyExtended(rp.Ctx, types.RoutePolicyExtendedRequest{
			DefaultExportAction: ossTypes.RoutePolicyActionReject, // do not advertise routes by default
			Policy:              p,
		})
		if err != nil {
			return runningPolicies, err
		}

		runningPolicies[p.Name] = p
	}

	// remove old policies
	for _, p := range toRemove {
		rp.Logger.Debug(
			"Removing route policy",
			ossTypes.PolicyLogField, p.Name,
		)

		err := rp.Router.RemoveRoutePolicyExtended(rp.Ctx, types.RoutePolicyExtendedRequest{Policy: p})
		if err != nil {
			return runningPolicies, err
		}
		delete(runningPolicies, p.Name)
	}

	// If we have all reset, process it first
	if allResetDirs.SoftResetDirection() != ossTypes.SoftResetDirectionNone {
		rp.Logger.Debug(
			"Resetting all peers due to a routing policy change",
			ossTypes.DirectionLogField, allResetDirs.SoftResetDirection().String(),
		)

		req := ossTypes.ResetAllNeighborsRequest{
			Soft:               true,
			SoftResetDirection: allResetDirs.SoftResetDirection(),
		}

		if err := rp.Router.ResetAllNeighbors(rp.Ctx, req); err != nil {
			// non-fatal error (may happen if the neighbor is not up), just log it
			rp.Logger.Debug(
				"resetting all peers failed after a routing policy change",
				logfields.Error, err,
				ossTypes.DirectionLogField, allResetDirs.SoftResetDirection().String(),
			)
		}
	}

	// Handle individual neighbor resets
	// soft-reset affected BGP peers to apply the changes on already advertised routes
	for peer, dirs := range resetPeers {
		// Skip if we already did all reset for this exact direction
		if allResetDirs.SoftResetDirection() == dirs.SoftResetDirection() {
			continue
		}
		// Skip if we did all reset for both directions (covers this peer)
		if allResetDirs.SoftResetDirection() == ossTypes.SoftResetDirectionBoth {
			continue
		}
		rp.Logger.Debug(
			"Resetting peer due to a routing policy change",
			ossTypes.PeerLogField, peer,
			ossTypes.DirectionLogField, dirs.SoftResetDirection().String(),
		)

		req := ossTypes.ResetNeighborRequest{
			PeerAddress:        peer,
			Soft:               true,
			SoftResetDirection: dirs.SoftResetDirection(),
		}

		if err := rp.Router.ResetNeighbor(rp.Ctx, req); err != nil {
			// non-fatal error (may happen if the neighbor is not up), just log it
			rp.Logger.Debug(
				"resetting peer failed after a routing policy change",
				logfields.Error, err,
				ossTypes.PeerLogField, peer,
				ossTypes.DirectionLogField, dirs.SoftResetDirection().String(),
			)
		}
	}

	return runningPolicies, nil
}

// PolicyName returns a unique route policy name for the provided peer, family and advertisement type.
// If there is a need for multiple route policies per advertisement type, unique resourceID can be provided.
func PolicyName(peer, family string, advertType v1.IsovalentBGPAdvertType, resourceID string) string {
	if resourceID == "" {
		return fmt.Sprintf("%s-%s-%s", peer, family, advertType)
	}
	return fmt.Sprintf("%s-%s-%s-%s", peer, family, advertType, resourceID)
}

// MergePolicies merges two route policies into a single policy, policy statements are sorted
// based on length of the first prefix in the match prefix list.
func MergePolicies(policyA, policyB *ossTypes.RoutePolicy) (*ossTypes.RoutePolicy, error) {
	// combine route policies into a single policy
	merged, err := reconciler.MergeRoutePolicies(policyA, policyB)
	if err != nil {
		return nil, err
	}

	// Sort statements based on prefix length:
	// - Statements with greater prefix length should go first, so that longer prefix match has higher priority.
	//   Main use-case is service route aggregation, where a single svc can have e.g. /32 and /24 match statements,
	//   and the /32 one should be prioritized.
	// - For simplicity, we only compare the length of the first prefix, as we never populate different prefix lengths
	//   in a single condition. PrefixLenMin and PrefixLenMax are always populated equally, so we only compare one of them.
	sort.SliceStable(merged.Statements, func(i, j int) bool {
		condI := merged.Statements[i].Conditions
		condJ := merged.Statements[j].Conditions
		if condI.MatchPrefixes != nil && condJ.MatchPrefixes != nil &&
			len(condI.MatchPrefixes.Prefixes) > 0 && len(condJ.MatchPrefixes.Prefixes) > 0 {
			return condI.MatchPrefixes.Prefixes[0].PrefixLenMin > condJ.MatchPrefixes.Prefixes[0].PrefixLenMin
		}
		return false
	})

	return merged, nil
}

// peerAddressesFromPolicy returns neighbor addresses found in a routing policy.
// It returns true when the policy contains the empty MatchNeighbors which means
// all neighbors.
func peerAddressesFromPolicy(p *types.ExtendedRoutePolicy) ([]netip.Addr, bool) {
	if p == nil {
		return []netip.Addr{}, false
	}
	addrs := []netip.Addr{}
	allPeers := false
	for _, s := range p.Statements {
		if s.Conditions.MatchNeighbors == nil || len(s.Conditions.MatchNeighbors.Neighbors) == 0 {
			allPeers = true
		} else {
			addrs = append(addrs, s.Conditions.MatchNeighbors.Neighbors...)
		}
	}
	return addrs, allPeers
}
