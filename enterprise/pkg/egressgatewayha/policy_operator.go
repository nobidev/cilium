//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package egressgatewayha

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"math/rand/v2"
	"net/netip"
	"slices"

	"github.com/cilium/statedb"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"go4.org/netipx"
	core_v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	k8sLabels "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

const (
	// egress gateway IPAM condition types to be set in IEGP status after allocation attempts
	egwIPAMRequestSatisfied = "isovalent.com/IPAMRequestSatisfied"

	egwIPAMInvalidCIDR         = "isovalent.com/InvalidCIDR"
	egwIPAMUnsupportedEgressIP = "isovalent.com/UnsupportedEgressIP"
	egwIPAMPoolExhausted       = "isovalent.com/PoolExhausted"
	egwIPAMPoolConflicting     = "isovalent.com/PoolConflict"

	egressGatewayPrefix                 = "egw.isovalent.com"
	nodeEgressGatewayKey                = egressGatewayPrefix + "/node"
	nodeEgressGatewayUnschedulableValue = "unschedulable"
)

// affinityZoneNoZone is the name of an "internal-only" affinity zone used to group together all
// active gateway IPs when the affinity zone feature is not enabled.
// This is useful to build a map affinityZone -> activeGateways to use as a source when allocating
// egress IPs (IPAM), just like we do when affinity zone feature is enabled.
const affinityZoneNoZone = "affinity-zone-disabled"

func (gs *groupStatus) filterGWsWithoutEgressIP() {
	filter := func(addrs []netip.Addr) []netip.Addr {
		return slices.DeleteFunc(addrs, func(addr netip.Addr) bool {
			_, found := gs.egressIPByGatewayIP[addr]
			return !found
		})
	}

	// filter away active gateways without an assigned egress IP
	gs.activeGatewayIPs = filter(gs.activeGatewayIPs)

	// filter away active gateways in each AZ without an assigned egress IP
	for az, gwsByAZ := range gs.activeGatewayIPsByAZ {
		gs.activeGatewayIPsByAZ[az] = filter(gwsByAZ)
	}
}

func (config *groupConfig) selectsNodeAsGateway(node nodeTypes.Node) bool {
	return config.nodeSelector.Matches(k8sLabels.Set(node.Labels))
}

func getIEGPForStatusUpdate(iegp *Policy, groupStatuses []groupStatus, conditions []meta_v1.Condition) *Policy {
	iegpGroupStatuses := make([]v1.IsovalentEgressGatewayPolicyGroupStatus, 0, len(groupStatuses))
	for _, gs := range groupStatuses {
		iegpGroupStatuses = append(iegpGroupStatuses, v1.IsovalentEgressGatewayPolicyGroupStatus{
			ActiveGatewayIPs:     toSortedStringSlice(gs.activeGatewayIPs),
			ActiveGatewayIPsByAZ: toStringMapStringSlice(gs.activeGatewayIPsByAZ),
			HealthyGatewayIPs:    toSortedStringSlice(gs.healthyGatewayIPs),
			EgressIPByGatewayIP:  toStringMap(gs.egressIPByGatewayIP),
		})
	}

	policy := &Policy{
		TypeMeta: meta_v1.TypeMeta{
			Kind:       iegp.Kind,
			APIVersion: iegp.APIVersion,
		},
		ObjectMeta: meta_v1.ObjectMeta{
			Name:              iegp.GetName(),
			Namespace:         iegp.GetNamespace(),
			ResourceVersion:   iegp.GetResourceVersion(),
			UID:               iegp.GetUID(),
			CreationTimestamp: iegp.GetCreationTimestamp(),
			Labels:            iegp.GetLabels(),
			Annotations:       iegp.GetAnnotations(),
			// The Generation isn't needed in production code, as UpdateStatus ignores the generation.
			// See the comment for the Spec bellow.
			Generation: iegp.GetGeneration(),
		},
		// The Spec isn't needed in production code, as this update object will be passed into an UpdateStatus client-go
		// method, that will promptly ignore the spec. However, it's needed in tests because the fake k8s client
		// implements UpdateStatus in a simplistic way, and overwrites the stored spec with the one on this object.
		// This results in us storing a blank spec, and breaking the test.
		Spec: iegp.Spec,
		Status: v1.IsovalentEgressGatewayPolicyStatus{
			ObservedGeneration: iegp.GetGeneration(),
			GroupStatuses:      iegpGroupStatuses,
		},
	}

	for _, cond := range conditions {
		meta.SetStatusCondition(&policy.Status.Conditions, cond)
	}

	return policy
}

func (gc *groupConfig) computeGroupStatus(operatorManager *OperatorManager, config *PolicyConfig, status *groupStatus) (groupStatus, gatewaySelectionMetrics, error) {
	healthyGatewayIPs := []netip.Addr{}
	availableHealthyGatewayIPs := []netip.Addr{}

	activeGatewayIPsByAZ := make(map[string][]netip.Addr)
	availableHealthyGatewayIPsByAZ := make(map[string][]netip.Addr)

	isLocalSelectedByAZ := make(map[string]bool)

	selectionMetrics := gatewaySelectionMetrics{
		activeGateways:     0,
		activeGatewaysByAZ: make(map[string]activeGatewaysByMetrics),
		healthyGateways:    0,
	}

	for _, node := range operatorManager.nodes {
		// if AZ affinity is enabled for the egress group, track the node's AZ.
		//
		// This will be used later on to ensure that even AZs with no gateway nodes selected by the policy
		// or no healthy gateway nodes can get non-local gateways assigned to
		// (and because of this tracking needs to happen before ignoring a non-gateway node and unhealthy node)
		if config.azAffinity.enabled() {
			if nodeAZ, ok := node.Labels[core_v1.LabelTopologyZone]; ok {
				// as the availableHealthyGatewayIPsByAZ map is used also to keep track of all the available AZs,
				// always create an empty entry if it doesn't exist yet.
				// In this way we can ensure all AZs will have a key in the map
				if _, ok = availableHealthyGatewayIPsByAZ[nodeAZ]; !ok {
					availableHealthyGatewayIPsByAZ[nodeAZ] = []netip.Addr{}
				}
			}
		}

		// if the group config doesn't match the node, ignore it and go to the next one
		if !gc.selectsNodeAsGateway(node) {
			continue
		}

		// if the node is not healthy, ignore it and move to the next one
		if !operatorManager.nodeIsReachable(node.Name) {
			continue
		}

		nodeIP, ok := netipx.FromStdIP(node.GetK8sNodeIP())
		if !ok {
			operatorManager.logger.Warn(
				"Failed to convert NodeIP, skipping this node.",
				logfields.NodeName, node.Name,
				logfields.NodeIPv4, node.GetK8sNodeIP(),
			)
			continue
		}

		// add the node to the list of healthy gateway IPs.
		// This list is global (i.e. it doesn't take into account the AZ of the node)
		healthyGatewayIPs = append(healthyGatewayIPs, nodeIP)

		if !operatorManager.nodeIsAvailable(node) {
			continue
		}

		availableHealthyGatewayIPs = append(availableHealthyGatewayIPs, nodeIP)

		// if AZ affinity is enabled, add the node IP also to the list of healthy gateway IPs
		if config.azAffinity.enabled() {
			if nodeAZ, ok := node.Labels[core_v1.LabelTopologyZone]; ok {
				availableHealthyGatewayIPsByAZ[nodeAZ] = append(availableHealthyGatewayIPsByAZ[nodeAZ], nodeIP)
			} else {
				operatorManager.logger.Warn(
					fmt.Sprintf("AZ affinity is enabled but node is missing %s label. Node will be ignored", core_v1.LabelTopologyZone),
					logfields.NodeName, node.Name,
				)
			}
		}
	}

	// if AZ affinity is enabled,
	// Choose maxGateway items from the list of per AZ healthy GWs  with random probability.
	// If the selected active GW list is not enough, choose from the non-local active GW list later
	// according to the azAffinity config.
	if config.azAffinity.enabled() {
		for az, healthyGatewayIPs := range availableHealthyGatewayIPsByAZ {
			var currentLocalActiveGWs []netip.Addr
			if status != nil {
				currentLocalActiveGWs = gc.selectCurrentLocalActiveGWs(operatorManager, az, status.activeGatewayIPsByAZ[az])
			}
			activeGWs, err := selectActiveGWs(az, gc.maxGatewayNodes, currentLocalActiveGWs, healthyGatewayIPs)
			if err != nil {
				return groupStatus{}, gatewaySelectionMetrics{}, err
			}
			activeGatewayIPsByAZ[az] = activeGWs

			selectionMetrics.activeGatewaysByAZ[az] = activeGatewaysByMetrics{local: len(activeGWs), remote: 0}
		}
	}

	// nonLocalActiveGatewayIPs is a helper that returns, given a particular AZ, a slice of non local gateways for
	// that AZ.
	//
	// This function selects active non-local GWs from a list of healthy non-local GWs with random probability
	// using a target zone name as a seed to make the result deterministic.
	nonLocalActiveGatewayIPs := func(targetAz string, maxGW int, currentActiveNonLocalGWs []netip.Addr) ([]netip.Addr, error) {
		// sort the AZs lexicographically
		sortedAZs := slices.Collect(maps.Keys(availableHealthyGatewayIPsByAZ))
		slices.Sort(sortedAZs)

		var healthyNonLocalGWs []netip.Addr
		for _, az := range sortedAZs {
			if az != targetAz {
				healthyNonLocalGWs = append(healthyNonLocalGWs, availableHealthyGatewayIPsByAZ[az]...)
			}
		}

		activeGWs, err := selectActiveGWs(targetAz, maxGW, currentActiveNonLocalGWs, healthyNonLocalGWs)
		if err != nil {
			return nil, err
		}

		return activeGWs, nil
	}

	// next do a second pass to populate the per-AZ list of active gateways
	switch config.azAffinity {
	case azAffinityLocalOnly:
		// for local only affinity there's nothing left to do

	case azAffinityLocalOnlyFirst:
		for az := range activeGatewayIPsByAZ {
			// only if there are no local gateways, pick the ones from the other AZs
			if len(activeGatewayIPsByAZ[az]) == 0 {
				var currentNonLocalActiveGWs []netip.Addr
				if status != nil {
					currentNonLocalActiveGWs = gc.selectCurrentNonLocalActiveGWs(operatorManager, az, status.activeGatewayIPsByAZ[az])
				}
				nonLocalActiveGWs, err := nonLocalActiveGatewayIPs(az, gc.maxGatewayNodes, currentNonLocalActiveGWs)
				if err != nil {
					return groupStatus{}, gatewaySelectionMetrics{}, err
				}
				activeGatewayIPsByAZ[az] = nonLocalActiveGWs
				isLocalSelectedByAZ[az] = false

				selectionMetrics.activeGatewaysByAZ[az] = activeGatewaysByMetrics{local: 0, remote: len(nonLocalActiveGWs)}

			} else {
				isLocalSelectedByAZ[az] = true
			}
		}

	case azAffinityLocalPriority:
		for az := range activeGatewayIPsByAZ {
			if gc.maxGatewayNodes != 0 && len(activeGatewayIPsByAZ[az]) < gc.maxGatewayNodes {
				var currentNonLocalActiveGWs []netip.Addr
				if status != nil {
					currentNonLocalActiveGWs = gc.selectCurrentNonLocalActiveGWs(operatorManager, az, status.activeGatewayIPsByAZ[az])
				}
				nonLocalActiveGWs, err := nonLocalActiveGatewayIPs(az, gc.maxGatewayNodes-len(activeGatewayIPsByAZ[az]), currentNonLocalActiveGWs)
				if err != nil {
					return groupStatus{}, gatewaySelectionMetrics{}, err
				}

				activeGatewayIPsByAZ[az] = append(activeGatewayIPsByAZ[az], nonLocalActiveGWs...)

				selectionMetrics.activeGatewaysByAZ[az] = activeGatewaysByMetrics{
					local:  selectionMetrics.activeGatewaysByAZ[az].local,
					remote: len(nonLocalActiveGWs)}

			}
		}
	}

	// Selects the active GWs from a list of the healthy GWs with random probability
	// using a uid as a seed to make the result deterministic. The result is used for the
	// non AZ affinity case.
	//
	// If the active GWs have already been selected, we exclude all the unhealthy and non gateway nodes,
	// and back-fill the currently selected group of active gateways, until maxGateways is reached.
	var currentActiveGWs []netip.Addr
	if status != nil {
		currentActiveGWs = gc.excludeUnavailableGWs(operatorManager, status.activeGatewayIPs)
	}
	activeGatewayIPs, err := selectActiveGWs(string(config.uid), gc.maxGatewayNodes, currentActiveGWs, availableHealthyGatewayIPs)
	if err != nil {
		return groupStatus{}, gatewaySelectionMetrics{}, err
	}

	selectionMetrics.activeGateways = len(activeGatewayIPs)
	selectionMetrics.healthyGateways = len(healthyGatewayIPs)

	return groupStatus{
		activeGatewayIPs:          activeGatewayIPs,
		activeGatewayIPsByAZ:      activeGatewayIPsByAZ,
		isLocalActiveGatewaysByAZ: isLocalSelectedByAZ,
		healthyGatewayIPs:         healthyGatewayIPs,
	}, selectionMetrics, nil
}

// selectCurrentLocalActiveGWs selects the current local active GWs.
// It excludes unhealthy and non-gateway nodes
func (gc *groupConfig) selectCurrentLocalActiveGWs(operatorManager *OperatorManager, az string, currentActiveGWs []netip.Addr) []netip.Addr {
	return gc.selectActiveGWsIf(operatorManager, az, currentActiveGWs, func(nodeAZ, targetAZ string) bool {
		return nodeAZ == targetAZ
	})
}

// selectCurrentNonLocalActiveGWs selects the current non-local active GWs.
// It excludes unhealthy and non-gateway nodes
func (gc *groupConfig) selectCurrentNonLocalActiveGWs(operatorManager *OperatorManager, az string, currentActiveGWs []netip.Addr) []netip.Addr {
	return gc.selectActiveGWsIf(operatorManager, az, currentActiveGWs, func(nodeAZ, targetAZ string) bool {
		return nodeAZ != targetAZ
	})
}

func (gc *groupConfig) selectActiveGWsIf(operatorManager *OperatorManager, az string, currentActiveGWs []netip.Addr, predicate func(nodeAZ, targetAZ string) bool) []netip.Addr {
	var localGWs []netip.Addr
	for _, gw := range currentActiveGWs {
		node, nodeExists := operatorManager.nodesByIP[gw.String()]
		if nodeExists {
			if nodeAZ, azExists := node.Labels[core_v1.LabelTopologyZone]; azExists && predicate(nodeAZ, az) {
				localGWs = append(localGWs, gw)
			}
		}
	}

	return gc.excludeUnavailableGWs(operatorManager, localGWs)
}

// excludeUnavailableGWs excludes unavailable or non-gateway nodes from the current active GWs.
func (gc *groupConfig) excludeUnavailableGWs(operatorManager *OperatorManager, currentActiveGWs []netip.Addr) []netip.Addr {
	var activeGWs []netip.Addr
	for _, gw := range currentActiveGWs {
		node, ok := operatorManager.nodesByIP[gw.String()]
		if ok && operatorManager.nodeIsAvailable(node) && gc.selectsNodeAsGateway(node) {
			activeGWs = append(activeGWs, gw)
		}
	}

	return activeGWs
}

// selectActiveGWs selects the maxGW number of the active GWs from the healthy GWs
// with random probability using a seed.
//
// If currentActiveGWs are specified, we back-fill the currently selected active gateways,
// until maxGateways is reached.
func selectActiveGWs(seed string, maxGW int, currentActiveGWs, healthyGWs []netip.Addr) ([]netip.Addr, error) {
	var activeGWs []netip.Addr

	if len(currentActiveGWs) > 0 {
		for _, gw := range currentActiveGWs {
			activeGWs = append(activeGWs, gw)
			if maxGW != 0 && len(activeGWs) == maxGW {
				return activeGWs, nil
			}
		}

		healthyGWs = excludeCurrentActiveGWsFromHealthyGWs(currentActiveGWs, healthyGWs)
	}

	// Choose active GWs from the healthy GWs list with a pseudo-random permutation
	// using a zone name as a seed
	h := sha256.New()
	if _, err := io.WriteString(h, seed); err != nil {
		return nil, err
	}
	s := binary.BigEndian.Uint64(h.Sum(nil))
	r := rand.New(rand.NewPCG(s, 0))
	for _, p := range r.Perm(len(healthyGWs)) {
		activeGWs = append(activeGWs, healthyGWs[p])
		if maxGW != 0 && len(activeGWs) == maxGW {
			break
		}
	}

	return activeGWs, nil
}

// excludeCurrentActiveGWsFromHealthyGWs excludes the gateway nodes that have been already
// selected from the healthy gateways
func excludeCurrentActiveGWsFromHealthyGWs(currentActiveGWs, healthyGWs []netip.Addr) []netip.Addr {
	activeGWsSet := make(map[netip.Addr]bool)
	for _, gw := range currentActiveGWs {
		activeGWsSet[gw] = true
	}

	var result []netip.Addr
	for _, gw := range healthyGWs {
		if !activeGWsSet[gw] {
			result = append(result, gw)
		}
	}

	return result
}

func (config *PolicyConfig) allocateEgressIPs(operatorManager *OperatorManager, groupStatuses []groupStatus) ([]groupStatus, []meta_v1.Condition) {
	egressCIDRs := make([]netip.Prefix, 0, len(config.egressCIDRs))
	for _, cidr := range config.egressCIDRs {
		// detect conflicting CIDRs
		if conflicting, found := operatorManager.cidrConflicts[policyEgressCIDR{config.id, cidr}]; found {
			msg := fmt.Sprintf(
				"egress CIDR %s in policy %s overlaps with egress CIDR %s in policy %s",
				cidr, config.id.Name, conflicting.cidr, conflicting.origin.Name,
			)
			return groupStatuses, conditionsForFailure(config.generation, []meta_v1.Condition{
				{
					Type:               egwIPAMPoolConflicting,
					Status:             meta_v1.ConditionUnknown,
					ObservedGeneration: config.generation,
					LastTransitionTime: meta_v1.Now(),
					Reason:             "noreason",
					Message:            msg,
				},
			}...)
		}
		egressCIDRs = append(egressCIDRs, cidr)
	}

	egressPool, err := newPool(egressCIDRs...)
	if err != nil {
		operatorManager.health.Degraded(fmt.Sprintf("found invalid egress CIDR in policy %s", config.id), err)
		return groupStatuses, conditionsForFailure(config.generation, []meta_v1.Condition{
			{
				Type:               egwIPAMInvalidCIDR,
				Status:             meta_v1.ConditionUnknown,
				ObservedGeneration: config.generation,
				LastTransitionTime: meta_v1.Now(),
				Reason:             "noreason",
				Message:            fmt.Sprintf("found invalid egress CIDR: %s", err),
			},
		}...)
	}

	haveSeenLatestIEGP := config.groupStatusesGeneration == config.generation

	for i := range groupStatuses {
		if addr := config.groupConfigs[i].egressIP; addr.IsValid() {
			msg := "egressIP not supported together with egressCIDR"
			operatorManager.health.Degraded(msg, fmt.Errorf("found egress IP %s in policy %s", addr, config.id.Name))
			return groupStatuses, conditionsForFailure(config.generation, []meta_v1.Condition{
				{
					Type:               egwIPAMUnsupportedEgressIP,
					Status:             meta_v1.ConditionUnknown,
					ObservedGeneration: config.generation,
					LastTransitionTime: meta_v1.Now(),
					Reason:             "noreason",
					Message:            msg,
				},
			}...)
		}

		// For all still-active gateways we strive to keep the same allocated Egress IP as before.
		var prevEgressIPs map[netip.Addr]netip.Addr
		if haveSeenLatestIEGP && i < len(config.groupStatuses) {
			prevEgressIPs = config.groupStatuses[i].egressIPByGatewayIP
		}

		// Proceed only if this group meets at least one of the following conditions:
		// 1. It has at least one healthy but inactive gateway with a previously allocated egress IP.
		//    This ensures that existing active connections are not disrupted by prematurely releasing
		//    the egress IP, allowing the inactive gateway to resume handling traffic.
		// 2. It has at least one active gateway, either in activeGatewayIPs or activeGatewayIPsByAZ
		//    (to account for AZ affinity).
		// Otherwise, skip this group as there is nothing to allocate.
		if !hasHealthyGatewaysWithAllocatedEgressIP(groupStatuses[i], prevEgressIPs) && !activeGatewaysInGroup(groupStatuses[i]) {
			continue
		}

		activeGWs := make(map[string][]netip.Addr)
		if len(groupStatuses[i].activeGatewayIPsByAZ) > 0 {
			// affinity zones enabled
			maps.Copy(activeGWs, groupStatuses[i].activeGatewayIPsByAZ)
		} else {
			// affinity zones not enabled, all active gateways are considered as belonging
			// to a "placeholder" affinity zone for the sake of egress IPs allocation.
			activeGWs[affinityZoneNoZone] = groupStatuses[i].activeGatewayIPs
		}

		groupStatuses[i].egressIPByGatewayIP, err = allocateEgressIPsForGroup(operatorManager.logger, egressPool, activeGWs, prevEgressIPs, groupStatuses[i].healthyGatewayIPs)
		if err != nil {
			operatorManager.health.Degraded(fmt.Sprintf("unable to fulfill allocations for policy %s", config.id), err)
			return groupStatuses, conditionsForFailure(config.generation, []meta_v1.Condition{
				{
					Type:               egwIPAMPoolExhausted,
					Status:             meta_v1.ConditionUnknown,
					ObservedGeneration: config.generation,
					LastTransitionTime: meta_v1.Now(),
					Reason:             "noreason",
					Message:            fmt.Sprintf("unable to fulfill allocations: %s", err),
				},
			}...)
		}
	}

	operatorManager.health.OK(fmt.Sprintf("IP allocations completed successfully for policy %s", config.id.Name))

	return groupStatuses, conditionsForSuccess(config.generation)
}

func conditionsForFailure(generation int64, conditions ...meta_v1.Condition) []meta_v1.Condition {
	return append(
		conditions,
		meta_v1.Condition{
			Type:               egwIPAMRequestSatisfied,
			Status:             meta_v1.ConditionFalse,
			ObservedGeneration: generation,
			LastTransitionTime: meta_v1.Now(),
			Reason:             "noreason",
			Message:            "allocation requests not satisfied",
		},
	)
}

func conditionsForSuccess(generation int64, conditions ...meta_v1.Condition) []meta_v1.Condition {
	return append(
		conditions,
		meta_v1.Condition{
			Type:               egwIPAMRequestSatisfied,
			Status:             meta_v1.ConditionTrue,
			ObservedGeneration: generation,
			LastTransitionTime: meta_v1.Now(),
			Reason:             "noreason",
			Message:            "allocation requests satisfied",
		},
	)
}

func activeGatewaysInGroup(group groupStatus) bool {
	if len(group.activeGatewayIPs) > 0 {
		return true
	}
	for _, gws := range group.activeGatewayIPsByAZ {
		if len(gws) > 0 {
			return true
		}
	}
	return false
}

func hasHealthyGatewaysWithAllocatedEgressIP(group groupStatus, prevEgressIPs map[netip.Addr]netip.Addr) bool {
	for _, healthyGW := range group.healthyGatewayIPs {
		if _, found := prevEgressIPs[healthyGW]; found {
			return true
		}
	}
	return false
}

func getInactiveHealthyGateways(activeGatewayIPsByAZ map[string][]netip.Addr, healthyGatewayIPs []netip.Addr) []netip.Addr {
	activeGatewayIPsSet := make(map[netip.Addr]struct{})
	for _, gws := range activeGatewayIPsByAZ {
		for _, gw := range gws {
			activeGatewayIPsSet[gw] = struct{}{}
		}
	}

	var inActiveHealthyGateways []netip.Addr
	for _, healthyGateway := range healthyGatewayIPs {
		if _, found := activeGatewayIPsSet[healthyGateway]; !found {
			inActiveHealthyGateways = append(inActiveHealthyGateways, healthyGateway)
		}
	}

	return inActiveHealthyGateways
}

func allocateEgressIPsForGroup(logger *slog.Logger, egressPool *pool, activeGatewayIPsByAZ map[string][]netip.Addr, prevEgressIPs map[netip.Addr]netip.Addr, healthyGatewayIPs []netip.Addr) (map[netip.Addr]netip.Addr, error) {
	// First, retain the egress IPs of gateways that are healthy but not currently active.
	// Releasing these IPs could disrupt existing connections that still depend on them.
	egressIPsOfInactiveGateways := make(map[netip.Addr]netip.Addr)
	for _, inActiveHealthyGateway := range getInactiveHealthyGateways(activeGatewayIPsByAZ, healthyGatewayIPs) {
		if egressIP, found := prevEgressIPs[inActiveHealthyGateway]; found {
			err := egressPool.allocate(egressIP)
			if err == nil {
				egressIPsOfInactiveGateways[inActiveHealthyGateway] = egressIP
				continue
			}
			logger.Debug(
				"Unable to reserve previously allocated egress IP for in-active gateway",
				logfields.EgressIP, egressIP,
				logfields.GatewayIP, inActiveHealthyGateway,
				logfields.Error, err,
			)
		}
	}

	// Second, initialize the allocations map creating an entry for each affinity zone.
	egressIPsByAZ := make(map[string]map[netip.Addr]netip.Addr)
	for az := range activeGatewayIPsByAZ {
		egressIPsByAZ[az] = make(map[netip.Addr]netip.Addr)
	}

	newActiveGatewayIPsByAZ := make(map[string][]netip.Addr)

	// for each affinity zone, try to reserve the same egress IPs previously allocated
	for az, gatewayIPs := range activeGatewayIPsByAZ {
		for _, gatewayIP := range gatewayIPs {
			if egressIP, found := prevEgressIPs[gatewayIP]; found {
				err := egressPool.allocate(egressIP)
				if err == nil {
					egressIPsByAZ[az][gatewayIP] = egressIP
					continue
				}
				// in case of failure, just log the error from the allocation attempt
				// and go ahead with a further attempt using a fresh egress IP
				logger.Debug(
					"Unable to reserve egress IP assigned to gateway IP in previous version of the policy",
					logfields.EgressIP, egressIP,
					logfields.GatewayIP, gatewayIP,
					logfields.Error, err,
				)
			}
			newActiveGatewayIPsByAZ[az] = append(newActiveGatewayIPsByAZ[az], gatewayIP)
		}
	}

	// then, sort the active gateway IPs in each affinity zone so that the allocation algorithm is deterministic.
	for az, gws := range newActiveGatewayIPsByAZ {
		slices.SortFunc(gws, func(a, b netip.Addr) int {
			return a.Compare(b)
		})
		newActiveGatewayIPsByAZ[az] = gws
	}

	// finally, back-fill as needed in a round-robin fashion, prioritizing affinity zones with fewer allocations.
	for allocationRequests(newActiveGatewayIPsByAZ) > 0 {
		zones := nextAffinityZonesToSatisfy(newActiveGatewayIPsByAZ, egressIPsByAZ)

		for _, zone := range zones {
			// allocate an egress IP for the first gateway of the zone
			gw := newActiveGatewayIPsByAZ[zone][0]
			egressIP, err := egressPool.allocateNext()
			if err != nil {
				// No more available addresses to allocate. If there were previously allocated addresses,
				// including IPs assigned to inactive but healthy gateways, an imbalance might occur,
				// potentially leaving one or more zones without an allocated IP.
				// Attempt to rebalance the allocations to ensure that each zone has at least one allocated
				// address, if possible. Prioritize allocating IPs from inactive gateways first.
				egressIPsByAZ, egressIPsOfInactiveGateways = ensureZonesCoverage(activeGatewayIPsByAZ, egressIPsByAZ, egressIPsOfInactiveGateways)
				return mergeEgressIPs(foldAllocations(egressIPsByAZ), egressIPsOfInactiveGateways), err
			}
			egressIPsByAZ[zone][gw] = egressIP

			// remove that gateway from the zone allocation requests
			newActiveGatewayIPsByAZ[zone] = newActiveGatewayIPsByAZ[zone][1:]

			// if all gateways in the zone have an egress IP, remove the zone
			if len(newActiveGatewayIPsByAZ[zone]) == 0 {
				delete(newActiveGatewayIPsByAZ, zone)
			}
		}
	}

	return mergeEgressIPs(foldAllocations(egressIPsByAZ), egressIPsOfInactiveGateways), nil
}

func allocationRequests(activeGatewayIPsByAZ map[string][]netip.Addr) int {
	var n int
	for _, gws := range activeGatewayIPsByAZ {
		n += len(gws)
	}
	return n
}

func nextAffinityZonesToSatisfy(activeGatewayIPsByAZ map[string][]netip.Addr, egressIPsByAZ map[string]map[netip.Addr]netip.Addr) []string {
	// get the current allocations histogram
	hist := allocsHistogram(egressIPsByAZ)

	// prioritize zones with fewer allocations
	for _, alloc := range hist {
		zonesToSatisfy := alloc.zones

		// but do not consider zones with no more pending requests
		zonesToSatisfy = slices.DeleteFunc(zonesToSatisfy, func(az string) bool {
			_, found := activeGatewayIPsByAZ[az]
			return !found
		})

		if len(zonesToSatisfy) > 0 {
			return zonesToSatisfy
		}
	}

	return nil
}

type allocsByAZ struct {
	nAllocs int
	zones   []string
}

func allocsHistogram(egressIPsByAZ map[string]map[netip.Addr]netip.Addr) []allocsByAZ {
	// build a map: # allocs -> zones with that # of allocs
	allocs := make(map[int][]string)
	for zone, addrs := range egressIPsByAZ {
		n := len(addrs)
		allocs[n] = append(allocs[n], zone)
	}

	// build a histogram from allocs, sorted by increasing number of allocs
	hist := make([]allocsByAZ, 0, len(allocs))
	for n, zones := range allocs {
		// sort the zones too, in order to keep the allocation algorithm consistent
		slices.Sort(zones)
		hist = append(hist, allocsByAZ{n, zones})
	}
	slices.SortFunc(hist, func(a, b allocsByAZ) int {
		return a.nAllocs - b.nAllocs
	})

	return hist
}

func ensureZonesCoverage(
	activeGatewayIPsByAZ map[string][]netip.Addr,
	egressIPsByAZ map[string]map[netip.Addr]netip.Addr,
	egressIPsOfInActiveGateways map[netip.Addr]netip.Addr,
) (map[string]map[netip.Addr]netip.Addr, map[netip.Addr]netip.Addr) {
	hist := allocsHistogram(egressIPsByAZ)

	// If total # of available egress IPs is less than the # of zones,
	// there is no possible assignment to cover all the zones.
	// If so, we avoid altering the current assignment to keep previous
	// allocations stable and not breaking existing connections.
	total := 0
	for _, allocs := range egressIPsByAZ {
		total += len(allocs)
	}
	total += len(egressIPsOfInActiveGateways)
	if total < len(egressIPsByAZ) {
		return egressIPsByAZ, egressIPsOfInActiveGateways
	}

	// loop until there is at least one zone without any IP
	for hist[0].nAllocs == 0 {
		// the zone that needs an allocation
		dstZone := hist[0].zones[0]

		var egressIP netip.Addr
		if len(egressIPsOfInActiveGateways) > 0 {
			egressIP, egressIPsOfInActiveGateways = releaseEgressIP(egressIPsOfInActiveGateways)
		} else {
			// the zone that will give up an allocation
			srcZone := hist[len(hist)-1].zones[0]

			var egressIPs map[netip.Addr]netip.Addr
			egressIP, egressIPs = releaseEgressIP(egressIPsByAZ[srcZone])
			egressIPsByAZ[srcZone] = egressIPs
		}

		// fetch the list of gateways in the dst zone
		dstGWs := activeGatewayIPsByAZ[dstZone]
		slices.SortFunc(dstGWs, func(a, b netip.Addr) int {
			return a.Compare(b)
		})

		// allocate the released address to the first listed
		// gateway in the dst zone
		dstGW := dstGWs[0]
		egressIPsByAZ[dstZone][dstGW] = egressIP

		// recalculate allocations histogram
		hist = allocsHistogram(egressIPsByAZ)
	}

	return egressIPsByAZ, egressIPsOfInActiveGateways
}

func releaseEgressIP(egressIPs map[netip.Addr]netip.Addr) (netip.Addr, map[netip.Addr]netip.Addr) {
	// fetch the list of gateways
	srcGWs := slices.Collect(maps.Keys(egressIPs))
	slices.SortFunc(srcGWs, func(a, b netip.Addr) int {
		return a.Compare(b)
	})

	// release the egress IP allocation for the last
	// listed gateway in the src gateway list
	srcGW := srcGWs[len(srcGWs)-1]
	egressIP := egressIPs[srcGW]
	delete(egressIPs, srcGW)

	return egressIP, egressIPs
}

func foldAllocations(egressIPsByAZ map[string]map[netip.Addr]netip.Addr) map[netip.Addr]netip.Addr {
	egressIPs := make(map[netip.Addr]netip.Addr)
	for _, zoneAllocs := range egressIPsByAZ {
		maps.Copy(egressIPs, zoneAllocs)
	}
	return egressIPs
}

func mergeEgressIPs(allocatedEgressIPs, egressIPsOfInactiveGateways map[netip.Addr]netip.Addr) map[netip.Addr]netip.Addr {
	egressIPs := make(map[netip.Addr]netip.Addr, len(allocatedEgressIPs)+len(egressIPsOfInactiveGateways))
	maps.Copy(egressIPs, allocatedEgressIPs)
	maps.Copy(egressIPs, egressIPsOfInactiveGateways)
	return egressIPs
}

type gatewaySelectionMetrics struct {
	activeGateways     int
	activeGatewaysByAZ map[string]activeGatewaysByMetrics
	healthyGateways    int
}

type activeGatewaysByMetrics struct {
	local  int
	remote int
}

// updateGroupStatuses updates the list of active and healthy gateway IPs in the
// IEGP k8s resource for the receiver PolicyConfig
func (config *PolicyConfig) updateGroupStatuses(operatorManager *OperatorManager, tx statedb.WriteTxn) error {
	haveSeenLatestIEGP := config.groupStatusesGeneration == config.generation

	groupStatuses := make([]groupStatus, 0, len(config.groupConfigs))
	zoneHasAnyLocalGateway := make(map[string]bool)
	selectionMetricsList := make([]gatewaySelectionMetrics, 0, len(config.groupConfigs))
	for i, gc := range config.groupConfigs {
		var status *groupStatus
		if haveSeenLatestIEGP && i < len(config.groupStatuses) {
			status = &config.groupStatuses[i]
		}
		gs, sm, err := gc.computeGroupStatus(operatorManager, config, status)
		if err != nil {
			return err
		}

		groupStatuses = append(groupStatuses, gs)
		for zone, isLocal := range gs.isLocalActiveGatewaysByAZ {
			zoneHasAnyLocalGateway[zone] = zoneHasAnyLocalGateway[zone] || isLocal
		}

		selectionMetricsList = append(selectionMetricsList, sm)
	}

	selectionMetrics := aggregateSelectionMetrics(selectionMetricsList)
	if config.azAffinity == azAffinityLocalOnlyFirst && len(groupStatuses) > 1 {
		for _, gs := range groupStatuses {
			for zone, isLocal := range gs.isLocalActiveGatewaysByAZ {
				if zoneHasAnyLocalGateway[zone] && !isLocal {
					if activeGatewaysByAZStats, ok := selectionMetrics.activeGatewaysByAZ[zone]; ok {
						activeGatewaysByAZStats.remote = activeGatewaysByAZStats.remote - len(gs.activeGatewayIPsByAZ[zone])
						selectionMetrics.activeGatewaysByAZ[zone] = activeGatewaysByAZStats
					}
					gs.activeGatewayIPsByAZ[zone] = nil
				}
			}
		}
	}

	var conditions []meta_v1.Condition
	if len(config.egressCIDRs) > 0 {
		groupStatuses, conditions = config.allocateEgressIPs(operatorManager, groupStatuses)

		// when using egw IPAM, a gateway should not be considered active if a valid egress IP
		// cannot be assigned. Therefore, we remove each gateway IP without an egress IP from
		// both the list of active gateways and the map of active gateways by affinity zones
		for i := range groupStatuses {
			groupStatuses[i].filterGWsWithoutEgressIP()
		}
	}

	// After building the list of active and healthy gateway IPs, update the
	// status of the corresponding IEGP k8s resource
	iegp, ok := operatorManager.policyCache[config.id]
	if !ok {
		operatorManager.logger.Error(
			"Cannot find cached policy, group statuses will not be updated",
			logfields.IsovalentEgressGatewayPolicyName, config.id.Name,
		)

		return nil
	}

	newIEGP := getIEGPForStatusUpdate(operatorManager.policyCache[config.id], groupStatuses, conditions)

	// if the IEGP's status is already up to date, that is:
	// - ObservedGeneration is already equal to the IEGP Generation
	// - GroupStatuses are already in sync with the computed ones
	// - Conditions are in sync with the computed ones
	// then skip updating the status to avoid emitting an update event for the policy
	if config.generation == config.groupStatusesGeneration &&
		cmp.Equal(iegp.Status.GroupStatuses, newIEGP.Status.GroupStatuses, cmpopts.EquateEmpty()) &&
		cmp.Equal(iegp.Status.Conditions, newIEGP.Status.Conditions, cmpopts.EquateEmpty()) {
		return nil
	}

	logger := operatorManager.logger.With(logfields.IsovalentEgressGatewayPolicyName, config.id.Name)
	logger.Debug("Updating policy", logfields.Status, newIEGP.Status)

	updatedIEGP, err := operatorManager.clientset.IsovalentV1().IsovalentEgressGatewayPolicies().
		UpdateStatus(context.TODO(), newIEGP, meta_v1.UpdateOptions{})
	if err != nil {
		logger.Warn("Cannot update IsovalentEgressGatewayPolicy status, retrying",
			logfields.K8sGeneration, newIEGP.Status.ObservedGeneration,
			logfields.Error, err,
		)

		return err
	}

	policyName := updatedIEGP.Name
	if config.azAffinity.enabled() {
		for zone, activeGatewaysByAZCount := range selectionMetrics.activeGatewaysByAZ {
			operatorManager.metrics.ActiveGatewaysByAZ.WithLabelValues(policyName, zone, labelValueScopeLocal).Set(float64(activeGatewaysByAZCount.local))
			operatorManager.metrics.ActiveGatewaysByAZ.WithLabelValues(policyName, zone, labelValueScopeRemote).Set(float64(activeGatewaysByAZCount.remote))
		}
	} else {
		operatorManager.metrics.ActiveGateways.WithLabelValues(policyName).Set(float64(selectionMetrics.activeGateways))
	}
	operatorManager.metrics.HealthyGateways.WithLabelValues(policyName).Set(float64(selectionMetrics.healthyGateways))

	// Now we've updated the IsovalentEgressGatewayPolicy, we need to update our local cache. The UpdateStatus
	// method on the Kubernetes client object helpfully returned the updated iegp. So we can just write that back to
	// the cache. By definition, if that call did not error, it's the most up-to-date version of the object.
	updatedPolicyConfig, err := ParseIEGP(logger, updatedIEGP)
	if err != nil {
		// This is a super-strange case where we've written an updated object that we then cannot parse.
		logger.Warn("Failed to parse IsovalentEgressGatewayPolicy after update",
			logfields.K8sGeneration, updatedIEGP.Status.ObservedGeneration,
			logfields.Error, err,
		)
		return err
	}
	operatorManager.policyCache[config.id] = updatedIEGP
	_, err = operatorManager.upsertPolicyConfig(tx, updatedPolicyConfig)
	if err != nil {
		logger.Error("failed to upsert policy config",
			logfields.Error, err,
		)
		return err
	}

	return nil
}

func aggregateSelectionMetrics(list []gatewaySelectionMetrics) gatewaySelectionMetrics {
	total := gatewaySelectionMetrics{
		activeGateways:     0,
		activeGatewaysByAZ: make(map[string]activeGatewaysByMetrics),
		healthyGateways:    0,
	}

	for _, m := range list {
		total.activeGateways += m.activeGateways
		total.healthyGateways += m.healthyGateways

		for az, ag := range m.activeGatewaysByAZ {
			sum := total.activeGatewaysByAZ[az]
			sum.local += ag.local
			sum.remote += ag.remote
			total.activeGatewaysByAZ[az] = sum
		}
	}

	return total
}
