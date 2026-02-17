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
	"fmt"
	"net/netip"
	"slices"

	fn "github.com/cilium/cilium/enterprise/pkg/functional"
	"github.com/cilium/cilium/pkg/logging/logfields"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"

	"go4.org/netipx"
	core_v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
)

// gatewayNodeIP is used to carry potential gateway node IPs for a
// policy.
// This is to be able to pre-compute viable gateways in a single pass
// such that each groupStatus has consistent inputs. The "per-group"
// policies are subsequently computed from a set of gatewayNodeIP's.
type gatewayNodeIP struct {
	*nodeTypes.Node

	// ip is the potential IP addr of the egress gateway that may
	// be used in a IEGP policy.
	ip netip.Addr
	// selectingGroupIndices contains a set of indices indicating
	// which groupConfigs matched this gateway in the pre-selection
	// stage (i.e. via the nodeSelector).
	// We use this later to compute per-groupConfig sets that only
	// match a particular group.
	selectingGroupIndices []int
	// zone indicates that this gatewayIP had a valid topology zone
	// set and can be used for "AZ-aware" policy computation.
	// We make this distinction as we also may need to perform "AZ-unaware"
	// computation for the fallback set.
	zone string
	// available indicates whether this gateway is available for active
	// gateway selection.
	available bool
}

func (gni *gatewayNodeIP) selectsGroupIndex(index int) bool {
	return slices.Contains(gni.selectingGroupIndices, index)
}

func (gni *gatewayNodeIP) zoneOK() bool {
	return gni.zone != ""
}

func (gni *gatewayNodeIP) isSelected() bool {
	return len(gni.selectingGroupIndices) > 0
}

func parseNodeIP(n nodeTypes.Node) netip.Addr {
	nodeIP, ok := netipx.FromStdIP(n.GetK8sNodeIP())
	if !ok {
		return netip.Addr{} // note: netip.Addr{}.IsValid() == false.
	}
	return nodeIP
}

func (config *PolicyConfig) preComputePolicyHealthyGateways(operatorManager *OperatorManager) (
	allAZs sets.Set[string], policyHealthyGatewayIPs []gatewayNodeIP) {
	allAZs = sets.New[string]()

	recordZone := func(gn gatewayNodeIP) {
		if gn.zoneOK() {
			// as the availableHealthyGatewayIPsByAZ map is used also to keep track of all the available AZs,
			// always create an empty entry if it doesn't exist yet.
			// In this way we can ensure all AZs will have a key in the map
			allAZs.Insert(gn.zone)
		}
	}

	logInvalidNodes := func(gn gatewayNodeIP) {
		if config.azAffinity.enabled() && !gn.zoneOK() {
			operatorManager.logger.Warn(
				fmt.Sprintf("AZ affinity is enabled but node is missing %s label. Node will be ignored", core_v1.LabelTopologyZone),
				logfields.NodeName, gn.Node.Name,
			)
		}
	}

	var policyHealthyGateways []gatewayNodeIP
	for _, n := range operatorManager.nodes {
		gn := gatewayNodeIP{
			ip:   parseNodeIP(n),
			Node: &n,
			zone: n.Labels[core_v1.LabelTopologyZone],

			selectingGroupIndices: config.selectingGroupConfigIndices(n),
			available:             operatorManager.nodeIsAvailable(n),
		}

		recordZone(gn)

		if !gn.ip.IsValid() || !gn.isSelected() || !operatorManager.nodeIsReachable(gn.Node.Name) {
			continue
		}

		logInvalidNodes(gn)

		policyHealthyGateways = append(policyHealthyGateways, gn)
	}

	return allAZs, policyHealthyGateways
}

func gwToAddr(gw gatewayNodeIP) netip.Addr {
	return gw.ip
}

// computeHealthyGateways takes in a list of policy-wide gatewayNodeIPs and translates it to
// a per groupConfig list used for the final healthyGatewayIPs groupStatus field.
func computeHealthyGateways(policyHealthyGatewayIPs []gatewayNodeIP, requireAvailable bool, groupIndex int) []netip.Addr {
	return slices.Collect(fn.Map(fn.Filter(slices.Values(policyHealthyGatewayIPs), func(n gatewayNodeIP) bool {
		return slices.Contains(n.selectingGroupIndices, groupIndex)
	}, func(n gatewayNodeIP) bool {
		return !requireAvailable || n.available
	}), gwToAddr))
}

// computeAvailableHealthyGatewaysByAZ takes the policy healthy and available gateways and translates it to
// only those selected by the group specified by the groupIndex.
// This is what's used for doing per groupConfig gateway selection.
func computeAvailableHealthyGatewaysByAZ(allAZs sets.Set[string], policyHealthyGatewayIPs []gatewayNodeIP, groupIndex int) map[string][]netip.Addr {
	availGWs := map[string][]netip.Addr{}
	for az := range allAZs {
		availGWs[az] = []netip.Addr{}
	}

	for _, gni := range policyHealthyGatewayIPs {
		if !gni.available || !gni.selectsGroupIndex(groupIndex) || !gni.zoneOK() {
			continue
		}
		availGWs[gni.zone] = append(availGWs[gni.zone], gni.ip)
	}

	return availGWs
}

func doSelection(statusActiveGateways, availableHealthyGatewayIPs []netip.Addr, selectionKey string, maxGatewayNodes int) []netip.Addr {
	var currentLocalActiveGWs []netip.Addr
	if len(statusActiveGateways) != 0 {
		// we have to reverify they're still local and active.
		availableForReselection := sets.New(availableHealthyGatewayIPs...).Has
		for _, activeGW := range statusActiveGateways {
			if !availableForReselection(activeGW) {
				continue
			}
			currentLocalActiveGWs = append(currentLocalActiveGWs, activeGW)
		}
	}
	// seed with zone
	return selectActiveGWs(selectionKey, maxGatewayNodes, currentLocalActiveGWs, availableHealthyGatewayIPs)
}
