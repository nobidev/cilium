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
	"k8s.io/apimachinery/pkg/types"
)

type nodeToZoneFn func(nodeTypes.Node) (string, bool)

func nodeToAZFn(azAffinity azAffinityMode, uid types.UID) nodeToZoneFn {
	return func(n nodeTypes.Node) (string, bool) {
		if !azAffinity.enabled() {
			// When az affinity mode is disabled we use the UID as this
			// is also used as the partition key for the zone selection
			// stage.
			return string(uid), true
		}
		nodeAZ, ok := n.Labels[core_v1.LabelTopologyZone]
		return nodeAZ, ok
	}
}

// gatewayNodeIP is used to carry potential gateway node IPs for a
// policy.
// This is to be able to pre-compute viable gateways in a single pass
// such that each groupStatus has consistent inputs. The "per-group"
// policies are subsequently computed from a set of gatewayNodeIP's.
type gatewayNodeIP struct {
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
	zone bool
	// available indicates whether this gateway is available for active
	// gateway selection.
	available bool
}

// preComputePolicyHealthyGateways computes all gateways that are healthy and available
// for selection by any group in the policy config.
//
// Later, these will be filtered down by individual group configs' selectors to determine
// the actual available and healthy gateway ips for each group.
func (config *PolicyConfig) preComputePolicyHealthyGateways(operatorManager *OperatorManager, nodeToAZ nodeToZoneFn) (
	policyHealthyGatewayIPs []gatewayNodeIP, policyHealthyGatewayIPsByAZ map[string][]gatewayNodeIP) {
	policyHealthyGatewayIPsByAZ = make(map[string][]gatewayNodeIP)

	for _, node := range operatorManager.nodes {
		// if AZ affinity is enabled for the egress group, track the node's AZ.
		// Track all node AZs such that our per az availableHealthy set spans all
		// zones.
		//
		// This will be used later on to ensure that even AZs with no gateway nodes selected by the policy
		// or no healthy gateway nodes can get non-local gateways assigned to
		// (and because of this tracking needs to happen before ignoring a non-gateway node and unhealthy node)
		var nodeAZ string
		var zoneOK bool
		if nodeAZ, zoneOK = nodeToAZ(node); zoneOK {
			// as the availableHealthyGatewayIPsByAZ map is used also to keep track of all the available AZs,
			// always create an empty entry if it doesn't exist yet.
			// In this way we can ensure all AZs will have a key in the map
			if _, ok := policyHealthyGatewayIPsByAZ[nodeAZ]; !ok {
				policyHealthyGatewayIPsByAZ[nodeAZ] = []gatewayNodeIP{}
			}
		}

		// If no group config matches the node, ignore it and go to the next one.
		selectingGroupIndices := config.selectingGroupConfigIndices(node)
		if len(selectingGroupIndices) == 0 {
			continue
		}

		// If the node is not healthy, ignore it and move to the next one.
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

		gn := gatewayNodeIP{
			ip:                    nodeIP,
			selectingGroupIndices: selectingGroupIndices,
			available:             operatorManager.nodeIsAvailable(node),
			zone:                  zoneOK,
		}

		// add the node to the list of healthy gateway IPs.
		// This list is global (i.e. it doesn't take into account the AZ of the node)
		policyHealthyGatewayIPs = append(policyHealthyGatewayIPs, gn)

		policyHealthyGatewayIPsByAZ[nodeAZ] = append(policyHealthyGatewayIPsByAZ[nodeAZ], gn)

		if !zoneOK {
			operatorManager.logger.Warn(
				fmt.Sprintf("AZ affinity is enabled but node is missing %s label. Node will be ignored", core_v1.LabelTopologyZone),
				logfields.NodeName, node.Name,
			)
		}
	}
	return
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
func computeAvailableHealthyGatewaysByAZ(policyHealthyGatewayIPs map[string][]gatewayNodeIP, requireZone bool, groupIndex int) map[string][]netip.Addr {
	availGWs := map[string][]netip.Addr{}
	for az := range policyHealthyGatewayIPs {
		availGWs[az] = slices.Collect(fn.Map(fn.Filter(slices.Values(policyHealthyGatewayIPs[az]), func(n gatewayNodeIP) bool {
			return slices.Contains(n.selectingGroupIndices, groupIndex) && (!requireZone || n.zone) && n.available
		}), gwToAddr))
		// Initialize to avoid leaving nil
		if availGWs[az] == nil {
			availGWs[az] = []netip.Addr{}
		}
	}

	return availGWs
}
