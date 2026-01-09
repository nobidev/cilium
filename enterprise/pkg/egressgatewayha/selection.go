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
	"net/netip"
	"slices"

	fn "github.com/cilium/cilium/enterprise/pkg/functional"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"

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

func gwToAddr(gw gatewayNodeIP) netip.Addr {
	return gw.ip
}

// computeHealthyGateways takes in a list of policy-wide gatewayNodeIPs and translates it to
// a per groupConfig list used for the final healthyGatewayIPs groupStatus field.
func computeHealthyGateways(policyHealthyGatewayIPs []gatewayNodeIP, groupIndex int) []netip.Addr {
	return slices.Collect(fn.Map(fn.Filter(slices.Values(policyHealthyGatewayIPs), func(n gatewayNodeIP) bool {
		return slices.Contains(n.selectingGroupIndices, groupIndex)
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
