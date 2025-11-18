// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package bgpv1

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	"github.com/cilium/cilium/enterprise/pkg/bgpv1/agent"
	"github.com/cilium/cilium/enterprise/pkg/bgpv1/agent/commands"
	"github.com/cilium/cilium/enterprise/pkg/bgpv1/manager/reconcilerv2"
	ossAgent "github.com/cilium/cilium/pkg/bgp/agent"
	"github.com/cilium/cilium/pkg/bgp/gobgp"
	"github.com/cilium/cilium/pkg/bgp/types"
	"github.com/cilium/cilium/pkg/k8s"
)

// Cell is module with Enterprise BGP Control Plane components
var Cell = cell.Module(
	"enterprise-bgp-control-plane",
	"Enterprise BGP Control Plane",

	// BGP resources
	cell.Provide(
		k8s.IsovalentBGPPeerConfigResource,
		k8s.IsovalentBGPAdvertisementResource,
		k8s.IsovalentBGPNodeConfigResource,
		k8s.IsovalentBGPPolicyResource,
		k8s.IsovalentBGPVRFConfigResource,
		k8s.CiliumBGPPeerConfigResource,
	),

	// enterprise-only reconcilers
	reconcilerv2.ConfigReconcilers,

	// set enterprise BGP config object in agent
	cell.Config(config.DefaultConfig),

	// enterprise BGP commands
	cell.Provide(
		commands.BGPCommands,

		// provide enterprise router manager (used by the enterprise commands)
		func(manager ossAgent.BGPRouterManager) agent.EnterpriseBGPRouterManager {
			return manager.(agent.EnterpriseBGPRouterManager)
		},
	),

	// override GoBGP router provider with the enterprise version
	cell.DecorateAll(
		func(_ types.RouterProvider) types.RouterProvider {
			return gobgp.NewEnterpriseRouterProvider()
		},
	),
)
