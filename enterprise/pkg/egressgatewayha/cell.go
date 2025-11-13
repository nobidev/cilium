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
	"github.com/cilium/cilium/enterprise/pkg/egressgatewayha/egressipconf"
	"github.com/cilium/cilium/pkg/metrics"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
)

// Cell provides a [Manager] for consumption with hive.
var Cell = cell.Module(
	"egressgatewayha",
	"Egress Gateway allows originating traffic from specific IPv4 addresses",

	egressipconf.Cell,

	cell.Config(defaultConfig),
	cell.Provide(NewEgressGatewayManager),
	cell.Provide(newTunnelEnabler),
	cell.Provide(func(mgr *Manager) EgressIPsProvider { return mgr }),

	cell.ProvidePrivate(newAgentTables),
	cell.Provide(statedb.RWTable[AgentPolicyConfig].ToTable),
)

// OperatorCell provides an [OperatorManager] for consumption with hive.
var OperatorCell = cell.Module(
	"egressgatewayha-operator",
	"The Egress Gateway Operator manages cluster wide EGW state",
	metrics.Metric(newMetrics),
	cell.Config(defaultOperatorConfig),
	cell.Provide(NewEgressGatewayOperatorManager),
	cell.Provide(newNodeResource),

	cell.ProvidePrivate(newOperatorTables),
	cell.Provide(statedb.RWTable[*PolicyConfig].ToTable),
)
