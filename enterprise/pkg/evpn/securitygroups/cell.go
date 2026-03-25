// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package securitygroups

import (
	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/enterprise/pkg/evpn/securitygroups/tables"
)

var Cell = cell.Group(
	cell.ProvidePrivate(
		tables.NewSecurityGroupsTable,
		tables.NewEndpointSecurityGroupTable,

		newSecurityGroups,
		newEndpointSecurityGroups,

		newEndpointLookupAdapter,
	),

	cell.Provide(
		statedb.RWTable[tables.SecurityGroup].ToTable,
		statedb.RWTable[tables.EndpointSecurityGroup].ToTable,
	),

	cell.Invoke(
		(*securityGroups).registerK8sReflector,
		(*endpointSecurityGroups).registerReconciler,
	),
)
