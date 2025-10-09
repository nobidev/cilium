// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package vni

import (
	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb/reconciler"

	vniMaps "github.com/cilium/cilium/enterprise/pkg/maps/vni"
	"github.com/cilium/cilium/pkg/bpf"
)

var Cell = cell.Group(
	cell.ProvidePrivate(
		// Provides vni-mappings StateDB table.
		newVNIMappingTable,

		// Provides reconciler populating vni-mappings statedb table.
		newVNIMappings,

		// Providers map operations used by the bpf map reconciler.
		func(vniMap vniMaps.VNI) reconciler.Operations[*vniMaps.VNIKeyVal] {
			return bpf.NewMapOps[*vniMaps.VNIKeyVal](vniMap.Map)
		},
	),

	cell.Invoke(
		// Registers the private-networks to vni-mappings statedb table reconciler.
		(*VNIMappings).registerReconciler,

		// Registers the vni-mappings to bpf map reconciler.
		registerMapReconciler,
	),
)
