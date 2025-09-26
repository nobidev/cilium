// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package status

import (
	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/enterprise/operator/pkg/privnet/tables"
)

var Cell = cell.Group(
	cell.ProvidePrivate(
		tables.NewPrivateNetworksStatusTable,
		statedb.RWTable[tables.PrivateNetworkStatus].ToTable,

		newStatusReconciler,
		newK8sReconciler,
	),
	cell.Invoke(
		(*statusReconciler).register,
		(*k8sReconciler).register,
	),
)
