//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package reconciler

import (
	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/enterprise/pkg/bfd/types"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/metrics"
)

var Cell = cell.Module(
	"bfd-reconciler",
	"BFD configuration reconciler",

	cell.Provide(
		types.NewBFDPeersTable,
		statedb.RWTable[*types.BFDPeerStatus].ToTable,
	),
	cell.Invoke(statedb.RegisterTable[*types.BFDPeerStatus]),

	cell.ProvidePrivate(
		k8s.IsovalentBFDProfileResource,
		k8s.IsovalentBFDNodeConfigResource,
	),

	cell.Invoke(func(p bfdReconcilerParams) {
		newBFDReconciler(p)
	}),

	metrics.Metric(newBFDMetrics),
)
