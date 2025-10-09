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
	"context"
	"iter"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"

	evpnConfig "github.com/cilium/cilium/enterprise/pkg/evpn/config"
	vniMaps "github.com/cilium/cilium/enterprise/pkg/maps/vni"
	privnetConfig "github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/reconcilers"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
)

type mapReconcilerParams struct {
	cell.In

	PrivnetConfig privnetConfig.Config
	EVPNConfig    evpnConfig.Config
	Ops           reconciler.Operations[*vniMaps.VNIKeyVal]
	Table         statedb.RWTable[VNIMapping]
	Params        reconciler.Params
	Fence         regeneration.Fence
}

type mappingOps struct {
	ops    reconciler.Operations[*vniMaps.VNIKeyVal]
	tables statedb.Table[VNIMapping]
}

var _ reconciler.Operations[VNIMapping] = (*mappingOps)(nil)

func newMappingsOps(ops reconciler.Operations[*vniMaps.VNIKeyVal], tables statedb.Table[VNIMapping]) reconciler.Operations[VNIMapping] {
	return &mappingOps{
		ops:    ops,
		tables: tables,
	}
}

func (v *mappingOps) Update(ctx context.Context, rtxn statedb.ReadTxn, revision statedb.Revision, vm VNIMapping) error {
	return v.ops.Update(ctx, rtxn, revision, mappingToMap(vm))
}

func (v *mappingOps) Delete(ctx context.Context, rtxn statedb.ReadTxn, revision statedb.Revision, vm VNIMapping) error {
	return v.ops.Delete(ctx, rtxn, revision, mappingToMap(vm))
}

func (v *mappingOps) Prune(ctx context.Context, rtxn statedb.ReadTxn, vms iter.Seq2[VNIMapping, statedb.Revision]) error {
	return v.ops.Prune(ctx, rtxn, statedb.Map[VNIMapping, *vniMaps.VNIKeyVal](vms, mappingToMap))
}

// Creates a BPF map reconciler that reconciles the contents of the VNI
// Mapping StateDB table with the VNI BPF Map.
func registerMapReconciler(params mapReconcilerParams) (reconciler.Reconciler[VNIMapping], error) {
	if !params.PrivnetConfig.Enabled || !params.EVPNConfig.Enabled {
		return nil, nil
	}

	// Block endpoint regeneration until we populate the map.
	params.Fence.Add("vni-map",
		// TODO: May be replaced with Reconciler.WaitUntilReconciled at a later point.
		reconcilers.NewWaitUntilReconciledFn(params.Params.DB, params.Table, func(obj VNIMapping) reconciler.Status { return obj.Status }))

	return reconciler.Register(
		// params
		params.Params,
		// table
		params.Table,
		// clone
		func(vm VNIMapping) VNIMapping {
			return vm
		},
		// setStatus
		func(vm VNIMapping, status reconciler.Status) VNIMapping {
			vm.Status = status
			return vm
		},
		// getStatus
		func(vm VNIMapping) reconciler.Status {
			return vm.Status
		},
		// ops
		newMappingsOps(params.Ops, params.Table),
		// batchOps
		nil,
	)
}

func mappingToMap(vm VNIMapping) *vniMaps.VNIKeyVal {
	return &vniMaps.VNIKeyVal{
		Key: vniMaps.VNIKey{
			VNI: vm.VNI.AsUint32(),
		},
		Val: vniMaps.VNIVal{
			NetID: uint16(vm.NetworkID),
		},
	}
}
