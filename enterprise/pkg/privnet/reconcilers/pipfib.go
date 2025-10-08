// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package reconcilers

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"net/netip"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"

	pnmaps "github.com/cilium/cilium/enterprise/pkg/maps/privnet"
	"github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/enterprise/pkg/vni"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/types"
)

// PIPFIBMapCell provides a reconciler which watches the contents of the private network map entries
// StateDB table and reconciles it with the FIB and PIP BPF maps.
var PIPFIBMapCell = cell.Group(
	cell.Provide(
		newPIPFIBMap,
	),

	cell.Invoke(
		(*PIPFIBMap).registerReconciler,
	),
)

type PIPFIBMap struct {
	config           config.Config
	db               *statedb.DB
	mapEntries       statedb.RWTable[*tables.MapEntry]
	fib              pnmaps.Map[*pnmaps.FIBKeyVal]
	pip              pnmaps.Map[*pnmaps.PIPKeyVal]
	reconcilerParams reconciler.Params
	fence            regeneration.Fence
}

func newPIPFIBMap(in struct {
	cell.In

	Config config.Config

	DB               *statedb.DB
	MapEntries       statedb.RWTable[*tables.MapEntry]
	FIB              pnmaps.Map[*pnmaps.FIBKeyVal]
	PIP              pnmaps.Map[*pnmaps.PIPKeyVal]
	ReconcilerParams reconciler.Params
	Fence            regeneration.Fence
}) *PIPFIBMap {
	return &PIPFIBMap{
		config: in.Config,

		db:               in.DB,
		mapEntries:       in.MapEntries,
		fib:              in.FIB,
		pip:              in.PIP,
		reconcilerParams: in.ReconcilerParams,
		fence:            in.Fence,
	}
}

func (b *PIPFIBMap) registerReconciler() (reconciler.Reconciler[*tables.MapEntry], error) {
	if !b.config.Enabled {
		return nil, nil
	}

	// Block regeneration until we populated the maps again.
	b.fence.Add(
		"private-network",
		b.newInitWaitFunc(),
	)

	return reconciler.Register(
		// params
		b.reconcilerParams,
		// table
		b.mapEntries,
		// clone
		func(ne *tables.MapEntry) *tables.MapEntry {
			// We can do a shallow clone for the reconciler.
			cpy := *ne
			return &cpy
		},
		// setStatus
		func(ne *tables.MapEntry, status reconciler.Status) *tables.MapEntry {
			ne.Status = status
			return ne
		},
		// getStatus
		func(ne *tables.MapEntry) reconciler.Status {
			return ne.Status
		},
		// ops
		&pipFIBMapOps{
			fibOps: b.fib.Ops(),
			pipOps: b.pip.Ops(),
		},
		// batchOps
		nil,
	)
}

var _ reconciler.Operations[*tables.MapEntry] = &pipFIBMapOps{}

// pipFIBMapOps wraps the existing BPF map operations for the PIP and FIB BPF maps so
// the two BPF maps can be written in parallel.
type pipFIBMapOps struct {
	fibOps reconciler.Operations[*pnmaps.FIBKeyVal]
	pipOps reconciler.Operations[*pnmaps.PIPKeyVal]
}

func (pmo *pipFIBMapOps) FIBKeyVal(me *tables.MapEntry) *pnmaps.FIBKeyVal {
	mac := types.MACAddr{}
	if me.Type == tables.MapEntryTypeEndpoint {
		mac = types.MACAddr(me.Target.MAC)
	}
	return &pnmaps.FIBKeyVal{
		Key: pnmaps.NewFIBKey(me.Target.NetworkID, me.Target.CIDR),
		Val: pnmaps.NewFIBVal(me.Routing.NextHop, mac, pmo.FIBFlags(me.Type, me.Routing.L2Announce), uint32(me.Routing.EgressIfIndex), vni.MustFromUint32(0)),
	}
}

func (pmo *pipFIBMapOps) FIBFlags(typ tables.MapEntryType, l2ann bool) pnmaps.FIBFlags {
	var flags pnmaps.FIBFlags

	switch typ {
	case tables.MapEntryTypeEndpoint, tables.MapEntryTypeExternalEndpoint:
		if l2ann {
			flags |= pnmaps.FIBFlagL2Announce
		}
	case tables.MapEntryTypeDCNRoute:
		flags |= pnmaps.FIBFlagSubnetRoute
	case tables.MapEntryTypeStaticRoute:
		flags |= pnmaps.FIBFlagStaticRoute
	}

	return flags
}

func (pmo *pipFIBMapOps) PIPKeyVal(me *tables.MapEntry) *pnmaps.PIPKeyVal {
	if me.Type != tables.MapEntryTypeEndpoint && me.Type != tables.MapEntryTypeExternalEndpoint {
		return nil
	}

	return &pnmaps.PIPKeyVal{
		Key: pnmaps.NewPIPKey(netip.PrefixFrom(me.Routing.NextHop, me.Routing.NextHop.BitLen())),
		Val: pnmaps.NewPIPVal(
			me.Target.NetworkID, me.Target.CIDR.Addr(),
			types.MACAddr(me.Target.MAC), uint32(me.Routing.EgressIfIndex),
		),
	}
}

func (pmo *pipFIBMapOps) Delete(ctx context.Context, txn statedb.ReadTxn, rev statedb.Revision, me *tables.MapEntry) error {
	if err := pmo.fibOps.Delete(ctx, txn, rev, pmo.FIBKeyVal(me)); err != nil {
		return fmt.Errorf("failed to delete map entry %q from FIB map: %w", me, err)
	}

	pip := pmo.PIPKeyVal(me)
	if pip != nil {
		if err := pmo.pipOps.Delete(ctx, txn, rev, pip); err != nil {
			return fmt.Errorf("failed to delete map entry %q from PIP map: %w", me, err)
		}
	}
	return nil
}

func (pmo *pipFIBMapOps) Update(ctx context.Context, txn statedb.ReadTxn, rev statedb.Revision, me *tables.MapEntry) error {
	if err := pmo.fibOps.Update(ctx, txn, rev, pmo.FIBKeyVal(me)); err != nil {
		return fmt.Errorf("failed to write map entry %q into FIB map: %w", me, err)
	}

	pip := pmo.PIPKeyVal(me)
	if pip != nil {
		if err := pmo.pipOps.Update(ctx, txn, rev, pip); err != nil {
			return fmt.Errorf("failed to write map entry %q into PIP map: %w", me, err)
		}
	}
	return nil
}

func (pmo *pipFIBMapOps) Prune(ctx context.Context, txn statedb.ReadTxn, iter iter.Seq2[*tables.MapEntry, statedb.Revision]) error {
	return errors.Join(
		pmo.fibOps.Prune(ctx, txn, statedb.Map(iter, pmo.FIBKeyVal)),
		pmo.pipOps.Prune(ctx, txn, statedb.Filter(
			statedb.Map(iter, pmo.PIPKeyVal),
			func(pip *pnmaps.PIPKeyVal) bool { return pip != nil }),
		),
	)
}

func (b *PIPFIBMap) newInitWaitFunc() hive.WaitFunc {
	return func(ctx context.Context) error {
		// Wait until the map entries table has been initialized.
		_, initDone := b.mapEntries.Initialized(b.db.ReadTxn())
		select {
		case <-initDone:
		case <-ctx.Done():
			return ctx.Err()
		}

		// Wait until no entries are in pending state.
		// FIXME: we should probably only check the ones present initially,
		// and wait for at least a couple of retries in case of errors,
		// but this works anyways for the moment.
		for {
			entries, watch := b.mapEntries.AllWatch(b.db.ReadTxn())

			ready := true
			for entry := range entries {
				if entry.Status.Kind == reconciler.StatusKindPending {
					ready = false
					break
				}
			}

			if ready {
				return nil
			}

			// Poor man's rate limiting, just to avoid waking up for all changes.
			select {
			case <-time.After(50 * time.Millisecond):
			case <-ctx.Done():
				return ctx.Err()
			}

			select {
			case <-watch:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
}
