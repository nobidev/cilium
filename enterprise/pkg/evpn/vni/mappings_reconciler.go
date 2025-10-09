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
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"

	evpnConfig "github.com/cilium/cilium/enterprise/pkg/evpn/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/config"
	privnetTables "github.com/cilium/cilium/enterprise/pkg/privnet/tables"
)

type VNIMappings struct {
	cfg      config.Config
	evpnCfg  evpnConfig.Config
	jg       job.Group
	logger   *slog.Logger
	db       *statedb.DB
	inTable  statedb.Table[privnetTables.PrivateNetwork]
	outTable statedb.RWTable[VNIMapping]
}

type vniMappingsIn struct {
	cell.In

	Cfg      config.Config
	EVPNCfg  evpnConfig.Config
	JG       job.Group
	Logger   *slog.Logger
	DB       *statedb.DB
	InTable  statedb.Table[privnetTables.PrivateNetwork]
	OutTable statedb.RWTable[VNIMapping]
}

func newVNIMappings(in vniMappingsIn) *VNIMappings {
	return &VNIMappings{
		cfg:      in.Cfg,
		evpnCfg:  in.EVPNCfg,
		jg:       in.JG,
		logger:   in.Logger,
		db:       in.DB,
		inTable:  in.InTable,
		outTable: in.OutTable,
	}
}

func (r *VNIMappings) registerReconciler() {
	if !r.cfg.Enabled || !r.evpnCfg.Enabled {
		return
	}

	wtxn := r.db.WriteTxn(r.outTable)
	initDone := r.outTable.RegisterInitializer(wtxn, "vni-mappings-initialized")
	wtxn.Commit()

	r.jg.Add(job.OneShot("vni-mappings", func(ctx context.Context, health cell.Health) error {
		wtxn := r.db.WriteTxn(r.inTable)
		iter, err := r.inTable.Changes(wtxn)
		wtxn.Commit()

		if err != nil {
			return err
		}

		for {
			wtxn := r.db.WriteTxn(r.outTable)

			changes, watch := iter.Next(wtxn)
			for change := range changes {
				pn := change.Object

				if change.Deleted {
					r.outTable.Delete(wtxn, VNIMapping{
						VNI: pn.VNI,
					})
					continue
				}

				oldMapping, _, hasOldMapping := r.outTable.Get(wtxn, VNIMappingByNetID(pn.ID))
				newMapping := VNIMapping{
					VNI:       pn.VNI,
					NetworkID: pn.ID,
					Status:    reconciler.StatusPending(),
				}

				switch {
				case pn.VNI.IsValid() && !hasOldMapping:
					r.outTable.Insert(wtxn, newMapping)
				case !pn.VNI.IsValid() && hasOldMapping:
					// Used to have a mapping, but no longer has a VNI
					r.outTable.Delete(wtxn, oldMapping)
				case pn.VNI.IsValid() && hasOldMapping && !oldMapping.Equal(newMapping):
					// Insert new mapping and delete old mapping
					r.outTable.Insert(wtxn, newMapping)
					r.outTable.Delete(wtxn, oldMapping)
				}
			}

			if initialized, _ := r.outTable.Initialized(wtxn); !initialized {
				initDone(wtxn)
			}
			wtxn.Commit()

			select {
			case <-watch:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}))
}
