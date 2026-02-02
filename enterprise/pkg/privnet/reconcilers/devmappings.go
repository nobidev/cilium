//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package reconcilers

import (
	"context"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
)

var DeviceMappingsCell = cell.Group(
	cell.ProvidePrivate(
		// Provides the ReadWrite DeviceMappings table.
		tables.NewDeviceMappingsTable,

		// Provides the reconciler handling device mappings.
		newDeviceMappings,
	),

	cell.Invoke(
		// Registers the reconciler populating the device mappings table.
		(*DeviceMappings).registerReconciler,
	),
)

// DeviceMappings is a reconciler which populates the DeviceMappings table,
// and synchronizes the entries into the corresponding BPF map.
type DeviceMappings struct {
	log *slog.Logger
	jg  job.Group

	cfg config.Config

	db       *statedb.DB
	networks statedb.Table[tables.PrivateNetwork]
	tbl      statedb.RWTable[tables.DeviceMapping]
}

func newDeviceMappings(in struct {
	cell.In

	Log      *slog.Logger
	JobGroup job.Group

	Config config.Config

	DB       *statedb.DB
	Networks statedb.Table[tables.PrivateNetwork]
	Table    statedb.RWTable[tables.DeviceMapping]
}) *DeviceMappings {
	return &DeviceMappings{
		log: in.Log,
		jg:  in.JobGroup,

		cfg: in.Config,

		db:       in.DB,
		networks: in.Networks,
		tbl:      in.Table,
	}
}

func (dm *DeviceMappings) registerReconciler() {
	if !dm.cfg.Enabled {
		return
	}

	wtx := dm.db.WriteTxn(dm.tbl)
	initialized := dm.tbl.RegisterInitializer(wtx, "device-mappings-initialized")
	wtx.Commit()

	dm.jg.Add(
		job.OneShot(
			"populate-device-mappings-table",
			func(ctx context.Context, health cell.Health) error {
				health.OK("Starting")

				var initDone bool

				wtx := dm.db.WriteTxn(dm.networks)
				netChangeIter, _ := dm.networks.Changes(wtx)
				wtx.Commit()

				for {
					var watchset = statedb.NewWatchSet()

					wtx := dm.db.WriteTxn(dm.tbl)
					netChanges, netWatch := netChangeIter.Next(wtx)
					watchset.Add(netWatch)

					for change := range netChanges {
						if change.Deleted {
							dm.deleteForNetwork(wtx, change.Object.Name)
						} else {
							dm.reconcile(wtx, dm.forNetwork(change.Object))
						}
					}

					if !initDone {
						netInit, nw := dm.networks.Initialized(wtx)

						switch {
						case !netInit:
							watchset.Add(nw)
						default:
							initDone = true
							initialized(wtx)
						}
					}

					wtx.Commit()
					health.OK("Reconciliation completed")

					// Wait until there's new changes to consume
					_, err := watchset.Wait(ctx, SettleTime)
					if err != nil {
						return nil
					}
				}
			},
		),
	)
}

func (dm *DeviceMappings) reconcile(wtx statedb.WriteTxn, new tables.DeviceMapping) {
	old, _, found := dm.tbl.Get(wtx, tables.DeviceMappingsByOwner(new.Owner))
	if found && old.DeviceIndex != new.DeviceIndex {
		// The table is indexed by DeviceIndex, hence we need to explicitly
		// delete the old entry if it changes.
		dm.tbl.Delete(wtx, old)
	}

	if new.DeviceIndex == 0 || new.Equal(&old) {
		return
	}

	new.Status = reconciler.StatusPending()
	dm.tbl.Insert(wtx, new)
}

func (dm *DeviceMappings) deleteForNetwork(wtx statedb.WriteTxn, network tables.NetworkName) {
	for mapping := range dm.tbl.List(wtx, tables.DeviceMappingsByNetwork(network)) {
		dm.tbl.Delete(wtx, mapping)
	}
}

func (dm *DeviceMappings) forNetwork(network tables.PrivateNetwork) tables.DeviceMapping {
	return tables.DeviceMapping{
		Owner:       tables.NewDeviceMappingOwner("icpn", string(network.Name)),
		DeviceIndex: network.Interface.Index,
		DeviceName:  network.Interface.Name,
		NetworkName: network.Name,
		NetworkID:   network.ID,
	}
}
