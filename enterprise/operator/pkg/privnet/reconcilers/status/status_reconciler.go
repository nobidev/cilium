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
	"context"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/enterprise/operator/pkg/evpn"
	"github.com/cilium/cilium/enterprise/operator/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/operator/pkg/privnet/tables"
	"github.com/cilium/cilium/enterprise/pkg/vni"
)

type statusReconciler struct {
	logger            *slog.Logger
	config            config.Config
	evpnConfig        evpn.Config
	db                *statedb.DB
	pnTable           statedb.Table[tables.PrivateNetwork]
	pnsTable          statedb.RWTable[tables.PrivateNetworkStatus]
	prevRequestedVNIs map[tables.NetworkName]vni.VNI
}

type statusReconcilerIn struct {
	cell.In

	Config     config.Config
	EVPNConfig evpn.Config

	Logger   *slog.Logger
	DB       *statedb.DB
	PNTable  statedb.Table[tables.PrivateNetwork]
	PNSTable statedb.RWTable[tables.PrivateNetworkStatus]
}

func newStatusReconciler(in statusReconcilerIn) *statusReconciler {
	return &statusReconciler{
		logger:            in.Logger,
		config:            in.Config,
		evpnConfig:        in.EVPNConfig,
		db:                in.DB,
		pnTable:           in.PNTable,
		pnsTable:          in.PNSTable,
		prevRequestedVNIs: make(map[tables.NetworkName]vni.VNI),
	}
}

func (r *statusReconciler) register(jg job.Group, config config.Config) {
	if !config.Enabled {
		return
	}

	wtxn := r.db.WriteTxn(r.pnsTable)
	initDone := r.pnsTable.RegisterInitializer(wtxn, "initializer")
	wtxn.Commit()

	jg.Add(job.OneShot("status-reconciler", func(ctx context.Context, health cell.Health) error {
		// Wait for the initial list of the k8s API. Some
		// reconciliation logic needs full view of existing private
		// networks.
		_, watch := r.pnTable.Initialized(r.db.ReadTxn())
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-watch:
		}

		wtxn := r.db.WriteTxn(r.pnTable)

		changeIter, err := r.pnTable.Changes(wtxn)
		if err != nil {
			return err
		}

		wtxn.Commit()

		for {
			wtxn := r.db.WriteTxn(r.pnsTable)
			changes, watch := changeIter.Next(wtxn)

			for change := range changes {
				var name = change.Object.Name

				if change.Deleted {
					// Delete the downstream object in case the private network got deleted.
					r.pnsTable.Delete(wtxn, tables.PrivateNetworkStatus{Name: name})
				} else {
					if _, _, found := r.pnsTable.Get(wtxn, tables.PrivateNetworkStatusByName(name)); !found {
						// Create the downstream object in case it doesn't exist yet.
						r.pnsTable.Insert(wtxn, tables.PrivateNetworkStatus{
							Name:         name,
							OrigResource: change.Object.OrigResource,
							Status:       reconciler.StatusPending(),
						})
					} else {
						// Update the OrigResource if there's an existing entry.
						r.pnsTable.Modify(wtxn, tables.PrivateNetworkStatus{
							Name:         name,
							OrigResource: change.Object.OrigResource,
							Status:       reconciler.StatusPending(),
						}, func(old, new tables.PrivateNetworkStatus) tables.PrivateNetworkStatus {
							old.OrigResource = new.OrigResource
							old.Status = new.Status
							return old
						})
					}
				}

				r.reconcileVNIStatus(wtxn, change.Object, change.Deleted)
			}

			if initDone != nil {
				initDone(wtxn)
				initDone = nil
			}

			wtxn.Commit()

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-watch:
			}
		}
	}))

}

func (r *statusReconciler) reconcileVNIStatus(wtxn statedb.WriteTxn, network tables.PrivateNetwork, deleted bool) {
	if !r.evpnConfig.Enabled {
		// Keep any VNI related status fields unset if EVPN is
		// disabled. This also results in clearing any existing VNI
		// status entries.
		return
	}

	prevVNI, hasPrev := r.prevRequestedVNIs[network.Name]
	if !deleted {
		switch {
		case !hasPrev && network.RequestedVNI.IsValid():
			// New case
			r.updateVNIStatus(wtxn, network.RequestedVNI)
			r.prevRequestedVNIs[network.Name] = network.RequestedVNI
		case hasPrev && network.RequestedVNI.IsValid() && prevVNI != network.RequestedVNI:
			// Update case
			r.updateVNIStatus(wtxn, prevVNI)
			r.updateVNIStatus(wtxn, network.RequestedVNI)
			r.prevRequestedVNIs[network.Name] = network.RequestedVNI
		case hasPrev && !network.RequestedVNI.IsValid():
			// Delete case
			r.clearVNIStatus(wtxn, network)
			r.updateVNIStatus(wtxn, prevVNI)
			delete(r.prevRequestedVNIs, network.Name)
		}
	} else {
		if hasPrev {
			// At this point, the status entry is already deleted.
			// We just need to trigger an update for other networks
			// that have had a conflict with this one.
			r.updateVNIStatus(wtxn, prevVNI)
			delete(r.prevRequestedVNIs, network.Name)
		}
	}

}

func (r *statusReconciler) updateVNIStatus(wtxn statedb.WriteTxn, requestedVNI vni.VNI) {
	var (
		networks    = statedb.Collect(r.pnTable.List(wtxn, tables.PrivateNetworksByRequestedVNI(requestedVNI)))
		conflict    = len(networks) > 1
		assignedVNI = requestedVNI
	)

	if conflict {
		assignedVNI = vni.VNI{}
	}

	for _, network := range networks {
		r.pnsTable.Modify(
			wtxn,
			tables.PrivateNetworkStatus{
				Name: network.Name,
				VNI: tables.PrivateNetworkVNIStatus{
					RequestedVNI:   requestedVNI,
					AllocatedVNI:   assignedVNI,
					HasVNIConflict: conflict,
				},
				OrigResource: network.OrigResource,
				Status:       reconciler.StatusPending(),
			},
			func(old, new tables.PrivateNetworkStatus) tables.PrivateNetworkStatus {
				if old.Equal(new) {
					return old
				}
				return new
			},
		)
	}
}

func (r *statusReconciler) clearVNIStatus(wtxn statedb.WriteTxn, network tables.PrivateNetwork) {
	r.pnsTable.Modify(
		wtxn,
		tables.PrivateNetworkStatus{
			Name: network.Name,
			VNI: tables.PrivateNetworkVNIStatus{
				AllocatedVNI:   vni.VNI{},
				HasVNIConflict: false,
			},
			OrigResource: network.OrigResource,
			Status:       reconciler.StatusPending(),
		},
		func(old, new tables.PrivateNetworkStatus) tables.PrivateNetworkStatus {
			if old.Equal(new) {
				return old
			}
			return new
		},
	)
}
