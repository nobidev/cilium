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
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/time"
)

const leaseSweepInterval = time.Minute

// dhcpLeaseReconciler watches local workloads and manages DHCP leases.
type dhcpLeaseReconciler struct {
	log       *slog.Logger
	db        *statedb.DB
	workloads statedb.RWTable[*tables.LocalWorkload]
	leases    statedb.RWTable[tables.DHCPLease]
}

// newDhcpLeaseReconciler constructs a DHCP lease manager.
func newDhcpLeaseReconciler(log *slog.Logger, jg job.Group, db *statedb.DB, workloads statedb.RWTable[*tables.LocalWorkload], leases statedb.RWTable[tables.DHCPLease]) *dhcpLeaseReconciler {
	m := &dhcpLeaseReconciler{
		log:       log,
		db:        db,
		workloads: workloads,
		leases:    leases,
	}
	if jg != nil {
		jg.Add(job.OneShot("dhcp-lease-reconciler", m.run))
	}
	return m
}

// run watches workloads and manages DHCP leases.
func (m *dhcpLeaseReconciler) run(ctx context.Context, _ cell.Health) error {
	txn := m.db.WriteTxn(m.workloads)
	iter, _ := m.workloads.Changes(txn)
	txn.Commit()

	sweep := time.NewTicker(leaseSweepInterval)
	defer sweep.Stop()

	for {
		wtxn := m.db.WriteTxn(m.leases, m.workloads)
		changes, watch := iter.Next(wtxn)
		for change := range changes {
			if lw := change.Object; lw != nil && lw.DHCP && change.Deleted {
				m.dropWorkloadLeases(wtxn, lw)
			}
		}
		wtxn.Commit()

		select {
		case <-ctx.Done():
			return nil
		case <-sweep.C:
			m.handleExpiredLeases()
		case <-watch:
		}
	}
}

func (m *dhcpLeaseReconciler) dropWorkloadLeases(wtxn statedb.WriteTxn, lw *tables.LocalWorkload) {
	if lw.Interface.Addressing.IPv4 != "" {
		updated := *lw
		updated.Interface.Addressing.IPv4 = ""
		m.workloads.Insert(wtxn, &updated)
	}
	mac, err := mac.ParseMAC(lw.Interface.MAC)
	if err != nil {
		return
	}
	for lease := range m.leases.List(wtxn, tables.DHCPLeaseByNetworkMAC(tables.NetworkName(lw.Interface.Network), mac)) {
		m.leases.Delete(wtxn, lease)
	}
}

func (m *dhcpLeaseReconciler) handleExpiredLeases() {
	now := time.Now()

	wtxn := m.db.WriteTxn(m.leases, m.workloads)
	defer wtxn.Abort()

	for lease := range m.leases.All(wtxn) {
		if !lease.ExpireAt.IsZero() && !lease.ExpireAt.After(now) {
			m.clearLocalWorkloadIP(wtxn, lease)
		}
	}

	wtxn.Commit()
}

func (m *dhcpLeaseReconciler) clearLocalWorkloadIP(wtxn statedb.WriteTxn, lease tables.DHCPLease) {
	lw, _, found := m.workloads.Get(wtxn, tables.LocalWorkloadsByID(lease.EndpointID))
	if !found {
		return
	}
	if lw.Interface.Addressing.IPv4 == "" {
		return
	}
	updated := *lw
	updated.Interface.Addressing.IPv4 = ""
	m.workloads.Insert(wtxn, &updated)
}
