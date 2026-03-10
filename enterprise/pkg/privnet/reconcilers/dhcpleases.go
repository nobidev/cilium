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
	"net/netip"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/enterprise/pkg/privnet/dhcp"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	iso_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/time"
)

var DhcpLeasesCell = cell.Invoke(newDhcpLeaseReconciler)

const leaseSweepInterval = time.Minute

// dhcpLeaseReconciler watches local workloads and manages DHCP leases.
type dhcpLeaseReconciler struct {
	log           *slog.Logger
	db            *statedb.DB
	workloads     statedb.RWTable[*tables.LocalWorkload]
	leases        statedb.RWTable[tables.DHCPLease]
	subnets       statedb.Table[tables.Subnet]
	sweepInterval time.Duration
}

type dhcpLeaseReconcilerParams struct {
	cell.In

	Log       *slog.Logger
	JobGroup  job.Group
	DB        *statedb.DB
	Workloads statedb.RWTable[*tables.LocalWorkload]
	Leases    statedb.RWTable[tables.DHCPLease]
	Subnets   statedb.Table[tables.Subnet]
	TestCfg   *dhcp.TestConfig `optional:"true"`
}

// newDhcpLeaseReconciler constructs a DHCP lease manager.
func newDhcpLeaseReconciler(in dhcpLeaseReconcilerParams) *dhcpLeaseReconciler {
	sweepInterval := leaseSweepInterval
	if in.TestCfg != nil && in.TestCfg.LeaseSweepInterval > 0 {
		sweepInterval = in.TestCfg.LeaseSweepInterval
	}

	m := &dhcpLeaseReconciler{
		log:           in.Log,
		db:            in.DB,
		workloads:     in.Workloads,
		leases:        in.Leases,
		subnets:       in.Subnets,
		sweepInterval: sweepInterval,
	}
	if in.JobGroup != nil {
		in.JobGroup.Add(job.OneShot("dhcp-lease-reconciler", m.run))
	}
	return m
}

func (m *dhcpLeaseReconciler) workloadUsesDHCP(txn statedb.ReadTxn, lw *tables.LocalWorkload) bool {
	if lw == nil {
		return false
	}
	subnet, _, found := m.subnets.Get(txn, tables.SubnetsByNetworkAndName(
		tables.NetworkName(lw.Interface.Network),
		lw.Subnet,
	))
	return found && subnet.DHCP.Mode != iso_v1alpha1.PrivateNetworkDHCPModeNone
}

// run watches workloads and manages DHCP leases.
func (m *dhcpLeaseReconciler) run(ctx context.Context, _ cell.Health) error {
	txn := m.db.WriteTxn(m.workloads)
	iter, _ := m.workloads.Changes(txn)
	txn.Commit()

	sweep := time.NewTicker(m.sweepInterval)
	defer sweep.Stop()

	for {
		wtxn := m.db.WriteTxn(m.leases, m.workloads)
		changes, watch := iter.Next(wtxn)
		for change := range changes {
			if lw := change.Object; lw != nil && m.workloadUsesDHCP(wtxn, lw) && change.Deleted {
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

var zeroAddrString = netip.IPv4Unspecified().String()

func (m *dhcpLeaseReconciler) clearLocalWorkloadIP(wtxn statedb.WriteTxn, lease tables.DHCPLease) {
	lw, _, found := m.workloads.Get(wtxn, tables.LocalWorkloadsByID(lease.EndpointID))
	if !found {
		return
	}
	if lw.Interface.Addressing.IPv4 == zeroAddrString {
		return
	}
	updated := *lw
	updated.Interface.Addressing.IPv4 = zeroAddrString
	m.workloads.Insert(wtxn, &updated)
}
