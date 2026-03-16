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
	"log/slog"
	"net"
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	iso_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

func TestDhcpReconcilerDropsLeasesWhenDHCPDisabled(t *testing.T) {
	db := statedb.New()
	workloads, err := tables.NewLocalWorkloadsTable(db)
	require.NoError(t, err)
	leaseWriter, leases, err := tables.NewDHCPLeaseWriter(slog.Default(), db, &option.DaemonConfig{
		StateDir: t.TempDir(),
	}, hivetest.Lifecycle(t))
	require.NoError(t, err)
	subnets, err := tables.NewSubnetTable(db)
	require.NoError(t, err)

	lw := &tables.LocalWorkload{
		EndpointID: 100,
		Subnet:     "default-v4",
		Interface: iso_v1alpha1.PrivateNetworkEndpointSliceInterface{
			Network: "blue",
			MAC:     "02:aa:bb:cc:dd:ee",
			Addressing: iso_v1alpha1.PrivateNetworkEndpointAddressing{
				IPv4: "192.168.1.10",
			},
		},
	}

	wtxn := db.WriteTxn(workloads, leases, subnets)
	workloads.Insert(wtxn, lw)
	subnets.Insert(wtxn, tables.Subnet{
		SubnetSpec: tables.SubnetSpec{
			Network: "blue",
			Name:    "default-v4",
			CIDRv4:  netip.MustParsePrefix("192.168.1.0/24"),
		},
		DHCP: iso_v1alpha1.PrivateNetworkSubnetDHCPSpec{
			Mode: iso_v1alpha1.PrivateNetworkDHCPModeBroadcast,
		},
	})
	leaseWriter.Insert(wtxn, tables.DHCPLease{
		Network:    "blue",
		EndpointID: 100,
		MAC:        mac.MAC(net.HardwareAddr{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee}),
	})
	wtxn.Commit()

	m := newDhcpLeaseReconciler(dhcpLeaseReconcilerParams{
		Log:         slog.Default(),
		DB:          db,
		Workloads:   workloads,
		LeaseWriter: leaseWriter,
		Subnets:     subnets,
	})
	wtxn = db.WriteTxn(workloads, leases, subnets)
	m.dropWorkloadLeases(wtxn, lw)
	rtxn := wtxn.Commit()

	_, _, found := leases.Get(rtxn, tables.DHCPLeaseByNetworkMAC("blue", mac.MAC(net.HardwareAddr{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee})))
	require.False(t, found)

	got, _, found := workloads.Get(rtxn, tables.LocalWorkloadsByID(100))
	require.True(t, found)
	require.Empty(t, got.Interface.Addressing.IPv4)
}

func TestDhcpReconcilerClearsExpiredLease(t *testing.T) {
	db := statedb.New()
	workloads, err := tables.NewLocalWorkloadsTable(db)
	require.NoError(t, err)
	leaseWriter, leases, err := tables.NewDHCPLeaseWriter(slog.Default(), db, &option.DaemonConfig{
		StateDir: t.TempDir(),
	}, hivetest.Lifecycle(t))
	require.NoError(t, err)
	subnets, err := tables.NewSubnetTable(db)
	require.NoError(t, err)

	now := time.Now()

	expired := &tables.LocalWorkload{
		EndpointID: 100,
		Subnet:     "default-v4",
		Interface: iso_v1alpha1.PrivateNetworkEndpointSliceInterface{
			Network: "blue",
			MAC:     "02:aa:bb:cc:dd:ee",
			Addressing: iso_v1alpha1.PrivateNetworkEndpointAddressing{
				IPv4: "192.168.1.10",
			},
		},
	}
	active := &tables.LocalWorkload{
		EndpointID: 101,
		Subnet:     "default-v4",
		Interface: iso_v1alpha1.PrivateNetworkEndpointSliceInterface{
			Network: "blue",
			MAC:     "02:aa:bb:cc:dd:ef",
			Addressing: iso_v1alpha1.PrivateNetworkEndpointAddressing{
				IPv4: "192.168.1.11",
			},
		},
	}

	wtx := db.WriteTxn(workloads, leases, subnets)
	workloads.Insert(wtx, expired)
	workloads.Insert(wtx, active)
	subnets.Insert(wtx, tables.Subnet{
		SubnetSpec: tables.SubnetSpec{
			Network: "blue",
			Name:    "default-v4",
			CIDRv4:  netip.MustParsePrefix("192.168.1.0/24"),
		},
		DHCP: iso_v1alpha1.PrivateNetworkSubnetDHCPSpec{
			Mode: iso_v1alpha1.PrivateNetworkDHCPModeBroadcast,
		},
	})
	leaseWriter.Insert(wtx, tables.DHCPLease{
		Network:    "blue",
		EndpointID: expired.EndpointID,
		MAC:        mac.MAC(net.HardwareAddr{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee}),
		ExpireAt:   now.Add(-time.Minute),
	})
	leaseWriter.Insert(wtx, tables.DHCPLease{
		Network:    "blue",
		EndpointID: active.EndpointID,
		MAC:        mac.MAC(net.HardwareAddr{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xef}),
		ExpireAt:   now.Add(time.Minute),
	})
	wtx.Commit()

	m := newDhcpLeaseReconciler(dhcpLeaseReconcilerParams{
		Log:         slog.Default(),
		DB:          db,
		Workloads:   workloads,
		LeaseWriter: leaseWriter,
		Subnets:     subnets,
	})
	m.handleExpiredLeases()

	rtx := db.ReadTxn()
	gotExpired, _, found := workloads.Get(rtx, tables.LocalWorkloadsByID(expired.EndpointID))
	require.True(t, found)
	require.Equal(t, "0.0.0.0", gotExpired.Interface.Addressing.IPv4)

	gotActive, _, found := workloads.Get(rtx, tables.LocalWorkloadsByID(active.EndpointID))
	require.True(t, found)
	require.Equal(t, "192.168.1.11", gotActive.Interface.Addressing.IPv4)
}

func TestDhcpReconcilerClearsRestoredExpiredLease(t *testing.T) {
	stateDir := t.TempDir()
	log := slog.Default()

	db := statedb.New()
	leaseWriter, leases, err := tables.NewDHCPLeaseWriter(log, db, &option.DaemonConfig{StateDir: stateDir}, hivetest.Lifecycle(t))
	require.NoError(t, err)

	wtxn := db.WriteTxn(leases)
	_, _, err = leaseWriter.Insert(wtxn, tables.DHCPLease{
		Network:    "blue",
		EndpointID: 100,
		MAC:        mac.MustParseMAC("02:aa:bb:cc:dd:ee"),
		IPv4:       netip.MustParseAddr("192.168.1.10"),
		ExpireAt:   time.Now().Add(-time.Minute),
	})
	require.NoError(t, err)
	wtxn.Commit()

	restartedDB := statedb.New()
	restartedWorkloads, err := tables.NewLocalWorkloadsTable(restartedDB)
	require.NoError(t, err)
	restartedSubnets, err := tables.NewSubnetTable(restartedDB)
	require.NoError(t, err)

	restartedLeaseWriter, restartedLeaseTable, err := tables.NewDHCPLeaseWriter(log, restartedDB, &option.DaemonConfig{StateDir: stateDir}, hivetest.Lifecycle(t))
	require.NoError(t, err)

	wtx := restartedDB.WriteTxn(restartedWorkloads, restartedSubnets)
	_, _, err = restartedWorkloads.Insert(wtx, &tables.LocalWorkload{
		EndpointID: 100,
		Subnet:     "default-v4",
		Interface: iso_v1alpha1.PrivateNetworkEndpointSliceInterface{
			Network: "blue",
			MAC:     "02:aa:bb:cc:dd:ee",
			Addressing: iso_v1alpha1.PrivateNetworkEndpointAddressing{
				IPv4: "192.168.1.10",
			},
		},
	})
	require.NoError(t, err)
	_, _, err = restartedSubnets.Insert(wtx, tables.Subnet{
		SubnetSpec: tables.SubnetSpec{
			Network: "blue",
			Name:    "default-v4",
			CIDRv4:  netip.MustParsePrefix("192.168.1.0/24"),
		},
		DHCP: iso_v1alpha1.PrivateNetworkSubnetDHCPSpec{
			Mode: iso_v1alpha1.PrivateNetworkDHCPModeBroadcast,
		},
	})
	require.NoError(t, err)
	wtx.Commit()

	rtx := restartedDB.ReadTxn()
	restoredLease, _, found := restartedLeaseTable.Get(rtx, tables.DHCPLeaseByNetworkMAC("blue", mac.MustParseMAC("02:aa:bb:cc:dd:ee")))
	require.True(t, found)
	require.Equal(t, uint16(100), restoredLease.EndpointID)

	m := newDhcpLeaseReconciler(dhcpLeaseReconcilerParams{
		Log:         log,
		DB:          restartedDB,
		Workloads:   restartedWorkloads,
		LeaseWriter: restartedLeaseWriter,
		Subnets:     restartedSubnets,
	})
	m.handleExpiredLeases()

	rtx = restartedDB.ReadTxn()
	got, _, found := restartedWorkloads.Get(rtx, tables.LocalWorkloadsByID(100))
	require.True(t, found)
	require.Equal(t, "0.0.0.0", got.Interface.Addressing.IPv4)
}
