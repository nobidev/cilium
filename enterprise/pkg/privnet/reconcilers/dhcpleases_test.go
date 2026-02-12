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
	"net"
	"testing"

	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	iso_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/time"
)

func TestDhcpReconcilerDropsLeasesWhenDHCPDisabled(t *testing.T) {
	db := statedb.New()
	workloads, err := tables.NewLocalWorkloadsTable(db)
	require.NoError(t, err)
	leases, err := tables.NewDHCPLeasesTable(db)
	require.NoError(t, err)

	lw := &tables.LocalWorkload{
		EndpointID: 100,
		DHCP:       true,
		Interface: iso_v1alpha1.PrivateNetworkEndpointSliceInterface{
			Network: "blue",
			MAC:     "02:aa:bb:cc:dd:ee",
			Addressing: iso_v1alpha1.PrivateNetworkEndpointAddressing{
				IPv4: "192.168.1.10",
			},
		},
	}

	wtxn := db.WriteTxn(workloads, leases)
	workloads.Insert(wtxn, lw)
	leases.Insert(wtxn, tables.DHCPLease{
		Network:    "blue",
		EndpointID: 100,
		MAC:        mac.MAC(net.HardwareAddr{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee}),
	})
	wtxn.Commit()

	m := newDhcpLeaseReconciler(nil, nil, db, workloads, leases)
	wtxn = db.WriteTxn(workloads, leases)
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
	leases, err := tables.NewDHCPLeasesTable(db)
	require.NoError(t, err)

	now := time.Now()

	expired := &tables.LocalWorkload{
		EndpointID: 100,
		DHCP:       true,
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
		DHCP:       true,
		Interface: iso_v1alpha1.PrivateNetworkEndpointSliceInterface{
			Network: "blue",
			MAC:     "02:aa:bb:cc:dd:ef",
			Addressing: iso_v1alpha1.PrivateNetworkEndpointAddressing{
				IPv4: "192.168.1.11",
			},
		},
	}

	wtx := db.WriteTxn(workloads, leases)
	workloads.Insert(wtx, expired)
	workloads.Insert(wtx, active)
	leases.Insert(wtx, tables.DHCPLease{
		Network:    "blue",
		EndpointID: expired.EndpointID,
		MAC:        mac.MAC(net.HardwareAddr{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee}),
		ExpireAt:   now.Add(-time.Minute),
	})
	leases.Insert(wtx, tables.DHCPLease{
		Network:    "blue",
		EndpointID: active.EndpointID,
		MAC:        mac.MAC(net.HardwareAddr{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xef}),
		ExpireAt:   now.Add(time.Minute),
	})
	wtx.Commit()

	m := newDhcpLeaseReconciler(nil, nil, db, workloads, leases)
	m.handleExpiredLeases()

	rtx := db.ReadTxn()
	gotExpired, _, found := workloads.Get(rtx, tables.LocalWorkloadsByID(expired.EndpointID))
	require.True(t, found)
	require.Empty(t, gotExpired.Interface.Addressing.IPv4)

	gotActive, _, found := workloads.Get(rtx, tables.LocalWorkloadsByID(active.EndpointID))
	require.True(t, found)
	require.Equal(t, "192.168.1.11", gotActive.Interface.Addressing.IPv4)
}
