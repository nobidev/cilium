// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package reconcilerv2

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	"github.com/cilium/cilium/pkg/bgpv1/agent/signaler"
	"github.com/cilium/cilium/pkg/bgpv1/manager/instance"
	"github.com/cilium/cilium/pkg/bgpv1/manager/reconcilerv2"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/logging"
)

const (
	linkLocalTestTimeout = 5 * time.Second
)

type linkLocalTestFixture struct {
	hive *hive.Hive

	reconciler  *LinkLocalReconciler
	bgpSignaler *signaler.BGPCPSignaler
	upgrader    *upgraderMock

	db            *statedb.DB
	deviceTable   statedb.RWTable[*tables.Device]
	neighborTable statedb.RWTable[*tables.Neighbor]
}

func newLinkLocalTestFixture() *linkLocalTestFixture {
	f := &linkLocalTestFixture{}
	f.hive = hive.New(
		cell.Module("link-local-reconciler-test", "Link-local reconciler test",
			cell.Config(config.Config{
				Enabled: true,
			}),
			cell.Provide(
				tables.NewDeviceTable,
				tables.NewNeighborTable,

				statedb.RWTable[*tables.Device].ToTable,
				statedb.RWTable[*tables.Neighbor].ToTable,

				signaler.NewBGPCPSignaler,
				func() paramUpgrader {
					out := newUpgraderMock(nil)
					f.upgrader = out.(*upgraderMock)
					return out
				},
			),

			cell.Invoke(func(p LinkLocalReconcilerIn) {
				out := NewLinkLocalReconciler(p)
				f.reconciler = out.Reconciler.(*LinkLocalReconciler)
			}),
			cell.Invoke(func(sig *signaler.BGPCPSignaler) {
				f.bgpSignaler = sig
			}),

			cell.Invoke(statedb.RegisterTable[*tables.Device]),
			cell.Invoke(func(db *statedb.DB, table statedb.RWTable[*tables.Device]) {
				f.db = db
				f.deviceTable = table
			}),
			cell.Invoke(statedb.RegisterTable[*tables.Neighbor]),
			cell.Invoke(func(db *statedb.DB, table statedb.RWTable[*tables.Neighbor]) {
				f.neighborTable = table
			}),
		),
	)
	return f
}

func TestLinkLocalReconciler(t *testing.T) {
	logging.DefaultLogger.SetLevel(logrus.DebugLevel)

	instance := &instance.BGPInstance{
		Name: "test-instance",
	}
	iNodeInstance := &isovalentv1alpha1.IsovalentBGPNodeInstance{
		Name:     instance.Name,
		LocalASN: ptr.To[int64](65001),
	}
	ossNodeInstance := &v2alpha1.CiliumBGPNodeInstance{
		Name:     iNodeInstance.Name,
		LocalASN: iNodeInstance.LocalASN,
	}

	devices := []*tables.Device{
		{
			Index: 1,
			Name:  "eth0",
		},
		{
			Index: 2,
			Name:  "eth1",
		},
	}

	var table = []struct {
		name            string
		initPeers       []isovalentv1alpha1.IsovalentBGPNodePeer
		expectedPeers   []isovalentv1alpha1.IsovalentBGPNodePeer
		neighborChanges []*tables.Neighbor
		deleteNeighbors bool
		expectSignal    bool
	}{
		{
			name: "peer0 with peer address set - no change",
			initPeers: []isovalentv1alpha1.IsovalentBGPNodePeer{
				{
					Name:        "peer0",
					PeerAddress: ptr.To("fc00::aabb"),
				},
			},
			neighborChanges: []*tables.Neighbor{
				{
					LinkIndex: 999, // unrelated
					IPAddr:    netip.MustParseAddr("fe80::aabb:aaaa:bbbb:cccc"),
				},
			},
			expectSignal: false, // no signal as there is no unnumbered peer configured
			expectedPeers: []isovalentv1alpha1.IsovalentBGPNodePeer{
				{
					Name:        "peer0",
					PeerAddress: ptr.To("fc00::aabb"),
				},
			},
		},
		{
			name: "peer1 with no neighbor entry - no change",
			initPeers: []isovalentv1alpha1.IsovalentBGPNodePeer{
				{
					Name:      "peer1",
					Interface: ptr.To("eth0"),
				},
			},
			neighborChanges: nil,
			expectSignal:    false, // no neighbor change
			expectedPeers: []isovalentv1alpha1.IsovalentBGPNodePeer{
				{
					Name:      "peer1",
					Interface: ptr.To("eth0"),
				},
			},
		},
		{
			name: "peer1 with new neighbor entry - set peer address",
			initPeers: []isovalentv1alpha1.IsovalentBGPNodePeer{
				{
					Name:      "peer1",
					Interface: ptr.To("eth0"),
				},
			},
			neighborChanges: []*tables.Neighbor{
				{
					LinkIndex: 1,
					IPAddr:    netip.MustParseAddr("fe80::aabb:1111:2222:3333"),
				},
			},
			expectSignal: true,
			expectedPeers: []isovalentv1alpha1.IsovalentBGPNodePeer{
				{
					Name:        "peer1",
					Interface:   ptr.To("eth0"),
					PeerAddress: ptr.To("fe80::aabb:1111:2222:3333%eth0"),
				},
			},
		},
		{
			name: "peer1 with deleted neighbor entry - keep old peer address",
			initPeers: []isovalentv1alpha1.IsovalentBGPNodePeer{
				{
					Name:      "peer1",
					Interface: ptr.To("eth0"),
				},
			},
			neighborChanges: []*tables.Neighbor{
				{
					LinkIndex: 1,
					IPAddr:    netip.MustParseAddr("fe80::aabb:1111:2222:3333"),
				},
			},
			deleteNeighbors: true,
			expectSignal:    true,
			expectedPeers: []isovalentv1alpha1.IsovalentBGPNodePeer{
				{
					Name:        "peer1",
					Interface:   ptr.To("eth0"),
					PeerAddress: ptr.To("fe80::aabb:1111:2222:3333%eth0"),
				},
			},
		},
		{
			name: "peer1 with re-inserted neighbor entry - change peer address",
			initPeers: []isovalentv1alpha1.IsovalentBGPNodePeer{
				{
					Name:      "peer1",
					Interface: ptr.To("eth0"),
				},
			},
			neighborChanges: []*tables.Neighbor{
				{
					LinkIndex: 1,
					IPAddr:    netip.MustParseAddr("fe80::ffff:aaaa:bbbb:cccc"),
				},
			},
			expectSignal: true,
			expectedPeers: []isovalentv1alpha1.IsovalentBGPNodePeer{
				{
					Name:        "peer1",
					Interface:   ptr.To("eth0"),
					PeerAddress: ptr.To("fe80::ffff:aaaa:bbbb:cccc%eth0"),
				},
			},
		},
		{
			name: "peer2 with non-existing interface - do not set peer address",
			initPeers: []isovalentv1alpha1.IsovalentBGPNodePeer{
				{
					Name:      "peer2",
					Interface: ptr.To("eth99"),
				},
			},
			neighborChanges: nil,
			expectSignal:    false,
			expectedPeers: []isovalentv1alpha1.IsovalentBGPNodePeer{
				{
					Name:      "peer2",
					Interface: ptr.To("eth99"),
				},
			},
		},
		{
			name: "peer2 with non-link-local neighbor entry - do not set peer address",
			initPeers: []isovalentv1alpha1.IsovalentBGPNodePeer{
				{
					Name:      "peer2",
					Interface: ptr.To("eth1"),
				},
			},
			neighborChanges: []*tables.Neighbor{
				{
					LinkIndex: 2,
					IPAddr:    netip.MustParseAddr("fc00::aabb"),
				},
			},
			expectSignal: false, // not a link-local neighbor update
			expectedPeers: []isovalentv1alpha1.IsovalentBGPNodePeer{
				{
					Name:      "peer2",
					Interface: ptr.To("eth1"),
				},
			},
		},
		{
			name: "peer2 with a link-local neighbor entry - set peer address",
			initPeers: []isovalentv1alpha1.IsovalentBGPNodePeer{
				{
					Name:      "peer2",
					Interface: ptr.To("eth1"),
				},
			},
			neighborChanges: []*tables.Neighbor{
				{
					LinkIndex: 888, // unrelated
					IPAddr:    netip.MustParseAddr("fe80::aabb:aaaa:bbbb:cccc"),
				},
				{
					LinkIndex: 2,
					IPAddr:    netip.MustParseAddr("fe80::9999:8888:7777:6666"),
				},
			},
			expectSignal: true,
			expectedPeers: []isovalentv1alpha1.IsovalentBGPNodePeer{
				{
					Name:        "peer2",
					Interface:   ptr.To("eth1"),
					PeerAddress: ptr.To("fe80::9999:8888:7777:6666%eth1"),
				},
			},
		},
	}

	// create test fixture
	testCtx, cancel := context.WithTimeout(context.Background(), linkLocalTestTimeout)
	t.Cleanup(func() {
		cancel()
	})
	f := newLinkLocalTestFixture()

	// start the test hive
	log := hivetest.Logger(t)
	err := f.hive.Start(log, context.Background())
	require.NoError(t, err)
	t.Cleanup(func() {
		f.hive.Stop(log, context.Background())
	})
	f.reconciler.Init(instance)
	f.upgrader.setNodeInstance(iNodeInstance)

	// write devices to statedb
	txn := f.db.WriteTxn(f.deviceTable)
	for _, d := range devices {
		_, _, err = f.deviceTable.Insert(txn, d)
		require.NoError(t, err)
	}
	txn.Commit()

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			var err error

			// set initial peers
			iNodeInstance.Peers = tt.initPeers
			ossNodeInstance.Peers = nil
			for _, peer := range tt.initPeers {
				ossNodeInstance.Peers = append(ossNodeInstance.Peers, v2alpha1.CiliumBGPNodePeer{
					Name:        peer.Name,
					PeerAddress: peer.PeerAddress,
				})
			}

			// drain signaller channel
			for i := 0; i < len(f.bgpSignaler.Sig); i++ {
				<-f.bgpSignaler.Sig
			}

			// write neighbor changes to statedb
			txn := f.db.WriteTxn(f.neighborTable)
			for _, peer := range tt.neighborChanges {
				if tt.deleteNeighbors {
					_, _, err = f.neighborTable.Delete(txn, peer)
				} else {
					_, _, err = f.neighborTable.Insert(txn, peer)
				}
				require.NoError(t, err)
			}
			txn.Commit()

			if tt.expectSignal {
				// wait for BGP signal
				select {
				case <-f.bgpSignaler.Sig:
				case <-testCtx.Done():
					t.Fatalf("missed expected BGP reconciliation signal")
				}
			}

			// run reconciliation
			reconcileParams := reconcilerv2.ReconcileParams{
				BGPInstance:   instance,
				DesiredConfig: ossNodeInstance,
			}
			err = f.reconciler.Reconcile(testCtx, reconcileParams)
			require.NoError(t, err)

			// verify expected peers in CEE and OSS instances
			require.EqualValues(t, tt.expectedPeers, iNodeInstance.Peers)
			for i := range tt.expectedPeers {
				require.EqualValues(t, tt.expectedPeers[i].PeerAddress, ossNodeInstance.Peers[i].PeerAddress)
			}
		})
	}
}

func TestLinkLocalReconcilerMultipleInstances(t *testing.T) {
	logging.DefaultLogger.SetLevel(logrus.DebugLevel)

	var table = []struct {
		name            string
		nodeInstance    *isovalentv1alpha1.IsovalentBGPNodeInstance
		deleteInstance  bool
		neighborChanges []*tables.Neighbor
		deleteNeighbors bool
		expectSignal    bool
	}{
		{
			name: "instance1, peer with peer address set - no signal",
			nodeInstance: &isovalentv1alpha1.IsovalentBGPNodeInstance{
				Name:     "instance-1",
				LocalASN: ptr.To[int64](65001),
				Peers: []isovalentv1alpha1.IsovalentBGPNodePeer{
					{
						Name:        "peer1",
						PeerAddress: ptr.To("fc00::aabb"),
					},
				},
			},
			neighborChanges: []*tables.Neighbor{
				{
					LinkIndex: 1,
					IPAddr:    netip.MustParseAddr("fe80::aabb:aaaa:bbbb:1111"),
				},
			},
			expectSignal: false,
		},
		{
			name: "instance2, unnumbered peer - signal",
			nodeInstance: &isovalentv1alpha1.IsovalentBGPNodeInstance{
				Name:     "instance-2",
				LocalASN: ptr.To[int64](65002),
				Peers: []isovalentv1alpha1.IsovalentBGPNodePeer{
					{
						Name:      "peer2",
						Interface: ptr.To("eth2"),
					},
				},
			},
			neighborChanges: []*tables.Neighbor{
				{
					LinkIndex: 2,
					IPAddr:    netip.MustParseAddr("fe80::9999:8888:7777:2222"),
				},
			},
			expectSignal: true,
		},
		{
			name: "instance1, unnumbered peer - signal",
			nodeInstance: &isovalentv1alpha1.IsovalentBGPNodeInstance{
				Name:     "instance-1",
				LocalASN: ptr.To[int64](65001),
				Peers: []isovalentv1alpha1.IsovalentBGPNodePeer{
					{
						Name:      "peer1",
						Interface: ptr.To("eth1"),
					},
				},
			},
			neighborChanges: []*tables.Neighbor{
				{
					LinkIndex: 1,
					IPAddr:    netip.MustParseAddr("fe80::9999:8888:7777:3333"),
				},
			},
			expectSignal: true,
		},
		{
			name: "delete instance2",
			nodeInstance: &isovalentv1alpha1.IsovalentBGPNodeInstance{
				Name: "instance-2",
			},
			deleteInstance: true,
		},
		{
			name: "instance1, unnumbered peer - signal",
			nodeInstance: &isovalentv1alpha1.IsovalentBGPNodeInstance{
				Name:     "instance-1",
				LocalASN: ptr.To[int64](65001),
				Peers: []isovalentv1alpha1.IsovalentBGPNodePeer{
					{
						Name:      "peer2",
						Interface: ptr.To("eth2"),
					},
				},
			},
			neighborChanges: []*tables.Neighbor{
				{
					LinkIndex: 2,
					IPAddr:    netip.MustParseAddr("fe80::9999:8888:7777:4444"),
				},
			},
			expectSignal: true,
		},
		{
			name: "delete instance1",
			nodeInstance: &isovalentv1alpha1.IsovalentBGPNodeInstance{
				Name: "instance-1",
			},
			deleteInstance: true,
		},
		{
			name: "instance3, peer with peer address set - no signal",
			nodeInstance: &isovalentv1alpha1.IsovalentBGPNodeInstance{
				Name:     "instance-3",
				LocalASN: ptr.To[int64](65001),
				Peers: []isovalentv1alpha1.IsovalentBGPNodePeer{
					{
						Name:        "peer3",
						PeerAddress: ptr.To("fc00::aabb"),
					},
				},
			},
			neighborChanges: []*tables.Neighbor{
				{
					LinkIndex: 3,
					IPAddr:    netip.MustParseAddr("fe80::aabb:aaaa:bbbb:5555"),
				},
			},
			expectSignal: false,
		},
		{
			name: "instance3,  unnumbered peer - signal",
			nodeInstance: &isovalentv1alpha1.IsovalentBGPNodeInstance{
				Name:     "instance-3",
				LocalASN: ptr.To[int64](65001),
				Peers: []isovalentv1alpha1.IsovalentBGPNodePeer{
					{
						Name:      "peer4",
						Interface: ptr.To("eth4"),
					},
				},
			},
			neighborChanges: []*tables.Neighbor{
				{
					LinkIndex: 4,
					IPAddr:    netip.MustParseAddr("fe80::aabb:aaaa:bbbb:6666"),
				},
			},
			expectSignal: true,
		},
	}

	// create test fixture
	testCtx, cancel := context.WithTimeout(context.Background(), linkLocalTestTimeout)
	t.Cleanup(func() {
		cancel()
	})
	f := newLinkLocalTestFixture()

	// start the test hive
	log := hivetest.Logger(t)
	err := f.hive.Start(log, context.Background())
	require.NoError(t, err)
	t.Cleanup(func() {
		f.hive.Stop(log, context.Background())
	})

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			var err error

			// configure instances
			instance := &instance.BGPInstance{
				Name: tt.nodeInstance.Name,
			}
			ossNodeInstance := &v2alpha1.CiliumBGPNodeInstance{
				Name:     tt.nodeInstance.Name,
				LocalASN: tt.nodeInstance.LocalASN,
			}
			for _, peer := range tt.nodeInstance.Peers {
				ossNodeInstance.Peers = append(ossNodeInstance.Peers, v2alpha1.CiliumBGPNodePeer{
					Name:        peer.Name,
					PeerAddress: peer.PeerAddress,
				})
			}
			if tt.deleteInstance {
				f.reconciler.Cleanup(instance)
				return
			}
			f.reconciler.Init(instance)
			f.upgrader.setNodeInstance(tt.nodeInstance)

			// run reconciliation
			reconcileParams := reconcilerv2.ReconcileParams{
				BGPInstance:   instance,
				DesiredConfig: ossNodeInstance,
			}
			err = f.reconciler.Reconcile(testCtx, reconcileParams)
			require.NoError(t, err)

			// drain signaller channel
			for i := 0; i < len(f.bgpSignaler.Sig); i++ {
				<-f.bgpSignaler.Sig
			}

			// write neighbor changes to statedb
			txn := f.db.WriteTxn(f.neighborTable)
			for _, peer := range tt.neighborChanges {
				if tt.deleteNeighbors {
					_, _, err = f.neighborTable.Delete(txn, peer)
				} else {
					_, _, err = f.neighborTable.Insert(txn, peer)
				}
				require.NoError(t, err)
			}
			txn.Commit()

			if tt.expectSignal {
				// wait for BGP signal
				select {
				case <-f.bgpSignaler.Sig:
				case <-testCtx.Done():
					t.Fatalf("missed expected BGP reconciliation signal")
				}
			}
		})
	}
}
