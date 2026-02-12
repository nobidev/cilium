//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package reconciler

import (
	"context"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/cilium/stream"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/enterprise/pkg/bfd/types"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

const (
	testTimeout = 5 * time.Second
)

func Test_BFDReconciler(t *testing.T) {
	var (
		bfdPeerName        = "test-peer-1"
		bfdPeerIP          = "10.0.0.1"
		bfdPeerIP2         = "10.0.0.2"
		bfdPeerLinkLocalIP = "fe80::aabb:aaaa:bbbb:1111"
		bfdPeerIPAddr      = netip.MustParseAddr(bfdPeerIP)
		bfdPeerIPAddr2     = netip.MustParseAddr(bfdPeerIP2)
		bfdPeerInterface   = "eth0"

		bfdPeer2Name        = "test-peer-2"
		bfdPeer2IP          = "10.0.0.2"
		bfdPeer2LinkLocalIP = "fe80::aabb:aaaa:bbbb:2222"
		bfdPeer2IPAddr      = netip.MustParseAddr(bfdPeer2IP)
		bfdPeer2Interface   = "eth1"

		bfdProfileName  = "test-profile"
		bfdProfileSpec1 = v1alpha1.BFDProfileSpec{
			ReceiveIntervalMilliseconds:  ptr.To[int32](10),
			TransmitIntervalMilliseconds: ptr.To[int32](20),
			DetectMultiplier:             ptr.To[int32](3),
			MinimumTTL:                   ptr.To[int32](255),
			EchoFunction: &v1alpha1.BFDEchoFunctionConfig{
				Directions: []v1alpha1.BFDEchoFunctionDirection{
					v1alpha1.BFDEchoFunctionDirectionReceive,
				},
				ReceiveIntervalMilliseconds: ptr.To[int32](5),
			},
		}
		bfdStatusProfile1 = types.BFDSessionStatus{
			State:               types.BFDStateDown,
			ReceiveInterval:     10 * time.Millisecond,
			TransmitInterval:    20 * time.Millisecond,
			DetectMultiplier:    3,
			EchoReceiveInterval: 5 * time.Millisecond,
		}

		bfdProfileSpec2 = v1alpha1.BFDProfileSpec{
			ReceiveIntervalMilliseconds:  ptr.To[int32](11),
			TransmitIntervalMilliseconds: ptr.To[int32](21),
			DetectMultiplier:             ptr.To[int32](4),
			MinimumTTL:                   ptr.To[int32](255),
			EchoFunction: &v1alpha1.BFDEchoFunctionConfig{
				Directions: []v1alpha1.BFDEchoFunctionDirection{
					v1alpha1.BFDEchoFunctionDirectionReceive,
				},
				ReceiveIntervalMilliseconds: ptr.To[int32](55),
			},
		}
		bfdStatusProfile2 = types.BFDSessionStatus{
			State:               types.BFDStateDown,
			ReceiveInterval:     11 * time.Millisecond,
			TransmitInterval:    21 * time.Millisecond,
			DetectMultiplier:    4,
			EchoReceiveInterval: 55 * time.Millisecond,
		}

		bfdProfileSpecMultihop = v1alpha1.BFDProfileSpec{
			ReceiveIntervalMilliseconds:  ptr.To[int32](11),
			TransmitIntervalMilliseconds: ptr.To[int32](21),
			DetectMultiplier:             ptr.To[int32](4),
			MinimumTTL:                   ptr.To[int32](200),
		}
		bfdStatusMultihop = types.BFDSessionStatus{
			State:            types.BFDStateDown,
			ReceiveInterval:  11 * time.Millisecond,
			TransmitInterval: 21 * time.Millisecond,
			DetectMultiplier: 4,
		}

		devices = []*tables.Device{
			{
				Index: 1,
				Name:  bfdPeerInterface,
			},
			{
				Index: 2,
				Name:  bfdPeer2Interface,
			},
		}
	)

	var steps = []struct {
		description    string
		operation      string // "create" / "update" / "delete"
		bfdProfiles    []*v1alpha1.IsovalentBFDProfile
		nodeConfigs    []*v1alpha1.IsovalentBFDNodeConfig
		neighbors      []*tables.Neighbor
		expectStatus   *types.BFDPeerStatus
		expectDelete   bool
		expectRecreate bool
	}{
		{
			description: "Add node config with missing profile",
			operation:   "create",
			bfdProfiles: nil,
			nodeConfigs: []*v1alpha1.IsovalentBFDNodeConfig{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: testNodeName,
					},
					Spec: v1alpha1.BFDNodeConfigSpec{
						NodeRef: testNodeName,
						Peers: []*v1alpha1.BFDNodePeerConfig{
							{
								Name:          bfdPeerName,
								PeerAddress:   &bfdPeerIP,
								Interface:     ptr.To[string](bfdPeerInterface),
								BFDProfileRef: bfdProfileName,
							},
						},
					},
				},
			},
			expectStatus: nil,
		},
		{
			description: "Add profile used in node config",
			operation:   "create",
			bfdProfiles: []*v1alpha1.IsovalentBFDProfile{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: bfdProfileName,
					},
					Spec: bfdProfileSpec1,
				},
			},
			nodeConfigs: nil,
			expectStatus: &types.BFDPeerStatus{
				PeerAddress: bfdPeerIPAddr,
				Interface:   bfdPeerInterface,
				Local:       bfdStatusProfile1,
			},
		},
		{
			description: "Update BFD profile - timer intervals",
			operation:   "update",
			bfdProfiles: []*v1alpha1.IsovalentBFDProfile{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: bfdProfileName,
					},
					Spec: bfdProfileSpec2,
				},
			},
			nodeConfigs: nil,
			expectStatus: &types.BFDPeerStatus{
				PeerAddress: bfdPeerIPAddr,
				Interface:   bfdPeerInterface,
				Local:       bfdStatusProfile2,
			},
		},
		{
			description: "Update BFD profile - multihop - recreate",
			operation:   "update",
			bfdProfiles: []*v1alpha1.IsovalentBFDProfile{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: bfdProfileName,
					},
					Spec: bfdProfileSpecMultihop,
				},
			},
			nodeConfigs: nil,
			expectStatus: &types.BFDPeerStatus{
				PeerAddress: bfdPeerIPAddr,
				Interface:   bfdPeerInterface,
				Local:       bfdStatusMultihop,
			},
			expectRecreate: true,
		},
		{
			description: "Delete BFD profile",
			operation:   "delete",
			bfdProfiles: []*v1alpha1.IsovalentBFDProfile{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: bfdProfileName,
					},
					Spec: bfdProfileSpecMultihop,
				},
			},
			nodeConfigs: nil,
			expectStatus: &types.BFDPeerStatus{
				PeerAddress: bfdPeerIPAddr,
				Interface:   bfdPeerInterface,
				Local:       bfdStatusMultihop,
			},
			expectDelete: true,
		},
		{
			description: "Re-create BFD profile",
			operation:   "create",
			bfdProfiles: []*v1alpha1.IsovalentBFDProfile{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: bfdProfileName,
					},
					Spec: bfdProfileSpec1,
				},
			},
			nodeConfigs: nil,
			expectStatus: &types.BFDPeerStatus{
				PeerAddress: bfdPeerIPAddr,
				Interface:   bfdPeerInterface,
				Local:       bfdStatusProfile1,
			},
		},
		{
			description: "Update BFD node config - peer address - recreate",
			operation:   "update",
			bfdProfiles: nil,
			nodeConfigs: []*v1alpha1.IsovalentBFDNodeConfig{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: testNodeName,
					},
					Spec: v1alpha1.BFDNodeConfigSpec{
						NodeRef: testNodeName,
						Peers: []*v1alpha1.BFDNodePeerConfig{
							{
								Name:          bfdPeerName,
								PeerAddress:   &bfdPeerIP2,
								Interface:     ptr.To[string](bfdPeerInterface),
								BFDProfileRef: bfdProfileName,
							},
						},
					},
				},
			},
			expectStatus: &types.BFDPeerStatus{
				PeerAddress: bfdPeerIPAddr2,
				Interface:   bfdPeerInterface,
				Local:       bfdStatusProfile1,
			},
			expectRecreate: true,
		},
		{
			description: "Update BFD node config - remove peer",
			operation:   "update",
			bfdProfiles: nil,
			nodeConfigs: []*v1alpha1.IsovalentBFDNodeConfig{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: testNodeName,
					},
					Spec: v1alpha1.BFDNodeConfigSpec{
						NodeRef: testNodeName,
						Peers:   []*v1alpha1.BFDNodePeerConfig{},
					},
				},
			},
			expectStatus: &types.BFDPeerStatus{
				PeerAddress: bfdPeerIPAddr2,
				Interface:   bfdPeerInterface,
				Local:       bfdStatusProfile1,
			},
			expectDelete: true,
		},
		{
			description: "Update BFD node config - add peer back",
			operation:   "update",
			bfdProfiles: nil,
			nodeConfigs: []*v1alpha1.IsovalentBFDNodeConfig{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: testNodeName,
					},
					Spec: v1alpha1.BFDNodeConfigSpec{
						NodeRef: testNodeName,
						Peers: []*v1alpha1.BFDNodePeerConfig{
							{
								Name:          bfdPeerName,
								PeerAddress:   &bfdPeerIP,
								Interface:     ptr.To[string](bfdPeerInterface),
								BFDProfileRef: bfdProfileName,
							},
						},
					},
				},
			},
			expectStatus: &types.BFDPeerStatus{
				PeerAddress: bfdPeerIPAddr,
				Interface:   bfdPeerInterface,
				Local:       bfdStatusProfile1,
			},
		},
		{
			description: "Update BFD node config - add 2nd peer",
			operation:   "update",
			bfdProfiles: nil,
			nodeConfigs: []*v1alpha1.IsovalentBFDNodeConfig{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: testNodeName,
					},
					Spec: v1alpha1.BFDNodeConfigSpec{
						NodeRef: testNodeName,
						Peers: []*v1alpha1.BFDNodePeerConfig{
							{
								Name:          bfdPeerName,
								PeerAddress:   &bfdPeerIP,
								Interface:     ptr.To[string](bfdPeerInterface),
								BFDProfileRef: bfdProfileName,
							},
							{
								Name:          bfdPeer2Name,
								PeerAddress:   &bfdPeer2IP,
								Interface:     ptr.To[string](bfdPeer2Interface),
								BFDProfileRef: bfdProfileName,
							},
						},
					},
				},
			},
			expectStatus: &types.BFDPeerStatus{
				PeerAddress: bfdPeer2IPAddr,
				Interface:   bfdPeer2Interface,
				Local:       bfdStatusProfile1,
			},
		},
		{
			description: "Update BFD node config - remove 2nd peer",
			operation:   "update",
			bfdProfiles: nil,
			nodeConfigs: []*v1alpha1.IsovalentBFDNodeConfig{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: testNodeName,
					},
					Spec: v1alpha1.BFDNodeConfigSpec{
						NodeRef: testNodeName,
						Peers: []*v1alpha1.BFDNodePeerConfig{
							{
								Name:          bfdPeerName,
								PeerAddress:   &bfdPeerIP,
								Interface:     ptr.To[string](bfdPeerInterface),
								BFDProfileRef: bfdProfileName,
							},
						},
					},
				},
			},
			expectStatus: &types.BFDPeerStatus{
				PeerAddress: bfdPeer2IPAddr,
				Interface:   bfdPeer2Interface,
				Local:       bfdStatusProfile1,
			},
			expectDelete: true,
		},
		{
			description: "Update BFD node config - invalid NodeRef",
			operation:   "update",
			bfdProfiles: nil,
			nodeConfigs: []*v1alpha1.IsovalentBFDNodeConfig{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: testNodeName,
					},
					Spec: v1alpha1.BFDNodeConfigSpec{
						NodeRef: "some-other-node",
						Peers:   []*v1alpha1.BFDNodePeerConfig{},
					},
				},
			},
			expectStatus: &types.BFDPeerStatus{
				PeerAddress: bfdPeerIPAddr,
				Interface:   bfdPeerInterface,
				Local:       bfdStatusProfile1,
			},
			expectDelete: true,
		},
		{
			description: "Update BFD node config - correct NodeRef",
			operation:   "update",
			bfdProfiles: nil,
			nodeConfigs: []*v1alpha1.IsovalentBFDNodeConfig{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: testNodeName,
					},
					Spec: v1alpha1.BFDNodeConfigSpec{
						NodeRef: testNodeName,
						Peers: []*v1alpha1.BFDNodePeerConfig{
							{
								Name:          bfdPeerName,
								PeerAddress:   &bfdPeerIP,
								Interface:     ptr.To[string](bfdPeerInterface),
								BFDProfileRef: bfdProfileName,
							},
						},
					},
				},
			},
			expectStatus: &types.BFDPeerStatus{
				PeerAddress: bfdPeerIPAddr,
				Interface:   bfdPeerInterface,
				Local:       bfdStatusProfile1,
			},
		},
		{
			description: "Remove BFD node config",
			operation:   "delete",
			bfdProfiles: nil,
			nodeConfigs: []*v1alpha1.IsovalentBFDNodeConfig{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: testNodeName,
					},
					Spec: v1alpha1.BFDNodeConfigSpec{
						NodeRef: testNodeName,
						Peers:   []*v1alpha1.BFDNodePeerConfig{},
					},
				},
			},
			expectStatus: &types.BFDPeerStatus{
				PeerAddress: bfdPeerIPAddr,
				Interface:   bfdPeerInterface,
				Local:       bfdStatusProfile1,
			},
			expectDelete: true,
		},
		{
			description: "Create multiple conflicting node configs - best effort reconciliation",
			operation:   "create",
			bfdProfiles: nil,
			nodeConfigs: []*v1alpha1.IsovalentBFDNodeConfig{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: testNodeName + "-1",
					},
					Spec: v1alpha1.BFDNodeConfigSpec{
						NodeRef: testNodeName,
						Peers: []*v1alpha1.BFDNodePeerConfig{
							{
								Name:          bfdPeerName + "-1",
								Interface:     ptr.To[string](bfdPeerInterface),
								PeerAddress:   &bfdPeerIP,
								BFDProfileRef: bfdProfileName,
							},
							{
								Name:          bfdPeerName + "-2",
								Interface:     ptr.To[string](bfdPeerInterface),
								PeerAddress:   &bfdPeerIP,
								BFDProfileRef: bfdProfileName,
							},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: testNodeName + "-2",
					},
					Spec: v1alpha1.BFDNodeConfigSpec{
						NodeRef: testNodeName,
						Peers: []*v1alpha1.BFDNodePeerConfig{
							{
								Name:          bfdPeerName,
								Interface:     ptr.To[string](bfdPeerInterface),
								PeerAddress:   &bfdPeerIP,
								BFDProfileRef: bfdProfileName,
							},
						},
					},
				},
			},
			expectStatus: &types.BFDPeerStatus{
				PeerAddress: bfdPeerIPAddr,
				Interface:   bfdPeerInterface,
				Local:       bfdStatusProfile1,
			},
		},
		{
			description: "Create LL neighbor table entry for link 1",
			operation:   "create",
			neighbors: []*tables.Neighbor{
				{
					LinkIndex: 1,
					IPAddr:    netip.MustParseAddr(bfdPeerLinkLocalIP),
				},
			},
			bfdProfiles:  nil,
			nodeConfigs:  nil,
			expectStatus: nil,
		},
		{
			description: "Create BFD node config with unnumbered BFD peers",
			operation:   "create",
			bfdProfiles: nil,
			nodeConfigs: []*v1alpha1.IsovalentBFDNodeConfig{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: testNodeName + "-unnumbered",
					},
					Spec: v1alpha1.BFDNodeConfigSpec{
						NodeRef: testNodeName,
						Peers: []*v1alpha1.BFDNodePeerConfig{
							{
								Name:          bfdPeerName + "-unnumbered",
								Interface:     ptr.To[string](bfdPeerInterface), // neighbor already in the neighbor table
								BFDProfileRef: bfdProfileName,
							},
							{
								Name:          bfdPeer2Name + "-unnumbered",
								Interface:     ptr.To[string](bfdPeer2Interface), // neighbor not yet in the neighbor table
								BFDProfileRef: bfdProfileName,
							},
						},
					},
				},
			},
			expectStatus: &types.BFDPeerStatus{
				PeerAddress: netip.MustParseAddr(bfdPeerLinkLocalIP).WithZone(bfdPeerInterface),
				Interface:   bfdPeerInterface,
				Local:       bfdStatusProfile1,
			},
		},
		{
			description: "Create neighbor table entry for link 2",
			operation:   "create",
			neighbors: []*tables.Neighbor{
				{
					LinkIndex: 2,
					IPAddr:    netip.MustParseAddr(bfdPeer2LinkLocalIP),
				},
			},
			bfdProfiles: nil,
			nodeConfigs: nil,
			expectStatus: &types.BFDPeerStatus{
				PeerAddress: netip.MustParseAddr(bfdPeer2LinkLocalIP).WithZone(bfdPeer2Interface),
				Interface:   bfdPeer2Interface,
				Local:       bfdStatusProfile1,
			},
		},
	}

	// create test fixture
	testCtx, cancel := context.WithTimeout(context.Background(), testTimeout)
	t.Cleanup(func() {
		cancel()
	})
	f, waitWatchersReady := newTestFixture(t, testCtx)

	// start the test hive
	log := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))
	err := f.hive.Start(log, context.Background())
	require.NoError(t, err)
	t.Cleanup(func() {
		f.hive.Stop(log, context.Background())
	})

	// wait until the watchers are ready
	waitWatchersReady()

	observable := statedb.Observable[*types.BFDPeerStatus](f.db, f.peerTable)
	peersEventCh := stream.ToChannel(testCtx, observable)

	// write devices to statedb
	txn := f.db.WriteTxn(f.deviceTable)
	for _, d := range devices {
		_, _, err = f.deviceTable.Insert(txn, d)
		require.NoError(t, err)
	}
	txn.Commit()

	// run the test steps
	for _, step := range steps {
		t.Run(step.description, func(t *testing.T) {
			// CRUD BFD profiles
			for _, profile := range step.bfdProfiles {
				switch step.operation {
				case "create":
					_, err = f.profileClient.Create(testCtx, profile, metav1.CreateOptions{})
				case "update":
					var prev *v1alpha1.IsovalentBFDProfile
					prev, err = f.profileClient.Get(testCtx, profile.GetName(), metav1.GetOptions{})
					if err == nil {
						profile.SetResourceVersion(prev.GetResourceVersion())
						_, err = f.profileClient.Update(testCtx, profile, metav1.UpdateOptions{})
					}
				case "delete":
					err = f.profileClient.Delete(testCtx, profile.Name, metav1.DeleteOptions{})
				}
				require.NoError(t, err)
			}
			// CRUD BFD node configs
			for _, nc := range step.nodeConfigs {
				switch step.operation {
				case "create":
					_, err = f.ncClient.Create(testCtx, nc, metav1.CreateOptions{})
				case "update":
					var prev *v1alpha1.IsovalentBFDNodeConfig
					prev, err = f.ncClient.Get(testCtx, nc.GetName(), metav1.GetOptions{})
					if err == nil {
						nc.SetResourceVersion(prev.GetResourceVersion())
						_, err = f.ncClient.Update(testCtx, nc, metav1.UpdateOptions{})
					}
				case "delete":
					err = f.ncClient.Delete(testCtx, nc.Name, metav1.DeleteOptions{})
				}
				require.NoError(t, err)
			}
			// CRUD neighbors
			for _, peer := range step.neighbors {
				txn := f.db.WriteTxn(f.neighborTable)
				switch step.operation {
				case "create":
					fallthrough
				case "update":
					_, _, err = f.neighborTable.Insert(txn, peer)
				case "delete":
					_, _, err = f.neighborTable.Delete(txn, peer)
				}
				require.NoError(t, err)
				txn.Commit()
			}
			// validate that the expected status event comes
			if step.expectStatus != nil {
			nextEvent:
				select {
				case event := <-peersEventCh:
					if event.Object.Local.State == types.BFDStateAdminDown {
						// ignore initial events with AdminDown state,
						// created for a session that was not yet configured on the BFD server.
						goto nextEvent
					}
					if statusMatches(step.expectStatus, event.Object) {
						if event.Deleted {
							if step.expectRecreate {
								// Deleted event is expected during recreate, but non-delete should follow.
								// Deleted event may not come during recreate if it was coalesced by statedb.
								goto nextEvent
							}
							if !step.expectDelete {
								t.Fatalf("update event expected, got delete %+v", event.Object)
							}
						} else if step.expectDelete {
							t.Fatalf("delete event expected, got update %+v", event.Object)
						}
						return // event matched - pass
					}
					goto nextEvent
				case <-testCtx.Done():
					t.Fatalf("missed expected event(s) %+v", step.expectStatus)
				}
			} else {
				// if no event is expected, validate there is none within a small time window
				timer := time.NewTimer(50 * time.Millisecond)
				select {
				case event := <-peersEventCh:
					t.Fatalf("unexpected event: %+v", event)
				case <-timer.C:
					// pass
				}
			}
		})
	}
}

func statusMatches(expected, actual *types.BFDPeerStatus) bool {
	return expected.PeerAddress == actual.PeerAddress &&
		expected.Interface == actual.Interface &&
		expected.Local.State == actual.Local.State &&
		expected.Local.ReceiveInterval == actual.Local.ReceiveInterval &&
		expected.Local.TransmitInterval == actual.Local.TransmitInterval &&
		expected.Local.EchoReceiveInterval == actual.Local.EchoReceiveInterval &&
		expected.Local.DetectMultiplier == actual.Local.DetectMultiplier
}

func Test_detectEgressInterface(t *testing.T) {
	ifName, err := detectEgressInterface(netip.MustParseAddr("127.0.0.1"), netip.Addr{})
	require.NoError(t, err)
	require.NotEmpty(t, ifName)

	ifName, err = detectEgressInterface(netip.Addr{}, netip.MustParseAddr("1.2.3.4"))
	require.NoError(t, err)
	require.NotEmpty(t, ifName)

	ifName, err = detectEgressInterface(netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("1.2.3.4"))
	require.NoError(t, err)
	require.NotEmpty(t, ifName)
}
