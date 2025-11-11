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
	"log/slog"
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	"github.com/cilium/cilium/pkg/bgp/manager/instance"
	"github.com/cilium/cilium/pkg/bgp/manager/reconciler"
	"github.com/cilium/cilium/pkg/bgp/manager/store"
	"github.com/cilium/cilium/pkg/bgp/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/option"
)

type checks struct {
	holdTimer         bool
	connectRetryTimer bool
	keepaliveTimer    bool
	grRestartTime     bool
}

var (
	peerData1 = PeerData{
		Peer: &v1.IsovalentBGPNodePeer{
			Name:        "peer-1",
			PeerAddress: ptr.To[string]("192.168.0.1"),
			PeerASN:     ptr.To[int64](64124),
			PeerConfigRef: &v1.PeerConfigReference{
				Name: "peer-config",
			},
		},
		Config: &v1.IsovalentBGPPeerConfigSpec{
			Transport: &v2.CiliumBGPTransport{
				PeerPort: ptr.To[int32](v2.DefaultBGPPeerPort),
			},
		},
	}

	peerData2 = PeerData{
		Peer: &v1.IsovalentBGPNodePeer{
			Name:        "peer-2",
			PeerAddress: ptr.To[string]("192.168.0.2"),
			PeerASN:     ptr.To[int64](64124),
			PeerConfigRef: &v1.PeerConfigReference{
				Name: "peer-config",
			},
		},
		Config: &v1.IsovalentBGPPeerConfigSpec{
			Transport: &v2.CiliumBGPTransport{
				PeerPort: ptr.To[int32](v2.DefaultBGPPeerPort),
			},
		},
	}

	peer2UpdatedASN = func() PeerData {
		peer2Copy := PeerData{
			Peer:     peerData2.Peer.DeepCopy(),
			Config:   peerData2.Config.DeepCopy(),
			Password: peerData2.Password,
		}

		peer2Copy.Peer.PeerASN = ptr.To[int64](64125)
		return peer2Copy
	}()

	peer2UpdatedTimers = func() PeerData {
		peer2Copy := PeerData{
			Peer:     peerData2.Peer.DeepCopy(),
			Config:   peerData2.Config.DeepCopy(),
			Password: peerData2.Password,
		}

		peer2Copy.Config.Timers = &v2.CiliumBGPTimers{
			ConnectRetryTimeSeconds: ptr.To[int32](3),
			HoldTimeSeconds:         ptr.To[int32](9),
			KeepAliveTimeSeconds:    ptr.To[int32](3),
		}

		return peer2Copy
	}()

	peer2UpdatedPorts = func() PeerData {
		peer2Copy := PeerData{
			Peer:     peerData2.Peer.DeepCopy(),
			Config:   peerData2.Config.DeepCopy(),
			Password: peerData2.Password,
		}

		peer2Copy.Config.Transport = &v2.CiliumBGPTransport{
			PeerPort: ptr.To[int32](1790),
		}

		return peer2Copy
	}()

	peer2UpdatedGR = func() PeerData {
		peer2Copy := PeerData{
			Peer:     peerData2.Peer.DeepCopy(),
			Config:   peerData2.Config.DeepCopy(),
			Password: peerData2.Password,
		}

		peer2Copy.Config.GracefulRestart = &v2.CiliumBGPNeighborGracefulRestart{
			Enabled:            true,
			RestartTimeSeconds: ptr.To[int32](3),
		}

		return peer2Copy
	}()

	peer2Pass = func() PeerData {
		peer2Copy := PeerData{
			Peer:     peerData2.Peer.DeepCopy(),
			Config:   peerData2.Config.DeepCopy(),
			Password: peerData2.Password,
		}

		peer2Copy.Config.AuthSecretRef = ptr.To[string]("a-secret")
		peer2Copy.Password = "a-password"

		return peer2Copy
	}()

	peer2UpdatePass = func() PeerData {
		peer2Copy := PeerData{
			Peer:     peerData2.Peer.DeepCopy(),
			Config:   peerData2.Config.DeepCopy(),
			Password: peerData2.Password,
		}

		peer2Copy.Config.AuthSecretRef = ptr.To[string]("a-secret")
		peer2Copy.Password = "b-password"

		return peer2Copy
	}()
)

// TestNeighborReconciler confirms the `neighborReconciler` function configures
// the desired BGP neighbors given a CiliumBGPVirtualRouter configuration.
func TestNeighborReconciler(t *testing.T) {
	req := require.New(t)
	logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))

	table := []struct {
		name         string
		neighbors    []PeerData
		newNeighbors []PeerData
		secretStore  resource.Store[*slim_corev1.Secret]
		checks       checks
		err          error
	}{
		{
			name:         "no change",
			neighbors:    []PeerData{peerData1, peerData2},
			newNeighbors: []PeerData{peerData1, peerData2},
			err:          nil,
		},
		{
			name:         "add peers",
			neighbors:    []PeerData{peerData1},
			newNeighbors: []PeerData{peerData1, peerData2},
			err:          nil,
		},
		{
			name:         "remove peers",
			neighbors:    []PeerData{peerData1, peerData2},
			newNeighbors: []PeerData{peerData1},
			err:          nil,
		},
		{
			name:         "update config : ASN",
			neighbors:    []PeerData{peerData1, peerData2},
			newNeighbors: []PeerData{peerData1, peer2UpdatedASN},
			err:          nil,
		},
		{
			name:         "update config : timers",
			neighbors:    []PeerData{peerData1, peerData2},
			newNeighbors: []PeerData{peerData1, peer2UpdatedTimers},
			err:          nil,
		},
		{
			name:         "update config : ports",
			neighbors:    []PeerData{peerData1, peerData2},
			newNeighbors: []PeerData{peerData1, peer2UpdatedPorts},
			err:          nil,
		},
		{
			name:         "update config : graceful restart",
			neighbors:    []PeerData{peerData1, peerData2},
			newNeighbors: []PeerData{peerData1, peer2UpdatedGR},
			err:          nil,
		},
		{
			name:         "update config : password",
			neighbors:    []PeerData{peerData2},
			newNeighbors: []PeerData{peer2Pass},
			err:          nil,
		},
		{
			name:         "update config : password updated",
			neighbors:    []PeerData{peer2Pass},
			newNeighbors: []PeerData{peer2UpdatePass},
			err:          nil,
		},
		{
			name:         "update config : password removed",
			neighbors:    []PeerData{peer2Pass},
			newNeighbors: []PeerData{peerData2},
			err:          nil,
		},
	}
	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			// our test BgpServer with our original router ID and local port
			srvParams := types.ServerParameters{
				Global: types.BGPGlobal{
					ASN:        64125,
					RouterID:   "127.0.0.1",
					ListenPort: -1,
				},
			}

			testInstance, err := instance.NewBGPInstance(context.Background(), logger, "test-instance", srvParams)
			req.NoError(err)

			t.Cleanup(func() {
				testInstance.Router.Stop(context.Background(), types.StopRequest{FullDestroy: true})
			})

			params, nodeConfig := setupNeighbors(logger, tt.neighbors)

			// setup initial neighbors
			neighborReconciler := NewNeighborReconciler(params).Reconciler
			neighborReconciler.Init(testInstance)
			defer neighborReconciler.Cleanup(testInstance)
			reconcileParams := reconciler.ReconcileParams{
				BGPInstance: testInstance,
				DesiredConfig: &v2.CiliumBGPNodeInstance{
					// Enterprise-specific logic. As the
					// NodeInstance is upgraded internally,
					// we only need to provide the name of
					// the NodeInstance.
					Name: nodeConfig.Name,
				},
			}
			err = neighborReconciler.Reconcile(context.Background(), reconcileParams)
			req.NoError(err)

			// validate neighbors
			validatePeers(req, tt.neighbors, getRunningPeers(req, testInstance), tt.checks)

			// update neighbors

			params, _ = setupNeighbors(logger, tt.newNeighbors)
			neighborReconciler.(*NeighborReconciler).PeerConfig = params.PeerConfig
			neighborReconciler.(*NeighborReconciler).SecretStore = params.SecretStore
			neighborReconciler.(*NeighborReconciler).upgrader = params.Upgrader
			reconcileParams = reconciler.ReconcileParams{
				BGPInstance: testInstance,
				DesiredConfig: &v2.CiliumBGPNodeInstance{
					// Enterprise-specific logic. As the
					// NodeInstance is upgraded internally,
					// we only need to provide the name of
					// the NodeInstance.
					Name: nodeConfig.Name,
				},
			}
			err = neighborReconciler.Reconcile(context.Background(), reconcileParams)
			req.NoError(err)

			// validate neighbors
			validatePeers(req, tt.newNeighbors, getRunningPeers(req, testInstance), tt.checks)
		})
	}
}

func setupNeighbors(logger *slog.Logger, peers []PeerData) (NeighborReconcilerIn, *v1.IsovalentBGPNodeInstance) {
	// Desired BGP Node config
	nodeConfig := &v1.IsovalentBGPNodeInstance{
		Name: "bgp-node",
	}

	// setup fake store for peer config
	var objects []*v1.IsovalentBGPPeerConfig
	for _, p := range peers {
		obj := &v1.IsovalentBGPPeerConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name: p.Peer.PeerConfigRef.Name,
			},
			Spec: *p.Config.DeepCopy(),
		}
		objects = append(objects, obj)
		nodeConfig.Peers = append(nodeConfig.Peers, *p.Peer)
	}
	peerConfigStore := store.InitMockStore(objects)

	// setup secret store
	secrets := make(map[string][]byte)
	for _, p := range peers {
		if p.Config.AuthSecretRef != nil {
			secrets[*p.Config.AuthSecretRef] = []byte(p.Password)
		}
	}
	var secretObjs []*slim_corev1.Secret
	for _, s := range secrets {
		secretObjs = append(secretObjs, &slim_corev1.Secret{
			ObjectMeta: slim_metav1.ObjectMeta{
				Namespace: "bgp-secrets",
				Name:      "a-secret",
			},
			Data: map[string]slim_corev1.Bytes{"password": slim_corev1.Bytes(s)},
		})
	}
	secretStore := store.InitMockStore(secretObjs)

	return NeighborReconcilerIn{
		BGPConfig:   config.Config{Enabled: true, StatusReportEnabled: false},
		Logger:      logger,
		SecretStore: secretStore,
		PeerConfig:  peerConfigStore,
		DaemonConfig: &option.DaemonConfig{
			EnterpriseDaemonConfig: option.EnterpriseDaemonConfig{
				EnableEnterpriseBGPControlPlane: true,
			},
			BGPSecretsNamespace: "bgp-secrets",
		},

		// Enterprise-specific logic. Provide a mock upgrader.
		Upgrader: newUpgraderMock(nodeConfig),
	}, nodeConfig
}

func validatePeers(req *require.Assertions, expected, running []PeerData, checks checks) {
	req.Len(running, len(expected))

	for _, expPeer := range expected {
		found := false
		for _, runPeer := range running {
			req.NotNil(runPeer.Peer.PeerAddress)
			req.NotNil(runPeer.Peer.PeerASN)

			if *expPeer.Peer.PeerAddress == *runPeer.Peer.PeerAddress && *expPeer.Peer.PeerASN == *runPeer.Peer.PeerASN {
				found = true

				if checks.holdTimer {
					req.Equal(*expPeer.Config.Timers.HoldTimeSeconds, *runPeer.Config.Timers.HoldTimeSeconds)
				}

				if checks.connectRetryTimer {
					req.Equal(*expPeer.Config.Timers.ConnectRetryTimeSeconds, *runPeer.Config.Timers.ConnectRetryTimeSeconds)
				}

				if checks.keepaliveTimer {
					req.Equal(*expPeer.Config.Timers.KeepAliveTimeSeconds, *runPeer.Config.Timers.KeepAliveTimeSeconds)
				}

				if checks.grRestartTime {
					req.Equal(expPeer.Config.GracefulRestart.Enabled, runPeer.Config.GracefulRestart.Enabled)
					req.Equal(*expPeer.Config.GracefulRestart.RestartTimeSeconds, *runPeer.Config.GracefulRestart.RestartTimeSeconds)
				}

				if expPeer.Password != "" {
					req.NotEmpty(runPeer.Password)
				}

				break
			}
		}
		req.True(found)
	}
}

func getRunningPeers(req *require.Assertions, instance *instance.BGPInstance) []PeerData {
	getPeerResp, err := instance.Router.GetPeerState(context.Background())
	req.NoError(err)

	var runningPeers []PeerData
	for _, peer := range getPeerResp.Peers {
		peerObj := &v1.IsovalentBGPNodePeer{
			PeerAddress: ptr.To[string](peer.PeerAddress),
			PeerASN:     ptr.To[int64](peer.PeerAsn),
		}

		peerConfObj := &v1.IsovalentBGPPeerConfigSpec{
			Transport: &v2.CiliumBGPTransport{
				PeerPort: ptr.To[int32](int32(peer.PeerPort)),
			},
			Timers: &v2.CiliumBGPTimers{
				ConnectRetryTimeSeconds: ptr.To[int32](int32(peer.ConnectRetryTimeSeconds)),
				HoldTimeSeconds:         ptr.To[int32](int32(peer.ConfiguredHoldTimeSeconds)),
				KeepAliveTimeSeconds:    ptr.To[int32](int32(peer.ConfiguredKeepAliveTimeSeconds)),
			},
			GracefulRestart: &v2.CiliumBGPNeighborGracefulRestart{
				Enabled:            peer.GracefulRestart.Enabled,
				RestartTimeSeconds: ptr.To[int32](int32(peer.GracefulRestart.RestartTimeSeconds)),
			},
			EBGPMultihop: ptr.To[int32](int32(peer.EbgpMultihopTTL)),
		}

		password := ""
		if peer.TCPPasswordEnabled {
			password = "something-is-set-dont-care-what"
		}

		runningPeers = append(runningPeers, PeerData{
			Peer:     peerObj,
			Config:   peerConfObj,
			Password: password,
		})
	}
	return runningPeers
}

func TestRouteReflectorPolicy(t *testing.T) {
	tests := []struct {
		name     string
		instance *v1.IsovalentBGPNodeInstance
		expected reconciler.RoutePolicyMap
	}{
		{
			name:     "non-route-reflector",
			instance: &v1.IsovalentBGPNodeInstance{},
			expected: reconciler.RoutePolicyMap{},
		},
		{
			name: "route-reflector no RR peer",
			instance: &v1.IsovalentBGPNodeInstance{
				RouteReflector: &v1.NodeRouteReflector{
					Role: v1.RouteReflectorRoleRouteReflector,
				},
			},
			expected: reconciler.RoutePolicyMap{},
		},
		{
			name: "client no RR peer",
			instance: &v1.IsovalentBGPNodeInstance{
				RouteReflector: &v1.NodeRouteReflector{
					Role: v1.RouteReflectorRoleClient,
				},
			},
			expected: reconciler.RoutePolicyMap{},
		},
		{
			name: "route-reflector to route-reflectors",
			instance: &v1.IsovalentBGPNodeInstance{
				RouteReflector: &v1.NodeRouteReflector{
					Role: v1.RouteReflectorRoleRouteReflector,
				},
				Peers: []v1.IsovalentBGPNodePeer{
					{
						PeerAddress: ptr.To("10.0.0.1"),
						RouteReflector: &v1.NodeRouteReflector{
							Role: v1.RouteReflectorRoleRouteReflector,
						},
					},
					{
						PeerAddress: ptr.To("10.0.0.2"),
						RouteReflector: &v1.NodeRouteReflector{
							Role: v1.RouteReflectorRoleRouteReflector,
						},
					},
				},
			},
			expected: reconciler.RoutePolicyMap{
				"rr-rr-allow-all-imports-from-rr": &types.RoutePolicy{
					Name: "rr-rr-allow-all-imports-from-rr",
					Type: types.RoutePolicyTypeImport,
					Statements: []*types.RoutePolicyStatement{
						{
							Conditions: types.RoutePolicyConditions{
								MatchNeighbors: []netip.Addr{
									netip.MustParseAddr("10.0.0.1"),
									netip.MustParseAddr("10.0.0.2"),
								},
							},
							Actions: types.RoutePolicyActions{
								RouteAction: types.RoutePolicyActionAccept,
							},
						},
					},
				},
				"rr-rr-allow-all-exports": &types.RoutePolicy{
					Name: "rr-rr-allow-all-exports",
					Type: types.RoutePolicyTypeExport,
					Statements: []*types.RoutePolicyStatement{
						{
							Conditions: types.RoutePolicyConditions{},
							Actions: types.RoutePolicyActions{
								RouteAction: types.RoutePolicyActionAccept,
							},
						},
					},
				},
			},
		},
		{
			name: "route-reflector to clients",
			instance: &v1.IsovalentBGPNodeInstance{
				RouteReflector: &v1.NodeRouteReflector{
					Role: v1.RouteReflectorRoleRouteReflector,
				},
				Peers: []v1.IsovalentBGPNodePeer{
					{
						PeerAddress: ptr.To("10.0.0.1"),
						RouteReflector: &v1.NodeRouteReflector{
							Role: v1.RouteReflectorRoleClient,
						},
					},
					{
						PeerAddress: ptr.To("10.0.0.2"),
						RouteReflector: &v1.NodeRouteReflector{
							Role: v1.RouteReflectorRoleClient,
						},
					},
				},
			},
			expected: reconciler.RoutePolicyMap{
				"rr-rr-allow-all-imports-from-clients": &types.RoutePolicy{
					Name: "rr-rr-allow-all-imports-from-clients",
					Type: types.RoutePolicyTypeImport,
					Statements: []*types.RoutePolicyStatement{
						{
							Conditions: types.RoutePolicyConditions{
								MatchNeighbors: []netip.Addr{
									netip.MustParseAddr("10.0.0.1"),
									netip.MustParseAddr("10.0.0.2"),
								},
							},
							Actions: types.RoutePolicyActions{
								RouteAction: types.RoutePolicyActionAccept,
							},
						},
					},
				},
				"rr-rr-allow-all-exports": &types.RoutePolicy{
					Name: "rr-rr-allow-all-exports",
					Type: types.RoutePolicyTypeExport,
					Statements: []*types.RoutePolicyStatement{
						{
							Conditions: types.RoutePolicyConditions{},
							Actions: types.RoutePolicyActions{
								RouteAction: types.RoutePolicyActionAccept,
							},
						},
					},
				},
			},
		},
		{
			name: "route-reflector to clients and route-reflectors",
			instance: &v1.IsovalentBGPNodeInstance{
				RouteReflector: &v1.NodeRouteReflector{
					Role: v1.RouteReflectorRoleRouteReflector,
				},
				Peers: []v1.IsovalentBGPNodePeer{
					{
						PeerAddress: ptr.To("10.0.0.1"),
						RouteReflector: &v1.NodeRouteReflector{
							Role: v1.RouteReflectorRoleClient,
						},
					},
					{
						PeerAddress: ptr.To("10.0.0.2"),
						RouteReflector: &v1.NodeRouteReflector{
							Role: v1.RouteReflectorRoleClient,
						},
					},
					{
						PeerAddress: ptr.To("10.0.0.3"),
						RouteReflector: &v1.NodeRouteReflector{
							Role: v1.RouteReflectorRoleRouteReflector,
						},
					},
					{
						PeerAddress: ptr.To("10.0.0.4"),
						RouteReflector: &v1.NodeRouteReflector{
							Role: v1.RouteReflectorRoleRouteReflector,
						},
					},
				},
			},
			expected: reconciler.RoutePolicyMap{
				"rr-rr-allow-all-imports-from-clients": &types.RoutePolicy{
					Name: "rr-rr-allow-all-imports-from-clients",
					Type: types.RoutePolicyTypeImport,
					Statements: []*types.RoutePolicyStatement{
						{
							Conditions: types.RoutePolicyConditions{
								MatchNeighbors: []netip.Addr{
									netip.MustParseAddr("10.0.0.1"),
									netip.MustParseAddr("10.0.0.2"),
								},
							},
							Actions: types.RoutePolicyActions{
								RouteAction: types.RoutePolicyActionAccept,
							},
						},
					},
				},
				"rr-rr-allow-all-imports-from-rr": &types.RoutePolicy{
					Name: "rr-rr-allow-all-imports-from-rr",
					Type: types.RoutePolicyTypeImport,
					Statements: []*types.RoutePolicyStatement{
						{
							Conditions: types.RoutePolicyConditions{
								MatchNeighbors: []netip.Addr{
									netip.MustParseAddr("10.0.0.3"),
									netip.MustParseAddr("10.0.0.4"),
								},
							},
							Actions: types.RoutePolicyActions{
								RouteAction: types.RoutePolicyActionAccept,
							},
						},
					},
				},
				"rr-rr-allow-all-exports": &types.RoutePolicy{
					Name: "rr-rr-allow-all-exports",
					Type: types.RoutePolicyTypeExport,
					Statements: []*types.RoutePolicyStatement{
						{
							Conditions: types.RoutePolicyConditions{},
							Actions: types.RoutePolicyActions{
								RouteAction: types.RoutePolicyActionAccept,
							},
						},
					},
				},
			},
		},
		{
			name: "client to route-reflectors",
			instance: &v1.IsovalentBGPNodeInstance{
				RouteReflector: &v1.NodeRouteReflector{
					Role: v1.RouteReflectorRoleClient,
				},
				Peers: []v1.IsovalentBGPNodePeer{
					{
						PeerAddress: ptr.To("10.0.0.1"),
						RouteReflector: &v1.NodeRouteReflector{
							Role: v1.RouteReflectorRoleRouteReflector,
						},
					},
					{
						PeerAddress: ptr.To("10.0.0.2"),
						RouteReflector: &v1.NodeRouteReflector{
							Role: v1.RouteReflectorRoleRouteReflector,
						},
					},
				},
			},
			expected: reconciler.RoutePolicyMap{
				"rr-client-allow-all-imports-from-rr": &types.RoutePolicy{
					Name: "rr-client-allow-all-imports-from-rr",
					Type: types.RoutePolicyTypeImport,
					Statements: []*types.RoutePolicyStatement{
						{
							Conditions: types.RoutePolicyConditions{
								MatchNeighbors: []netip.Addr{
									netip.MustParseAddr("10.0.0.1"),
									netip.MustParseAddr("10.0.0.2"),
								},
							},
							Actions: types.RoutePolicyActions{
								RouteAction: types.RoutePolicyActionAccept,
							},
						},
					},
				},
			},
		},
		{
			name: "route-reflector to eBGP peer",
			instance: &v1.IsovalentBGPNodeInstance{
				LocalASN: ptr.To(int64(65000)),
				RouteReflector: &v1.NodeRouteReflector{
					Role: v1.RouteReflectorRoleRouteReflector,
				},
				Peers: []v1.IsovalentBGPNodePeer{
					{
						PeerAddress: ptr.To("10.0.0.1"),
						PeerASN:     ptr.To(int64(65000)),
						RouteReflector: &v1.NodeRouteReflector{
							Role: v1.RouteReflectorRoleClient,
						},
					},
					{
						PeerAddress: ptr.To("10.0.0.2"),
						PeerASN:     ptr.To(int64(65001)),
					},
				},
			},
			expected: reconciler.RoutePolicyMap{
				"rr-rr-allow-all-imports-from-clients": &types.RoutePolicy{
					Name: "rr-rr-allow-all-imports-from-clients",
					Type: types.RoutePolicyTypeImport,
					Statements: []*types.RoutePolicyStatement{
						{
							Conditions: types.RoutePolicyConditions{
								MatchNeighbors: []netip.Addr{
									netip.MustParseAddr("10.0.0.1"),
								},
							},
							Actions: types.RoutePolicyActions{
								RouteAction: types.RoutePolicyActionAccept,
							},
						},
					},
				},
				"rr-rr-allow-all-exports": &types.RoutePolicy{
					Name: "rr-rr-allow-all-exports",
					Type: types.RoutePolicyTypeExport,
					Statements: []*types.RoutePolicyStatement{
						{
							Conditions: types.RoutePolicyConditions{
								MatchNeighbors: []netip.Addr{
									netip.MustParseAddr("10.0.0.2"),
								},
							},
							Actions: types.RoutePolicyActions{
								RouteAction: types.RoutePolicyActionAccept,
								NextHop: &types.RoutePolicyActionNextHop{
									Unchanged: true,
								},
							},
						},
						{
							Conditions: types.RoutePolicyConditions{},
							Actions: types.RoutePolicyActions{
								RouteAction: types.RoutePolicyActionAccept,
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getDesiredRouteReflectorPolicies(tt.instance)
			require.Equal(t, tt.expected, result)
		})
	}
}
