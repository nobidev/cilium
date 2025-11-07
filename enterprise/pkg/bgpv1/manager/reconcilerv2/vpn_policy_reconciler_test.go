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

	"github.com/cilium/cilium/pkg/bgpv1/manager/instance"
	"github.com/cilium/cilium/pkg/bgpv1/manager/reconcilerv2"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
)

var (
	peerConfigIPv4Unicast = &v1.IsovalentBGPPeerConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "peer-config-ipv4-unicast",
		},
		Spec: v1.IsovalentBGPPeerConfigSpec{
			Families: []v1.IsovalentBGPFamilyWithAdverts{
				{
					CiliumBGPFamily: v2.CiliumBGPFamily{
						Afi:  "ipv4",
						Safi: "unicast",
					},
				},
			},
		},
	}

	peerConfigIPv4VPN = &v1.IsovalentBGPPeerConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "peer-config-ipv4-mpls_vpn",
		},
		Spec: v1.IsovalentBGPPeerConfigSpec{
			Families: []v1.IsovalentBGPFamilyWithAdverts{
				{
					CiliumBGPFamily: v2.CiliumBGPFamily{
						Afi:  "ipv4",
						Safi: "mpls_vpn",
					},
				},
			},
		},
	}

	expectedPeerRoutePolicy = func(policyType types.RoutePolicyType, name string, peerAddr netip.Addr) *types.RoutePolicy {
		return &types.RoutePolicy{
			Name: name,
			Type: policyType,
			Statements: []*types.RoutePolicyStatement{
				{
					Conditions: types.RoutePolicyConditions{
						MatchNeighbors: []netip.Addr{peerAddr},
						MatchFamilies: []types.Family{
							{
								Afi:  types.AfiIPv4,
								Safi: types.SafiMplsVpn,
							},
						},
					},
					Actions: types.RoutePolicyActions{
						RouteAction: types.RoutePolicyActionAccept,
					},
				},
			},
		}
	}

	importPeerPolicy = expectedPeerRoutePolicy(
		types.RoutePolicyTypeImport,
		"VPNRoutePolicy-import-red-peer-65001",
		netip.MustParseAddr("192.168.0.10"),
	)

	exportPeerPolicy = expectedPeerRoutePolicy(
		types.RoutePolicyTypeExport,
		"VPNRoutePolicy-export-red-peer-65001",
		netip.MustParseAddr("192.168.0.10"),
	)
)

func TestVPNRoutePolicy(t *testing.T) {
	tests := []struct {
		name        string
		preRPs      reconcilerv2.RoutePolicyMap
		peerConfigs []*v1.IsovalentBGPPeerConfig
		peers       []v1.IsovalentBGPNodePeer
		expectedRPs reconcilerv2.RoutePolicyMap
	}{
		{
			name:        "ipv4-unicast peer, no policy",
			preRPs:      nil,
			peerConfigs: []*v1.IsovalentBGPPeerConfig{peerConfigIPv4Unicast},
			peers: []v1.IsovalentBGPNodePeer{
				{
					Name:        "red-peer-65001",
					PeerAddress: ptr.To[string]("192.168.0.10"),
					PeerConfigRef: &v1.PeerConfigReference{
						Name: "peer-config-ipv4-unicast",
					},
				},
			},
			expectedRPs: make(reconcilerv2.RoutePolicyMap),
		},
		{
			name:        "ipv4-vpn peer, policies applied",
			preRPs:      nil,
			peerConfigs: []*v1.IsovalentBGPPeerConfig{peerConfigIPv4VPN},
			peers: []v1.IsovalentBGPNodePeer{
				{
					Name:        "red-peer-65001",
					PeerAddress: ptr.To[string]("192.168.0.10"),
					PeerConfigRef: &v1.PeerConfigReference{
						Name: "peer-config-ipv4-mpls_vpn",
					},
				},
			},
			expectedRPs: reconcilerv2.RoutePolicyMap{
				importPeerPolicy.Name: importPeerPolicy,
				exportPeerPolicy.Name: exportPeerPolicy,
			},
		},
		{
			name: "ipv4-unicast peer, cleanup old policies",
			preRPs: reconcilerv2.RoutePolicyMap{
				importPeerPolicy.Name: importPeerPolicy,
				exportPeerPolicy.Name: exportPeerPolicy,
			},
			peerConfigs: []*v1.IsovalentBGPPeerConfig{peerConfigIPv4Unicast},
			peers: []v1.IsovalentBGPNodePeer{
				{
					Name:        "red-peer-65001",
					PeerAddress: ptr.To[string]("192.168.0.10"),
					PeerConfigRef: &v1.PeerConfigReference{
						Name: "peer-config-ipv4-unicast",
					},
				},
			},
			expectedRPs: make(reconcilerv2.RoutePolicyMap),
		},
		{
			name: "no peer found, cleanup old policies",
			preRPs: reconcilerv2.RoutePolicyMap{
				importPeerPolicy.Name: importPeerPolicy,
				exportPeerPolicy.Name: exportPeerPolicy,
			},
			peerConfigs: []*v1.IsovalentBGPPeerConfig{peerConfigIPv4Unicast},
			peers: []v1.IsovalentBGPNodePeer{
				{
					Name:        "red-peer-65001",
					PeerAddress: ptr.To[string]("192.168.0.10"),
					PeerConfigRef: &v1.PeerConfigReference{
						Name: "no_matching_peer_config",
					},
				},
			},
			expectedRPs: make(reconcilerv2.RoutePolicyMap),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := require.New(t)

			testOSSBGPInstance := instance.NewFakeBGPInstance()
			testBGPInstance := &EnterpriseBGPInstance{
				Name:   testOSSBGPInstance.Name,
				Router: testOSSBGPInstance.Router,
			}
			iNodeInstance := &v1.IsovalentBGPNodeInstance{
				Name:     "test-instance",
				LocalASN: ptr.To[int64](65001),
				Peers:    tt.peers,
			}
			ossNodeInstance := &v2.CiliumBGPNodeInstance{
				Name:     iNodeInstance.Name,
				LocalASN: iNodeInstance.LocalASN,
			}
			for _, peer := range iNodeInstance.Peers {
				ossNodeInstance.Peers = append(ossNodeInstance.Peers, v2.CiliumBGPNodePeer{
					Name:        peer.Name,
					PeerAddress: peer.PeerAddress,
					PeerConfigRef: &v2.PeerConfigReference{
						Name: peer.PeerConfigRef.Name,
					},
				})
			}

			reconciler := &VPNRoutePolicyReconciler{
				logger:          hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug)),
				peerConfigStore: newMockResourceStore[*v1.IsovalentBGPPeerConfig](),
				metadata:        make(map[string]VPNRoutePolicyMetadata),
				upgrader:        newUpgraderMock(iNodeInstance),
			}

			if len(tt.peerConfigs) > 0 {
				reconciler.peerConfigStore = InitMockStore[*v1.IsovalentBGPPeerConfig](tt.peerConfigs)
			}

			reconciler.Init(testOSSBGPInstance)
			defer reconciler.Cleanup(testOSSBGPInstance)
			reconciler.initialized.Store(true)

			// set preconfigured route policies
			reconciler.SetMetadata(testBGPInstance, VPNRoutePolicyMetadata{
				VPNPolicies: tt.preRPs,
			})

			// reconcile peer configs
			for range 2 {
				err := reconciler.Reconcile(context.Background(), reconcilerv2.ReconcileParams{
					BGPInstance:   testOSSBGPInstance,
					DesiredConfig: ossNodeInstance,
				})
				req.NoError(err)
			}

			req.Equal(tt.expectedRPs, reconciler.GetMetadata(testBGPInstance).VPNPolicies)
		})
	}
}
