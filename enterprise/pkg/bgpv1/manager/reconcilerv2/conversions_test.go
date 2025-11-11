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
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/pkg/bgp/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
)

func TestToNeighbor(t *testing.T) {
	table := []struct {
		name         string
		nodePeer     *v1.IsovalentBGPNodePeer
		peerConfig   *v1.IsovalentBGPPeerConfigSpec
		authPassword string
		selfRRRole   v1.RouteReflectorRole
		expected     *types.Neighbor
	}{
		{
			name: "IPv4 Minimal",
			nodePeer: &v1.IsovalentBGPNodePeer{
				PeerAddress: ptr.To("10.0.0.1"),
				PeerASN:     ptr.To(int64(64512)),
			},
			peerConfig: &v1.IsovalentBGPPeerConfigSpec{},
			expected: &types.Neighbor{
				Address: netip.MustParseAddr("10.0.0.1"),
				ASN:     64512,
			},
		},
		{
			name: "IPv6 Minimal",
			nodePeer: &v1.IsovalentBGPNodePeer{
				PeerAddress: ptr.To("fd00::1"),
				PeerASN:     ptr.To(int64(64512)),
			},
			peerConfig: &v1.IsovalentBGPPeerConfigSpec{},
			expected: &types.Neighbor{
				Address: netip.MustParseAddr("fd00::1"),
				ASN:     64512,
			},
		},
		{
			name: "LocalAddress",
			nodePeer: &v1.IsovalentBGPNodePeer{
				PeerAddress:  ptr.To("fd00::1"),
				PeerASN:      ptr.To(int64(64512)),
				LocalAddress: ptr.To("fd00::2"),
			},
			peerConfig: &v1.IsovalentBGPPeerConfigSpec{},
			expected: &types.Neighbor{
				Address: netip.MustParseAddr("fd00::1"),
				ASN:     64512,
				Transport: &types.NeighborTransport{
					LocalAddress: "fd00::2",
				},
			},
		},
		{
			name: "PeerPort",
			nodePeer: &v1.IsovalentBGPNodePeer{
				PeerAddress: ptr.To("fd00::1"),
				PeerASN:     ptr.To(int64(64512)),
			},
			peerConfig: &v1.IsovalentBGPPeerConfigSpec{
				Transport: &v2.CiliumBGPTransport{
					PeerPort: ptr.To(int32(1790)),
				},
			},
			expected: &types.Neighbor{
				Address: netip.MustParseAddr("fd00::1"),
				ASN:     64512,
				Transport: &types.NeighborTransport{
					RemotePort: 1790,
				},
			},
		},
		{
			name: "Timers",
			nodePeer: &v1.IsovalentBGPNodePeer{
				PeerAddress: ptr.To("fd00::1"),
				PeerASN:     ptr.To(int64(64512)),
			},
			peerConfig: &v1.IsovalentBGPPeerConfigSpec{
				Timers: &v2.CiliumBGPTimers{
					ConnectRetryTimeSeconds: ptr.To(int32(1)),
					HoldTimeSeconds:         ptr.To(int32(3)),
					KeepAliveTimeSeconds:    ptr.To(int32(1)),
				},
			},
			expected: &types.Neighbor{
				Address: netip.MustParseAddr("fd00::1"),
				ASN:     64512,
				Timers: &types.NeighborTimers{
					ConnectRetry:      1,
					HoldTime:          3,
					KeepaliveInterval: 1,
				},
			},
		},
		{
			name: "AuthPassword",
			nodePeer: &v1.IsovalentBGPNodePeer{
				PeerAddress: ptr.To("fd00::1"),
				PeerASN:     ptr.To(int64(64512)),
			},
			peerConfig:   &v1.IsovalentBGPPeerConfigSpec{},
			authPassword: "password",
			expected: &types.Neighbor{
				Address:      netip.MustParseAddr("fd00::1"),
				ASN:          64512,
				AuthPassword: "password",
			},
		},
		{
			name: "GracefulRestart",
			nodePeer: &v1.IsovalentBGPNodePeer{
				PeerAddress: ptr.To("fd00::1"),
				PeerASN:     ptr.To(int64(64512)),
			},
			peerConfig: &v1.IsovalentBGPPeerConfigSpec{
				GracefulRestart: &v2.CiliumBGPNeighborGracefulRestart{
					Enabled:            true,
					RestartTimeSeconds: ptr.To(int32(3)),
				},
			},
			expected: &types.Neighbor{
				Address: netip.MustParseAddr("fd00::1"),
				ASN:     64512,
				GracefulRestart: &types.NeighborGracefulRestart{
					Enabled:     true,
					RestartTime: 3,
				},
			},
		},
		{
			name: "EBGPMultihop",
			nodePeer: &v1.IsovalentBGPNodePeer{
				PeerAddress: ptr.To("fd00::1"),
				PeerASN:     ptr.To(int64(64512)),
			},
			peerConfig: &v1.IsovalentBGPPeerConfigSpec{
				EBGPMultihop: ptr.To(int32(3)),
			},
			expected: &types.Neighbor{
				Address: netip.MustParseAddr("fd00::1"),
				ASN:     64512,
				EbgpMultihop: &types.NeighborEbgpMultihop{
					TTL: 3,
				},
			},
		},
		{
			name: "RouteReflector to RouteReflector",
			nodePeer: &v1.IsovalentBGPNodePeer{
				PeerAddress: ptr.To("fd00::1"),
				PeerASN:     ptr.To(int64(64512)),
				RouteReflector: &v1.NodeRouteReflector{
					Role:      v1.RouteReflectorRoleRouteReflector,
					ClusterID: "255.0.0.1",
				},
			},
			peerConfig: &v1.IsovalentBGPPeerConfigSpec{},
			selfRRRole: v1.RouteReflectorRoleRouteReflector,
			expected: &types.Neighbor{
				Address: netip.MustParseAddr("fd00::1"),
				ASN:     64512,
				RouteReflector: &types.NeighborRouteReflector{
					Client:    true,
					ClusterID: "255.0.0.1",
				},
			},
		},
		{
			name: "RouteReflector to Client",
			nodePeer: &v1.IsovalentBGPNodePeer{
				PeerAddress: ptr.To("fd00::1"),
				PeerASN:     ptr.To(int64(64512)),
				RouteReflector: &v1.NodeRouteReflector{
					Role:      v1.RouteReflectorRoleClient,
					ClusterID: "255.0.0.1",
				},
			},
			peerConfig: &v1.IsovalentBGPPeerConfigSpec{},
			selfRRRole: v1.RouteReflectorRoleRouteReflector,
			expected: &types.Neighbor{
				Address: netip.MustParseAddr("fd00::1"),
				ASN:     64512,
				RouteReflector: &types.NeighborRouteReflector{
					Client:    true,
					ClusterID: "255.0.0.1",
				},
			},
		},
		{
			name: "Client to RouteReflector",
			nodePeer: &v1.IsovalentBGPNodePeer{
				PeerAddress: ptr.To("fd00::1"),
				PeerASN:     ptr.To(int64(64512)),
				RouteReflector: &v1.NodeRouteReflector{
					Role:      v1.RouteReflectorRoleClient,
					ClusterID: "255.0.0.1",
				},
			},
			peerConfig: &v1.IsovalentBGPPeerConfigSpec{},
			selfRRRole: v1.RouteReflectorRoleClient,
			expected: &types.Neighbor{
				Address: netip.MustParseAddr("fd00::1"),
				ASN:     64512,
			},
		},
		{
			name: "Families",
			nodePeer: &v1.IsovalentBGPNodePeer{
				PeerAddress: ptr.To("fd00::1"),
				PeerASN:     ptr.To(int64(64512)),
			},

			peerConfig: &v1.IsovalentBGPPeerConfigSpec{
				Families: []v1.IsovalentBGPFamilyWithAdverts{
					{

						CiliumBGPFamily: v2.CiliumBGPFamily{
							Afi:  "ipv4",
							Safi: "unicast",
						},
					},
					{
						CiliumBGPFamily: v2.CiliumBGPFamily{
							Afi:  "ipv6",
							Safi: "unicast",
						},
					},
				},
			},
			expected: &types.Neighbor{
				Address: netip.MustParseAddr("fd00::1"),
				ASN:     64512,
				AfiSafis: []*types.Family{
					{
						Afi:  types.AfiIPv4,
						Safi: types.SafiUnicast,
					},
					{
						Afi:  types.AfiIPv6,
						Safi: types.SafiUnicast,
					},
				},
			},
		},
		{
			name: "Maximum",
			nodePeer: &v1.IsovalentBGPNodePeer{
				PeerAddress:  ptr.To("fd00::1"),
				PeerASN:      ptr.To(int64(64512)),
				LocalAddress: ptr.To("fd00::2"),
			},
			peerConfig: &v1.IsovalentBGPPeerConfigSpec{
				Transport: &v2.CiliumBGPTransport{
					PeerPort: ptr.To(int32(1790)),
				},
				Timers: &v2.CiliumBGPTimers{
					ConnectRetryTimeSeconds: ptr.To(int32(1)),
					HoldTimeSeconds:         ptr.To(int32(3)),
					KeepAliveTimeSeconds:    ptr.To(int32(1)),
				},
				GracefulRestart: &v2.CiliumBGPNeighborGracefulRestart{
					Enabled:            true,
					RestartTimeSeconds: ptr.To(int32(3)),
				},
				EBGPMultihop: ptr.To(int32(3)),
				Families: []v1.IsovalentBGPFamilyWithAdverts{
					{
						CiliumBGPFamily: v2.CiliumBGPFamily{
							Afi:  "ipv4",
							Safi: "unicast",
						},
					},
					{
						CiliumBGPFamily: v2.CiliumBGPFamily{
							Afi:  "ipv6",
							Safi: "unicast",
						},
					},
				},
			},
			authPassword: "password",
			expected: &types.Neighbor{
				Address:      netip.MustParseAddr("fd00::1"),
				ASN:          64512,
				AuthPassword: "password",
				EbgpMultihop: &types.NeighborEbgpMultihop{
					TTL: 3,
				},
				Timers: &types.NeighborTimers{
					ConnectRetry:      1,
					HoldTime:          3,
					KeepaliveInterval: 1,
				},
				Transport: &types.NeighborTransport{
					LocalAddress: "fd00::2",
					RemotePort:   1790,
				},
				GracefulRestart: &types.NeighborGracefulRestart{
					Enabled:     true,
					RestartTime: 3,
				},
				AfiSafis: []*types.Family{
					{
						Afi:  types.AfiIPv4,
						Safi: types.SafiUnicast,
					},
					{
						Afi:  types.AfiIPv6,
						Safi: types.SafiUnicast,
					},
				},
			},
		},
	}
	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			neighbor := toNeighbor(tt.nodePeer, tt.peerConfig, tt.authPassword, tt.selfRRRole)
			require.Equal(t, tt.expected, neighbor)
		})
	}
}
