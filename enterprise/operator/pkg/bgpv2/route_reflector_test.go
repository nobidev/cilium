// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package bgpv2

import (
	"testing"

	"github.com/stretchr/testify/require"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	"github.com/cilium/cilium/pkg/node/addressing"
)

func TestRRClusterIPv4Only(t *testing.T) {
	asn := int64(65000)

	// Nodes
	newNode := func(name, ip string) *v2.CiliumNode {
		return &v2.CiliumNode{
			ObjectMeta: meta_v1.ObjectMeta{
				Name: name,
			},
			Spec: v2.NodeSpec{
				Addresses: []v2.NodeAddress{
					{
						Type: addressing.NodeInternalIP,
						IP:   ip,
					},
				},
			},
		}
	}

	node0 := newNode("node0", "10.0.0.0")
	node1 := newNode("node1", "10.0.0.1")
	node2 := newNode("node2", "10.0.0.2")
	node3 := newNode("node3", "10.0.0.3")

	// Instances
	newInstance := func(name string, role v1.RouteReflectorRole) *v1.IsovalentBGPInstance {
		return &v1.IsovalentBGPInstance{
			Name:     name,
			LocalASN: &asn,
			RouteReflector: &v1.RouteReflector{
				Role:                 role,
				ClusterID:            "255.0.0.1",
				PeeringAddressFamily: ptr.To(v1.RouteReflectorPeeringAddressFamilyIPv4Only),
				PeerConfigRefV4: &v1.PeerConfigReference{
					Name: "peer-config",
				},
			},
		}
	}

	rr0 := newInstance("rr0", v1.RouteReflectorRoleRouteReflector)
	rr1 := newInstance("rr1", v1.RouteReflectorRoleRouteReflector)
	client0 := newInstance("client0", v1.RouteReflectorRoleClient)
	client1 := newInstance("client1", v1.RouteReflectorRoleClient)

	// Use a strange default to test the explicit specification is working
	rrCluster := newRRCluster(v1.RouteReflectorPeeringAddressFamilyIPv6Only)
	rrCluster.AddInstance(node0, rr0)
	rrCluster.AddInstance(node1, rr1)
	rrCluster.AddInstance(node2, client0)
	rrCluster.AddInstance(node3, client1)

	t.Run("rr0 peers with rr1 and clients", func(t *testing.T) {
		// Ensure the correct peers are returned with the correct order (alphabetical)
		require.Equal(
			t,
			[]*rrClusterPeer{
				{
					Name:          "rr-client-node2-client0-v4",
					Address:       "10.0.0.2",
					PeerConfigRef: rr0.RouteReflector.PeerConfigRefV4,
					RouteReflector: &v1.NodeRouteReflector{
						Role:      v1.RouteReflectorRoleClient,
						ClusterID: "255.0.0.1",
					},
				},
				{
					Name:          "rr-client-node3-client1-v4",
					Address:       "10.0.0.3",
					PeerConfigRef: rr0.RouteReflector.PeerConfigRefV4,
					RouteReflector: &v1.NodeRouteReflector{
						Role:      v1.RouteReflectorRoleClient,
						ClusterID: "255.0.0.1",
					},
				},
				{
					Name:          "rr-route-reflector-node1-rr1-v4",
					Address:       "10.0.0.1",
					PeerConfigRef: rr0.RouteReflector.PeerConfigRefV4,
					RouteReflector: &v1.NodeRouteReflector{
						Role:      v1.RouteReflectorRoleRouteReflector,
						ClusterID: "255.0.0.1",
					},
				},
			},
			rrCluster.ListPeers(instanceID{NodeName: "node0", InstanceName: "rr0"}),
		)
	})
	t.Run("rr1 peers with rr0 and clients", func(t *testing.T) {
		require.Equal(
			t,
			[]*rrClusterPeer{
				{
					Name:          "rr-client-node2-client0-v4",
					Address:       "10.0.0.2",
					PeerConfigRef: rr1.RouteReflector.PeerConfigRefV4,
					RouteReflector: &v1.NodeRouteReflector{
						Role:      v1.RouteReflectorRoleClient,
						ClusterID: "255.0.0.1",
					},
				},
				{
					Name:          "rr-client-node3-client1-v4",
					Address:       "10.0.0.3",
					PeerConfigRef: rr1.RouteReflector.PeerConfigRefV4,
					RouteReflector: &v1.NodeRouteReflector{
						Role:      v1.RouteReflectorRoleClient,
						ClusterID: "255.0.0.1",
					},
				},
				{
					Name:          "rr-route-reflector-node0-rr0-v4",
					Address:       "10.0.0.0",
					PeerConfigRef: rr1.RouteReflector.PeerConfigRefV4,
					RouteReflector: &v1.NodeRouteReflector{
						Role:      v1.RouteReflectorRoleRouteReflector,
						ClusterID: "255.0.0.1",
					},
				},
			},
			rrCluster.ListPeers(instanceID{NodeName: "node1", InstanceName: "rr1"}),
		)
	})
	t.Run("client0 peers with rrs", func(t *testing.T) {
		require.Equal(
			t,
			[]*rrClusterPeer{
				{
					Name:          "rr-route-reflector-node0-rr0-v4",
					Address:       "10.0.0.0",
					PeerConfigRef: client0.RouteReflector.PeerConfigRefV4,
					RouteReflector: &v1.NodeRouteReflector{
						Role:      v1.RouteReflectorRoleRouteReflector,
						ClusterID: "255.0.0.1",
					},
				},
				{
					Name:          "rr-route-reflector-node1-rr1-v4",
					Address:       "10.0.0.1",
					PeerConfigRef: client0.RouteReflector.PeerConfigRefV4,
					RouteReflector: &v1.NodeRouteReflector{
						Role:      v1.RouteReflectorRoleRouteReflector,
						ClusterID: "255.0.0.1",
					},
				},
			},
			rrCluster.ListPeers(instanceID{NodeName: "node2", InstanceName: "client0"}),
		)
	})
	t.Run("client1 peers with rrs", func(t *testing.T) {
		require.Equal(
			t,
			[]*rrClusterPeer{
				{
					Name:          "rr-route-reflector-node0-rr0-v4",
					Address:       "10.0.0.0",
					PeerConfigRef: client1.RouteReflector.PeerConfigRefV4,
					RouteReflector: &v1.NodeRouteReflector{
						Role:      v1.RouteReflectorRoleRouteReflector,
						ClusterID: "255.0.0.1",
					},
				},
				{
					Name:          "rr-route-reflector-node1-rr1-v4",
					Address:       "10.0.0.1",
					PeerConfigRef: client1.RouteReflector.PeerConfigRefV4,
					RouteReflector: &v1.NodeRouteReflector{
						Role:      v1.RouteReflectorRoleRouteReflector,
						ClusterID: "255.0.0.1",
					},
				},
			},
			rrCluster.ListPeers(instanceID{NodeName: "node3", InstanceName: "client1"}),
		)
	})
}

func TestRRClusterIPv6Only(t *testing.T) {
	asn := int64(65000)

	// Nodes
	newNode := func(name, ip string) *v2.CiliumNode {
		return &v2.CiliumNode{
			ObjectMeta: meta_v1.ObjectMeta{
				Name: name,
			},
			Spec: v2.NodeSpec{
				Addresses: []v2.NodeAddress{
					{
						Type: addressing.NodeInternalIP,
						IP:   ip,
					},
				},
			},
		}
	}

	node0 := newNode("node0", "fd00:10::0")
	node1 := newNode("node1", "fd00:10::1")
	node2 := newNode("node2", "fd00:10::2")
	node3 := newNode("node3", "fd00:10::3")

	// Instances
	newInstance := func(name string, role v1.RouteReflectorRole) *v1.IsovalentBGPInstance {
		return &v1.IsovalentBGPInstance{
			Name:     name,
			LocalASN: &asn,
			RouteReflector: &v1.RouteReflector{
				Role:                 role,
				ClusterID:            "255.0.0.1",
				PeeringAddressFamily: ptr.To(v1.RouteReflectorPeeringAddressFamilyIPv6Only),
				PeerConfigRefV6: &v1.PeerConfigReference{
					Name: "peer-config",
				},
			},
		}
	}

	rr0 := newInstance("rr0", v1.RouteReflectorRoleRouteReflector)
	rr1 := newInstance("rr1", v1.RouteReflectorRoleRouteReflector)
	client0 := newInstance("client0", v1.RouteReflectorRoleClient)
	client1 := newInstance("client1", v1.RouteReflectorRoleClient)

	// Use a strange default to test the explicit specification is working
	rrCluster := newRRCluster(v1.RouteReflectorPeeringAddressFamilyIPv4Only)
	rrCluster.AddInstance(node0, rr0)
	rrCluster.AddInstance(node1, rr1)
	rrCluster.AddInstance(node2, client0)
	rrCluster.AddInstance(node3, client1)

	t.Run("rr0 peers with rr1 and clients", func(t *testing.T) {
		// Ensure the correct peers are returned with the correct order (alphabetical)
		require.Equal(
			t,
			[]*rrClusterPeer{
				{
					Name:          "rr-client-node2-client0-v6",
					Address:       "fd00:10::2",
					PeerConfigRef: rr0.RouteReflector.PeerConfigRefV6,
					RouteReflector: &v1.NodeRouteReflector{
						Role:      v1.RouteReflectorRoleClient,
						ClusterID: "255.0.0.1",
					},
				},
				{
					Name:          "rr-client-node3-client1-v6",
					Address:       "fd00:10::3",
					PeerConfigRef: rr0.RouteReflector.PeerConfigRefV6,
					RouteReflector: &v1.NodeRouteReflector{
						Role:      v1.RouteReflectorRoleClient,
						ClusterID: "255.0.0.1",
					},
				},
				{
					Name:          "rr-route-reflector-node1-rr1-v6",
					Address:       "fd00:10::1",
					PeerConfigRef: rr0.RouteReflector.PeerConfigRefV6,
					RouteReflector: &v1.NodeRouteReflector{
						Role:      v1.RouteReflectorRoleRouteReflector,
						ClusterID: "255.0.0.1",
					},
				},
			},
			rrCluster.ListPeers(instanceID{NodeName: "node0", InstanceName: "rr0"}),
		)
	})
	t.Run("rr1 peers with rr0 and clients", func(t *testing.T) {
		require.Equal(
			t,
			[]*rrClusterPeer{
				{
					Name:          "rr-client-node2-client0-v6",
					Address:       "fd00:10::2",
					PeerConfigRef: rr1.RouteReflector.PeerConfigRefV6,
					RouteReflector: &v1.NodeRouteReflector{
						Role:      v1.RouteReflectorRoleClient,
						ClusterID: "255.0.0.1",
					},
				},
				{
					Name:          "rr-client-node3-client1-v6",
					Address:       "fd00:10::3",
					PeerConfigRef: rr1.RouteReflector.PeerConfigRefV6,
					RouteReflector: &v1.NodeRouteReflector{
						Role:      v1.RouteReflectorRoleClient,
						ClusterID: "255.0.0.1",
					},
				},
				{
					Name:          "rr-route-reflector-node0-rr0-v6",
					Address:       "fd00:10::",
					PeerConfigRef: rr1.RouteReflector.PeerConfigRefV6,
					RouteReflector: &v1.NodeRouteReflector{
						Role:      v1.RouteReflectorRoleRouteReflector,
						ClusterID: "255.0.0.1",
					},
				},
			},
			rrCluster.ListPeers(instanceID{NodeName: "node1", InstanceName: "rr1"}),
		)
	})
	t.Run("client0 peers with rrs", func(t *testing.T) {
		require.Equal(
			t,
			[]*rrClusterPeer{
				{
					Name:          "rr-route-reflector-node0-rr0-v6",
					Address:       "fd00:10::",
					PeerConfigRef: client0.RouteReflector.PeerConfigRefV6,
					RouteReflector: &v1.NodeRouteReflector{
						Role:      v1.RouteReflectorRoleRouteReflector,
						ClusterID: "255.0.0.1",
					},
				},
				{
					Name:          "rr-route-reflector-node1-rr1-v6",
					Address:       "fd00:10::1",
					PeerConfigRef: client0.RouteReflector.PeerConfigRefV6,
					RouteReflector: &v1.NodeRouteReflector{
						Role:      v1.RouteReflectorRoleRouteReflector,
						ClusterID: "255.0.0.1",
					},
				},
			},
			rrCluster.ListPeers(instanceID{NodeName: "node2", InstanceName: "client0"}),
		)
	})
	t.Run("client1 peers with rrs", func(t *testing.T) {
		require.Equal(
			t,
			[]*rrClusterPeer{
				{
					Name:          "rr-route-reflector-node0-rr0-v6",
					Address:       "fd00:10::",
					PeerConfigRef: client1.RouteReflector.PeerConfigRefV6,
					RouteReflector: &v1.NodeRouteReflector{
						Role:      v1.RouteReflectorRoleRouteReflector,
						ClusterID: "255.0.0.1",
					},
				},
				{
					Name:          "rr-route-reflector-node1-rr1-v6",
					Address:       "fd00:10::1",
					PeerConfigRef: client1.RouteReflector.PeerConfigRefV6,
					RouteReflector: &v1.NodeRouteReflector{
						Role:      v1.RouteReflectorRoleRouteReflector,
						ClusterID: "255.0.0.1",
					},
				},
			},
			rrCluster.ListPeers(instanceID{NodeName: "node3", InstanceName: "client1"}),
		)
	})
}

func TestRRClusterDual(t *testing.T) {
	asn := int64(65000)

	// Nodes
	newNode := func(name, ipv4, ipv6 string) *v2.CiliumNode {
		return &v2.CiliumNode{
			ObjectMeta: meta_v1.ObjectMeta{
				Name: name,
			},
			Spec: v2.NodeSpec{
				Addresses: []v2.NodeAddress{
					{
						Type: addressing.NodeInternalIP,
						IP:   ipv4,
					},
					{
						Type: addressing.NodeInternalIP,
						IP:   ipv6,
					},
				},
			},
		}
	}

	node0 := newNode("node0", "10.0.0.0", "fd00:10::")
	node1 := newNode("node1", "10.0.0.1", "fd00:10::1")
	node2 := newNode("node2", "10.0.0.2", "fd00:10::2")
	node3 := newNode("node3", "10.0.0.3", "fd00:10::3")

	// Instances
	newInstance := func(name string, role v1.RouteReflectorRole) *v1.IsovalentBGPInstance {
		return &v1.IsovalentBGPInstance{
			Name:     name,
			LocalASN: &asn,
			RouteReflector: &v1.RouteReflector{
				Role:                 role,
				ClusterID:            "255.0.0.1",
				PeeringAddressFamily: ptr.To(v1.RouteReflectorPeeringAddressFamilyDual),
				PeerConfigRefV4: &v1.PeerConfigReference{
					Name: "peer-config-v4",
				},
				PeerConfigRefV6: &v1.PeerConfigReference{
					Name: "peer-config-v6",
				},
			},
		}
	}

	rr0 := newInstance("rr0", v1.RouteReflectorRoleRouteReflector)
	rr1 := newInstance("rr1", v1.RouteReflectorRoleRouteReflector)
	client0 := newInstance("client0", v1.RouteReflectorRoleClient)
	client1 := newInstance("client1", v1.RouteReflectorRoleClient)

	// Use a strange default to test the explicit specification is working
	rrCluster := newRRCluster(v1.RouteReflectorPeeringAddressFamilyIPv4Only)
	rrCluster.AddInstance(node0, rr0)
	rrCluster.AddInstance(node1, rr1)
	rrCluster.AddInstance(node2, client0)
	rrCluster.AddInstance(node3, client1)

	t.Run("rr0 peers with rr1 and clients", func(t *testing.T) {
		// Ensure the correct peers are returned with the correct order (alphabetical)
		require.Equal(
			t,
			[]*rrClusterPeer{
				{
					Name:          "rr-client-node2-client0-v4",
					Address:       "10.0.0.2",
					PeerConfigRef: rr0.RouteReflector.PeerConfigRefV4,
					RouteReflector: &v1.NodeRouteReflector{
						Role:      v1.RouteReflectorRoleClient,
						ClusterID: "255.0.0.1",
					},
				},
				{
					Name:          "rr-client-node2-client0-v6",
					Address:       "fd00:10::2",
					PeerConfigRef: rr0.RouteReflector.PeerConfigRefV6,
					RouteReflector: &v1.NodeRouteReflector{
						Role:      v1.RouteReflectorRoleClient,
						ClusterID: "255.0.0.1",
					},
				},
				{
					Name:          "rr-client-node3-client1-v4",
					Address:       "10.0.0.3",
					PeerConfigRef: rr0.RouteReflector.PeerConfigRefV4,
					RouteReflector: &v1.NodeRouteReflector{
						Role:      v1.RouteReflectorRoleClient,
						ClusterID: "255.0.0.1",
					},
				},
				{
					Name:          "rr-client-node3-client1-v6",
					Address:       "fd00:10::3",
					PeerConfigRef: rr0.RouteReflector.PeerConfigRefV6,
					RouteReflector: &v1.NodeRouteReflector{
						Role:      v1.RouteReflectorRoleClient,
						ClusterID: "255.0.0.1",
					},
				},
				{
					Name:          "rr-route-reflector-node1-rr1-v4",
					Address:       "10.0.0.1",
					PeerConfigRef: rr0.RouteReflector.PeerConfigRefV4,
					RouteReflector: &v1.NodeRouteReflector{
						Role:      v1.RouteReflectorRoleRouteReflector,
						ClusterID: "255.0.0.1",
					},
				},
				{
					Name:          "rr-route-reflector-node1-rr1-v6",
					Address:       "fd00:10::1",
					PeerConfigRef: rr0.RouteReflector.PeerConfigRefV6,
					RouteReflector: &v1.NodeRouteReflector{
						Role:      v1.RouteReflectorRoleRouteReflector,
						ClusterID: "255.0.0.1",
					},
				},
			},
			rrCluster.ListPeers(instanceID{NodeName: "node0", InstanceName: "rr0"}),
		)
	})
	t.Run("rr1 peers with rr0 and clients", func(t *testing.T) {
		require.Equal(
			t,
			[]*rrClusterPeer{
				{
					Name:          "rr-client-node2-client0-v4",
					Address:       "10.0.0.2",
					PeerConfigRef: rr1.RouteReflector.PeerConfigRefV4,
					RouteReflector: &v1.NodeRouteReflector{
						Role:      v1.RouteReflectorRoleClient,
						ClusterID: "255.0.0.1",
					},
				},
				{
					Name:          "rr-client-node2-client0-v6",
					Address:       "fd00:10::2",
					PeerConfigRef: rr1.RouteReflector.PeerConfigRefV6,
					RouteReflector: &v1.NodeRouteReflector{
						Role:      v1.RouteReflectorRoleClient,
						ClusterID: "255.0.0.1",
					},
				},
				{
					Name:          "rr-client-node3-client1-v4",
					Address:       "10.0.0.3",
					PeerConfigRef: rr1.RouteReflector.PeerConfigRefV4,
					RouteReflector: &v1.NodeRouteReflector{
						Role:      v1.RouteReflectorRoleClient,
						ClusterID: "255.0.0.1",
					},
				},
				{
					Name:          "rr-client-node3-client1-v6",
					Address:       "fd00:10::3",
					PeerConfigRef: rr1.RouteReflector.PeerConfigRefV6,
					RouteReflector: &v1.NodeRouteReflector{
						Role:      v1.RouteReflectorRoleClient,
						ClusterID: "255.0.0.1",
					},
				},
				{
					Name:          "rr-route-reflector-node0-rr0-v4",
					Address:       "10.0.0.0",
					PeerConfigRef: rr1.RouteReflector.PeerConfigRefV4,
					RouteReflector: &v1.NodeRouteReflector{
						Role:      v1.RouteReflectorRoleRouteReflector,
						ClusterID: "255.0.0.1",
					},
				},
				{
					Name:          "rr-route-reflector-node0-rr0-v6",
					Address:       "fd00:10::",
					PeerConfigRef: rr1.RouteReflector.PeerConfigRefV6,
					RouteReflector: &v1.NodeRouteReflector{
						Role:      v1.RouteReflectorRoleRouteReflector,
						ClusterID: "255.0.0.1",
					},
				},
			},
			rrCluster.ListPeers(instanceID{NodeName: "node1", InstanceName: "rr1"}),
		)
	})
	t.Run("client0 peers with rrs", func(t *testing.T) {
		require.Equal(
			t,
			[]*rrClusterPeer{
				{
					Name:          "rr-route-reflector-node0-rr0-v4",
					Address:       "10.0.0.0",
					PeerConfigRef: client0.RouteReflector.PeerConfigRefV4,
					RouteReflector: &v1.NodeRouteReflector{
						Role:      v1.RouteReflectorRoleRouteReflector,
						ClusterID: "255.0.0.1",
					},
				},
				{
					Name:          "rr-route-reflector-node0-rr0-v6",
					Address:       "fd00:10::",
					PeerConfigRef: client0.RouteReflector.PeerConfigRefV6,
					RouteReflector: &v1.NodeRouteReflector{
						Role:      v1.RouteReflectorRoleRouteReflector,
						ClusterID: "255.0.0.1",
					},
				},
				{
					Name:          "rr-route-reflector-node1-rr1-v4",
					Address:       "10.0.0.1",
					PeerConfigRef: client0.RouteReflector.PeerConfigRefV4,
					RouteReflector: &v1.NodeRouteReflector{
						Role:      v1.RouteReflectorRoleRouteReflector,
						ClusterID: "255.0.0.1",
					},
				},
				{
					Name:          "rr-route-reflector-node1-rr1-v6",
					Address:       "fd00:10::1",
					PeerConfigRef: client0.RouteReflector.PeerConfigRefV6,
					RouteReflector: &v1.NodeRouteReflector{
						Role:      v1.RouteReflectorRoleRouteReflector,
						ClusterID: "255.0.0.1",
					},
				},
			},
			rrCluster.ListPeers(instanceID{NodeName: "node2", InstanceName: "client0"}),
		)
	})
	t.Run("client1 peers with rrs", func(t *testing.T) {
		require.Equal(
			t,
			[]*rrClusterPeer{
				{
					Name:          "rr-route-reflector-node0-rr0-v4",
					Address:       "10.0.0.0",
					PeerConfigRef: client1.RouteReflector.PeerConfigRefV4,
					RouteReflector: &v1.NodeRouteReflector{
						Role:      v1.RouteReflectorRoleRouteReflector,
						ClusterID: "255.0.0.1",
					},
				},
				{
					Name:          "rr-route-reflector-node0-rr0-v6",
					Address:       "fd00:10::",
					PeerConfigRef: client1.RouteReflector.PeerConfigRefV6,
					RouteReflector: &v1.NodeRouteReflector{
						Role:      v1.RouteReflectorRoleRouteReflector,
						ClusterID: "255.0.0.1",
					},
				},
				{
					Name:          "rr-route-reflector-node1-rr1-v4",
					Address:       "10.0.0.1",
					PeerConfigRef: client1.RouteReflector.PeerConfigRefV4,
					RouteReflector: &v1.NodeRouteReflector{
						Role:      v1.RouteReflectorRoleRouteReflector,
						ClusterID: "255.0.0.1",
					},
				},
				{
					Name:          "rr-route-reflector-node1-rr1-v6",
					Address:       "fd00:10::1",
					PeerConfigRef: client1.RouteReflector.PeerConfigRefV6,
					RouteReflector: &v1.NodeRouteReflector{
						Role:      v1.RouteReflectorRoleRouteReflector,
						ClusterID: "255.0.0.1",
					},
				},
			},
			rrCluster.ListPeers(instanceID{NodeName: "node3", InstanceName: "client1"}),
		)
	})
}

func TestRRClusterDualPartial(t *testing.T) {
	asn := int64(65000)

	// Nodes
	newNode := func(name, ipv4, ipv6 string) *v2.CiliumNode {
		return &v2.CiliumNode{
			ObjectMeta: meta_v1.ObjectMeta{
				Name: name,
			},
			Spec: v2.NodeSpec{
				Addresses: []v2.NodeAddress{
					{
						Type: addressing.NodeInternalIP,
						IP:   ipv4,
					},
					{
						Type: addressing.NodeInternalIP,
						IP:   ipv6,
					},
				},
			},
		}
	}

	node0 := newNode("node0", "10.0.0.0", "fd00:10::")
	node1 := newNode("node1", "10.0.0.1", "") // missing IPv6
	node2 := newNode("node2", "10.0.0.2", "fd00:10::2")
	node3 := newNode("node3", "", "fd00:10::3") // missing IPv4

	// Instances
	newInstance := func(name string, role v1.RouteReflectorRole) *v1.IsovalentBGPInstance {
		return &v1.IsovalentBGPInstance{
			Name:     name,
			LocalASN: &asn,
			RouteReflector: &v1.RouteReflector{
				Role:      role,
				ClusterID: "255.0.0.1",
				// Don't specify peering mode, we're testing defaulting
				PeerConfigRefV4: &v1.PeerConfigReference{
					Name: "peer-config-v4",
				},
				PeerConfigRefV6: &v1.PeerConfigReference{
					Name: "peer-config-v6",
				},
			},
		}
	}

	rr0 := newInstance("rr0", v1.RouteReflectorRoleRouteReflector)
	rr1 := newInstance("rr1", v1.RouteReflectorRoleRouteReflector)
	client0 := newInstance("client0", v1.RouteReflectorRoleClient)
	client1 := newInstance("client1", v1.RouteReflectorRoleClient)

	// Test defaulting behavior here
	rrCluster := newRRCluster(v1.RouteReflectorPeeringAddressFamilyDual)
	rrCluster.AddInstance(node0, rr0)
	rrCluster.AddInstance(node1, rr1)
	rrCluster.AddInstance(node2, client0)
	rrCluster.AddInstance(node3, client1)

	t.Run("rr0 peers with rr1 and clients", func(t *testing.T) {
		// Ensure the correct peers are returned with the correct order (alphabetical)
		require.Equal(
			t,
			[]*rrClusterPeer{
				{
					Name:          "rr-client-node2-client0-v4",
					Address:       "10.0.0.2",
					PeerConfigRef: rr0.RouteReflector.PeerConfigRefV4,
					RouteReflector: &v1.NodeRouteReflector{
						Role:      v1.RouteReflectorRoleClient,
						ClusterID: "255.0.0.1",
					},
				},
				{
					Name:          "rr-client-node2-client0-v6",
					Address:       "fd00:10::2",
					PeerConfigRef: rr0.RouteReflector.PeerConfigRefV6,
					RouteReflector: &v1.NodeRouteReflector{
						Role:      v1.RouteReflectorRoleClient,
						ClusterID: "255.0.0.1",
					},
				},
				// missing rr-client-node3-client1-v4
				{
					Name:          "rr-client-node3-client1-v6",
					Address:       "fd00:10::3",
					PeerConfigRef: rr0.RouteReflector.PeerConfigRefV6,
					RouteReflector: &v1.NodeRouteReflector{
						Role:      v1.RouteReflectorRoleClient,
						ClusterID: "255.0.0.1",
					},
				},
				{
					Name:          "rr-route-reflector-node1-rr1-v4",
					Address:       "10.0.0.1",
					PeerConfigRef: rr0.RouteReflector.PeerConfigRefV4,
					RouteReflector: &v1.NodeRouteReflector{
						Role:      v1.RouteReflectorRoleRouteReflector,
						ClusterID: "255.0.0.1",
					},
				},
				// missing rr-route-reflector-node1-rr1-v6
			},
			rrCluster.ListPeers(instanceID{NodeName: "node0", InstanceName: "rr0"}),
		)
	})
	t.Run("rr1 peers with rr0 and clients", func(t *testing.T) {
		require.Equal(
			t,
			[]*rrClusterPeer{
				{
					Name:          "rr-client-node2-client0-v4",
					Address:       "10.0.0.2",
					PeerConfigRef: rr1.RouteReflector.PeerConfigRefV4,
					RouteReflector: &v1.NodeRouteReflector{
						Role:      v1.RouteReflectorRoleClient,
						ClusterID: "255.0.0.1",
					},
				},
				{
					Name:          "rr-client-node2-client0-v6",
					Address:       "fd00:10::2",
					PeerConfigRef: rr1.RouteReflector.PeerConfigRefV6,
					RouteReflector: &v1.NodeRouteReflector{
						Role:      v1.RouteReflectorRoleClient,
						ClusterID: "255.0.0.1",
					},
				},
				// missing rr-client-node3-client1-v4
				{
					Name:          "rr-client-node3-client1-v6",
					Address:       "fd00:10::3",
					PeerConfigRef: rr1.RouteReflector.PeerConfigRefV6,
					RouteReflector: &v1.NodeRouteReflector{
						Role:      v1.RouteReflectorRoleClient,
						ClusterID: "255.0.0.1",
					},
				},
				{
					Name:          "rr-route-reflector-node0-rr0-v4",
					Address:       "10.0.0.0",
					PeerConfigRef: rr1.RouteReflector.PeerConfigRefV4,
					RouteReflector: &v1.NodeRouteReflector{
						Role:      v1.RouteReflectorRoleRouteReflector,
						ClusterID: "255.0.0.1",
					},
				},
				{
					Name:          "rr-route-reflector-node0-rr0-v6",
					Address:       "fd00:10::",
					PeerConfigRef: rr1.RouteReflector.PeerConfigRefV6,
					RouteReflector: &v1.NodeRouteReflector{
						Role:      v1.RouteReflectorRoleRouteReflector,
						ClusterID: "255.0.0.1",
					},
				},
			},
			rrCluster.ListPeers(instanceID{NodeName: "node1", InstanceName: "rr1"}),
		)
	})
	t.Run("client0 peers with rrs", func(t *testing.T) {
		require.Equal(
			t,
			[]*rrClusterPeer{
				{
					Name:          "rr-route-reflector-node0-rr0-v4",
					Address:       "10.0.0.0",
					PeerConfigRef: client0.RouteReflector.PeerConfigRefV4,
					RouteReflector: &v1.NodeRouteReflector{
						Role:      v1.RouteReflectorRoleRouteReflector,
						ClusterID: "255.0.0.1",
					},
				},
				{
					Name:          "rr-route-reflector-node0-rr0-v6",
					Address:       "fd00:10::",
					PeerConfigRef: client0.RouteReflector.PeerConfigRefV6,
					RouteReflector: &v1.NodeRouteReflector{
						Role:      v1.RouteReflectorRoleRouteReflector,
						ClusterID: "255.0.0.1",
					},
				},
				{
					Name:          "rr-route-reflector-node1-rr1-v4",
					Address:       "10.0.0.1",
					PeerConfigRef: client0.RouteReflector.PeerConfigRefV4,
					RouteReflector: &v1.NodeRouteReflector{
						Role:      v1.RouteReflectorRoleRouteReflector,
						ClusterID: "255.0.0.1",
					},
				},
				// missing rr-route-reflector-node1-rr1-v6
			},
			rrCluster.ListPeers(instanceID{NodeName: "node2", InstanceName: "client0"}),
		)
	})
	t.Run("client1 peers with rrs", func(t *testing.T) {
		require.Equal(
			t,
			[]*rrClusterPeer{
				{
					Name:          "rr-route-reflector-node0-rr0-v4",
					Address:       "10.0.0.0",
					PeerConfigRef: client1.RouteReflector.PeerConfigRefV4,
					RouteReflector: &v1.NodeRouteReflector{
						Role:      v1.RouteReflectorRoleRouteReflector,
						ClusterID: "255.0.0.1",
					},
				},
				{
					Name:          "rr-route-reflector-node0-rr0-v6",
					Address:       "fd00:10::",
					PeerConfigRef: client1.RouteReflector.PeerConfigRefV6,
					RouteReflector: &v1.NodeRouteReflector{
						Role:      v1.RouteReflectorRoleRouteReflector,
						ClusterID: "255.0.0.1",
					},
				},
				{
					Name:          "rr-route-reflector-node1-rr1-v4",
					Address:       "10.0.0.1",
					PeerConfigRef: client1.RouteReflector.PeerConfigRefV4,
					RouteReflector: &v1.NodeRouteReflector{
						Role:      v1.RouteReflectorRoleRouteReflector,
						ClusterID: "255.0.0.1",
					},
				},
				// missing rr-route-reflector-node1-rr1-v6
			},
			rrCluster.ListPeers(instanceID{NodeName: "node3", InstanceName: "client1"}),
		)
	})
}
