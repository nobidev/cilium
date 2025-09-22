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
	"net/netip"
	"slices"
	"strings"

	"go4.org/netipx"

	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
)

// instanceID uniquely identifies a BGP instance in a k8s cluster
type instanceID struct {
	NodeName     string
	InstanceName string
}

// rrCluster represents a route reflector cluster
type rrCluster struct {
	RRs                         []*rrClusterInstance
	Clients                     []*rrClusterInstance
	InstanceByName              map[instanceID]*rrClusterInstance
	DefaultPeeringAddressFamily v1.RouteReflectorPeeringAddressFamily
}

// rrClusterInstance represents a BGP instance in a route reflector cluster
type rrClusterInstance struct {
	Name      string
	V4Address netip.Addr
	V6Address netip.Addr
	Config    *v1.RouteReflector
}

// rrClusterPeer represents a peer in a route reflector cluster
type rrClusterPeer struct {
	Name           string
	Address        string
	PeerConfigRef  *v1.PeerConfigReference
	RouteReflector *v1.NodeRouteReflector
}

func newRRCluster(defaultPeeringAddressFamily v1.RouteReflectorPeeringAddressFamily) *rrCluster {
	return &rrCluster{
		RRs:                         []*rrClusterInstance{},
		Clients:                     []*rrClusterInstance{},
		InstanceByName:              map[instanceID]*rrClusterInstance{},
		DefaultPeeringAddressFamily: defaultPeeringAddressFamily,
	}
}

// Add Instance adds a BGP instance to the route reflector cluster with given
// peering mode. Depending on the mode, one or two peer will be created for
// give instance. The caller is responsible for ensuring that the instance is
// not already present in the cluster and all instances have the same ClusterID
// and LocalASN.
func (c *rrCluster) AddInstance(node *v2.CiliumNode, instance *v1.IsovalentBGPInstance) {
	v4PeeringAddr, _ := netipx.FromStdIP(node.GetIP(false))
	v6PeeringAddr, _ := netipx.FromStdIP(node.GetIP(true))
	if !v4PeeringAddr.IsValid() && !v6PeeringAddr.IsValid() {
		// Cannot peer with this instance which is expected. The node
		// may not have an IP address yet. When it gets one, the
		// reconciliation will be triggered again. Ignore this instance
		// for now.
		return
	}

	name := c.instanceName(instance.RouteReflector.Role, node.Name, instance.Name)

	// Store the instance per role
	var newInstance *rrClusterInstance
	switch instance.RouteReflector.Role {
	case v1.RouteReflectorRoleRouteReflector:
		newInstance = &rrClusterInstance{
			Name:      name,
			V4Address: v4PeeringAddr,
			V6Address: v6PeeringAddr,
			Config:    instance.RouteReflector,
		}
		c.RRs = append(c.RRs, newInstance)
	case v1.RouteReflectorRoleClient:
		newInstance = &rrClusterInstance{
			Name:      name,
			V4Address: v4PeeringAddr,
			V6Address: v6PeeringAddr,
			Config:    instance.RouteReflector,
		}
		c.Clients = append(c.Clients, newInstance)
	default:
		// Unknown role. This should never happen. Ignore.
		return
	}

	// Index the instance by ID for later lookup
	c.InstanceByName[instanceID{NodeName: node.Name, InstanceName: instance.Name}] = newInstance
}

// ListPeers returns a list of peers for the given instance in the route
// reflector cluster. The instance must be already added to the cluster with
// AddInstance prior to this function (when the instance is not found, an empty
// list is returned). The list of peers is determined by the role of the
// instance. Route Reflectors (rr) peer with both Clients and other RRs.
// Clients peer only with RRs.
func (c *rrCluster) ListPeers(instanceID instanceID) []*rrClusterPeer {
	self, found := c.InstanceByName[instanceID]
	if !found {
		// Instance not found
		return []*rrClusterPeer{}
	}

	peers := []*rrClusterPeer{}

	peeringAF := c.DefaultPeeringAddressFamily
	if self.Config.PeeringAddressFamily != nil {
		peeringAF = *self.Config.PeeringAddressFamily
	}

	switch self.Config.Role {
	case v1.RouteReflectorRoleRouteReflector:
		// Route Reflectors peer with clients
		for _, client := range c.Clients {
			if client.Name == self.Name {
				// Don't peer with itself
				continue
			}
			if (peeringAF == v1.RouteReflectorPeeringAddressFamilyDual || peeringAF == v1.RouteReflectorPeeringAddressFamilyIPv4Only) && client.V4Address.IsValid() {
				peers = append(peers, &rrClusterPeer{
					Name:          client.Name + "-v4",
					Address:       client.V4Address.String(),
					PeerConfigRef: self.Config.PeerConfigRefV4,
					RouteReflector: &v1.NodeRouteReflector{
						Role:      client.Config.Role,
						ClusterID: client.Config.ClusterID,
					},
				})
			}
			if (peeringAF == v1.RouteReflectorPeeringAddressFamilyDual || peeringAF == v1.RouteReflectorPeeringAddressFamilyIPv6Only) && client.V6Address.IsValid() {
				peers = append(peers, &rrClusterPeer{
					Name:          client.Name + "-v6",
					Address:       client.V6Address.String(),
					PeerConfigRef: self.Config.PeerConfigRefV6,
					RouteReflector: &v1.NodeRouteReflector{
						Role:      client.Config.Role,
						ClusterID: client.Config.ClusterID,
					},
				})
			}
		}
		// Route Reflector also need to peer with other RRs.
		fallthrough
	case v1.RouteReflectorRoleClient:
		// RRs and Clients peer with RRs
		for _, rr := range c.RRs {
			if rr.Name == self.Name {
				// Don't peer with itself
				continue
			}
			if (peeringAF == v1.RouteReflectorPeeringAddressFamilyDual || peeringAF == v1.RouteReflectorPeeringAddressFamilyIPv4Only) && rr.V4Address.IsValid() {
				peers = append(peers, &rrClusterPeer{
					Name:          rr.Name + "-v4",
					Address:       rr.V4Address.String(),
					PeerConfigRef: self.Config.PeerConfigRefV4,
					RouteReflector: &v1.NodeRouteReflector{
						Role:      rr.Config.Role,
						ClusterID: rr.Config.ClusterID,
					},
				})
			}
			if (peeringAF == v1.RouteReflectorPeeringAddressFamilyDual || peeringAF == v1.RouteReflectorPeeringAddressFamilyIPv6Only) && rr.V6Address.IsValid() {
				peers = append(peers, &rrClusterPeer{
					Name:          rr.Name + "-v6",
					Address:       rr.V6Address.String(),
					PeerConfigRef: self.Config.PeerConfigRefV6,
					RouteReflector: &v1.NodeRouteReflector{
						Role:      rr.Config.Role,
						ClusterID: rr.Config.ClusterID,
					},
				})
			}
		}
	}

	// Sort results for deterministic output
	slices.SortStableFunc(peers, func(i0, i1 *rrClusterPeer) int {
		return strings.Compare(i0.Name, i1.Name)
	})

	return peers
}

func (c *rrCluster) instanceName(role v1.RouteReflectorRole, nodeName, instanceName string) string {
	return "rr-" + string(role) + "-" + nodeName + "-" + instanceName
}
