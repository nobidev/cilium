//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package status

import (
	"net/netip"

	"github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
)

// NodeStatus is a summary of the state of the privnet subsystem for one node
type NodeStatus struct {
	// Name is the name of the node
	Name tables.NodeName
	// Cluster is the cluster name
	Cluster tables.ClusterName

	// ConnectedClusters is a list of connected clusters
	ConnectedClusters []ConnectedCluster

	// Enabled shows if the privnet feature is enabled
	Enabled bool
	// Mode is the mode the node is running in ("default" or "bridge")
	Mode string
	// Networks provides the status for every configured private network
	Networks []NetworkStatus
}

// ConnectedCluster represents a cluster connected to the node
type ConnectedCluster struct {
	// Name is the name of the cluster
	Name tables.ClusterName
	// NodeNames is a list containing all known nodes in the cluster
	NodeNames []tables.NodeName
}

// NetworkStatus is a summary of the state of a single private network
type NetworkStatus struct {
	// Name of the network
	Name tables.NetworkName

	// Error is any critical error related to the network
	Error string

	// The set of routes configured for this private network.
	Routes []Route
	// The set of subnets (that is, L2 domains) associated with, and directly
	// reachable, from this private network.
	Subnets []Subnet
	// The list of known endpoint in this network
	Endpoints []EndpointStatus

	// The status of the INB - empty for non INB nodes
	INBStatus INBStatus

	// The status of the workload nodes - empty for INB nodes
	WorkerStatus WorkerStatus
}

// Route is a route configured on the private network
type Route struct {
	// Destination is the route's destination CIDR.
	Destination netip.Prefix

	// Gateway is the route's gateway IP address.
	Gateway netip.Addr
}

// Subnet is a subnet configured on the private network
type Subnet struct {
	// CIDR defines the subnet
	CIDR netip.Prefix
}

type EndpointStatus struct {
	// The name identifying the target endpoint.
	Name string
	// In what cluster the endpoint is in
	Cluster tables.ClusterName
	// The name of the node hosting the target endpoint. It is the name of
	// the Isovalent Network Bridge when operating in bridge mode.
	Node tables.NodeName

	// The pod IPv4
	IPv4 netip.Addr
	// The network IPv4
	NetIPv4 netip.Addr

	// The pod IPv6
	IPv6 netip.Addr
	// The network IPv6
	NetIPv6 netip.Addr

	// Whether the endpoint is active
	Active bool
	// Whether the endpoint is an external endpoint
	External bool
}

type INBStatus struct {
	// Whether the local node is an INB that is able to serve the network
	Serving bool
	// The network interface providing external connectivity to this private
	// network. Applies to the Isovalent Network Bridge cluster only.
	Interface Interface
	// The list of WorkloadNodes that are being actively served by the local node
	// as an INB.
	ActiveWorkloadNodes []WorkloadNode
}

// Interface is the network interface providing external
// connectivity to a private network.
type Interface struct {
	// Name is the name of the interface.
	Name string

	// Index is the (positive) index of the interface.
	Index int

	// Error is the possible error occurred mapping the interface name to its index.
	Error string
}

// WorkloadNode represents a workload node served by an Isovalent Network Bridge (INB).
type WorkloadNode struct {
	// Cluster is the name of the cluster hosting the node.
	Cluster tables.ClusterName
	// Name is the name of the workload node.
	Name tables.NodeName
}

type WorkerStatus struct {
	// The name of the active INB
	ActiveINB string
	// A list of connected INBs for this network. Only applies to workload nodes
	ConnectedINBCluster []INBCluster
}

// INBCluster represents a cluster containing one or more INBs
type INBCluster struct {
	// The cluster name of the INB cluster
	Name tables.ClusterName
	// A list of INBs in the cluster and their status for the network
	INBs []ConnectedINB
}

type ConnectedINB struct {
	// Cluster is the name of the cluster hosting the node.
	Cluster tables.ClusterName
	// Name is the name of the Kubernetes node.
	Name tables.NodeName

	// If the INB is active
	Active bool
	// If the INB is healthy and ready to serve the network
	Healthy bool
}

// Format will represent the Privnet Node status in a human readable format
func (s NodeStatus) Format() string {
	if !s.Enabled {
		return fmtErr("Error: Private Networking not enabled\n")
	}

	switch s.Mode {
	case config.ModeBridge:
		return s.formatINBNode()
	default:
		return s.formatWorkerNode()
	}
}
