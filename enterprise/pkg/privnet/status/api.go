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
	"encoding/json"
	"net/netip"

	"github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
)

// The schema version of the node status API. Bump this number whenever making
// a change to the API
const NodeStatusSchemaVersion = 0

// NodeStatus is a summary of the state of the privnet subsystem for one node
//
// WARNING - STABLE API: Changing the structure or values of this may break
// backwards compatibility with cilium-cli
type NodeStatus struct {
	// Version is the schema version of the node status API. Bump on any change.
	Version int `json:"revision"`

	// Name is the name of the node
	Name tables.NodeName `json:"name"`

	// Cluster is the cluster name
	Cluster tables.ClusterName `json:"cluster"`

	// ConnectedClusters is a list of connected clusters
	ConnectedClusters []ConnectedCluster `json:"connectedClusters,omitempty"`

	// Enabled shows if the privnet feature is enabled
	Enabled bool `json:"enabled"`
	// Mode is the mode the node is running in ("default" or "bridge")
	Mode string `json:"mode"`
	// Networks provides the status for every configured private network
	Networks []NetworkStatus `json:"networks,omitempty"`
}

// ConnectedCluster represents a cluster connected to the node
type ConnectedCluster struct {
	// Name is the name of the cluster
	Name tables.ClusterName `json:"name"`
	// NodeNames is a list containing the names of all known nodes in the cluster
	NodeNames []tables.NodeName `json:"nodeNames,omitempty"`
}

// NetworkStatus is a summary of the state of a single private network
type NetworkStatus struct {
	// Name of the network
	Name tables.NetworkName `json:"name"`

	// Error is any critical error related to the network
	Error string `json:"error,omitzero"`

	// The set of routes configured for this private network.
	Routes []Route `json:"routes,omitempty"`
	// The set of subnets (that is, L2 domains) associated with, and directly
	// reachable, from this private network.
	Subnets []Subnet `json:"subnets,omitempty"`
	// The list of known endpoint in this network
	Endpoints []EndpointStatus `json:"endpoints,omitempty"`

	// The status of the INB - empty for non INB nodes
	INBStatus INBStatus `json:"inbStatus,omitzero"`

	// The status of the workload nodes - empty for INB nodes
	WorkerStatus WorkerStatus `json:"workerStatus,omitzero"`
}

// Route is a route configured on the private network
type Route struct {
	// Destination is the route's destination CIDR.
	Destination netip.Prefix `json:"destination"`

	// Gateway is the route's gateway IP address.
	Gateway netip.Addr `json:"gateway"`
}

// Subnet is a subnet configured on the private network
type Subnet struct {
	// CIDR defines the subnet
	CIDR netip.Prefix `json:"cidr"`
}

type EndpointStatus struct {
	// The name identifying the target endpoint.
	Name string `json:"name"`
	// In what cluster the endpoint is in
	Cluster tables.ClusterName `json:"cluster"`
	// The name of the node hosting the target endpoint. It is the name of
	// the Isovalent Network Bridge when operating in bridge mode.
	Node tables.NodeName `json:"node"`

	// The pod IPv4
	IPv4 netip.Addr `json:"ipv4,omitzero"`
	// The network IPv4
	NetIPv4 netip.Addr `json:"netIPv4,omitzero"`

	// The pod IPv6
	IPv6 netip.Addr `json:"ipv6,omitzero"`
	// The network IPv6
	NetIPv6 netip.Addr `json:"netIPv6,omitzero"`

	// Whether the endpoint is active
	Active bool `json:"active"`
	// Whether the endpoint is an external endpoint
	External bool `json:"external,omitzero"`
}

type INBStatus struct {
	// Whether the local node is an INB that is able to serve the network
	Serving bool `json:"serving"`
	// The network interface providing external connectivity to this private
	// network. Applies to the Isovalent Network Bridge cluster only.
	Interface Interface `json:"interface"`
	// The list of WorkloadNodes that are being actively served by the local node
	// as an INB.
	ActiveWorkloadNodes []WorkloadNode `json:"activeWorkloadNodes,omitempty"`
}

// Interface is the network interface providing external
// connectivity to a private network.
type Interface struct {
	// Name is the name of the interface.
	Name string `json:"name"`

	// Index is the (positive) index of the interface.
	Index int `json:"index"`

	// Error is the possible error occurred mapping the interface name to its index.
	Error string `json:"error,omitzero"`
}

// WorkloadNode represents a workload node served by an Isovalent Network Bridge (INB).
type WorkloadNode struct {
	// Name is the name of the workload node.
	Name tables.NodeName `json:"name"`
	// Cluster is the name of the cluster hosting the node.
	Cluster tables.ClusterName `json:"cluster"`
}

type WorkerStatus struct {
	// The name of the active INB
	ActiveINB string `json:"activeINB"`
	// A list of connected INBs for this network. Only applies to workload nodes
	ConnectedINBCluster []INBCluster `json:"connectedINBCluster,omitempty"`
}

// INBCluster represents a cluster containing one or more INBs
type INBCluster struct {
	// The cluster name of the INB cluster
	Name tables.ClusterName `json:"name"`
	// A list of INBs in the cluster and their status for the network
	INBs []ConnectedINB `json:"inbs,omitempty"`
}

type ConnectedINB struct {
	// Name is the name of the Kubernetes node.
	Name tables.NodeName `json:"name"`
	// Cluster is the name of the cluster hosting the node.
	Cluster tables.ClusterName `json:"cluster"`
	// If the INB is active
	Active bool `json:"active"`
	// If the INB is healthy and ready to serve the network
	Healthy bool `json:"healthy"`
}

func (s NodeStatus) MarshalJSON() ([]byte, error) {
	s.Version = NodeStatusSchemaVersion
	// Prevent a loop of calling MarshalJSON again by retyping the status.
	// Tags should survive the retype
	type _NodeStatus NodeStatus
	return json.Marshal(_NodeStatus(s))
}

func (s *NodeStatus) UnmarshalJSON(b []byte) error {
	// Prevent a loop of calling UnmarshalJSON again by retyping the status.
	// Tags should survive the retype
	type _NodeStatus *NodeStatus
	return json.Unmarshal(b, _NodeStatus(s))
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
