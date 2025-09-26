// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package tables

import (
	"errors"
	"net/netip"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"

	"github.com/cilium/cilium/enterprise/pkg/privnet/types"
	"github.com/cilium/cilium/pkg/time"
)

// NodeName is the name of a node.
type NodeName = types.NodeName

// INB represents an Isovalent Network Bridge (INB) instance for a given network.
type INB struct {
	// Network is the name of the private network this INB is serving.
	Network NetworkName

	// Node represents the node hosting this INB.
	Node INBNode

	// Health represents the current state of the INB for the given network,
	// as returned by the health checker.
	Health INBHealthState

	// Role represents the current role of the INB for the given network.
	Role INBRole

	// UpdatedAt is the instance in time of the last update.
	UpdatedAt time.Time
}

var _ statedb.TableWritable = INB{}

func (i INB) TableHeader() []string {
	return []string{"Cluster", "Node", "IP", "Network", "Health", "Role", "LastUpdate"}
}

func (i INB) TableRow() []string {
	var updatedAt = "Never"
	if !i.UpdatedAt.IsZero() {
		updatedAt = i.UpdatedAt.Format(time.RFC3339)
	}

	return []string{
		string(i.Node.Cluster), string(i.Node.Name),
		i.Node.IP.String(),
		string(i.Network),
		i.Health.String(),
		i.Role.String(),
		updatedAt,
	}
}

// Update updates the INB state, and possibly role, based on the provided health
// state. Returns whether the update was effective or a no-op.
func (i *INB) Update(health INBHealthState) (updated bool) {
	if i.Health == health {
		return false
	}

	i.Health = health
	i.UpdatedAt = time.Now()

	i.Role = INBRoleNone
	if health.Node == INBNodeStateHealthy && health.Network == INBNetworkStateConfirmed {
		i.Role = INBRoleStandby
	}

	return true
}

// Activate promotes a previously standby INB to active. Returns an error if the
// state transition is not valid.
func (i *INB) Activate() error {
	switch i.Role {
	case INBRoleActive:
		return nil
	case INBRoleStandby:
		i.Role = INBRoleActive
		i.UpdatedAt = time.Now()
		return nil
	default:
		return errors.New("current role is not 'Standby'")
	}
}

// INBNode represents a node hosting an INB.
type INBNode struct {
	// Cluster is the name of the cluster hosting the node.
	Cluster ClusterName

	// Name is the name of the Kubernetes node.
	Name NodeName

	// IP is the IP address this node is reachable at.
	IP netip.Addr
}

func (node INBNode) String() string {
	return string(node.Cluster) + "/" + string(node.Name)
}

// INBState represents the health state of an INB for a given private network.
type INBHealthState struct {
	// Node is the health state of the INB node.
	Node INBNodeState

	// Network represents whether the INB is will.
	Network INBNetworkState
}

func (state INBHealthState) String() string {
	return state.Node.String() + ", " + state.Network.String()
}

// INBNodeState represents the health state of an INB node from the point of
// view of the local node.
type INBNodeState uint8

const (
	// INBNodeStateUnknown: the INB node state is unknown.
	INBNodeStateUnknown INBNodeState = iota
	// INBNodeStateUnhealthy: the INB node is unhealthy.
	INBNodeStateUnhealthy
	// INBNodeStateHealthy: the INB node is healthy.
	INBNodeStateHealthy
)

func (state INBNodeState) String() string {
	switch state {
	case INBNodeStateUnhealthy:
		return "Unhealthy"
	case INBNodeStateHealthy:
		return "Healthy"
	default:
		return "Unknown"
	}
}

// INBNetworkState represents the state of the target network as reported by the INB.
type INBNetworkState uint8

const (
	// INBNetworkStateUnknown: the private network state is unknown.
	INBNetworkStateUnknown INBNetworkState = iota
	// INBNetworkStateDenied: the INB denied serving this private network.
	INBNetworkStateDenied
	// INBNetworkStateConfirmed: the INB confirmed serving this private network.
	INBNetworkStateConfirmed
)

func (state INBNetworkState) String() string {
	switch state {
	case INBNetworkStateDenied:
		return "Denied"
	case INBNetworkStateConfirmed:
		return "Confirmed"
	default:
		return "Unknown"
	}
}

// INBRole represents the role of the INB for this private network.
type INBRole uint8

const (
	// INBRoleNone: the INB has no role for the given network.
	INBRoleNone INBRole = iota
	// INBRoleStandby: the INB is a candidate to serve the given network.
	INBRoleStandby
	// INBRoleActive: the INB is serving the given network.
	INBRoleActive
)

func (role INBRole) String() string {
	switch role {
	case INBRoleStandby:
		return "Standby"
	case INBRoleActive:
		return "Active"
	default:
		return "Unknown"
	}
}

func (role INBRole) Key() uint8 {
	switch role {
	case INBRoleStandby:
		return 'S'
	case INBRoleActive:
		return 'A'
	default:
		return '?'
	}
}

// inbKey is <cluster>|<node>|<network>
type inbKey string

func (key inbKey) Key() index.Key {
	return index.String(string(key))
}

func newINBKeyFromCluster(cluster ClusterName) inbKey {
	return inbKey(cluster + indexDelimiter)
}

func newINBKeyFromNode(cluster ClusterName, node NodeName) inbKey {
	return newINBKeyFromCluster(cluster) + inbKey(node+indexDelimiter)
}

func newINBKey(cluster ClusterName, node NodeName, network NetworkName) inbKey {
	return newINBKeyFromNode(cluster, node) + inbKey(string(network))
}

// inbNetRoleKey is <network>|<role>
type inbNetRoleKey string

func (key inbNetRoleKey) Key() index.Key {
	return index.String(string(key))
}

func newINBNetRoleKeyFromNetwork(network NetworkName) inbNetRoleKey {
	return inbNetRoleKey(string(network) + indexDelimiter)
}

func newINBNetRoleKey(network NetworkName, role INBRole) inbNetRoleKey {
	return newINBNetRoleKeyFromNetwork(network) + inbNetRoleKey(role.Key())
}

var (
	inbPrimaryIndex = statedb.Index[INB, inbKey]{
		Name: "primary",
		FromObject: func(obj INB) index.KeySet {
			return index.NewKeySet(
				newINBKey(obj.Node.Cluster, obj.Node.Name, obj.Network).Key())
		},
		FromKey:    inbKey.Key,
		FromString: index.FromString,
		Unique:     true,
	}

	inbNetRoleIndex = statedb.Index[INB, inbNetRoleKey]{
		Name: "network-role",
		FromObject: func(obj INB) index.KeySet {
			return index.NewKeySet(
				newINBNetRoleKey(obj.Network, obj.Role).Key())
		},
		FromKey:    inbNetRoleKey.Key,
		FromString: index.FromString,
		Unique:     false,
	}
)

// INBsByCluster queries the INBs table by cluster name.
func INBsByCluster(cluster ClusterName) statedb.Query[INB] {
	return inbPrimaryIndex.Query(newINBKeyFromCluster(cluster))
}

// INBsByNode queries the INBs table by cluster and node name.
func INBsByNode(cluster ClusterName, node NodeName) statedb.Query[INB] {
	return inbPrimaryIndex.Query(newINBKeyFromNode(cluster, node))
}

// INBByNodeAndNetwork queries the INBs table by cluster, node and network name.
func INBByNodeAndNetwork(cluster ClusterName, node NodeName, network NetworkName) statedb.Query[INB] {
	return inbPrimaryIndex.Query(newINBKey(cluster, node, network))
}

// INBsByNetwork queries the INBs table by network name.
func INBsByNetwork(network NetworkName) statedb.Query[INB] {
	return inbNetRoleIndex.Query(newINBNetRoleKeyFromNetwork(network))
}

// INBsByNetworkAndRole queries the INBs table by network name and INB role.
func INBsByNetworkAndRole(network NetworkName, role INBRole) statedb.Query[INB] {
	return inbNetRoleIndex.Query(newINBNetRoleKey(network, role))
}

func NewINBsTable(db *statedb.DB) (statedb.RWTable[INB], error) {
	return statedb.NewTable(
		db,
		"privnet-inbs",
		inbPrimaryIndex,
		inbNetRoleIndex,
	)
}
