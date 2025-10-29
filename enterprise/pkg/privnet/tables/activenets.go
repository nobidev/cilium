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
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
)

// ActiveNetwork represents a network activated by a given workload node.
type ActiveNetwork struct {
	// Node is the target workload node.
	Node WorkloadNode

	// Network is the active private network.
	Network NetworkName
}

// WorkloadNode represents a workload node served by an Isovalent Network Bridge (INB).
type WorkloadNode struct {
	// Cluster is the name of the cluster hosting the node.
	Cluster ClusterName

	// Name is the name of the workload node.
	Name NodeName
}

func (wn WorkloadNode) String() string {
	return string(wn.Cluster) + "/" + string(wn.Name)
}

var _ statedb.TableWritable = ActiveNetwork{}

func (an ActiveNetwork) TableHeader() []string {
	return []string{"Node", "Network"}
}

func (an ActiveNetwork) TableRow() []string {
	return []string{an.Node.String(), string(an.Network)}
}

// activeNetworkKey is <node>|<network>
type activeNetworkKey string

func (key activeNetworkKey) Key() index.Key {
	return index.String(string(key))
}

func newActiveNetworkKeyByNode(node WorkloadNode) activeNetworkKey {
	return activeNetworkKey(node.String() + indexDelimiter)
}

func newActiveNetworkKey(node WorkloadNode, network NetworkName) activeNetworkKey {
	return newActiveNetworkKeyByNode(node) + activeNetworkKey(network)
}

var (
	activeNetworkPrimaryIndex = statedb.Index[ActiveNetwork, activeNetworkKey]{
		Name: "node-network",
		FromObject: func(an ActiveNetwork) index.KeySet {
			return index.NewKeySet(
				newActiveNetworkKey(an.Node, an.Network).Key())
		},
		FromKey:    activeNetworkKey.Key,
		FromString: index.FromString,
		Unique:     true,
	}
)

// ActiveNetworkByKey queries the ActiveNetworks table by workload node and network.
func ActiveNetworkByKey(node WorkloadNode, network NetworkName) statedb.Query[ActiveNetwork] {
	return activeNetworkPrimaryIndex.Query(newActiveNetworkKey(node, network))
}

// ActiveNetworkByNode queries the ActiveNetworks table by workload node.
func ActiveNetworkByNode(node WorkloadNode) statedb.Query[ActiveNetwork] {
	return activeNetworkPrimaryIndex.Query(newActiveNetworkKeyByNode(node))
}

func NewActiveNetworksTable(db *statedb.DB) (statedb.RWTable[ActiveNetwork], error) {
	return statedb.NewTable(
		db,
		"privnet-inb-active-networks",
		activeNetworkPrimaryIndex,
	)
}
