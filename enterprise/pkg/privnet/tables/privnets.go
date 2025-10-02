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
	"cmp"
	"math"
	"net/netip"
	"strconv"
	"strings"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"

	"github.com/cilium/cilium/enterprise/pkg/privnet/types"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	cslices "github.com/cilium/cilium/pkg/slices"
)

type (
	// ClusterName is the name of a cluster.
	ClusterName = types.ClusterName

	// NetworkID is a numeric identifier of a private network.
	NetworkID uint16

	// NetworkName is the name of a private network.
	NetworkName string
)

const (
	// NetworkIDReserved represents the reserved NetworkID that cannot be assigned.
	NetworkIDReserved = NetworkID(0)

	// NetworkIDMax represents the highest NetworkID value.
	NetworkIDMax = NetworkID(math.MaxUint16)
)

// PrivateNetwork represents a private network instance.
type PrivateNetwork struct {
	// Name is the name of the private network.
	Name NetworkName

	// ID is the local-scoped numeric identifier of the private network.
	ID NetworkID

	// The candidate Isovalent Network Bridges (INBs) serving this private network.
	INBs PrivateNetworkINBs

	// The network interface providing external connectivity to this private
	// network. Applies to the Isovalent Network Bridge cluster only.
	Interface PrivateNetworkInterface

	// The set of routes configured for this private network.
	Routes []PrivateNetworkRoute

	// The set of subnets (that is, L2 domains) associated with, and directly
	// reachable, from this private network.
	Subnets []PrivateNetworkSubnet
}

// PrivateNetworkInterface is the network interface providing external
// connectivity to a private network.
type PrivateNetworkInterface struct {
	// Name is the name of the interface.
	Name string

	// Index is the (positive) index of the interface.
	Index int

	// Error is the possible error occurred mapping the interface name to its index.
	Error string
}

// PrivateNetworkINBs contains the network bridge configuration of the private network
type PrivateNetworkINBs struct {
	// IPs is the IP address of the network bridge
	IPs []netip.Addr

	// Selectors selects the candidate INB nodes for this private network.
	Selectors map[ClusterName]PrivateNetworkINBNodeSelector
}

// PrivateNetworkINBNodeSelector wraps a [labels.Selector] so that it can be
// pretty-printed when outputting the statedb table in json/yaml format.
type PrivateNetworkINBNodeSelector struct{ labels.Selector }

// MarshalText implements the [TextMarshaler] interface.
func (sel PrivateNetworkINBNodeSelector) MarshalText() ([]byte, error) {
	return []byte(sel.Selector.String()), nil
}

// PrivateNetworkRoute is a route configured on the private network
type PrivateNetworkRoute struct {
	// Destination is the route's destination CIDR.
	Destination netip.Prefix

	// Gateway is the route's gateway IP address.
	Gateway netip.Addr
}

// PrivateNetworkSubnet is a subnet configured on the private network
type PrivateNetworkSubnet struct {
	// CIDR defines the subnet
	CIDR netip.Prefix
}

var _ statedb.TableWritable = PrivateNetwork{}

func (pn PrivateNetwork) TableHeader() []string {
	return []string{"Name", "ID", "Interface", "INBs", "Subnets", "Routes"}
}

func (pn PrivateNetwork) TableRow() []string {
	return []string{
		string(pn.Name),
		"0x" + strconv.FormatUint(uint64(pn.ID), 16),
		cmp.Or(pn.Interface.Name, "N/A"),
		cmp.Or(strings.Join(cslices.Map(pn.INBs.IPs,
			func(i netip.Addr) string { return i.String() },
		), ","), "N/A"),
		strings.Join(cslices.Map(pn.Subnets,
			func(s PrivateNetworkSubnet) string { return s.CIDR.String() },
		), ","),
		strconv.FormatInt(int64(len(pn.Routes)), 10),
	}
}

// ToSlim returns a [SlimPrivateNetwork] object for this private network.
func (pn PrivateNetwork) ToSlim(activeINB INBNode) SlimPrivateNetwork {
	var inb netip.Addr
	if len(pn.INBs.IPs) > 0 {
		inb = pn.INBs.IPs[0]
	}

	return SlimPrivateNetwork{
		Name:          pn.Name,
		ID:            pn.ID,
		EgressIfIndex: pn.Interface.Index,
		// TODO: replace with the following when enabling INB autodetection.
		// ActiveINB: activeINB,
		ActiveINB: INBNode{IP: inb},
	}
}

// SlimPrivateNetwork wraps the core private network information for MapEntry construction.
type SlimPrivateNetwork struct {
	// Name is the name of the private network.
	Name NetworkName

	// ID is the local-scoped numeric identifier of the private network.
	ID NetworkID

	// EgressIfIndex is the index of the network interface providing external
	// connectivity to this private network.
	EgressIfIndex int

	// ActiveINB is the active INB node.
	ActiveINB INBNode
}

var (
	privateNetworksNameIndex = statedb.Index[PrivateNetwork, string]{
		Name: "name",
		FromObject: func(obj PrivateNetwork) index.KeySet {
			return index.NewKeySet(index.String(string(obj.Name)))
		},
		FromKey:    index.String,
		FromString: index.FromString,
		Unique:     true,
	}
)

// PrivateNetworkByName queries the private networks table by name
func PrivateNetworkByName(name NetworkName) statedb.Query[PrivateNetwork] {
	return privateNetworksNameIndex.Query(string(name))
}

func NewPrivateNetworksTable(db *statedb.DB) (statedb.RWTable[PrivateNetwork], error) {
	return statedb.NewTable(
		db,
		"private-networks",
		privateNetworksNameIndex,
	)
}
