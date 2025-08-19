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
	"strconv"
	"strings"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"

	iso_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	cslices "github.com/cilium/cilium/pkg/slices"
)

type (
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

	// The list of Isovalent Network Bridges (INBs) serving this private network.
	INBs []iso_v1alpha1.INBRef

	// The network interface providing external connectivity to this private
	// network. Applies to the Isovalent Network Bridge cluster only.
	Interface PrivateNetworkInterface

	// The set of routes configured for this private network.
	Routes []iso_v1alpha1.RouteSpec

	// The set of subnets (that is, L2 domains) associated with, and directly
	// reachable, from this private network.
	Subnets []iso_v1alpha1.SubnetSpec
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

var _ statedb.TableWritable = PrivateNetwork{}

func (pn PrivateNetwork) TableHeader() []string {
	return []string{"Name", "ID", "Interface", "INBs", "Subnets", "Routes"}
}

func (pn PrivateNetwork) TableRow() []string {
	return []string{
		string(pn.Name),
		"0x" + strconv.FormatUint(uint64(pn.ID), 16),
		cmp.Or(pn.Interface.Name, "N/A"),
		cmp.Or(strings.Join(cslices.Map(pn.INBs,
			func(i iso_v1alpha1.INBRef) string { return string(i.IP) },
		), ","), "N/A"),
		strings.Join(cslices.Map(pn.Subnets,
			func(s iso_v1alpha1.SubnetSpec) string { return string(s.CIDR) },
		), ","),
		strconv.FormatInt(int64(len(pn.Routes)), 10),
	}
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
