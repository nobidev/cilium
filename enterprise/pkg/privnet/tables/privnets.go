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
	"iter"
	"maps"
	"math"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"

	"github.com/cilium/cilium/enterprise/pkg/privnet/types"
	"github.com/cilium/cilium/enterprise/pkg/vni"
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

func (nid NetworkID) String() string {
	return "0x" + strconv.FormatUint(uint64(nid), 16)
}

const (
	// NetworkIDReserved represents the reserved NetworkID that cannot be assigned.
	NetworkIDReserved = NetworkID(0)

	// NetworkIDMax represents the highest NetworkID value.
	NetworkIDMax = NetworkID(math.MaxUint16) - 1
	// NetworkIDUnknown is reserved for signaling that the NetworkID is unknown.
	NetworkIDUnknown = NetworkID(math.MaxUint16)
)

func (nid NetworkID) Key() index.Key {
	return index.Uint16(uint16(nid))
}

// PrivateNetwork represents a private network instance.
type PrivateNetwork struct {
	// Name is the name of the private network.
	Name NetworkName

	// ID is the local-scoped numeric identifier of the private network.
	ID NetworkID

	// VNI is the allocated value of the VXLAN Network Identifier of the private network.
	VNI vni.VNI

	// The candidate Isovalent Network Bridges (INBs) serving this private network.
	INBs PrivateNetworkINBs

	// The network interface providing external connectivity to this private
	// network. Applies to the Isovalent Network Bridge cluster only.
	Interface PrivateNetworkInterface

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

	// Conflict is true in case the interface is selected by multiple private networks.
	Conflict bool
}

func (pni PrivateNetworkInterface) String() string {
	if pni.Name == "" {
		return "N/A"
	}

	if pni.Error == "" {
		return pni.Name
	}

	return pni.Name + " !"
}

// PrivateNetworkINBs contains the network bridge configuration of the private network
type PrivateNetworkINBs struct {
	// Selectors selects the candidate INB nodes for this private network.
	Selectors map[ClusterName]PrivateNetworkINBNodeSelector
}

// PrivateNetworkINBNodeSelector wraps a [labels.Selector] so that it can be
// pretty-printed when outputting the statedb table in json/yaml format.
type PrivateNetworkINBNodeSelector struct{ labels.Selector }

// MarshalText implements the [encoding.TextMarshaler] interface.
func (sel PrivateNetworkINBNodeSelector) MarshalText() ([]byte, error) {
	return []byte(sel.Selector.String()), nil
}

// UnmarshalText implements the [encoding.TextUnmarshaler] interface.
func (sel *PrivateNetworkINBNodeSelector) UnmarshalText(in []byte) (err error) {
	sel.Selector, err = labels.Parse(string(in))
	return err
}

// PrivateNetworkRoute is a route configured on the private network
type PrivateNetworkRoute struct {
	// Destination is the route's destination CIDR.
	Destination netip.Prefix

	// Gateway is the route's gateway IP address.
	Gateway netip.Addr

	// EVPNGateway is true if destination is reachable via evpn gateway
	EVPNGateway bool
}

// PrivateNetworkSubnet is a subnet configured on the private network
type PrivateNetworkSubnet struct {
	// Name is the name of the subnet
	Name SubnetName
	// CIDRv4 defines the IPv4 subnet
	CIDRv4 netip.Prefix
	// CIDRv6 defines the IPv6 subnet
	CIDRv6 netip.Prefix
	// The set of routes configured for this subnet.
	Routes []PrivateNetworkRoute
}

func (sub PrivateNetworkSubnet) CIDRs() iter.Seq[netip.Prefix] {
	return func(yield func(cidr netip.Prefix) bool) {
		if sub.CIDRv4.IsValid() && sub.CIDRv4.Addr().Is4() {
			if !yield(sub.CIDRv4) {
				return
			}
		}
		if sub.CIDRv6.IsValid() && sub.CIDRv6.Addr().Is6() {
			if !yield(sub.CIDRv6) {
				return
			}
		}
	}
}

var _ statedb.TableWritable = PrivateNetwork{}

func (pn PrivateNetwork) TableHeader() []string {
	return []string{"Name", "ID", "VNI", "Interface", "INBClusters", "Subnets"}
}

func (pn PrivateNetwork) TableRow() []string {
	return []string{
		string(pn.Name),
		pn.ID.String(),
		cmp.Or(pn.VNI.String(), "N/A"),
		pn.Interface.String(),
		cmp.Or(strings.Join(slices.Sorted(
			cslices.MapIter(maps.Keys(pn.INBs.Selectors),
				func(cn ClusterName) string { return string(cn) },
			)), ","), "N/A"),
		strconv.FormatInt(int64(len(pn.Subnets)), 10),
	}
}

// CanBeServedByINB returns whether this private network can be served by an INB.
func (pn PrivateNetwork) CanBeServedByINB() bool {
	return pn.Interface.Index > 0
}

// Error returns any errors associated with this private network
func (pn PrivateNetwork) Error() string {
	return pn.Interface.Error
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

	privateNetworksInterfaceIndex = statedb.Index[PrivateNetwork, string]{
		Name: "interface",
		FromObject: func(obj PrivateNetwork) index.KeySet {
			if ifname := obj.Interface.Name; ifname != "" {
				return index.NewKeySet(index.String(ifname))
			}
			return index.NewKeySet()
		},
		FromKey:    index.String,
		FromString: index.FromString,
	}
)

// PrivateNetworkByName queries the private networks table by name
func PrivateNetworkByName(name NetworkName) statedb.Query[PrivateNetwork] {
	return privateNetworksNameIndex.Query(string(name))
}

// PrivateNetworksByInterface queries the private networks table by interface name
func PrivateNetworksByInterface(ifname string) statedb.Query[PrivateNetwork] {
	return privateNetworksInterfaceIndex.Query(ifname)
}

func NewPrivateNetworksTable(db *statedb.DB) (statedb.RWTable[PrivateNetwork], error) {
	return statedb.NewTable(
		db,
		"private-networks",
		privateNetworksNameIndex,
		privateNetworksInterfaceIndex,
	)
}
