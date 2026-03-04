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
	"fmt"
	"iter"
	"math"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"

	"github.com/cilium/cilium/enterprise/pkg/vni"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

type (
	// SubnetName is the name of a subnet.
	SubnetName string

	// SubnetID is a numeric identifier of a private network subnet.
	SubnetID uint16
)

func (sid SubnetID) String() string {
	return "0x" + strconv.FormatUint(uint64(sid), 16)
}

const (
	// SubnetIDReserved represents the reserved SubnetID that cannot be assigned.
	SubnetIDReserved = SubnetID(0)
	// SubnetIDMax represents the highest SubnetID value.
	SubnetIDMax = SubnetID(math.MaxUint16)
)

// SubnetIDPair contains both the subnet and privnet ID of a subnet.
type SubnetIDPair struct {
	// Network is the ID of the privnet for the referenced subnet.
	Network NetworkID
	// Subnet is the subnet ID of the referenced subnet.
	Subnet SubnetID
}

func (idp SubnetIDPair) String() string {
	return idp.Network.String() + "/" + idp.Subnet.String()
}

// Subnet represents a private network subnet instance.
type Subnet struct {
	SubnetSpec `json:",inline" yaml:",inline"`

	// The set of routes configured for this Subnet
	Routes []PrivateNetworkRoute

	// The set of peers of this Subnet.
	// For subnet equality duplicates and slice order are ignored.
	// The slice is not guaranteed to be sorted. Don't rely on its order.
	Peers []SubnetPeer

	// DHCP relay configuration for this subnet.
	DHCP v1alpha1.PrivateNetworkSubnetDHCPSpec
}

type SubnetPeer struct {
	// Network is the name of the peered Private Network.
	Network NetworkName
	// Name is the name of the peered subnet.
	Subnet SubnetName
	// CIDRv4 defines the IPv4 subnet of the peer.
	// This is not directly used, but necessary to trigger reconciliation of
	// peering routes on CIDR change.
	CIDRv4 netip.Prefix
	// CIDRv6 defines the IPv6 subnet of the peer.
	// This is not directly used, but necessary to trigger reconciliation of
	// peering routes on CIDR change.
	CIDRv6 netip.Prefix
}

// SubnetSpec wraps the core subnet information for MapEntry construction.
type SubnetSpec struct {
	// Network is the name of the Private Network this subnet belongs to.
	Network NetworkName
	// NetworkID is the local-scoped numeric identifier of the Private Network this subnet belongs to.
	NetworkID NetworkID

	// VNI is the allocated value of the VXLAN Network Identifier of the subnet.
	VNI vni.VNI

	// Name is the name of the subnet.
	Name SubnetName
	// ID is the per node and per privnet scoped numeric identifier of the subnet
	ID SubnetID
	// CIDRv4 defines the IPv4 subnet.
	CIDRv4 netip.Prefix
	// CIDRv6 defines the IPv6 subnet.
	CIDRv6 netip.Prefix

	// EgressIfIndex is the index of the network interface providing external
	// connectivity to this subnet.
	EgressIfIndex int
	// EgressIfName is the name of the network interface providing external
	// connectivity to this subnet. It is provided for convenience only (e.g., in
	// the table output), and shall not be depended on during reconciliation.
	EgressIfName string
}

var _ statedb.TableWritable = Subnet{}

func (s Subnet) TableHeader() []string {
	return []string{"Network", "Name", "ID", "CIDRv4", "CIDRv6", "Routes", "DHCP", "Interface"}
}

func (s Subnet) TableRow() []string {
	fmtCIDR := func(cidr netip.Prefix) string {
		if cidr.IsValid() {
			return cidr.String()
		} else {
			return "-"
		}
	}
	return []string{
		string(s.Network),
		string(s.Name),
		s.ID.String(),
		fmtCIDR(s.CIDRv4),
		fmtCIDR(s.CIDRv6),
		strconv.FormatInt(int64(len(s.Routes)), 10),
		formatSubnetDHCP(s.DHCP),
		func() string {
			if s.EgressIfIndex == 0 {
				return "N/A"
			}
			return fmt.Sprintf("%s (%d)", s.EgressIfName, s.EgressIfIndex)
		}(),
	}
}

func (s Subnet) Key() SubnetKey {
	return NewSubnetKey(s.Network, s.Name)
}

func (s Subnet) Equals(other Subnet) bool {
	return s.SubnetSpec == other.SubnetSpec &&
		slices.Equal(s.Routes, other.Routes) &&
		equalElements(s.Peers, other.Peers) &&
		s.DHCP.DeepEqual(&other.DHCP)
}

func formatSubnetDHCP(cfg v1alpha1.PrivateNetworkSubnetDHCPSpec) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s", cfg.Mode)
	if r := cfg.Relay; cfg.Mode == v1alpha1.PrivateNetworkDHCPModeRelay && r != nil {
		fmt.Fprintf(&b, "(%s)", r.ServerAddress)
	}
	return b.String()
}

func (s Subnet) CIDRs() iter.Seq[netip.Prefix] {
	return func(yield func(cidr netip.Prefix) bool) {
		if s.CIDRv4.IsValid() {
			if !yield(s.CIDRv4) {
				return
			}
		}
		if s.CIDRv6.IsValid() {
			if !yield(s.CIDRv6) {
				return
			}
		}
	}
}

// SubnetKey is <network-name>|<subnet-name>
type SubnetKey string

func (key SubnetKey) Key() index.Key {
	return index.String(string(key))
}

func newSubnetKeyFromNetwork(network NetworkName) SubnetKey {
	return SubnetKey(string(network) + indexDelimiter)
}

func NewSubnetKey(network NetworkName, subnet SubnetName) SubnetKey {
	return newSubnetKeyFromNetwork(network) + SubnetKey(subnet)
}

var (
	subnetNameIndex = statedb.Index[Subnet, SubnetKey]{
		Name: "name",
		FromObject: func(obj Subnet) index.KeySet {
			return index.NewKeySet(obj.Key().Key())
		},
		FromKey:    SubnetKey.Key,
		FromString: index.FromString,
		Unique:     true,
	}
)

// SubnetsByNetwork queries the private network subnet table by network
func SubnetsByNetwork(network NetworkName) statedb.Query[Subnet] {
	return subnetNameIndex.Query(newSubnetKeyFromNetwork(network))
}

// SubnetsByNetworkAndName queries the private network subnet table by network and subnet name
func SubnetsByNetworkAndName(network NetworkName, subnet SubnetName) statedb.Query[Subnet] {
	return subnetNameIndex.Query(NewSubnetKey(network, subnet))
}

func NewSubnetTable(db *statedb.DB) (statedb.RWTable[Subnet], error) {
	return statedb.NewTable(
		db,
		"privnet-subnets",
		subnetNameIndex,
	)
}

// FindSubnetForIPs returns the first subnet that contains all the provided IPs (if the subnet table is consistent this should always be the only one)
func FindSubnetForIPs(tbl statedb.Table[Subnet], txn statedb.ReadTxn, network NetworkName, ips ...netip.Addr) (Subnet, bool) {
	for entry := range tbl.Prefix(txn, SubnetsByNetwork(network)) {
		// return subnet if there is no ip in the provided list that is not either contained in the v4 or v6 CIDR
		if !slices.ContainsFunc(ips, func(ip netip.Addr) bool {
			return !entry.CIDRv4.Contains(ip) && !entry.CIDRv6.Contains(ip)
		}) {
			return entry, true
		}
	}
	return Subnet{}, false
}
