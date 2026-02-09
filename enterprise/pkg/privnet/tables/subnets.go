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
	"iter"
	"net/netip"
	"slices"
	"strconv"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
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
)

// Subnet represents a private network subnet instance.
type Subnet struct {
	// Network is the name of the Private Network this subnet belongs to.
	Network NetworkName
	// NetworkID is the local-scoped numeric identifier of the Private Network this subnet belongs to.
	NetworkID NetworkID

	// Name is the name of the subnet.
	Name SubnetName
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
	return []string{"Network", "Name", "CIDRv4", "CIDRv6"}
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
		fmtCIDR(s.CIDRv4),
		fmtCIDR(s.CIDRv6),
	}
}

func (s Subnet) Key() SubnetKey {
	return newSubnetKey(s.Network, s.Name)
}

func (s Subnet) Equals(other Subnet) bool {
	return s == other
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

func newSubnetKey(network NetworkName, subnet SubnetName) SubnetKey {
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
	return subnetNameIndex.Query(newSubnetKey(network, subnet))
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
