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
	"encoding"
	"fmt"
	"net/netip"
	"slices"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/enterprise/pkg/vni"
	"github.com/cilium/cilium/pkg/mac"
)

// MapEntry represents a single entry of the private networks maps.
type MapEntry struct {
	// Type represents the type of this entry.
	Type MapEntryType

	// Target represents the target network CIDR reachable via this entry.
	Target MapEntryTarget

	// Routing represents the routing information to reach the target network CIDR.
	Routing MapEntryRouting

	// Status is the status of the reconciliation of this entry into the BPF maps.
	Status reconciler.Status

	// GneighStatus is the status of the periodic gratuitous ARP/ND propagation.
	// Applicable on the INB cluster only.
	GneighStatus reconciler.Status
}

// Equal returns whether two MapEntry objects are identical, excluding the reconcilers status.
func (me *MapEntry) Equal(other *MapEntry) bool {
	if me == nil || other == nil {
		return me == other
	}

	return me.Type == other.Type &&
		me.Target.Equal(other.Target) &&
		me.Routing == other.Routing
}

// Key returns the key uniquely identifying this endpoint in the nat table.
func (me *MapEntry) Key() MapEntryKey {
	return newMapEntryKey(me.Target.NetworkName, me.Target.SubnetName, me.Type, me.Target.CIDR)
}

func (me MapEntry) String() string {
	return fmt.Sprintf("%s %s/%s/%s -> %s",
		me.Type,
		me.Target.NetworkName,
		me.Target.SubnetName,
		me.Target.CIDR,
		me.Routing.NextHop,
	)
}

var _ statedb.TableWritable = &MapEntry{}

func (me *MapEntry) TableHeader() []string {
	return []string{"Type", "Network", "Subnet", "CIDR", "Nexthop", "IfIndex", "MAC", "L2Ann", "VNI", "Status"}
}

func (me MapEntry) TableRow() []string {
	var ifIndex = "N/A"
	if me.Routing.EgressIfIndex != 0 {
		ifIndex = fmt.Sprintf("%d", me.Routing.EgressIfIndex)
	}
	var mac = "N/A"
	if len(me.Target.MAC) > 0 {
		mac = me.Target.MAC.String()
	}
	var l2Announce = "No"
	if me.Routing.L2Announce {
		l2Announce = "Yes"
	}

	return []string{
		me.Type.String(),
		string(me.Target.NetworkName), string(me.Target.SubnetName), me.Target.CIDR.String(),
		me.Routing.NextHop.String(),
		ifIndex,
		mac,
		l2Announce,
		cmp.Or(me.Routing.VNI.String(), "N/A"),
		me.Status.String(),
	}
}

// MapEntryType represents the type of the NAT entry.
type MapEntryType uint8

const (
	// MapEntryTypeEndpoint represents an endpoint.
	MapEntryTypeEndpoint MapEntryType = iota
	// MapEntryTypeExternalEndpoint represents an expoint external to the
	// cluster(mesh), accessible via the INB.
	MapEntryTypeExternalEndpoint
	// MapEntryTypeDCNRoute represents an L2 route.
	MapEntryTypeDCNRoute
	// MapEntryTypeStaticRoute represents an L3 static route.
	MapEntryTypeStaticRoute
	// MapEntryTypeEVPNRoute represents an EVPN route.
	MapEntryTypeEVPNRoute
)

func (typ MapEntryType) String() string {
	switch typ {
	case MapEntryTypeEndpoint:
		return "E"
	case MapEntryTypeExternalEndpoint:
		return "X"
	case MapEntryTypeDCNRoute:
		return "D"
	case MapEntryTypeStaticRoute:
		return "S"
	case MapEntryTypeEVPNRoute:
		return "V"
	default:
		return "?"
	}
}

var _ encoding.TextMarshaler = MapEntryType(0)
var _ encoding.TextUnmarshaler = (*MapEntryType)(nil)

// MarshalText implements the [encoding.TextMarshaler] interface.
func (typ MapEntryType) MarshalText() ([]byte, error) {
	return []byte(typ.String()), nil
}

// UnmarshalText implements the [encoding.TextUnmarshaler] interface.
func (typ *MapEntryType) UnmarshalText(in []byte) error {
	switch string(in) {
	case "E":
		*typ = MapEntryTypeEndpoint
	case "X":
		*typ = MapEntryTypeExternalEndpoint
	case "D":
		*typ = MapEntryTypeDCNRoute
	case "S":
		*typ = MapEntryTypeStaticRoute
	case "V":
		*typ = MapEntryTypeEVPNRoute
	default:
		return fmt.Errorf("invalid MapEntryType %q", string(in))
	}

	return nil
}

// MapEntryTarget represents the target network CIDR reachable via this entry.
type MapEntryTarget struct {
	// NetworkName is the name of the target private network.
	NetworkName NetworkName

	// NetworkID is the NetworkID of the target private network.
	NetworkID NetworkID

	// SubnetName is the name of the target subnet.
	SubnetName SubnetName

	// SubnetID is the local ID of the target subnet.
	SubnetID SubnetID

	// CIDR is the CIDR of the target endpoint/route.
	CIDR netip.Prefix

	// MAC is the MAC address of the endpoint.
	// Currently applicable only for [MapEntryTypeEndpoint].
	MAC mac.MAC
}

// Equal returns whether two MapEntryTarget objects are identical.
func (met MapEntryTarget) Equal(other MapEntryTarget) bool {
	return met.NetworkName == other.NetworkName &&
		met.NetworkID == other.NetworkID &&
		met.SubnetName == other.SubnetName &&
		met.SubnetID == other.SubnetID &&
		met.CIDR == other.CIDR &&
		slices.Equal(met.MAC, other.MAC)
}

// MapEntryRouting represents the routing information to reach the target network CIDR.
type MapEntryRouting struct {
	// NextHop is the IP address of the next hop to reach the target network prefix.
	// * For [MapEntryTypeEndpoint], NextHop is the PodIP of the endpoint.
	// * For [MapEntryTypeDCNRoute], NextHop is:
	//   - On the main cluster, the IP address of the INB node serving the network.
	//   - On the INB cluster(s), the unspecified address (0.0.0.0/::).
	// * For [MapEntryTypeStaticRoute], NextHop is:
	//   - On the main cluster, the IP address of the INB node serving the network.
	//   - On the INB cluster(s), the actual nexthop configured via the ClusterwidePrivateNetwork.
	NextHop netip.Addr

	// EgressIfIndex is the index of the interface to egress traffic towards the target network.
	// Currently applicable on the INB clusters only.
	EgressIfIndex int

	// VNI associated with the private-network
	VNI vni.VNI

	// L2Announce is whether the local node should announce the target endpoint on
	// the egress facing interface, replying to ARP/ND requests, as well as sending
	// gratuitous ARP and ND packets. Currently applicable on the INB cluster(s) only,
	// and for entries of type [MapEntryTypeEndpoint].
	L2Announce bool
}

// MapEntryKey is <network>|<subnet>|<type>|<network-cidr>.
type MapEntryKey string

func (key MapEntryKey) Key() index.Key {
	return index.String(string(key))
}

func newMapEntryKeyFromNetwork(network NetworkName) MapEntryKey {
	return MapEntryKey(string(network) + indexDelimiter)
}
func newMapEntryKeyFromNetworkSubnet(network NetworkName, subnet SubnetName) MapEntryKey {
	return newMapEntryKeyFromNetwork(network) + MapEntryKey(subnet) + indexDelimiter
}

func newMapEntryKeyFromNetworkSubnetAndType(network NetworkName, subnet SubnetName, typ MapEntryType) MapEntryKey {
	return newMapEntryKeyFromNetworkSubnet(network, subnet) + MapEntryKey(typ.String()+indexDelimiter)
}

func newMapEntryKey(network NetworkName, subnet SubnetName, typ MapEntryType, networkCIDR netip.Prefix) MapEntryKey {
	return newMapEntryKeyFromNetworkSubnetAndType(network, subnet, typ) + MapEntryKey(networkCIDR.String())
}

// mapEntryNetTypeKey is <network>|<type>
type mapEntryNetTypeKey string

func (key mapEntryNetTypeKey) Key() index.Key {
	return index.String(string(key))
}

func newMapEntryNetTypeKey(network NetworkName, typ MapEntryType) mapEntryNetTypeKey {
	return mapEntryNetTypeKey(network) + indexDelimiter + mapEntryNetTypeKey(typ.String())
}

var (
	mapEntriesTypeNetCIDRIndex = statedb.Index[*MapEntry, MapEntryKey]{
		Name: "network-subnet-cidr",
		FromObject: func(obj *MapEntry) index.KeySet {
			return index.NewKeySet(obj.Key().Key())
		},
		FromKey:    MapEntryKey.Key,
		FromString: index.FromString,
		Unique:     true,
	}
	mapEntriesNetTypeIndex = statedb.Index[*MapEntry, mapEntryNetTypeKey]{
		Name: "network-type",
		FromObject: func(obj *MapEntry) index.KeySet {
			return index.NewKeySet(newMapEntryNetTypeKey(obj.Target.NetworkName, obj.Type).Key())
		},
		FromKey:    mapEntryNetTypeKey.Key,
		FromString: index.FromString,
		Unique:     false,
	}

	// MapEntryByKey queries the map entries table by entry type, network name and CIDR.
	MapEntryByKey = mapEntriesTypeNetCIDRIndex.Query
)

// MapEntriesByNetwork queries the map entries table by network name.
func MapEntriesByNetwork(network NetworkName) statedb.Query[*MapEntry] {
	return mapEntriesTypeNetCIDRIndex.Query(newMapEntryKeyFromNetwork(network))
}

// MapEntriesByNetworkSubnet queries the map entries table by network and subnet name.
func MapEntriesByNetworkSubnet(network NetworkName, subnet SubnetName) statedb.Query[*MapEntry] {
	return mapEntriesTypeNetCIDRIndex.Query(newMapEntryKeyFromNetworkSubnet(network, subnet))
}

// MapEntriesByNetworkSubnetAndType queries the map entries table by network and subnet name and entry type.
func MapEntriesByNetworkSubnetAndType(network NetworkName, subnet SubnetName, typ MapEntryType) statedb.Query[*MapEntry] {
	return mapEntriesTypeNetCIDRIndex.Query(newMapEntryKeyFromNetworkSubnetAndType(network, subnet, typ))
}

// MapEntriesByNetworkAndType queries the map entries table by network name and entry type.
func MapEntriesByNetworkAndType(network NetworkName, typ MapEntryType) statedb.Query[*MapEntry] {
	return mapEntriesNetTypeIndex.Query(newMapEntryNetTypeKey(network, typ))
}

// MapEntryByTypeNetworkSubnetCIDR queries the map entries table by entry type, network and subnet name and CIDR.
func MapEntryByTypeNetworkSubnetCIDR(network NetworkName, subnet SubnetName, typ MapEntryType, networkCIDR netip.Prefix) statedb.Query[*MapEntry] {
	return MapEntryByKey(newMapEntryKey(network, subnet, typ, networkCIDR))
}

func NewMapEntriesTable(db *statedb.DB) (statedb.RWTable[*MapEntry], error) {
	return statedb.NewTable(
		db,
		"privnet-mapentries",
		mapEntriesTypeNetCIDRIndex,
		mapEntriesNetTypeIndex,
	)
}
