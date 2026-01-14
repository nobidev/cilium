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
	"encoding"
	"fmt"
	"net/netip"
	"slices"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/reconciler"

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
	return newMapEntryKey(me.Target.NetworkName, me.Type, me.Target.CIDR)
}

func (me MapEntry) String() string {
	return fmt.Sprintf("%s %s/%s -> %s",
		me.Type,
		me.Target.NetworkName,
		me.Target.CIDR,
		me.Routing.NextHop,
	)
}

var _ statedb.TableWritable = &MapEntry{}

func (me *MapEntry) TableHeader() []string {
	return []string{"Type", "Network", "CIDR", "Nexthop", "L2Ann", "Status"}
}

func (me MapEntry) TableRow() []string {
	var l2Announce = "No"
	if me.Routing.L2Announce {
		l2Announce = "Yes"
	}

	return []string{
		me.Type.String(),
		string(me.Target.NetworkName), me.Target.CIDR.String(),
		me.Routing.NextHop.String(),
		l2Announce,
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

	// L2Announce is whether the local node should announce the target endpoint on
	// the egress facing interface, replying to ARP/ND requests, as well as sending
	// gratuitous ARP and ND packets. Currently applicable on the INB cluster(s) only,
	// and for entries of type [MapEntryTypeEndpoint].
	L2Announce bool
}

// MapEntryKey is <network>|<type>|<network-cidr>.
type MapEntryKey string

func (key MapEntryKey) Key() index.Key {
	return index.String(string(key))
}

func newMapEntryKeyFromNetwork(network NetworkName) MapEntryKey {
	return MapEntryKey(string(network) + indexDelimiter)
}

func newMapEntryKeyFromNetworkAndType(network NetworkName, typ MapEntryType) MapEntryKey {
	return newMapEntryKeyFromNetwork(network) + MapEntryKey(typ.String()+indexDelimiter)
}

func newMapEntryKey(network NetworkName, typ MapEntryType, networkCIDR netip.Prefix) MapEntryKey {
	return newMapEntryKeyFromNetworkAndType(network, typ) + MapEntryKey(networkCIDR.String())
}

var (
	mapEntriesTypeNetCIDRIndex = statedb.Index[*MapEntry, MapEntryKey]{
		Name: "network-cidr",
		FromObject: func(obj *MapEntry) index.KeySet {
			return index.NewKeySet(obj.Key().Key())
		},
		FromKey:    MapEntryKey.Key,
		FromString: index.FromString,
		Unique:     true,
	}

	// MapEntryByKey queries the map entries table by entry type, network name and CIDR.
	MapEntryByKey = mapEntriesTypeNetCIDRIndex.Query
)

// MapEntriesByNetwork queries the map entries table by network name.
func MapEntriesByNetwork(network NetworkName) statedb.Query[*MapEntry] {
	return mapEntriesTypeNetCIDRIndex.Query(newMapEntryKeyFromNetwork(network))
}

// MapEntriesByNetworkAndType queries the map entries table by network name and entry type.
func MapEntriesByNetworkAndType(network NetworkName, typ MapEntryType) statedb.Query[*MapEntry] {
	return mapEntriesTypeNetCIDRIndex.Query(newMapEntryKeyFromNetworkAndType(network, typ))
}

// MapEntryByTypeNetworkCIDR queries the map entries table by entry type, network name and CIDR.
func MapEntryByTypeNetworkCIDR(network NetworkName, typ MapEntryType, networkCIDR netip.Prefix) statedb.Query[*MapEntry] {
	return MapEntryByKey(newMapEntryKey(network, typ, networkCIDR))
}

func NewMapEntriesTable(db *statedb.DB) (statedb.RWTable[*MapEntry], error) {
	return statedb.NewTable(
		db,
		"privnet-mapentries",
		mapEntriesTypeNetCIDRIndex,
	)
}
