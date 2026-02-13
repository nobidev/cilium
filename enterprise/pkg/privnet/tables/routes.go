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
	"net/netip"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/enterprise/pkg/vni"
)

// Route represents a route for one subnet
type Route struct {
	// Network is the name of the private network CR this route came from
	Network NetworkName

	// Subnet is the name of the subnet this route came from
	Subnet SubnetName

	// Destination is the destination of the route
	Destination netip.Prefix

	// Gateway is the gateway of a route. This is empty for DCN and EVPN routes.
	Gateway netip.Addr

	// EVPNGateway is set if network is reachable via EVPN/Vxlan.
	EVPNGateway bool
}

var _ statedb.TableWritable = Route{}

func (r Route) TableHeader() []string {
	return []string{"Network", "Subnet", "Destination", "Gateway"}
}

func (r Route) TableRow() []string {
	gw := "N/A"
	if r.Gateway.IsValid() {
		gw = r.Gateway.String()
	}
	return []string{
		string(r.Network),
		string(r.Subnet),
		r.Destination.String(),
		func() string {
			if r.EVPNGateway {
				return "evpn"
			}
			return gw
		}(),
	}
}

func (r Route) MapEntryType() MapEntryType {
	if r.EVPNGateway {
		return MapEntryTypeEVPNRoute
	}
	if r.Gateway.IsValid() {
		return MapEntryTypeStaticRoute
	}
	return MapEntryTypeDCNRoute
}

func (r Route) ToMapEntry(subnet SubnetSpec, activeINB INBNode, bridgeMode bool) *MapEntry {
	nexthop := r.getNexthop(activeINB, bridgeMode)
	if !nexthop.IsValid() {
		return nil
	}

	return &MapEntry{
		Type: r.MapEntryType(),
		Target: MapEntryTarget{
			NetworkName: subnet.Network,
			NetworkID:   subnet.NetworkID,
			SubnetName:  subnet.Name,
			SubnetID:    subnet.ID,
			CIDR:        r.Destination,
		},
		Routing: MapEntryRouting{
			NextHop: nexthop,
			VNI:     r.getVNI(subnet),
		},

		Status: reconciler.StatusPending(),

		// No need to do gratuitous ARP/ND for routes.
		GneighStatus: reconciler.StatusDone(),
	}
}

func (r Route) Key() RouteKey {
	return newRouteKey(r.Network, r.Subnet, r.Destination)
}

// RouteKey is <network>|<subnet>|<destination>
type RouteKey string

func (key RouteKey) Key() index.Key {
	return index.String(string(key))
}

func newRouteKeyFromNetwork(network NetworkName) RouteKey {
	return RouteKey(string(network) + indexDelimiter)
}

func newRouteKeyFromNetworkSubnet(network NetworkName, subnet SubnetName) RouteKey {
	return newRouteKeyFromNetwork(network) + RouteKey(subnet) + indexDelimiter
}

func newRouteKey(network NetworkName, subnet SubnetName, destination netip.Prefix) RouteKey {
	return newRouteKeyFromNetworkSubnet(network, subnet) + RouteKey(destination.Masked().String())
}

// RouteKey is <network>|<destination>
type routeNetworkDestinationKey string

func (key routeNetworkDestinationKey) Key() index.Key {
	return index.String(string(key))
}
func newRouteNetworkDestinationKey(network NetworkName, destination netip.Prefix) routeNetworkDestinationKey {
	return routeNetworkDestinationKey(network) + indexDelimiter + routeNetworkDestinationKey(destination.Masked().String())
}

var (
	routeIndex = statedb.Index[Route, RouteKey]{
		Name: "network-subnet-cidr",
		FromObject: func(obj Route) index.KeySet {
			return index.NewKeySet(obj.Key().Key())
		},
		FromKey:    RouteKey.Key,
		FromString: index.FromString,
		Unique:     true,
	}

	routeNetDestinationIndex = statedb.Index[Route, routeNetworkDestinationKey]{
		Name: "network-cidr",
		FromObject: func(obj Route) index.KeySet {
			return index.NewKeySet(newRouteNetworkDestinationKey(obj.Network, obj.Destination).Key())
		},
		FromKey:    routeNetworkDestinationKey.Key,
		FromString: index.FromString,
	}
)

// RouteByNetwork queries the private network route table by network name
func RouteByNetwork(network NetworkName) statedb.Query[Route] {
	return routeIndex.Query(newRouteKeyFromNetwork(network))
}

// SubnetRoutesByNetworkSubnet queries the subnet route table by network name and subnet name
func RoutesByNetworkSubnet(network NetworkName, subnet SubnetName) statedb.Query[Route] {
	return routeIndex.Query(newRouteKeyFromNetworkSubnet(network, subnet))
}

// RouteByNetworkSubnetAndDestination queries the private network route table by network name, subnet name and route destination
func RouteByNetworkSubnetAndDestination(network NetworkName, subnet SubnetName, cidr netip.Prefix) statedb.Query[Route] {
	return routeIndex.Query(newRouteKey(network, subnet, cidr))
}

// RouteByNetworkAndDestination queries the private network route table by network name and route destination
func RouteByNetworkAndDestination(network NetworkName, cidr netip.Prefix) statedb.Query[Route] {
	return routeNetDestinationIndex.Query(newRouteNetworkDestinationKey(network, cidr))
}

func NewRouteTable(db *statedb.DB) (statedb.RWTable[Route], error) {
	return statedb.NewTable(
		db,
		"privnet-routes",
		routeIndex,
		routeNetDestinationIndex,
	)
}

func (r Route) getNexthop(activeINB INBNode, bridgeMode bool) netip.Addr {
	var nexthop netip.Addr

	if r.EVPNGateway {
		nexthop = r.unspecifiedNexthop()
	} else if !bridgeMode {
		if activeINB.IP.IsValid() {
			nexthop = activeINB.IP
		}
	} else {
		switch r.MapEntryType() {
		case MapEntryTypeStaticRoute:
			nexthop = r.Gateway
		case MapEntryTypeDCNRoute:
			nexthop = r.unspecifiedNexthop()
		}
	}

	return nexthop
}

func (r Route) unspecifiedNexthop() netip.Addr {
	if r.Destination.Addr().Is6() {
		return netip.IPv6Unspecified()
	}
	return netip.IPv4Unspecified()
}

func (r Route) getVNI(subnet SubnetSpec) vni.VNI {
	if r.EVPNGateway {
		return subnet.VNI
	}
	return vni.MustFromUint32(0)
}
