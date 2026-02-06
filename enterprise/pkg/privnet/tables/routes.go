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

// Route represents a subnet or route found in a private network CR
type Route struct {
	// Network is the name of the private network CR this route or subnet came from
	Network NetworkName

	// Destination is the destination of the subnet or route
	Destination netip.Prefix

	// Gateway is the gateway of a route. This is empty for subnets.
	Gateway netip.Addr

	// EVPNGateway is set if network is reachable via EVPN/Vxlan.
	EVPNGateway bool
}

var _ statedb.TableWritable = Route{}

func (r Route) TableHeader() []string {
	return []string{"Network", "Destination", "Gateway"}
}

func (r Route) TableRow() []string {
	gw := "N/A"
	if r.Gateway.IsValid() {
		gw = r.Gateway.String()
	}
	return []string{
		string(r.Network),
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

func (r Route) ToMapEntry(privNet SlimPrivateNetwork, bridgeMode bool) *MapEntry {
	nexthop := r.getNexthop(privNet, bridgeMode)
	if !nexthop.IsValid() {
		return nil
	}

	return &MapEntry{
		Type: r.MapEntryType(),
		Target: MapEntryTarget{
			NetworkName: privNet.Name,
			NetworkID:   privNet.ID,
			CIDR:        r.Destination,
		},
		Routing: MapEntryRouting{
			NextHop: nexthop,
			VNI:     r.getVNI(privNet),
		},

		Status: reconciler.StatusPending(),

		// No need to do gratuitous ARP/ND for routes.
		GneighStatus: reconciler.StatusDone(),
	}
}

func (r Route) Key() RouteKey {
	return newRouteKey(r.Network, r.Destination)
}

// RouteKey is <network>|<destination>
type RouteKey string

func (key RouteKey) Key() index.Key {
	return index.String(string(key))
}

func newRouteKeyFromNetwork(network NetworkName) RouteKey {
	return RouteKey(string(network) + indexDelimiter)
}

func newRouteKey(network NetworkName, destination netip.Prefix) RouteKey {
	return newRouteKeyFromNetwork(network) + RouteKey(destination.String())
}

var (
	routeIndex = statedb.Index[Route, RouteKey]{
		Name: "network-cidr",
		FromObject: func(obj Route) index.KeySet {
			return index.NewKeySet(obj.Key().Key())
		},
		FromKey:    RouteKey.Key,
		FromString: index.FromString,
		Unique:     true,
	}
)

// RouteByNetwork queries the private network route table by network name
func RouteByNetwork(network NetworkName) statedb.Query[Route] {
	return routeIndex.Query(newRouteKeyFromNetwork(network))
}

// RouteByNetworkAndDestination queries the private network route table by network name and route destination
func RouteByNetworkAndDestination(network NetworkName, cidr netip.Prefix) statedb.Query[Route] {
	return routeIndex.Query(newRouteKey(network, cidr))
}

func NewRouteTable(db *statedb.DB) (statedb.RWTable[Route], error) {
	return statedb.NewTable(
		db,
		"privnet-routes",
		routeIndex,
	)
}

func (r Route) getNexthop(privNet SlimPrivateNetwork, bridgeMode bool) netip.Addr {
	var nexthop netip.Addr

	if r.EVPNGateway {
		nexthop = r.unspecifiedNexthop()
	} else if !bridgeMode {
		if privNet.ActiveINB.IP.IsValid() {
			nexthop = privNet.ActiveINB.IP
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

func (r Route) getVNI(privNet SlimPrivateNetwork) vni.VNI {
	if r.EVPNGateway {
		return privNet.VNI
	}
	return vni.MustFromUint32(0)
}
