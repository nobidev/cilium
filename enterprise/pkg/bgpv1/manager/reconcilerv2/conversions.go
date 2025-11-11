// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package reconcilerv2

import (
	"net/netip"

	"github.com/cilium/cilium/pkg/bgp/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
)

// toNeighbor converts a IsovalentBGPNodePeer to Neighbor which can be used
// with Router API. The caller must ensure that the np, np.PeerAddress,
// np.PeerASN and pc are not nil.
func toNeighbor(np *v1.IsovalentBGPNodePeer, pc *v1.IsovalentBGPPeerConfigSpec, password string, selfRRRole v1.RouteReflectorRole) *types.Neighbor {
	neighbor := &types.Neighbor{}

	neighbor.Address = toPeerAddress(*np.PeerAddress)
	neighbor.ASN = uint32(*np.PeerASN)
	neighbor.AuthPassword = password
	neighbor.EbgpMultihop = toNeighborEbgpMultihop(pc.EBGPMultihop)
	neighbor.RouteReflector = toRouteReflector(np.RouteReflector, selfRRRole)
	neighbor.Timers = toNeighborTimers(pc.Timers)
	neighbor.Transport = toNeighborTransport(np.LocalAddress, pc.Transport)
	neighbor.GracefulRestart = toNeighborGracefulRestart(pc.GracefulRestart)
	neighbor.AfiSafis = toNeighborAfiSafis(pc.Families)

	return neighbor
}

func toPeerAddress(peerAddress string) netip.Addr {
	addr, err := netip.ParseAddr(peerAddress)
	if err != nil {
		return netip.Addr{}
	}
	return addr
}

func toNeighborEbgpMultihop(ebgpMultihop *int32) *types.NeighborEbgpMultihop {
	if ebgpMultihop == nil || *ebgpMultihop <= 1 {
		return nil
	}
	return &types.NeighborEbgpMultihop{
		TTL: uint32(*ebgpMultihop),
	}
}

func toRouteReflector(routeReflector *v1.NodeRouteReflector, selfRRRole v1.RouteReflectorRole) *types.NeighborRouteReflector {
	if routeReflector == nil || selfRRRole == "" || selfRRRole == v1.RouteReflectorRoleClient {
		return nil
	}
	// RR to RR peering should be also considered as client peering.
	// Otherwise, CLUSTER_LIST attributes will not be sent and the peer RR
	// will reflect the routes to its clients.
	return &types.NeighborRouteReflector{
		Client:    true,
		ClusterID: routeReflector.ClusterID,
	}
}

func toNeighborTimers(apiTimers *v2.CiliumBGPTimers) *types.NeighborTimers {
	if apiTimers == nil {
		return nil
	}

	timers := &types.NeighborTimers{}

	if apiTimers.ConnectRetryTimeSeconds != nil {
		timers.ConnectRetry = uint64(*apiTimers.ConnectRetryTimeSeconds)
	}

	if apiTimers.HoldTimeSeconds != nil {
		timers.HoldTime = uint64(*apiTimers.HoldTimeSeconds)
	}

	if apiTimers.KeepAliveTimeSeconds != nil {
		timers.KeepaliveInterval = uint64(*apiTimers.KeepAliveTimeSeconds)
	}

	return timers
}

func toNeighborTransport(apiLocalAddress *string, apiTransport *v2.CiliumBGPTransport) *types.NeighborTransport {
	if apiLocalAddress == nil && apiTransport == nil {
		return nil
	}

	transport := &types.NeighborTransport{}

	if apiLocalAddress != nil {
		transport.LocalAddress = *apiLocalAddress
	}

	if apiTransport != nil {
		if apiTransport.PeerPort != nil {
			transport.RemotePort = uint32(*apiTransport.PeerPort)
		}
	}

	return transport
}

func toNeighborGracefulRestart(apiGR *v2.CiliumBGPNeighborGracefulRestart) *types.NeighborGracefulRestart {
	if apiGR == nil || apiGR.RestartTimeSeconds == nil {
		return nil
	}
	return &types.NeighborGracefulRestart{
		Enabled:     apiGR.Enabled,
		RestartTime: uint32(*apiGR.RestartTimeSeconds),
	}
}

func toNeighborAfiSafis(families []v1.IsovalentBGPFamilyWithAdverts) []*types.Family {
	if len(families) == 0 {
		return nil
	}

	afiSafis := []*types.Family{}

	for _, family := range families {
		afiSafis = append(afiSafis, &types.Family{
			Afi:  types.ParseAfi(family.Afi),
			Safi: types.ParseSafi(family.Safi),
		})
	}

	return afiSafis
}

func toV1FamilyWithAdverts(fam v2alpha1.CiliumBGPFamilyWithAdverts) v1.IsovalentBGPFamilyWithAdverts {
	return v1.IsovalentBGPFamilyWithAdverts{
		CiliumBGPFamily: v2.CiliumBGPFamily{
			Afi:  fam.Afi,
			Safi: fam.Safi,
		},
		Advertisements: fam.Advertisements,
	}
}
