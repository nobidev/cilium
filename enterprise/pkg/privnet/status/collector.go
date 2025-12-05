//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package status

import (
	"cmp"
	"fmt"
	"maps"
	"net/netip"
	"slices"

	"github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/container/set"
	nomgr "github.com/cilium/cilium/pkg/node/manager"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	cslices "github.com/cilium/cilium/pkg/slices"

	"github.com/cilium/statedb"
)

type statusCollector struct {
	config      config.Config
	clusterInfo cmtypes.ClusterInfo

	db              *statedb.DB
	privateNetworks statedb.Table[tables.PrivateNetwork]
	endpoints       statedb.Table[tables.Endpoint]
	mapEntries      statedb.Table[*tables.MapEntry]
	activeNetworks  statedb.Table[tables.ActiveNetwork]
	inbs            statedb.Table[tables.INB]

	nm nomgr.NodeManager
}

func (sc *statusCollector) collectNodeStatus() NodeStatus {
	tx := sc.db.ReadTxn()

	status := NodeStatus{
		Name:              tables.NodeName(nodeTypes.GetName()),
		Cluster:           tables.ClusterName(sc.clusterInfo.Name),
		Enabled:           sc.config.Enabled,
		Mode:              sc.config.Mode,
		ConnectedClusters: sc.collectConnectedClusters(),
	}

	if !sc.config.Enabled {
		return status
	}

	activeWorkloadNodesByNet := sc.collectActiveWorkloadNodesByNet(tx)
	inbsByNet := sc.collectINBsByNet(tx)

	for pn := range sc.privateNetworks.All(tx) {
		pns := NetworkStatus{
			Name: pn.Name,
			Routes: cslices.Map(pn.Routes, func(r tables.PrivateNetworkRoute) Route {
				return Route{
					Destination: r.Destination,
					Gateway:     r.Gateway,
				}
			}),
			Subnets: cslices.Map(pn.Subnets, func(s tables.PrivateNetworkSubnet) Subnet {
				return Subnet{
					CIDR: s.CIDR,
				}
			}),
			Error: pn.Error(),
		}

		var ok bool
		activeINB, ok := findActiveINB(inbsByNet[pn.Name])
		pns.WorkerStatus = WorkerStatus{
			ActiveINB:           activeINB,
			ConnectedINBCluster: inbsByNet[pn.Name],
		}
		if !ok && len(pn.INBs.Selectors) > 0 {
			if pns.Error != "" {
				pns.Error += "\n"
			}
			pns.Error += "No Active INB"
		}

		pns.INBStatus = INBStatus{
			Interface: Interface{
				Name:  pn.Interface.Name,
				Index: pn.Interface.Index,
				Error: pn.Interface.Error,
			},
			Serving:             pn.CanBeServedByINB(),
			ActiveWorkloadNodes: activeWorkloadNodesByNet[pn.Name],
		}

		pns.Endpoints = sc.collectEndpointsForNet(tx, pns.Name)

		status.Networks = append(status.Networks, pns)
	}

	return status
}

func (sc *statusCollector) collectActiveWorkloadNodesByNet(tx statedb.ReadTxn) map[tables.NetworkName][]WorkloadNode {
	activeWorkloadNodesByNet := map[tables.NetworkName][]WorkloadNode{}
	for cnet := range sc.activeNetworks.All(tx) {
		activeWorkloadNodesByNet[cnet.Network] = append(activeWorkloadNodesByNet[cnet.Network], WorkloadNode{
			Name:    cnet.Node.Name,
			Cluster: cnet.Node.Cluster,
		})
	}
	return activeWorkloadNodesByNet
}

func (sc *statusCollector) collectINBsByNet(tx statedb.ReadTxn) map[tables.NetworkName][]INBCluster {
	inbsByNetAndCluster := map[tables.NetworkName]map[tables.ClusterName]INBCluster{}

	for inb := range sc.inbs.All(tx) {
		inbsByCluster, ok := inbsByNetAndCluster[inb.Network]
		if !ok {
			inbsByCluster = map[tables.ClusterName]INBCluster{}
		}
		inbs := inbsByCluster[inb.Node.Cluster]
		inbs.Name = inb.Node.Cluster
		inbs.INBs = append(inbs.INBs, ConnectedINB{
			Cluster: inb.Node.Cluster,
			Name:    inb.Node.Name,
			Active:  inb.Role == tables.INBRoleActive,
			Healthy: inb.Health.Node == tables.INBNodeStateHealthy &&
				inb.Health.Network == tables.INBNetworkStateConfirmed,
		})
		inbsByCluster[inb.Node.Cluster] = inbs
		inbsByNetAndCluster[inb.Network] = inbsByCluster

	}

	inbByNet := map[tables.NetworkName][]INBCluster{}
	for net, clusters := range inbsByNetAndCluster {
		inbs := slices.SortedFunc(maps.Values(clusters), func(a, b INBCluster) int {
			return cmp.Compare(a.Name, b.Name)
		})
		inbByNet[net] = inbs
	}

	return inbByNet
}

func findActiveINB(clusters []INBCluster) (string, bool) {
	for _, cl := range clusters {
		for _, inb := range cl.INBs {
			if inb.Active {
				return fmt.Sprintf("%s/%s", inb.Cluster, inb.Name), true
			}
		}
	}
	return "", false
}

func (sc *statusCollector) collectConnectedClusters() []ConnectedCluster {
	knownNodesByCluster := map[string][]tables.NodeName{}
	for _, node := range sc.nm.GetNodes() {
		knownNodesByCluster[node.Cluster] = append(knownNodesByCluster[node.Cluster], tables.NodeName(node.Name))
	}

	cc := []ConnectedCluster{}

	for _, cluster := range slices.Sorted(maps.Keys(knownNodesByCluster)) {
		nodes := knownNodesByCluster[cluster]
		slices.Sort(nodes)
		cc = append(cc, ConnectedCluster{
			Name:      tables.ClusterName(cluster),
			NodeNames: nodes,
		})
	}
	return cc
}

func (sc *statusCollector) collectEndpointsForNet(tx statedb.ReadTxn, net tables.NetworkName) []EndpointStatus {
	epsByName := map[string]EndpointStatus{}

	activePIPs := set.Set[netip.Addr]{}
	for activeEP := range sc.mapEntries.Prefix(tx, tables.MapEntriesByNetworkAndType(net, tables.MapEntryTypeEndpoint)) {
		if activeEP.Routing.L2Announce {
			activePIPs.Insert(activeEP.Routing.NextHop)
		}
	}

	for ep := range sc.endpoints.Prefix(tx, tables.EndpointsByNetwork(net)) {
		epStatus := epsByName[ep.Source.String()+"|"+ep.Name]
		epStatus.Name = ep.Name
		epStatus.Node = tables.NodeName(ep.NodeName)
		epStatus.Cluster = tables.ClusterName(ep.Source.Cluster)
		if ep.IP.Is4() {
			epStatus.IPv4 = ep.IP
			epStatus.NetIPv4 = ep.Network.IP
		}
		if ep.IP.Is6() {
			epStatus.IPv6 = ep.IP
			epStatus.NetIPv6 = ep.Network.IP
		}
		epStatus.External = ep.Flags.External
		epStatus.Active = epStatus.Active || activePIPs.Has(ep.IP)

		epsByName[ep.Source.String()+"|"+ep.Name] = epStatus
	}

	return slices.SortedFunc(maps.Values(epsByName), func(a, b EndpointStatus) int {
		return cmp.Or(cmp.Compare(a.Cluster, b.Cluster), cmp.Compare(a.Name, b.Name))
	})
}

type connectedEndpointsSummary struct {
	clusters map[tables.ClusterName]connectedClusterSummary

	localEPs    int
	localExtEPs int

	activeEps int
	totalEps  int
}

type connectedClusterSummary struct {
	activeNodes int
	totalNodes  int
	activeEps   int
	totalEps    int
	extEps      int
}

func summarizeConnectedCluster(net NetworkStatus, clusters []ConnectedCluster, localCluster tables.ClusterName, localNode tables.NodeName) connectedEndpointsSummary {
	infoByCluster := map[tables.ClusterName]connectedClusterSummary{}

	localExtEPs := 0
	localEPs := 0
	activeEps := 0
	totalEps := 0

	for _, cluster := range clusters {
		info := infoByCluster[cluster.Name]
		info.totalNodes += len(cluster.NodeNames)
		infoByCluster[cluster.Name] = info
	}

	for _, ep := range net.Endpoints {

		counters := infoByCluster[ep.Cluster]

		if ep.Cluster == localCluster && ep.Node == localNode {
			if ep.External {
				localExtEPs++
			} else {
				localEPs++
			}
		}

		if ep.External {
			counters.extEps++
		}
		if ep.Active {
			counters.activeEps++
			activeEps++
		}

		counters.totalEps++
		totalEps++

		infoByCluster[ep.Cluster] = counters
	}

	for _, node := range net.INBStatus.ActiveWorkloadNodes {
		info := infoByCluster[node.Cluster]
		info.activeNodes += 1
		infoByCluster[node.Cluster] = info
	}

	return connectedEndpointsSummary{
		clusters:    infoByCluster,
		localEPs:    localEPs,
		localExtEPs: localExtEPs,
		activeEps:   activeEps,
		totalEps:    totalEps,
	}
}
