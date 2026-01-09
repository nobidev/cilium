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
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
)

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
