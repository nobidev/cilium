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
	"testing"

	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/enterprise/pkg/privnet/types"

	"github.com/stretchr/testify/require"
)

func TestSummarizeConnectedClusters(t *testing.T) {

	for _, tc := range []struct {
		name string

		net       NetworkStatus
		connected []ConnectedCluster
		cluster   tables.ClusterName
		node      tables.NodeName

		want connectedEndpointsSummary
	}{
		{
			name:    "simple",
			cluster: "cluster-east",
			node:    "worker-0",
			net: NetworkStatus{
				Endpoints: []EndpointStatus{
					{
						Name:    "ew0-1",
						Cluster: "cluster-east",
						Node:    "worker-0",
					},
					{
						Name:    "ew0-2",
						Cluster: "cluster-east",
						Node:    "worker-0",
					},
					{
						Name:    "ew2-1",
						Cluster: "cluster-east",
						Node:    "worker-2",
					},
					{
						Name:    "ew2-2",
						Cluster: "cluster-east",
						Node:    "worker-2",
					},
					{
						Name:    "ww0-1",
						Cluster: "cluster-west",
						Node:    "worker-0",
					},
					{
						Name:    "ww1-1",
						Cluster: "cluster-west",
						Node:    "worker-1",
					},
					{
						Name:    "ww3-1",
						Cluster: "cluster-west",
						Node:    "worker-3",
					},
					{
						Name:     "inb-1",
						Cluster:  "inb",
						Node:     "inb-0",
						External: true,
					},
				},
			},
			connected: []ConnectedCluster{
				{
					Name: "cluster-east",
					NodeNames: []types.NodeName{
						"worker-0",
						"worker-1",
						"worker-2",
						"worker-3",
					},
				},
				{
					Name: "cluster-west",
					NodeNames: []types.NodeName{
						"worker-0",
						"worker-1",
						"worker-2",
						"worker-3",
					},
				},
				{
					Name: "inb",
					NodeNames: []types.NodeName{
						"inb-0",
					},
				},
			},
			want: connectedEndpointsSummary{
				localEPs: 2,
				totalEps: 8,
				clusters: map[types.ClusterName]connectedClusterSummary{
					"cluster-east": {
						totalNodes: 4,
						totalEps:   4,
					},
					"cluster-west": {
						totalNodes: 4,
						totalEps:   3,
					},
					"inb": {
						totalNodes: 1,
						totalEps:   1,
						extEps:     1,
					},
				},
			},
		},
		{
			name:    "simple inb",
			cluster: "inb",
			node:    "inb-0",
			net: NetworkStatus{
				INBStatus: INBStatus{
					Serving: true,
					ActiveWorkloadNodes: []WorkloadNode{
						{
							Cluster: "cluster-east",
							Name:    "worker-0",
						},
						{
							Cluster: "cluster-east",
							Name:    "worker-1",
						},
						{
							Cluster: "cluster-west",
							Name:    "worker-1",
						},
						{
							Cluster: "cluster-west",
							Name:    "worker-3",
						},
					},
				},
				Endpoints: []EndpointStatus{
					{
						Name:    "ew0-1",
						Cluster: "cluster-east",
						Node:    "worker-0",
						Active:  true,
					},
					{
						Name:    "ew0-2",
						Cluster: "cluster-east",
						Node:    "worker-0",
						Active:  true,
					},
					{
						Name:    "ew2-1",
						Cluster: "cluster-east",
						Node:    "worker-2",
					},
					{
						Name:    "ew2-2",
						Cluster: "cluster-east",
						Node:    "worker-2",
					},
					{
						Name:    "ww0-1",
						Cluster: "cluster-west",
						Node:    "worker-0",
					},
					{
						Name:    "ww1-1",
						Cluster: "cluster-west",
						Node:    "worker-1",
						Active:  true,
					},
					{
						Name:    "ww3-1",
						Cluster: "cluster-west",
						Node:    "worker-3",
						Active:  true,
					},
					{
						Name:     "inb-1",
						Cluster:  "inb",
						Node:     "inb-0",
						External: true,
					},
				},
			},
			connected: []ConnectedCluster{
				{
					Name: "cluster-east",
					NodeNames: []types.NodeName{
						"worker-0",
						"worker-1",
						"worker-2",
						"worker-3",
					},
				},
				{
					Name: "cluster-west",
					NodeNames: []types.NodeName{
						"worker-0",
						"worker-1",
						"worker-2",
						"worker-3",
					},
				},
				{
					Name: "inb",
					NodeNames: []types.NodeName{
						"inb-0",
					},
				},
			},
			want: connectedEndpointsSummary{
				localExtEPs: 1,
				localEPs:    0,
				totalEps:    8,
				activeEps:   4,
				clusters: map[types.ClusterName]connectedClusterSummary{
					"cluster-east": {
						totalNodes:  4,
						activeNodes: 2,
						totalEps:    4,
						activeEps:   2,
					},
					"cluster-west": {
						totalNodes:  4,
						activeNodes: 2,
						totalEps:    3,
						activeEps:   2,
					},
					"inb": {
						totalNodes: 1,
						totalEps:   1,
						extEps:     1,
					},
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {

			got := summarizeConnectedCluster(tc.net, tc.connected, tc.cluster, tc.node)

			require.Equal(t, tc.want, got)
		})
	}
}
