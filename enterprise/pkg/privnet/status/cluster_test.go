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
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/enterprise/pkg/privnet/types"
)

func TestMergeNetworkStatus(t *testing.T) {
	for _, tc := range []struct {
		name           string
		clusterStatus  ClusterStatus
		expectedMerged []mergedNetworkStatus
	}{
		{
			name: "simple",
			clusterStatus: ClusterStatus{
				Name: "foobar",
				Nodes: []NodeStatus{
					{
						Name:    "foobar-1",
						Cluster: "foobar",
						Enabled: true,
						Mode:    "default",
						Networks: []NetworkStatus{
							{
								Name: "net-a",
								Routes: []Route{
									{
										Destination: netip.MustParsePrefix("0.0.0.0/0"),
										Gateway:     netip.MustParseAddr("10.1.1.1"),
									},
								},
								Subnets: []Subnet{
									{
										CIDR: netip.MustParsePrefix("10.1.1.1/24"),
									},
								},
								Endpoints: []EndpointStatus{
									{
										Name:    "app-1",
										Cluster: "foobar",
										Node:    "foobar-1",
										IPv4:    netip.MustParseAddr("10.233.1.13"),
										NetIPv4: netip.MustParseAddr("10.1.1.13"),
										Active:  true,
									},
								},
								WorkerStatus: WorkerStatus{
									ActiveINB: "inb-west-1",
									ConnectedINBClusters: []INBCluster{
										{
											Name: "inb-west",
											INBs: []ConnectedINB{
												{
													Name:    "inb-west-1",
													Cluster: "inb-west",
													Active:  true,
													Healthy: true,
												},
												{
													Name:    "inb-west-2",
													Cluster: "inb-west",
													Active:  false,
													Healthy: true,
												},
											},
										},
									},
								},
							},
						},
					},
					{
						Name:    "foobar-2",
						Cluster: "foobar",
						Enabled: true,
						Mode:    "default",
						Networks: []NetworkStatus{
							{
								Name: "net-a",
								Routes: []Route{
									{
										Destination: netip.MustParsePrefix("0.0.0.0/0"),
										Gateway:     netip.MustParseAddr("10.1.1.1"),
									},
								},
								Subnets: []Subnet{
									{
										CIDR: netip.MustParsePrefix("10.1.1.1/24"),
									},
								},
								Endpoints: []EndpointStatus{
									{
										Name:    "app-1",
										Cluster: "foobar",
										Node:    "foobar-1",
										IPv4:    netip.MustParseAddr("10.233.1.13"),
										NetIPv4: netip.MustParseAddr("10.1.1.13"),
										Active:  true,
									},
								},
								WorkerStatus: WorkerStatus{
									ActiveINB: "inb-west-1",
									ConnectedINBClusters: []INBCluster{
										{
											Name: "inb-west",
											INBs: []ConnectedINB{
												{
													Name:    "inb-west-1",
													Cluster: "inb-west",
													Active:  false,
													Healthy: false,
												},
												{
													Name:    "inb-west-2",
													Cluster: "inb-west",
													Active:  true,
													Healthy: true,
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			expectedMerged: []mergedNetworkStatus{
				{
					Name:   "net-a",
					nodes:  []types.NodeName{"foobar-1", "foobar-2"},
					errors: []merged[string]{},
					subnets: []merged[Subnet]{
						{
							nodes: []types.NodeName{"foobar-1", "foobar-2"},
							entry: Subnet{CIDR: netip.MustParsePrefix("10.1.1.1/24")},
						},
					},
					routes: []merged[Route]{
						{
							nodes: []types.NodeName{"foobar-1", "foobar-2"},
							entry: Route{
								Destination: netip.MustParsePrefix("0.0.0.0/0"),
								Gateway:     netip.MustParseAddr("10.1.1.1"),
							},
						},
					},
					endpoints: []merged[EndpointStatus]{
						{
							nodes: []types.NodeName{"foobar-1", "foobar-2"},
							entry: EndpointStatus{
								Name:    "app-1",
								Cluster: "foobar",
								Node:    "foobar-1",
								IPv4:    netip.MustParseAddr("10.233.1.13"),
								NetIPv4: netip.MustParseAddr("10.1.1.13"),
								Active:  true,
							},
						},
					},
					inbs: []merged[ConnectedINB]{
						{
							nodes: []types.NodeName{"foobar-2"},
							entry: ConnectedINB{Name: "inb-west-1", Cluster: "inb-west", Active: false, Healthy: false},
						},
						{
							nodes: []types.NodeName{"foobar-1"},
							entry: ConnectedINB{Name: "inb-west-1", Cluster: "inb-west", Active: true, Healthy: true},
						},
						{
							nodes: []types.NodeName{"foobar-1"},
							entry: ConnectedINB{Name: "inb-west-2", Cluster: "inb-west", Active: false, Healthy: true},
						},
						{
							nodes: []types.NodeName{"foobar-2"},
							entry: ConnectedINB{Name: "inb-west-2", Cluster: "inb-west", Active: true, Healthy: true},
						},
					},
				},
			},
		},

		{
			name: "conflicts",
			clusterStatus: ClusterStatus{
				Name: "foobar",
				Nodes: []NodeStatus{
					{
						Name:    "foobar-1",
						Cluster: "foobar",
						Enabled: true,
						Mode:    "default",
						Networks: []NetworkStatus{
							{
								Name: "net-a",
								Routes: []Route{
									{
										Destination: netip.MustParsePrefix("0.0.0.0/0"),
										Gateway:     netip.MustParseAddr("10.1.1.1"),
									},
								},
								Subnets: []Subnet{
									{
										CIDR: netip.MustParsePrefix("10.1.1.1/24"),
									},
									{
										CIDR: netip.MustParsePrefix("10.2.1.1/24"),
									},
								},
								Endpoints: []EndpointStatus{
									{
										Name:    "app-1",
										Cluster: "foobar",
										Node:    "foobar-1",
										IPv4:    netip.MustParseAddr("10.233.1.16"),
										NetIPv4: netip.MustParseAddr("10.1.1.15"),
										Active:  true,
									},
								},
								WorkerStatus: WorkerStatus{
									ActiveINB: "inb-west-1",
									ConnectedINBClusters: []INBCluster{
										{
											Name: "inb-west",
											INBs: []ConnectedINB{
												{
													Name:    "inb-west-1",
													Cluster: "inb-west",
													Active:  true,
													Healthy: true,
												},
												{
													Name:    "inb-west-2",
													Cluster: "inb-west",
													Active:  false,
													Healthy: true,
												},
											},
										},
									},
								},
							},
							{
								Name: "only-on-1",
							},
						},
					},
					{
						Name:    "foobar-2",
						Cluster: "foobar",
						Enabled: true,
						Mode:    "default",
						Networks: []NetworkStatus{
							{
								Name: "net-a",
								Errors: []string{
									"foobar-2 has issues",
								},
								Routes: []Route{
									{
										Destination: netip.MustParsePrefix("0.0.0.0/0"),
										Gateway:     netip.MustParseAddr("10.1.1.1"),
									},
								},
								Subnets: []Subnet{
									{
										CIDR: netip.MustParsePrefix("10.1.1.1/24"),
									},
								},
								Endpoints: []EndpointStatus{
									{
										Name:    "app-2",
										Cluster: "foobar",
										Node:    "foobar-2",
										IPv4:    netip.MustParseAddr("10.233.1.13"),
										NetIPv4: netip.MustParseAddr("10.1.1.13"),
										Active:  true,
									},
								},
								WorkerStatus: WorkerStatus{
									ActiveINB: "inb-west-1",
									ConnectedINBClusters: []INBCluster{
										{
											Name: "inb-west",
											INBs: []ConnectedINB{
												{
													Name:    "inb-west-1",
													Cluster: "inb-west",
													Active:  false,
													Healthy: false,
												},
												{
													Name:    "inb-west-2",
													Cluster: "inb-west",
													Active:  true,
													Healthy: true,
												},
											},
										},
									},
								},
							},
							{
								Name: "only-on-2",
							},
						},
					},
				},
			},
			expectedMerged: []mergedNetworkStatus{
				{
					Name:  "net-a",
					nodes: []types.NodeName{"foobar-1", "foobar-2"},
					errors: []merged[string]{
						{
							nodes: []types.NodeName{"foobar-2"},
							entry: "foobar-2 has issues",
						},
					},
					warnings: []merged[string]{
						{
							nodes: []types.NodeName{"foobar-2"},
							entry: "subnet 10.2.1.1/24 not configured",
						},
						{
							nodes: []types.NodeName{"foobar-2"},
							entry: "endpoint app-1 unknown",
						},
						{
							nodes: []types.NodeName{"foobar-1"},
							entry: "endpoint app-2 unknown",
						},
					},
					subnets: []merged[Subnet]{
						{
							nodes: []types.NodeName{"foobar-1", "foobar-2"},
							entry: Subnet{CIDR: netip.MustParsePrefix("10.1.1.1/24")},
						},
						{
							nodes: []types.NodeName{"foobar-1"},
							entry: Subnet{CIDR: netip.MustParsePrefix("10.2.1.1/24")},
						},
					},
					routes: []merged[Route]{
						{
							nodes: []types.NodeName{"foobar-1", "foobar-2"},
							entry: Route{
								Destination: netip.MustParsePrefix("0.0.0.0/0"),
								Gateway:     netip.MustParseAddr("10.1.1.1"),
							},
						},
					},
					endpoints: []merged[EndpointStatus]{
						{
							nodes: []types.NodeName{"foobar-1"},
							entry: EndpointStatus{
								Name:    "app-1",
								Cluster: "foobar",
								Node:    "foobar-1",
								IPv4:    netip.MustParseAddr("10.233.1.16"),
								NetIPv4: netip.MustParseAddr("10.1.1.15"),
								Active:  true,
							},
						},
						{
							nodes: []types.NodeName{"foobar-2"},
							entry: EndpointStatus{
								Name:    "app-2",
								Cluster: "foobar",
								Node:    "foobar-2",
								IPv4:    netip.MustParseAddr("10.233.1.13"),
								NetIPv4: netip.MustParseAddr("10.1.1.13"),
								Active:  true,
							},
						},
					},
					inbs: []merged[ConnectedINB]{
						{
							nodes: []types.NodeName{"foobar-2"},
							entry: ConnectedINB{Name: "inb-west-1", Cluster: "inb-west", Active: false, Healthy: false},
						},
						{
							nodes: []types.NodeName{"foobar-1"},
							entry: ConnectedINB{Name: "inb-west-1", Cluster: "inb-west", Active: true, Healthy: true},
						},
						{
							nodes: []types.NodeName{"foobar-1"},
							entry: ConnectedINB{Name: "inb-west-2", Cluster: "inb-west", Active: false, Healthy: true},
						},
						{
							nodes: []types.NodeName{"foobar-2"},
							entry: ConnectedINB{Name: "inb-west-2", Cluster: "inb-west", Active: true, Healthy: true},
						},
					},
				},
				{
					Name:  "only-on-1",
					nodes: []types.NodeName{"foobar-1"},
					errors: []merged[string]{
						{nodes: []types.NodeName{"foobar-2"}, entry: "network not configured"},
					},
					subnets:   []merged[Subnet]{},
					routes:    []merged[Route]{},
					endpoints: []merged[EndpointStatus]{},
					inbs:      []merged[ConnectedINB]{},
				},
				{
					Name:  "only-on-2",
					nodes: []types.NodeName{"foobar-2"},
					errors: []merged[string]{
						{nodes: []types.NodeName{"foobar-1"}, entry: "network not configured"},
					},
					subnets:   []merged[Subnet]{},
					routes:    []merged[Route]{},
					endpoints: []merged[EndpointStatus]{},
					inbs:      []merged[ConnectedINB]{},
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.expectedMerged, tc.clusterStatus.networks())
		})

	}

}
