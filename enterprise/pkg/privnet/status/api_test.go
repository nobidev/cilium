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
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/enterprise/pkg/privnet/types"
)

// TestAPIStability should test that we're able to parse older API formats.
// DON'T MODIFY EXISTING JSON FILES. Once we explicitly drop support for older
// API revisions, remove the relevant test case(s).
func TestAPIStability(t *testing.T) {
	for _, tc := range []struct {
		name     string
		jsonFile string
		status   NodeStatus
	}{
		{
			name:     "Pre first revision INB",
			jsonFile: "inb-pre0.json",

			status: NodeStatus{
				Name:    "foobar-worker-1",
				Cluster: "default",
				ConnectedClusters: []ConnectedCluster{
					{
						Name: "default",
						NodeNames: []types.NodeName{
							"foobar-worker-1",
							"foobar-worker-2",
						},
					},
					{
						Name: "felidae",
						NodeNames: []types.NodeName{
							"cougar",
							"lion",
						},
					},
				},
				Enabled: true,
				Mode:    "bridge",
				Networks: []NetworkStatus{
					{
						Name:   "firefly",
						Routes: []Route{},
						Subnets: []Subnet{
							{
								CIDR: netip.MustParsePrefix("192.168.251.0/24"),
							},
						},
						Endpoints: []EndpointStatus{
							{
								Name:    "moved-racer",
								Cluster: "default",
								Node:    "foobar-worker-2",
								IPv4:    netip.MustParseAddr("10.245.8.30"),
								NetIPv4: netip.MustParseAddr("192.168.251.30"),
							},
							{
								Name:     "shining-burro",
								Cluster:  "default",
								Node:     "foobar-worker-1",
								IPv4:     netip.MustParseAddr("10.245.8.39"),
								NetIPv4:  netip.MustParseAddr("192.168.251.39"),
								External: true,
							},
							{
								Name:    "eminent-griffon",
								Cluster: "felidae",
								Node:    "cougar",
								IPv4:    netip.MustParseAddr("10.245.8.31"),
								NetIPv4: netip.MustParseAddr("192.168.251.31"),
							},
							{
								Name:    "grateful-raccoon",
								Cluster: "felidae",
								Node:    "lion",
								IPv4:    netip.MustParseAddr("10.245.8.32"),
								NetIPv4: netip.MustParseAddr("192.168.251.32"),
								Active:  true,
							},
						},

						INBStatus: INBStatus{
							Serving: true,
							Interface: Interface{
								Name:  "eth2",
								Index: 11,
							},
							ActiveWorkloadNodes: []WorkloadNode{
								{
									Cluster: "felidae",
									Name:    "lion",
								},
							},
						},
					},
					{
						Name:   "maggot",
						Error:  `Interface "eth1" has "link-layer-down" operational status`,
						Routes: []Route{},
						Subnets: []Subnet{
							{
								CIDR: netip.MustParsePrefix("192.168.250.0/24"),
							},
						},
						Endpoints: []EndpointStatus{
							{
								Name:     "destined-bluejay",
								Cluster:  "default",
								Node:     "foobar-worker-2",
								IPv4:     netip.MustParseAddr("10.245.8.40"),
								NetIPv4:  netip.MustParseAddr("192.168.250.40"),
								External: true,
							},
							{
								Name:    "optimum-mouse",
								Cluster: "default",
								Node:    "foobar-worker-1",
								IPv4:    netip.MustParseAddr("10.245.8.20"),
								NetIPv4: netip.MustParseAddr("192.168.250.20"),
							},
							{
								Name:    "intense-phoenix",
								Cluster: "felidae",
								Node:    "cougar",
								IPv4:    netip.MustParseAddr("10.245.8.22"),
								NetIPv4: netip.MustParseAddr("192.168.250.22"),
							},
							{
								Name:    "valid-monkey",
								Cluster: "felidae",
								Node:    "cougar",
								IPv4:    netip.MustParseAddr("10.245.8.21"),
								NetIPv4: netip.MustParseAddr("192.168.250.21"),
							},
						},

						INBStatus: INBStatus{
							Serving: false,
							Interface: Interface{
								Name:  "eth1",
								Error: `Interface "eth1" has "link-layer-down" operational status`,
							},
						},
					},
				},
			},
		},
		{
			name:     "Pre first revision worker node",
			jsonFile: "worker-pre0.json",
			status: NodeStatus{
				Name:    "foobar-worker-1",
				Cluster: "default",
				ConnectedClusters: []ConnectedCluster{
					{
						Name: "camelidae",
						NodeNames: []types.NodeName{
							"alpaca",
						},
					},
					{
						Name: "felidae",
						NodeNames: []types.NodeName{
							"cougar",
						},
					},
				},
				Enabled: true,
				Mode:    "default",
				Networks: []NetworkStatus{
					{
						Name: "blue-network",
						Routes: []Route{
							{
								Destination: netip.MustParsePrefix("192.168.252.0/24"),
								Gateway:     netip.MustParseAddr("192.168.250.2"),
							},
							{
								Destination: netip.MustParsePrefix("0.0.0.0/0"),
								Gateway:     netip.MustParseAddr("192.168.250.1"),
							},
						},
						Subnets: []Subnet{
							{
								CIDR: netip.MustParsePrefix("192.168.250.0/23"),
							},
							{
								CIDR: netip.MustParsePrefix("fd10:0:250::/64"),
							},
							{
								CIDR: netip.MustParsePrefix("192.168.250.24/32"),
							},
						},
						Endpoints: []EndpointStatus{
							{
								Name:     "resolved-monster",
								Cluster:  "camelidae",
								Node:     "alpaca",
								IPv4:     netip.MustParseAddr("10.245.9.41"),
								NetIPv4:  netip.MustParseAddr("192.168.250.201"),
								External: true,
							},
							{
								Name:    "optimum-mouse",
								Cluster: "default",
								Node:    "crayfish",
								IPv4:    netip.MustParseAddr("10.244.5.108"),
								NetIPv4: netip.MustParseAddr("192.168.250.20"),
								IPv6:    netip.MustParseAddr("fd00:10:244:5::108"),
								NetIPv6: netip.MustParseAddr("fd10:0:250::20"),
							},
							{
								Name:    "regular-koi",
								Cluster: "default",
								Node:    "crayfish",
								IPv4:    netip.MustParseAddr("10.244.5.109"),
								NetIPv4: netip.MustParseAddr("192.168.250.21"),
								IPv6:    netip.MustParseAddr("fd00:10:244:5::109"),
								NetIPv6: netip.MustParseAddr("fd10:0:250::21"),
							},
							{
								Name:     "resolved-monster",
								Cluster:  "felidae",
								Node:     "cougar",
								IPv4:     netip.MustParseAddr("10.245.8.87"),
								NetIPv4:  netip.MustParseAddr("192.168.250.201"),
								External: true,
							},
							{
								Name:     "valid-monkey",
								Cluster:  "felidae",
								Node:     "cougar",
								IPv4:     netip.MustParseAddr("10.245.8.21"),
								NetIPv4:  netip.MustParseAddr("192.168.250.200"),
								External: true,
							},
						},
						WorkerStatus: WorkerStatus{
							ActiveINB: "felidae/cougar",
							ConnectedINBCluster: []INBCluster{
								{
									Name: "camelidae",
									INBs: []ConnectedINB{
										{
											Cluster: "camelidae",
											Name:    "alpaca",
										},
									},
								},
								{
									Name: "felidae",
									INBs: []ConnectedINB{
										{
											Cluster: "felidae",
											Name:    "cougar",
											Active:  true,
											Healthy: true,
										},
									},
								},
							},
						},
					},
					{
						Name:  "green-network",
						Error: "No Active INB",
						Subnets: []Subnet{
							{
								CIDR: netip.MustParsePrefix("10.0.100.0/24"),
							},
							{
								CIDR: netip.MustParsePrefix("fd00:10:100::/64"),
							},
						},
						Endpoints: []EndpointStatus{
							{
								Name:    "admiring-wombat",
								Cluster: "default",
								Node:    "crayfish",
								IPv4:    netip.MustParseAddr("10.244.5.111"),
								NetIPv4: netip.MustParseAddr("10.0.100.31"),
								IPv6:    netip.MustParseAddr("fd00:10:244:5::111"),
								NetIPv6: netip.MustParseAddr("fd00:10:100::31"),
							},
							{
								Name:    "pumped-ocelot",
								Cluster: "default",
								Node:    "crayfish",
								IPv4:    netip.MustParseAddr("10.244.5.110"),
								NetIPv4: netip.MustParseAddr("10.0.100.30"),
								IPv6:    netip.MustParseAddr("fd00:10:244:5::110"),
								NetIPv6: netip.MustParseAddr("fd00:10:100::30"),
							},
						},
						WorkerStatus: WorkerStatus{
							ConnectedINBCluster: []INBCluster{
								{
									Name: "camelidae",
									INBs: []ConnectedINB{
										{
											Cluster: "camelidae",
											Name:    "alpaca",
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name:     "Revision 0 INB",
			jsonFile: "inb-rev0.json",

			status: NodeStatus{
				Name:    "foobar-worker-1",
				Cluster: "default",
				ConnectedClusters: []ConnectedCluster{
					{
						Name: "default",
						NodeNames: []types.NodeName{
							"foobar-worker-1",
							"foobar-worker-2",
						},
					},
					{
						Name: "felidae",
						NodeNames: []types.NodeName{
							"cougar",
							"lion",
						},
					},
				},
				Enabled: true,
				Mode:    "bridge",
				Networks: []NetworkStatus{
					{
						Name:   "firefly",
						Routes: []Route{},
						Subnets: []Subnet{
							{
								CIDR: netip.MustParsePrefix("192.168.251.0/24"),
							},
						},
						Endpoints: []EndpointStatus{
							{
								Name:    "moved-racer",
								Cluster: "default",
								Node:    "foobar-worker-2",
								IPv4:    netip.MustParseAddr("10.245.8.30"),
								NetIPv4: netip.MustParseAddr("192.168.251.30"),
							},
							{
								Name:     "shining-burro",
								Cluster:  "default",
								Node:     "foobar-worker-1",
								IPv4:     netip.MustParseAddr("10.245.8.39"),
								NetIPv4:  netip.MustParseAddr("192.168.251.39"),
								External: true,
							},
							{
								Name:    "eminent-griffon",
								Cluster: "felidae",
								Node:    "cougar",
								IPv4:    netip.MustParseAddr("10.245.8.31"),
								NetIPv4: netip.MustParseAddr("192.168.251.31"),
							},
							{
								Name:    "grateful-raccoon",
								Cluster: "felidae",
								Node:    "lion",
								IPv4:    netip.MustParseAddr("10.245.8.32"),
								NetIPv4: netip.MustParseAddr("192.168.251.32"),
								Active:  true,
							},
						},

						INBStatus: INBStatus{
							Serving: true,
							Interface: Interface{
								Name:  "eth2",
								Index: 11,
							},
							ActiveWorkloadNodes: []WorkloadNode{
								{
									Cluster: "felidae",
									Name:    "lion",
								},
							},
						},
					},
					{
						Name:   "maggot",
						Error:  `Interface "eth1" has "link-layer-down" operational status`,
						Routes: []Route{},
						Subnets: []Subnet{
							{
								CIDR: netip.MustParsePrefix("192.168.250.0/24"),
							},
						},
						Endpoints: []EndpointStatus{
							{
								Name:     "destined-bluejay",
								Cluster:  "default",
								Node:     "foobar-worker-2",
								IPv4:     netip.MustParseAddr("10.245.8.40"),
								NetIPv4:  netip.MustParseAddr("192.168.250.40"),
								External: true,
							},
							{
								Name:    "optimum-mouse",
								Cluster: "default",
								Node:    "foobar-worker-1",
								IPv4:    netip.MustParseAddr("10.245.8.20"),
								NetIPv4: netip.MustParseAddr("192.168.250.20"),
							},
							{
								Name:    "intense-phoenix",
								Cluster: "felidae",
								Node:    "cougar",
								IPv4:    netip.MustParseAddr("10.245.8.22"),
								NetIPv4: netip.MustParseAddr("192.168.250.22"),
							},
							{
								Name:    "valid-monkey",
								Cluster: "felidae",
								Node:    "cougar",
								IPv4:    netip.MustParseAddr("10.245.8.21"),
								NetIPv4: netip.MustParseAddr("192.168.250.21"),
							},
						},

						INBStatus: INBStatus{
							Serving: false,
							Interface: Interface{
								Name:  "eth1",
								Error: `Interface "eth1" has "link-layer-down" operational status`,
							},
						},
					},
				},
			},
		},
		{
			name:     "Revision 0 worker node",
			jsonFile: "worker-rev0.json",
			status: NodeStatus{
				Name:    "foobar-worker-1",
				Cluster: "default",
				ConnectedClusters: []ConnectedCluster{
					{
						Name: "default",
						NodeNames: []types.NodeName{
							"foobar-worker-1",
							"foobar-worker-2",
						},
					},
					{
						Name: "felidae",
						NodeNames: []types.NodeName{
							"cougar",
							"lion",
						},
					},
				},
				Enabled: true,
				Mode:    "bridge",
				Networks: []NetworkStatus{
					{
						Name:   "firefly",
						Routes: []Route{},
						Subnets: []Subnet{
							{
								CIDR: netip.MustParsePrefix("192.168.251.0/24"),
							},
						},
						Endpoints: []EndpointStatus{
							{
								Name:    "moved-racer",
								Cluster: "default",
								Node:    "foobar-worker-2",
								IPv4:    netip.MustParseAddr("10.245.8.30"),
								NetIPv4: netip.MustParseAddr("192.168.251.30"),
							},
							{
								Name:     "shining-burro",
								Cluster:  "default",
								Node:     "foobar-worker-1",
								IPv4:     netip.MustParseAddr("10.245.8.39"),
								NetIPv4:  netip.MustParseAddr("192.168.251.39"),
								External: true,
							},
							{
								Name:    "eminent-griffon",
								Cluster: "felidae",
								Node:    "cougar",
								IPv4:    netip.MustParseAddr("10.245.8.31"),
								NetIPv4: netip.MustParseAddr("192.168.251.31"),
							},
							{
								Name:    "grateful-raccoon",
								Cluster: "felidae",
								Node:    "lion",
								IPv4:    netip.MustParseAddr("10.245.8.32"),
								NetIPv4: netip.MustParseAddr("192.168.251.32"),
								Active:  true,
							},
						},

						INBStatus: INBStatus{
							Serving: true,
							Interface: Interface{
								Name:  "eth2",
								Index: 11,
							},
							ActiveWorkloadNodes: []WorkloadNode{
								{
									Cluster: "felidae",
									Name:    "lion",
								},
							},
						},
					},
					{
						Name:   "maggot",
						Error:  `Interface "eth1" has "link-layer-down" operational status`,
						Routes: []Route{},
						Subnets: []Subnet{
							{
								CIDR: netip.MustParsePrefix("192.168.250.0/24"),
							},
						},
						Endpoints: []EndpointStatus{
							{
								Name:     "destined-bluejay",
								Cluster:  "default",
								Node:     "foobar-worker-2",
								IPv4:     netip.MustParseAddr("10.245.8.40"),
								NetIPv4:  netip.MustParseAddr("192.168.250.40"),
								External: true,
							},
							{
								Name:    "optimum-mouse",
								Cluster: "default",
								Node:    "foobar-worker-1",
								IPv4:    netip.MustParseAddr("10.245.8.20"),
								NetIPv4: netip.MustParseAddr("192.168.250.20"),
							},
							{
								Name:    "intense-phoenix",
								Cluster: "felidae",
								Node:    "cougar",
								IPv4:    netip.MustParseAddr("10.245.8.22"),
								NetIPv4: netip.MustParseAddr("192.168.250.22"),
							},
							{
								Name:    "valid-monkey",
								Cluster: "felidae",
								Node:    "cougar",
								IPv4:    netip.MustParseAddr("10.245.8.21"),
								NetIPv4: netip.MustParseAddr("192.168.250.21"),
							},
						},

						INBStatus: INBStatus{
							Serving: false,
							Interface: Interface{
								Name:  "eth1",
								Error: `Interface "eth1" has "link-layer-down" operational status`,
							},
						},
					},
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := tc.status

			jsonFile, err := os.OpenFile(fmt.Sprintf("testdata/parser/%s", tc.jsonFile), os.O_RDONLY, 0644)
			require.NoError(t, err)
			defer jsonFile.Close()

			d := json.NewDecoder(jsonFile)
			got := NodeStatus{}
			require.NoError(t, d.Decode(&got))

			// Convert back to JSON gives use more usable diff
			wantJ, err := json.Marshal(want)
			require.NoError(t, err)
			gotJ, err := json.Marshal(got)
			require.NoError(t, err)
			require.JSONEq(t, string(wantJ), string(gotJ))
		})
	}
}
