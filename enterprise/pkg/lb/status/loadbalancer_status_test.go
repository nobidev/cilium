// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package status

import (
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

func TestExpectedStatus(t *testing.T) {
	testCases := []struct {
		ok             int
		total          int
		expectedStatus string
	}{
		{
			ok:             1,
			total:          1,
			expectedStatus: "OK",
		},
		{
			ok:             1,
			total:          2,
			expectedStatus: "DEG",
		},
		{
			ok:             0,
			total:          0,
			expectedStatus: "DEG",
		},
	}

	lb := &LoadbalancerClient{}
	for _, tc := range testCases {
		require.Equal(t, tc.expectedStatus, lb.statusText(tc.ok, tc.total))
	}
}

func TestGetT2Status(t *testing.T) {
	ipv4 := "1.1.1.1"
	testCases := []struct {
		lbsvc           isovalentv1alpha1.LBService
		nodeEnvoyConfig map[string]*EnvoyConfigModel
		expectedStatus  LoadbalancerStatusModelSimpleStatus
	}{
		{
			expectedStatus: LoadbalancerStatusModelSimpleStatus{
				Status: "N/A",
			},
		},
		{
			lbsvc: isovalentv1alpha1.LBService{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-ns",
					Name:      "test-svc",
				},
				Status: isovalentv1alpha1.LBServiceStatus{
					Addresses: isovalentv1alpha1.LBServiceVIPAddresses{
						IPv4: &ipv4,
					},
				},
			},
			nodeEnvoyConfig: map[string]*EnvoyConfigModel{
				"t2-node": {
					Configs: []struct {
						Type                  string "json:\"@type\""
						DynamicActiveClusters []struct {
							Cluster struct {
								Name string "json:\"name\""
							} "json:\"cluster,omitempty\""
						} "json:\"dynamic_active_clusters,omitempty\""
						DynamicEndpointConfigs []struct {
							EndpointConfig struct {
								ClusterName string "json:\"cluster_name\""
								Endpoints   []struct {
									LbEndpoints []struct {
										Endpoint struct {
											Address struct {
												SocketAddress struct {
													Address   string "json:\"address\""
													PortValue int    "json:\"port_value\""
												} "json:\"socket_address\""
											} "json:\"address\""
										} "json:\"endpoint\""
										HealthStatus string "json:\"health_status\""
									} "json:\"lb_endpoints\""
								} "json:\"endpoints\""
							} "json:\"endpoint_config\""
						} "json:\"dynamic_endpoint_configs,omitempty\""
						DynamicListeners []struct {
							Name        string "json:\"name\""
							ActiveState struct {
								Listener struct {
									Name    string "json:\"name\""
									Address struct {
										SocketAddress struct {
											Address   string "json:\"address\""
											PortValue int    "json:\"port_value\""
										} "json:\"socket_address\""
									} "json:\"address\""
								} "json:\"listener\""
							} "json:\"active_state\""
						} "json:\"dynamic_listeners,omitempty\""
						DynamicRouteConfigs []struct {
							RouteConfig struct {
								Name string "json:\"name\""
							} "json:\"route_config,omitempty\""
						} "json:\"dynamic_route_configs,omitempty\""
						DynamicActiveSecrets []struct {
							Name   string "json:\"name\""
							Secret struct {
								Name string "json:\"name\""
							} "json:\"secret,omitempty\""
						} "json:\"dynamic_active_secrets,omitempty\""
					}{
						{
							Type: "type.googleapis.com/envoy.admin.v3.EndpointsConfigDump",
							DynamicEndpointConfigs: []struct {
								EndpointConfig struct {
									ClusterName string "json:\"cluster_name\""
									Endpoints   []struct {
										LbEndpoints []struct {
											Endpoint struct {
												Address struct {
													SocketAddress struct {
														Address   string "json:\"address\""
														PortValue int    "json:\"port_value\""
													} "json:\"socket_address\""
												} "json:\"address\""
											} "json:\"endpoint\""
											HealthStatus string "json:\"health_status\""
										} "json:\"lb_endpoints\""
									} "json:\"endpoints\""
								} "json:\"endpoint_config\""
							}{
								{
									EndpointConfig: struct {
										ClusterName string "json:\"cluster_name\""
										Endpoints   []struct {
											LbEndpoints []struct {
												Endpoint struct {
													Address struct {
														SocketAddress struct {
															Address   string "json:\"address\""
															PortValue int    "json:\"port_value\""
														} "json:\"socket_address\""
													} "json:\"address\""
												} "json:\"endpoint\""
												HealthStatus string "json:\"health_status\""
											} "json:\"lb_endpoints\""
										} "json:\"endpoints\""
									}{
										ClusterName: "test-ns/lbfe-test-svc/",
										Endpoints: []struct {
											LbEndpoints []struct {
												Endpoint struct {
													Address struct {
														SocketAddress struct {
															Address   string "json:\"address\""
															PortValue int    "json:\"port_value\""
														} "json:\"socket_address\""
													} "json:\"address\""
												} "json:\"endpoint\""
												HealthStatus string "json:\"health_status\""
											} "json:\"lb_endpoints\""
										}{
											{
												[]struct {
													Endpoint struct {
														Address struct {
															SocketAddress struct {
																Address   string "json:\"address\""
																PortValue int    "json:\"port_value\""
															} "json:\"socket_address\""
														} "json:\"address\""
													} "json:\"endpoint\""
													HealthStatus string "json:\"health_status\""
												}{
													{
														HealthStatus: "HEALTHY",
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
			},
			expectedStatus: LoadbalancerStatusModelSimpleStatus{
				Status: "OK",
				OK:     1,
				Total:  1,
			},
		},
	}

	lb := &LoadbalancerClient{}
	for _, tc := range testCases {
		require.Equal(t, tc.expectedStatus, lb.getT2Status(tc.lbsvc, tc.nodeEnvoyConfig))
	}
}
