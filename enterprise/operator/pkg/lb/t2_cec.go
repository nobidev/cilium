//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package lb

import (
	"fmt"
	"time"

	envoy_config_cluster_v3 "github.com/cilium/proxy/go/envoy/config/cluster/v3"
	corev3 "github.com/cilium/proxy/go/envoy/config/core/v3"
	endpointv3 "github.com/cilium/proxy/go/envoy/config/endpoint/v3"
	envoy_config_listener_v3 "github.com/cilium/proxy/go/envoy/config/listener/v3"
	envoy_config_route_v3 "github.com/cilium/proxy/go/envoy/config/route/v3"
	health_check_v3 "github.com/cilium/proxy/go/envoy/extensions/filters/http/health_check/v3"
	envoy_extensions_filters_http_router_v3 "github.com/cilium/proxy/go/envoy/extensions/filters/http/router/v3"
	http_connection_manager_v3 "github.com/cilium/proxy/go/envoy/extensions/filters/network/http_connection_manager/v3"
	typev3 "github.com/cilium/proxy/go/envoy/type/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/envoy"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func (r *standaloneLbReconciler) desiredCiliumEnvoyConfig(lb *isovalentv1alpha1.IsovalentLB) (*ciliumv2.CiliumEnvoyConfig, error) {
	intervalDuration, err := time.ParseDuration(lb.Spec.Healthcheck.Interval)
	if err != nil {
		return nil, fmt.Errorf("failed to parse healthcheck interval duration: %w", err)
	}

	lbEndpoints := make([]*endpointv3.LbEndpoint, 0, len(lb.Spec.Backends))
	for _, be := range lb.Spec.Backends {
		lbEndpoints = append(lbEndpoints, &endpointv3.LbEndpoint{
			HostIdentifier: &endpointv3.LbEndpoint_Endpoint{Endpoint: &endpointv3.Endpoint{
				Address: &corev3.Address{Address: &corev3.Address_SocketAddress{SocketAddress: &corev3.SocketAddress{
					Address:       be.IP,
					PortSpecifier: &corev3.SocketAddress_PortValue{PortValue: uint32(be.Port)},
				}}},
			}},
		})
	}
	cluster := envoy_config_cluster_v3.Cluster{
		Name: "cluster",
		ClusterDiscoveryType: &envoy_config_cluster_v3.Cluster_Type{
			Type: envoy_config_cluster_v3.Cluster_STATIC,
		},
		CommonLbConfig: &envoy_config_cluster_v3.Cluster_CommonLbConfig{
			// disabling panic mode (https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/upstream/load_balancing/panic_threshold)
			HealthyPanicThreshold: &typev3.Percent{Value: 0.0},
		},
		ConnectTimeout: &durationpb.Duration{Seconds: 5}, // default
		HealthChecks: []*corev3.HealthCheck{
			{
				HealthChecker: &corev3.HealthCheck_HttpHealthCheck_{HttpHealthCheck: &corev3.HealthCheck_HttpHealthCheck{
					Host: "envoy",
					Path: "/health",
				}},
				// T1->T2 health check interval should be half of the actual interval to keep reaction time lower
				Interval:           &durationpb.Duration{Seconds: int64(intervalDuration.Seconds() * 0.5)},
				Timeout:            &durationpb.Duration{Seconds: 5},
				HealthyThreshold:   &wrapperspb.UInt32Value{Value: 2},
				UnhealthyThreshold: &wrapperspb.UInt32Value{Value: 2},
				// T1's quarantine timeout
				UnhealthyEdgeInterval: &durationpb.Duration{Seconds: 30},
				// explicitly set unhealthy interval to the same value as interval (T1 doesn't support unhealthy interval)
				UnhealthyInterval: &durationpb.Duration{Seconds: int64(intervalDuration.Seconds() * 0.5)},
			},
		},
		LbPolicy: envoy_config_cluster_v3.Cluster_ROUND_ROBIN,
		LoadAssignment: &endpointv3.ClusterLoadAssignment{
			ClusterName: "cluster",
			Endpoints: []*endpointv3.LocalityLbEndpoints{
				{
					LbEndpoints: lbEndpoints,
				},
			},
		},
	}
	clusterBytes, err := proto.Marshal(&cluster)
	if err != nil {
		return nil, err
	}
	listener := envoy_config_listener_v3.Listener{
		Name: "listener",
		Address: &corev3.Address{Address: &corev3.Address_SocketAddress{SocketAddress: &corev3.SocketAddress{
			Address:       lb.Spec.VIP,
			PortSpecifier: &corev3.SocketAddress_PortValue{PortValue: uint32(lb.Spec.Port)},
		}}},
		FilterChains: []*envoy_config_listener_v3.FilterChain{
			{
				Filters: []*envoy_config_listener_v3.Filter{
					{
						Name: "envoy.filters.network.http_connection_manager",
						ConfigType: &envoy_config_listener_v3.Filter_TypedConfig{
							TypedConfig: toAny(&http_connection_manager_v3.HttpConnectionManager{
								StatPrefix: "listener_http",
								CodecType:  http_connection_manager_v3.HttpConnectionManager_AUTO,
								HttpFilters: []*http_connection_manager_v3.HttpFilter{
									{
										Name: "envoy.filters.http.health_check",
										ConfigType: &http_connection_manager_v3.HttpFilter_TypedConfig{
											TypedConfig: toAny(&health_check_v3.HealthCheck{
												PassThroughMode: &wrapperspb.BoolValue{Value: false},
												ClusterMinHealthyPercentages: map[string]*typev3.Percent{
													"cluster": {
														Value: 20,
													},
												},
												Headers: []*envoy_config_route_v3.HeaderMatcher{
													{
														HeaderMatchSpecifier: &envoy_config_route_v3.HeaderMatcher_ExactMatch{ExactMatch: healthCheckHttpPath},
														Name:                 ":path",
													},
													{
														HeaderMatchSpecifier: &envoy_config_route_v3.HeaderMatcher_ExactMatch{ExactMatch: healthCheckHttpMethod},
														Name:                 ":method",
													},
												},
											}),
										},
									},
									{
										Name: "envoy.filters.http.router",
										ConfigType: &http_connection_manager_v3.HttpFilter_TypedConfig{
											TypedConfig: toAny(&envoy_extensions_filters_http_router_v3.Router{}),
										},
									},
								},
								RouteSpecifier: &http_connection_manager_v3.HttpConnectionManager_RouteConfig{
									RouteConfig: &envoy_config_route_v3.RouteConfiguration{
										Name: "local_route",
										VirtualHosts: []*envoy_config_route_v3.VirtualHost{
											{
												Name:    "local_service",
												Domains: []string{"*"},
												Routes: []*envoy_config_route_v3.Route{
													{
														Match: &envoy_config_route_v3.RouteMatch{
															PathSpecifier: &envoy_config_route_v3.RouteMatch_Prefix{
																Prefix: "/",
															},
														},
														Action: &envoy_config_route_v3.Route_Route{
															Route: &envoy_config_route_v3.RouteAction{
																ClusterSpecifier: &envoy_config_route_v3.RouteAction_Cluster{
																	Cluster: "cluster",
																},
															},
														},
													},
												},
											},
										},
									},
								},
							}),
						},
					},
				},
			},
		},
	}
	listenerBytes, err := proto.Marshal(&listener)
	if err != nil {
		return nil, err
	}
	return &ciliumv2.CiliumEnvoyConfig{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: lb.Namespace,
			Name:      lb.Name,
		},
		Spec: ciliumv2.CiliumEnvoyConfigSpec{
			NodeSelector: &slim_metav1.LabelSelector{
				MatchLabels: map[string]slim_metav1.MatchLabelsValue{
					"lb.cilium.io/tier": "t2",
				},
			},
			Resources: []ciliumv2.XDSResource{
				{
					Any: &anypb.Any{
						TypeUrl: envoy.ClusterTypeURL,
						Value:   clusterBytes,
					},
				},
				{
					Any: &anypb.Any{
						TypeUrl: envoy.ListenerTypeURL,
						Value:   listenerBytes,
					},
				},
			},
		},
	}, nil
}

func toAny(message proto.Message) *anypb.Any {
	a, err := anypb.New(message)
	if err != nil {
		return nil
	}
	return a
}
