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
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/envoy"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	isovalent_api_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/policy/api"
)

func (lbm *LBManager) populateCEC(obj *isovalent_api_v1alpha1.IsovalentLB, svc *v1.Service) (*cilium_api_v2.CiliumEnvoyConfig, error) {
	clusterName, _ := api.ResourceQualifiedName(obj.Namespace, obj.Name, "cluster")

	intervalDuration, err := time.ParseDuration(obj.Spec.Healthcheck.Interval)
	if err != nil {
		return nil, fmt.Errorf("failed to parse healthcheck interval duration: %w", err)
	}

	lbEndpoints := make([]*endpointv3.LbEndpoint, 0, len(obj.Spec.Backends))
	for _, be := range obj.Spec.Backends {
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
		CommonLbConfig: &envoy_config_cluster_v3.Cluster_CommonLbConfig{
			HealthyPanicThreshold: &typev3.Percent{Value: 0.0},
		},
		ConnectTimeout: &durationpb.Duration{Seconds: 2},
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
				UnhealthyInterval: &durationpb.Duration{Seconds: int64(intervalDuration.Seconds())},
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
		// Temporarily disable passive health checks
		// OutlierDetection: &envoy_config_cluster_v3.OutlierDetection{
		// 	ConsecutiveLocalOriginFailure:         &wrapperspb.UInt32Value{Value: 2},
		// 	EnforcingFailurePercentage:            &wrapperspb.UInt32Value{Value: 100},
		// 	EnforcingFailurePercentageLocalOrigin: &wrapperspb.UInt32Value{Value: 100},
		// 	FailurePercentageMinimumHosts:         &wrapperspb.UInt32Value{Value: 1},
		// 	FailurePercentageRequestVolume:        &wrapperspb.UInt32Value{Value: 1},
		// 	MaxEjectionPercent:                    &wrapperspb.UInt32Value{Value: 100},
		// 	MaxEjectionTime:                       &durationpb.Duration{Seconds: 30},
		// 	SplitExternalLocalOriginErrors:        false,
		// },
	}
	clusterBytes, err := proto.Marshal(&cluster)
	if err != nil {
		return nil, err
	}
	listener := envoy_config_listener_v3.Listener{
		Name: "listener",
		Address: &corev3.Address{Address: &corev3.Address_SocketAddress{SocketAddress: &corev3.SocketAddress{
			Address:       obj.Spec.VIP,
			PortSpecifier: &corev3.SocketAddress_PortValue{PortValue: uint32(obj.Spec.Port)},
		}}},
		FilterChains: []*envoy_config_listener_v3.FilterChain{
			{
				Filters: []*envoy_config_listener_v3.Filter{
					{
						Name: "envoy.filters.network.http_connection_manager",
						ConfigType: &envoy_config_listener_v3.Filter_TypedConfig{TypedConfig: toAny(&http_connection_manager_v3.HttpConnectionManager{
							CodecType: http_connection_manager_v3.HttpConnectionManager_AUTO,
							HttpFilters: []*http_connection_manager_v3.HttpFilter{
								{
									Name: "envoy.filters.http.health_check",
									ConfigType: &http_connection_manager_v3.HttpFilter_TypedConfig{TypedConfig: toAny(&health_check_v3.HealthCheck{
										PassThroughMode: &wrapperspb.BoolValue{Value: false},
										ClusterMinHealthyPercentages: map[string]*typev3.Percent{
											clusterName: {
												Value: 20,
											},
										},
										Headers: []*envoy_config_route_v3.HeaderMatcher{
											{
												HeaderMatchSpecifier: &envoy_config_route_v3.HeaderMatcher_ExactMatch{ExactMatch: "/health"},
												Name:                 ":path",
											},
										},
									})},
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
													Match: &envoy_config_route_v3.RouteMatch{PathSpecifier: &envoy_config_route_v3.RouteMatch_Prefix{Prefix: "/"}},
													Action: &envoy_config_route_v3.Route_Route{
														Route: &envoy_config_route_v3.RouteAction{ClusterSpecifier: &envoy_config_route_v3.RouteAction_Cluster{
															Cluster: "cluster",
														}},
													},
												},
											},
										},
									},
								},
							},
							StatPrefix: "ingress_http",
						})},
					},
				},
			},
		},
	}
	listenerBytes, err := proto.Marshal(&listener)
	if err != nil {
		return nil, err
	}
	return &cilium_api_v2.CiliumEnvoyConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:      obj.Name,
			Namespace: obj.Namespace,
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: isovalent_api_v1alpha1.SchemeGroupVersion.String(),
					Kind:       isovalent_api_v1alpha1.IsovalentLBKindDefinition,
					Name:       obj.Name,
					UID:        obj.UID,
				},
				{
					APIVersion: "v1",
					Kind:       "Service",
					Name:       svc.Name,
					UID:        svc.UID,
				},
			},
		},
		Spec: cilium_api_v2.CiliumEnvoyConfigSpec{
			Resources: []cilium_api_v2.XDSResource{
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
