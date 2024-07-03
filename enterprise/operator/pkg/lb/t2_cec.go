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

	envoy_config_cluster_v3 "github.com/cilium/proxy/go/envoy/config/cluster/v3"
	envoy_corev3 "github.com/cilium/proxy/go/envoy/config/core/v3"
	envoy_endpointv3 "github.com/cilium/proxy/go/envoy/config/endpoint/v3"
	envoy_config_listener_v3 "github.com/cilium/proxy/go/envoy/config/listener/v3"
	envoy_config_route_v3 "github.com/cilium/proxy/go/envoy/config/route/v3"
	envoy_health_check_v3 "github.com/cilium/proxy/go/envoy/extensions/filters/http/health_check/v3"
	envoy_extensions_filters_http_router_v3 "github.com/cilium/proxy/go/envoy/extensions/filters/http/router/v3"
	envoy_extensions_listener_tls_inspector_v3 "github.com/cilium/proxy/go/envoy/extensions/filters/listener/tls_inspector/v3"
	envoy_hcm_v3 "github.com/cilium/proxy/go/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_extensions_transport_sockets_tls_v3 "github.com/cilium/proxy/go/envoy/extensions/transport_sockets/tls/v3"
	envoy_typev3 "github.com/cilium/proxy/go/envoy/type/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/envoy"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func (r *standaloneLbReconciler) desiredCiliumEnvoyConfig(model *lbFrontend) (*ciliumv2.CiliumEnvoyConfig, error) {
	if model.assignedIP == nil {
		return nil, nil
	}

	envoyResources := []ciliumv2.XDSResource{}

	// Frontend (with route(s)) -> Envoy Listener & Route(s)

	listener := r.desiredEnvoyListener(model)

	listenerXdsResource, err := toXdsResource(listener, envoy.ListenerTypeURL)
	if err != nil {
		return nil, err
	}

	envoyResources = append(envoyResources, listenerXdsResource)

	routeConfigs := r.desiredEnvoyRouteConfigs(model)

	for _, rc := range routeConfigs {
		routeConfigXdsResource, err := toXdsResource(rc, envoy.RouteTypeURL)
		if err != nil {
			return nil, err
		}

		envoyResources = append(envoyResources, routeConfigXdsResource)
	}

	// Backend(s)-> Envoy Cluster(s)

	clusters := r.desiredEnvoyClusters(model)

	for _, c := range clusters {
		clusterXdsResource, err := toXdsResource(c, envoy.ClusterTypeURL)
		if err != nil {
			return nil, err
		}

		envoyResources = append(envoyResources, clusterXdsResource)
	}

	return &ciliumv2.CiliumEnvoyConfig{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: model.namespace,
			Name:      model.getOwningResourceName(),
		},
		Spec: ciliumv2.CiliumEnvoyConfigSpec{
			NodeSelector: &slim_metav1.LabelSelector{
				MatchLabels: map[string]slim_metav1.MatchLabelsValue{
					"lb.cilium.io/tier": "t2",
				},
			},
			Resources: envoyResources,
		},
	}, nil
}

func (r *standaloneLbReconciler) desiredEnvoyListener(model *lbFrontend) *envoy_config_listener_v3.Listener {
	return &envoy_config_listener_v3.Listener{
		Name: "frontend_listener",
		Address: &envoy_corev3.Address{
			Address: &envoy_corev3.Address_SocketAddress{
				SocketAddress: &envoy_corev3.SocketAddress{
					Address: *model.assignedIP,
					PortSpecifier: &envoy_corev3.SocketAddress_PortValue{
						PortValue: uint32(model.port),
					},
				},
			},
		},
		ListenerFilters: []*envoy_config_listener_v3.ListenerFilter{
			{
				Name: "envoy.filters.listener.tls_inspector",
				ConfigType: &envoy_config_listener_v3.ListenerFilter_TypedConfig{
					TypedConfig: toAny(&envoy_extensions_listener_tls_inspector_v3.TlsInspector{}),
				},
			},
		},
		FilterChains: r.desiredEnvoyListenerFilterChains(model),
	}
}

func (r *standaloneLbReconciler) desiredEnvoyListenerFilterChains(model *lbFrontend) []*envoy_config_listener_v3.FilterChain {
	filterChains := []*envoy_config_listener_v3.FilterChain{}

	httpFilterChain := r.desiredEnvoyListenerHttpFilterChain(model)
	filterChains = append(filterChains, httpFilterChain)

	if model.tls != nil {
		httpsFilterChain := r.desiredEnvoyListenerHttpsFilterChain(model)
		filterChains = append(filterChains, httpsFilterChain)
	}

	return filterChains
}

func (r *standaloneLbReconciler) desiredEnvoyListenerHttpFilterChain(model *lbFrontend) *envoy_config_listener_v3.FilterChain {
	return &envoy_config_listener_v3.FilterChain{
		FilterChainMatch: &envoy_config_listener_v3.FilterChainMatch{
			TransportProtocol: "raw_buffer",
		},
		Filters: []*envoy_config_listener_v3.Filter{
			{
				Name: "envoy.filters.network.http_connection_manager",
				ConfigType: &envoy_config_listener_v3.Filter_TypedConfig{
					TypedConfig: toAny(&envoy_hcm_v3.HttpConnectionManager{
						StatPrefix: "frontend_listener_http",
						CodecType:  envoy_hcm_v3.HttpConnectionManager_AUTO,
						HttpFilters: []*envoy_hcm_v3.HttpFilter{
							// Health Check filter is only exposed on HTTP
							{
								Name: "envoy.filters.http.health_check",
								ConfigType: &envoy_hcm_v3.HttpFilter_TypedConfig{
									TypedConfig: toAny(desiredHealthCheckFilter(model)),
								},
							},
							{
								Name: "envoy.filters.http.router",
								ConfigType: &envoy_hcm_v3.HttpFilter_TypedConfig{
									TypedConfig: toAny(&envoy_extensions_filters_http_router_v3.Router{}),
								},
							},
						},
						RouteSpecifier: &envoy_hcm_v3.HttpConnectionManager_Rds{
							Rds: &envoy_hcm_v3.Rds{
								RouteConfigName: "frontend_routeconfig_http",
							},
						},
					}),
				},
			},
		},
	}
}

func toServerNames(domainNames []string) []string {
	serverNames := []string{}

	for _, dn := range domainNames {
		if dn == "*" {
			continue
		}

		// TODO: validate for * only as starting prefix with *.

		serverNames = append(serverNames, dn)
	}

	return serverNames
}

func (r *standaloneLbReconciler) toSdsConfigs(model *lbFrontend) []*envoy_extensions_transport_sockets_tls_v3.SdsSecretConfig {
	secrets := []*envoy_extensions_transport_sockets_tls_v3.SdsSecretConfig{}

	for _, cs := range model.tls.certificateSecrets {
		secrets = append(secrets, &envoy_extensions_transport_sockets_tls_v3.SdsSecretConfig{
			Name: fmt.Sprintf("%s/%s-%s", r.secretsNamespace, model.namespace, cs),
		})
	}

	return secrets
}

func (r *standaloneLbReconciler) desiredEnvoyListenerHttpsFilterChain(model *lbFrontend) *envoy_config_listener_v3.FilterChain {
	return &envoy_config_listener_v3.FilterChain{
		FilterChainMatch: &envoy_config_listener_v3.FilterChainMatch{
			TransportProtocol: "tls",
			ServerNames:       toServerNames(model.tls.domainNames),
		},
		TransportSocket: &envoy_corev3.TransportSocket{
			Name: "envoy.transport_sockets.tls",
			ConfigType: &envoy_corev3.TransportSocket_TypedConfig{
				TypedConfig: toAny(&envoy_extensions_transport_sockets_tls_v3.DownstreamTlsContext{
					CommonTlsContext: &envoy_extensions_transport_sockets_tls_v3.CommonTlsContext{
						TlsCertificateSdsSecretConfigs: r.toSdsConfigs(model),
					},
				}),
			},
		},
		Filters: []*envoy_config_listener_v3.Filter{
			{
				Name: "envoy.filters.network.http_connection_manager",
				ConfigType: &envoy_config_listener_v3.Filter_TypedConfig{
					TypedConfig: toAny(&envoy_hcm_v3.HttpConnectionManager{
						StatPrefix: "frontend_listener_https",
						CodecType:  envoy_hcm_v3.HttpConnectionManager_AUTO,
						HttpFilters: []*envoy_hcm_v3.HttpFilter{
							{
								Name: "envoy.filters.http.router",
								ConfigType: &envoy_hcm_v3.HttpFilter_TypedConfig{
									TypedConfig: toAny(&envoy_extensions_filters_http_router_v3.Router{}),
								},
							},
						},
						RouteSpecifier: &envoy_hcm_v3.HttpConnectionManager_Rds{
							Rds: &envoy_hcm_v3.Rds{
								RouteConfigName: "frontend_routeconfig_https",
							},
						},
					}),
				},
			},
		},
	}
}

func (r *standaloneLbReconciler) desiredEnvoyRouteConfigs(model *lbFrontend) []*envoy_config_route_v3.RouteConfiguration {
	routeConfigs := []*envoy_config_route_v3.RouteConfiguration{}

	httpRouteConfig := r.desiredEnvoyHttpRouteConfig(model)
	routeConfigs = append(routeConfigs, httpRouteConfig)

	if model.tls != nil {
		httpsRouteConfig := r.desiredEnvoyHttpsRouteConfig(model)
		routeConfigs = append(routeConfigs, httpsRouteConfig)

	}
	return routeConfigs
}

func (r *standaloneLbReconciler) desiredEnvoyHttpRouteConfig(model *lbFrontend) *envoy_config_route_v3.RouteConfiguration {
	return &envoy_config_route_v3.RouteConfiguration{
		Name:         "frontend_routeconfig_http",
		VirtualHosts: r.desiredEnvoyHttpRouteVirtualHosts(model, "http"),
	}
}

func (r *standaloneLbReconciler) desiredEnvoyHttpsRouteConfig(model *lbFrontend) *envoy_config_route_v3.RouteConfiguration {
	return &envoy_config_route_v3.RouteConfiguration{
		Name:         "frontend_routeconfig_https",
		VirtualHosts: r.desiredEnvoyHttpRouteVirtualHosts(model, "https"),
	}
}

func (*standaloneLbReconciler) desiredEnvoyHttpRouteVirtualHosts(model *lbFrontend, httpType string) []*envoy_config_route_v3.VirtualHost {
	hostnameToHttpRoutes := map[string][]*envoy_config_route_v3.Route{}

	for i, route := range model.routes {
		// TODO: currently only http routes supported
		if route.http != nil {
			httpRoute := &envoy_config_route_v3.Route{
				Action: &envoy_config_route_v3.Route_Route{
					Route: &envoy_config_route_v3.RouteAction{
						ClusterSpecifier: &envoy_config_route_v3.RouteAction_Cluster{
							Cluster: fmt.Sprintf("backend_cluster_%d", i),
						},
					},
				},
			}

			if route.http.pathType != pathTypePrefix {
				// TODO: currently only pathtype prefix supported
				continue
			}

			httpRoute.Match = &envoy_config_route_v3.RouteMatch{
				PathSpecifier: &envoy_config_route_v3.RouteMatch_Prefix{
					Prefix: route.http.path,
				},
			}

			// TODO: wildcard handling?
			_, ok := hostnameToHttpRoutes[route.http.hostname]
			if !ok {
				hostnameToHttpRoutes[route.http.hostname] = []*envoy_config_route_v3.Route{}
			}

			hostnameToHttpRoutes[route.http.hostname] = append(hostnameToHttpRoutes[route.http.hostname], httpRoute)
		}
	}

	virtualHosts := []*envoy_config_route_v3.VirtualHost{}

	for hostname, httpRoutes := range hostnameToHttpRoutes {
		virtualHosts = append(virtualHosts,
			&envoy_config_route_v3.VirtualHost{
				Name:    fmt.Sprintf("frontend_virtualhost_%s_%s", httpType, hostname),
				Domains: []string{hostname},
				Routes:  httpRoutes,
			},
		)
	}

	return virtualHosts
}

func desiredHealthCheckFilter(model *lbFrontend) *envoy_health_check_v3.HealthCheck {
	healthCheckFilterClusters := map[string]*envoy_typev3.Percent{}

	for i := range model.routes {
		healthCheckFilterClusters[fmt.Sprintf("backend_cluster_%d", i)] = &envoy_typev3.Percent{Value: 20}
	}

	healthCheckFilter := &envoy_health_check_v3.HealthCheck{
		PassThroughMode:              &wrapperspb.BoolValue{Value: false},
		ClusterMinHealthyPercentages: healthCheckFilterClusters,
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
	}

	return healthCheckFilter
}

func (*standaloneLbReconciler) desiredEnvoyClusters(model *lbFrontend) []*envoy_config_cluster_v3.Cluster {
	clusters := []*envoy_config_cluster_v3.Cluster{}

	for i, route := range model.routes {
		backend := route.backend

		lbEndpoints := make([]*envoy_endpointv3.LbEndpoint, 0, len(backend.ips))

		for _, ipBackends := range backend.ips {
			lbEndpoints = append(lbEndpoints, &envoy_endpointv3.LbEndpoint{
				HostIdentifier: &envoy_endpointv3.LbEndpoint_Endpoint{Endpoint: &envoy_endpointv3.Endpoint{
					Address: &envoy_corev3.Address{Address: &envoy_corev3.Address_SocketAddress{SocketAddress: &envoy_corev3.SocketAddress{
						Address:       ipBackends.address,
						PortSpecifier: &envoy_corev3.SocketAddress_PortValue{PortValue: uint32(ipBackends.port)},
					}}},
				}},
			})
		}

		cluster := envoy_config_cluster_v3.Cluster{
			Name: fmt.Sprintf("backend_cluster_%d", i),
			ClusterDiscoveryType: &envoy_config_cluster_v3.Cluster_Type{
				Type: envoy_config_cluster_v3.Cluster_STATIC,
			},
			CommonLbConfig: &envoy_config_cluster_v3.Cluster_CommonLbConfig{
				// disabling panic mode (https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/upstream/load_balancing/panic_threshold)
				HealthyPanicThreshold: &envoy_typev3.Percent{Value: 0.0},
			},
			ConnectTimeout: &durationpb.Duration{Seconds: 5}, // default
			HealthChecks: []*envoy_corev3.HealthCheck{
				{
					// TODO: create HC depending on health check type
					HealthChecker: &envoy_corev3.HealthCheck_HttpHealthCheck_{HttpHealthCheck: &envoy_corev3.HealthCheck_HttpHealthCheck{
						Host: backend.healthCheckConfig.http.host,
						Path: backend.healthCheckConfig.http.path,
					}},
					Interval: &durationpb.Duration{Seconds: int64(backend.healthCheckConfig.intervalSeconds)},
					// TODO: NoTrafficInterval
					// TODO: Jitter
					Timeout:            &durationpb.Duration{Seconds: int64(backend.healthCheckConfig.timeoutSeconds)},
					HealthyThreshold:   &wrapperspb.UInt32Value{Value: uint32(backend.healthCheckConfig.healthyThreshold)},
					UnhealthyThreshold: &wrapperspb.UInt32Value{Value: uint32(backend.healthCheckConfig.unhealthyThreshold)},
					// T1's quarantine timeout
					UnhealthyEdgeInterval: &durationpb.Duration{Seconds: int64(backend.healthCheckConfig.unhealthyEdgeIntervalSeconds)},
					// explicitly set unhealthy interval to the same value as interval (T1 doesn't support unhealthy interval)
					UnhealthyInterval: &durationpb.Duration{Seconds: int64(backend.healthCheckConfig.unhealthyIntervalSeconds)},
				},
			},
			LbPolicy: mapLbPolicy(backend.lbAlgorithm),
			LoadAssignment: &envoy_endpointv3.ClusterLoadAssignment{
				ClusterName: fmt.Sprintf("backend_cluster_%d", i),
				Endpoints: []*envoy_endpointv3.LocalityLbEndpoints{
					{
						LbEndpoints: lbEndpoints,
					},
				},
			},
		}

		clusters = append(clusters, &cluster)
	}

	return clusters
}

func mapLbPolicy(lbAlgorithm lbAlgorithmType) envoy_config_cluster_v3.Cluster_LbPolicy {
	switch lbAlgorithm {
	case lbAlgorithmRoundRobin:
		return envoy_config_cluster_v3.Cluster_ROUND_ROBIN
	default:
		return envoy_config_cluster_v3.Cluster_ROUND_ROBIN
	}
}

func toXdsResource(m proto.Message, typeUrl string) (ciliumv2.XDSResource, error) {
	protoBytes, err := proto.Marshal(m)
	if err != nil {
		return ciliumv2.XDSResource{}, err
	}

	return ciliumv2.XDSResource{
		Any: &anypb.Any{
			TypeUrl: typeUrl,
			Value:   protoBytes,
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
