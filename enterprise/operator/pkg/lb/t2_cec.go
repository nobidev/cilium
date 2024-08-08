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
	"context"
	"fmt"
	"slices"

	cilium_proxy "github.com/cilium/proxy/go/cilium/api"
	envoy_accesslog_v3 "github.com/cilium/proxy/go/envoy/config/accesslog/v3"
	envoy_config_cluster_v3 "github.com/cilium/proxy/go/envoy/config/cluster/v3"
	envoy_corev3 "github.com/cilium/proxy/go/envoy/config/core/v3"
	envoy_config_endpoint_v3 "github.com/cilium/proxy/go/envoy/config/endpoint/v3"
	envoy_config_listener_v3 "github.com/cilium/proxy/go/envoy/config/listener/v3"
	envoy_config_route_v3 "github.com/cilium/proxy/go/envoy/config/route/v3"
	envoy_extensions_accessloggers_stream_v3 "github.com/cilium/proxy/go/envoy/extensions/access_loggers/stream/v3"
	envoy_health_check_v3 "github.com/cilium/proxy/go/envoy/extensions/filters/http/health_check/v3"
	envoy_extensions_filters_http_router_v3 "github.com/cilium/proxy/go/envoy/extensions/filters/http/router/v3"
	envoy_extensions_listener_tls_inspector_v3 "github.com/cilium/proxy/go/envoy/extensions/filters/listener/tls_inspector/v3"
	envoy_hcm_v3 "github.com/cilium/proxy/go/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_tcpproxy_v3 "github.com/cilium/proxy/go/envoy/extensions/filters/network/tcp_proxy/v3"
	envoy_extensions_transport_sockets_tls_v3 "github.com/cilium/proxy/go/envoy/extensions/transport_sockets/tls/v3"
	envoy_extensions_upstreams_http_v3 "github.com/cilium/proxy/go/envoy/extensions/upstreams/http/v3"
	envoy_matcher_v3 "github.com/cilium/proxy/go/envoy/type/matcher/v3"
	envoy_typev3 "github.com/cilium/proxy/go/envoy/type/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/envoy"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func (r *lbFrontendReconciler) desiredCiliumEnvoyConfig(model *lbFrontend) (*ciliumv2.CiliumEnvoyConfig, error) {
	if model.vip.assignedIPv4 == nil {
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

	// Backend(s)-> Envoy Cluster(s) & Envoy Endpoints (ClusterLoadAssignments)

	clusters := r.desiredEnvoyClusters(model)

	for _, c := range clusters {
		clusterXdsResource, err := toXdsResource(c, envoy.ClusterTypeURL)
		if err != nil {
			return nil, err
		}

		envoyResources = append(envoyResources, clusterXdsResource)
	}

	endpoints := r.desiredEnvoyEndpoints(model)

	for _, e := range endpoints {
		endpointXdsResource, err := toXdsResource(e, envoy.EndpointTypeURL)
		if err != nil {
			return nil, err
		}

		envoyResources = append(envoyResources, endpointXdsResource)
	}

	return &ciliumv2.CiliumEnvoyConfig{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: model.namespace,
			Name:      model.getOwningResourceName(),
		},
		Spec: ciliumv2.CiliumEnvoyConfigSpec{
			NodeSelector: &slim_metav1.LabelSelector{
				MatchLabels: map[string]slim_metav1.MatchLabelsValue{
					"service.cilium.io/node": "t2",
				},
			},
			Resources: envoyResources,
		},
	}, nil
}

func (r *lbFrontendReconciler) desiredEnvoyListener(model *lbFrontend) *envoy_config_listener_v3.Listener {
	accessLoggers := []*envoy_accesslog_v3.AccessLog{}

	if r.config.AccessLog.EnableTCP {
		accessLoggers = append(accessLoggers, &envoy_accesslog_v3.AccessLog{
			Name: "stdout",
			ConfigType: &envoy_accesslog_v3.AccessLog_TypedConfig{
				TypedConfig: toAny(&envoy_extensions_accessloggers_stream_v3.StdoutAccessLog{
					AccessLogFormat: &envoy_extensions_accessloggers_stream_v3.StdoutAccessLog_LogFormat{
						LogFormat: &envoy_corev3.SubstitutionFormatString{
							Format: &envoy_corev3.SubstitutionFormatString_TextFormatSource{
								TextFormatSource: &envoy_corev3.DataSource{
									Specifier: &envoy_corev3.DataSource_InlineString{
										InlineString: fmt.Sprintf("%s\n", r.config.AccessLog.FormatTCP),
									},
								},
							},
						},
					},
				}),
			},
		})
	}

	return &envoy_config_listener_v3.Listener{
		Name: "frontend_listener",
		Address: &envoy_corev3.Address{
			Address: &envoy_corev3.Address_SocketAddress{
				SocketAddress: &envoy_corev3.SocketAddress{
					Address: *model.vip.assignedIPv4,
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
			// Explicit configuration of Cilium's BPF Metadata Listener Filter with BPF map lookups
			// disabled. This prevents the CiliumEnvoyConfig parse logic to inject the default one that
			// comes with BPF map lookups enabled.
			{
				Name: "cilium.bpf_metadata",
				ConfigType: &envoy_config_listener_v3.ListenerFilter_TypedConfig{
					TypedConfig: toAny(&cilium_proxy.BpfMetadata{
						BpfRoot: "", // disable actual BPF map lookup (no policy enforcement and hubble flows either)
					}),
				},
			},
		},
		FilterChains:                  r.desiredEnvoyListenerFilterChains(model),
		AccessLog:                     accessLoggers,
		PerConnectionBufferLimitBytes: wrapperspb.UInt32(32768), // 32KiB
	}
}

func (r *lbFrontendReconciler) desiredEnvoyListenerFilterChains(model *lbFrontend) []*envoy_config_listener_v3.FilterChain {
	filterChains := []*envoy_config_listener_v3.FilterChain{}

	if model.applications.isHTTPProxyConfigured() {
		httpFilterChain := r.desiredEnvoyListenerHttpFilterChain(model)
		filterChains = append(filterChains, httpFilterChain)
	}

	if model.applications.isHTTPSProxyConfigured() {
		httpsFilterChain := r.desiredEnvoyListenerHttpsFilterChain(model)
		filterChains = append(filterChains, httpsFilterChain)
	}

	if model.applications.isTLSPassthroughConfigured() {
		tlsPassthroughFilterChains := r.desiredEnvoyListenerTLSPassthroughFilterChains(model)
		filterChains = append(filterChains, tlsPassthroughFilterChains...)
	}

	return filterChains
}

func (r *lbFrontendReconciler) desiredEnvoyListenerHttpFilterChain(model *lbFrontend) *envoy_config_listener_v3.FilterChain {
	return &envoy_config_listener_v3.FilterChain{
		FilterChainMatch: &envoy_config_listener_v3.FilterChainMatch{
			TransportProtocol: "raw_buffer",
		},
		Filters: []*envoy_config_listener_v3.Filter{
			{
				Name: "envoy.filters.network.http_connection_manager",
				ConfigType: &envoy_config_listener_v3.Filter_TypedConfig{
					TypedConfig: toAny(&envoy_hcm_v3.HttpConnectionManager{
						ServerName:                   r.config.ServerName,
						AccessLog:                    r.desiredEnvoyHTTPAccessLoggers(),
						GenerateRequestId:            wrapperspb.Bool(r.config.RequestID.Generate),
						PreserveExternalRequestId:    r.config.RequestID.Preserve,
						AlwaysSetRequestIdInResponse: r.config.RequestID.Response,
						StatPrefix:                   "frontend_listener_http",
						CodecType:                    r.toCodecType(model.applications.getHTTPHTTPConfig()),
						NormalizePath:                wrapperspb.Bool(true),
						UseRemoteAddress:             wrapperspb.Bool(true),
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
						Http2ProtocolOptions: &envoy_corev3.Http2ProtocolOptions{
							MaxConcurrentStreams:        wrapperspb.UInt32(100),
							InitialStreamWindowSize:     wrapperspb.UInt32(65535),
							InitialConnectionWindowSize: wrapperspb.UInt32(1048576),
						},
					}),
				},
			},
		},
	}
}

func (r *lbFrontendReconciler) toHTTPSServerNames(model *lbFrontend) []string {
	// get all HTTPS hostnames
	httpsDomainNames := []string{}

	if model.applications.httpsProxy != nil {
		for _, lr := range model.applications.httpsProxy.routes {
			httpsDomainNames = append(httpsDomainNames, lr.match.hostNames...)
		}
	}

	// remove duplicates and raw '*' that is not allowed by Envoy
	serverNames := []string{}
	for _, dn := range httpsDomainNames {
		if dn == "*" {
			continue
		}

		serverNames = append(serverNames, dn)
	}

	slices.Sort(serverNames)
	return slices.Compact(serverNames)
}

func (r *lbFrontendReconciler) toCodecType(httpConfig *lbFrontendHTTPConfig) envoy_hcm_v3.HttpConnectionManager_CodecType {
	if httpConfig == nil {
		return envoy_hcm_v3.HttpConnectionManager_AUTO
	}

	if httpConfig.enableHTTP11 && !httpConfig.enableHTTP2 {
		return envoy_hcm_v3.HttpConnectionManager_HTTP1
	}

	if httpConfig.enableHTTP2 && !httpConfig.enableHTTP11 {
		return envoy_hcm_v3.HttpConnectionManager_HTTP2
	}

	return envoy_hcm_v3.HttpConnectionManager_AUTO
}

func (r *lbFrontendReconciler) toAlpnProtocols(model *lbFrontend) []string {
	if model.applications.httpsProxy == nil || model.applications.httpsProxy.httpConfig == nil {
		return nil
	}

	alpnProtocols := []string{}

	// Note: be aware that the order of ALPN protocols matters
	if model.applications.httpsProxy.httpConfig.enableHTTP2 {
		alpnProtocols = append(alpnProtocols, "h2")
	}

	if model.applications.httpsProxy.httpConfig.enableHTTP11 {
		alpnProtocols = append(alpnProtocols, "http/1.1")
	}

	return alpnProtocols
}

func (r *lbFrontendReconciler) toTLSPassthroughServerNames(tlsPassthroughHostNames []string) []string {
	// remove duplicates and raw '*' that is not allowed by Envoy
	serverNames := []string{}
	for _, dn := range tlsPassthroughHostNames {
		if dn == "*" {
			continue
		}

		serverNames = append(serverNames, dn)
	}

	slices.Sort(serverNames)
	return slices.Compact(serverNames)
}

func (r *lbFrontendReconciler) toSdsConfigs(model *lbFrontend) []*envoy_extensions_transport_sockets_tls_v3.SdsSecretConfig {
	secrets := []*envoy_extensions_transport_sockets_tls_v3.SdsSecretConfig{}

	if model.applications.httpsProxy == nil || model.applications.httpsProxy.tlsConfig == nil {
		return secrets
	}

	for _, cs := range model.applications.httpsProxy.tlsConfig.certificateSecrets {
		secrets = append(secrets, &envoy_extensions_transport_sockets_tls_v3.SdsSecretConfig{
			Name: fmt.Sprintf("%s/%s-%s", r.config.SecretsNamespace, model.namespace, cs),
		})
	}

	return secrets
}

func (r *lbFrontendReconciler) desiredEnvoyListenerHttpsFilterChain(model *lbFrontend) *envoy_config_listener_v3.FilterChain {
	return &envoy_config_listener_v3.FilterChain{
		FilterChainMatch: &envoy_config_listener_v3.FilterChainMatch{
			TransportProtocol: "tls",
			ServerNames:       r.toHTTPSServerNames(model),
		},
		TransportSocket: &envoy_corev3.TransportSocket{
			Name: "envoy.transport_sockets.tls",
			ConfigType: &envoy_corev3.TransportSocket_TypedConfig{
				TypedConfig: toAny(&envoy_extensions_transport_sockets_tls_v3.DownstreamTlsContext{
					CommonTlsContext: &envoy_extensions_transport_sockets_tls_v3.CommonTlsContext{
						TlsCertificateSdsSecretConfigs: r.toSdsConfigs(model),
						AlpnProtocols:                  r.toAlpnProtocols(model),
					},
				}),
			},
		},
		Filters: []*envoy_config_listener_v3.Filter{
			{
				Name: "envoy.filters.network.http_connection_manager",
				ConfigType: &envoy_config_listener_v3.Filter_TypedConfig{
					TypedConfig: toAny(&envoy_hcm_v3.HttpConnectionManager{
						ServerName:                   r.config.ServerName,
						AccessLog:                    r.desiredEnvoyHTTPAccessLoggers(),
						GenerateRequestId:            wrapperspb.Bool(r.config.RequestID.Generate),
						PreserveExternalRequestId:    r.config.RequestID.Preserve,
						AlwaysSetRequestIdInResponse: r.config.RequestID.Response,
						StatPrefix:                   "frontend_listener_https",
						CodecType:                    r.toCodecType(model.applications.getHTTPSHTTPConfig()),
						NormalizePath:                wrapperspb.Bool(true),
						UseRemoteAddress:             wrapperspb.Bool(true),
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
						Http2ProtocolOptions: &envoy_corev3.Http2ProtocolOptions{
							MaxConcurrentStreams:        wrapperspb.UInt32(100),
							InitialStreamWindowSize:     wrapperspb.UInt32(65535),
							InitialConnectionWindowSize: wrapperspb.UInt32(1048576),
						},
					}),
				},
			},
		},
	}
}

func (r *lbFrontendReconciler) desiredEnvoyListenerTLSPassthroughFilterChains(model *lbFrontend) []*envoy_config_listener_v3.FilterChain {
	tlsPassthroughFilterChains := []*envoy_config_listener_v3.FilterChain{}

	if model.applications.tlsPassthrough == nil {
		return tlsPassthroughFilterChains
	}
	for i, tr := range model.applications.tlsPassthrough.routes {
		f := &envoy_config_listener_v3.FilterChain{
			FilterChainMatch: &envoy_config_listener_v3.FilterChainMatch{
				TransportProtocol: "tls",
				ServerNames:       r.toTLSPassthroughServerNames(tr.match.hostNames),
			},
			Filters: []*envoy_config_listener_v3.Filter{
				{
					Name: "envoy.filters.network.tcp_proxy",
					ConfigType: &envoy_config_listener_v3.Filter_TypedConfig{
						TypedConfig: toAny(&envoy_tcpproxy_v3.TcpProxy{
							AccessLog:  r.desiredEnvoyTLSAccessLoggers(),
							StatPrefix: fmt.Sprintf("frontend_listener_tls_passthrough_%d", i),
							ClusterSpecifier: &envoy_tcpproxy_v3.TcpProxy_Cluster{
								Cluster: fmt.Sprintf("backend_cluster_tlspt_%d", i),
							},
						}),
					},
				},
			},
		}

		tlsPassthroughFilterChains = append(tlsPassthroughFilterChains, f)
	}

	return tlsPassthroughFilterChains
}

func (r *lbFrontendReconciler) desiredEnvoyHTTPAccessLoggers() []*envoy_accesslog_v3.AccessLog {
	var hcFilter *envoy_accesslog_v3.AccessLogFilter

	if r.config.AccessLog.ExcludeHC {
		// Exclude T1->T2 HC requests by the user-agent
		hcFilter = &envoy_accesslog_v3.AccessLogFilter{
			FilterSpecifier: &envoy_accesslog_v3.AccessLogFilter_HeaderFilter{
				HeaderFilter: &envoy_accesslog_v3.HeaderFilter{
					Header: &envoy_config_route_v3.HeaderMatcher{
						InvertMatch: true,
						Name:        "user-agent",
						HeaderMatchSpecifier: &envoy_config_route_v3.HeaderMatcher_StringMatch{
							StringMatch: &envoy_matcher_v3.StringMatcher{
								MatchPattern: &envoy_matcher_v3.StringMatcher_Prefix{
									Prefix: "cilium-probe/", // Sent by T1 HC
								},
							},
						},
					},
				},
			},
		}
	}

	return []*envoy_accesslog_v3.AccessLog{
		{
			Name:   "stdout",
			Filter: hcFilter,
			ConfigType: &envoy_accesslog_v3.AccessLog_TypedConfig{
				TypedConfig: toAny(&envoy_extensions_accessloggers_stream_v3.StdoutAccessLog{
					AccessLogFormat: &envoy_extensions_accessloggers_stream_v3.StdoutAccessLog_LogFormat{
						LogFormat: &envoy_corev3.SubstitutionFormatString{
							Format: &envoy_corev3.SubstitutionFormatString_TextFormatSource{
								TextFormatSource: &envoy_corev3.DataSource{
									Specifier: &envoy_corev3.DataSource_InlineString{
										InlineString: fmt.Sprintf("%s\n", r.config.AccessLog.FormatHTTP),
									},
								},
							},
						},
					},
				}),
			},
		},
	}
}

func (r *lbFrontendReconciler) desiredEnvoyTLSAccessLoggers() []*envoy_accesslog_v3.AccessLog {
	var hcFilter *envoy_accesslog_v3.AccessLogFilter

	return []*envoy_accesslog_v3.AccessLog{
		{
			Name:   "stdout",
			Filter: hcFilter,
			ConfigType: &envoy_accesslog_v3.AccessLog_TypedConfig{
				TypedConfig: toAny(&envoy_extensions_accessloggers_stream_v3.StdoutAccessLog{
					AccessLogFormat: &envoy_extensions_accessloggers_stream_v3.StdoutAccessLog_LogFormat{
						LogFormat: &envoy_corev3.SubstitutionFormatString{
							Format: &envoy_corev3.SubstitutionFormatString_TextFormatSource{
								TextFormatSource: &envoy_corev3.DataSource{
									Specifier: &envoy_corev3.DataSource_InlineString{
										InlineString: fmt.Sprintf("%s\n", r.config.AccessLog.FormatTLS),
									},
								},
							},
						},
					},
				}),
			},
		},
	}
}

func (r *lbFrontendReconciler) desiredEnvoyRouteConfigs(model *lbFrontend) []*envoy_config_route_v3.RouteConfiguration {
	routeConfigs := []*envoy_config_route_v3.RouteConfiguration{}

	if model.applications.isHTTPProxyConfigured() {
		httpRouteConfig := r.desiredEnvoyHttpRouteConfig(model)
		routeConfigs = append(routeConfigs, httpRouteConfig)
	}

	if model.applications.isHTTPSProxyConfigured() {
		httpsRouteConfig := r.desiredEnvoyHttpsRouteConfig(model)
		routeConfigs = append(routeConfigs, httpsRouteConfig)

	}

	return routeConfigs
}

func (r *lbFrontendReconciler) desiredEnvoyHttpRouteConfig(model *lbFrontend) *envoy_config_route_v3.RouteConfiguration {
	return &envoy_config_route_v3.RouteConfiguration{
		Name:         "frontend_routeconfig_http",
		VirtualHosts: r.desiredEnvoyHttpRouteVirtualHosts(model, "http"),
	}
}

func (r *lbFrontendReconciler) desiredEnvoyHttpRouteVirtualHosts(model *lbFrontend, httpType string) []*envoy_config_route_v3.VirtualHost {
	virtualHosts := []*envoy_config_route_v3.VirtualHost{}

	if model.applications.httpProxy == nil {
		return virtualHosts
	}

	for i, route := range model.applications.httpProxy.routes {
		virtualHosts = append(virtualHosts,
			&envoy_config_route_v3.VirtualHost{
				Name:    fmt.Sprintf("frontend_virtualhost_%s_%d", httpType, i),
				Domains: r.toHostNamesWithPort(route.match.hostNames, int32(80), model.port),
				Routes: []*envoy_config_route_v3.Route{
					{
						Match: toRouteMatch(route.match),
						Action: &envoy_config_route_v3.Route_Route{
							Route: &envoy_config_route_v3.RouteAction{
								ClusterSpecifier: &envoy_config_route_v3.RouteAction_Cluster{
									Cluster: fmt.Sprintf("backend_cluster_%s_%d", httpType, i),
								},
							},
						},
					},
				},
				RequestHeadersToRemove: []string{
					"x-envoy-internal",
					"x-envoy-external-address",
				},
				ResponseHeadersToRemove: []string{
					"x-envoy-upstream-service-time",
					"x-envoy-overloaded",
				},
			},
		)
	}

	return virtualHosts
}

func (r *lbFrontendReconciler) desiredEnvoyHttpsRouteConfig(model *lbFrontend) *envoy_config_route_v3.RouteConfiguration {
	return &envoy_config_route_v3.RouteConfiguration{
		Name:         "frontend_routeconfig_https",
		VirtualHosts: r.desiredEnvoyHttpsRouteVirtualHosts(model, "https"),
	}
}

func (r *lbFrontendReconciler) desiredEnvoyHttpsRouteVirtualHosts(model *lbFrontend, httpType string) []*envoy_config_route_v3.VirtualHost {
	virtualHosts := []*envoy_config_route_v3.VirtualHost{}

	if model.applications.httpsProxy == nil {
		return virtualHosts
	}

	for i, route := range model.applications.httpsProxy.routes {
		virtualHosts = append(virtualHosts,
			&envoy_config_route_v3.VirtualHost{
				Name:    fmt.Sprintf("frontend_virtualhost_%s_%d", httpType, i),
				Domains: r.toHostNamesWithPort(route.match.hostNames, int32(443), model.port),
				Routes: []*envoy_config_route_v3.Route{
					{
						Match: toRouteMatch(route.match),
						Action: &envoy_config_route_v3.Route_Route{
							Route: &envoy_config_route_v3.RouteAction{
								ClusterSpecifier: &envoy_config_route_v3.RouteAction_Cluster{
									Cluster: fmt.Sprintf("backend_cluster_%s_%d", httpType, i),
								},
							},
						},
					},
				},
				RequestHeadersToRemove: []string{
					"x-envoy-internal",
					"x-envoy-external-address",
				},
				ResponseHeadersToRemove: []string{
					"x-envoy-upstream-service-time",
					"x-envoy-overloaded",
				},
			},
		)
	}

	return virtualHosts
}

func toRouteMatch(match lbRouteHTTPMatch) *envoy_config_route_v3.RouteMatch {
	switch match.pathType {
	case pathTypePrefix:
		return &envoy_config_route_v3.RouteMatch{
			PathSpecifier: &envoy_config_route_v3.RouteMatch_Prefix{
				Prefix: match.path,
			},
		}
	case pathTypeExact:
		return &envoy_config_route_v3.RouteMatch{
			PathSpecifier: &envoy_config_route_v3.RouteMatch_Path{
				Path: match.path,
			},
		}

	default:
		return &envoy_config_route_v3.RouteMatch{
			PathSpecifier: &envoy_config_route_v3.RouteMatch_Prefix{
				Prefix: "/",
			},
		}
	}
}

// toHostNamesWithPort appends the port to the hostname because Envoy' domain matching on the virtualhost
// checks for port too. But only if it's different than the expected default port.
func (r *lbFrontendReconciler) toHostNamesWithPort(hostnames []string, defaultPort int32, port int32) []string {
	hostNamesWithPort := []string{}
	for _, v := range hostnames {
		if v == "*" || defaultPort == port {
			hostNamesWithPort = append(hostNamesWithPort, v)
		} else {
			hostNamesWithPort = append(hostNamesWithPort, fmt.Sprintf("%s:%d", v, port))
		}
	}

	return hostNamesWithPort
}

func desiredHealthCheckFilter(model *lbFrontend) *envoy_health_check_v3.HealthCheck {
	healthCheckFilterClusters := map[string]*envoy_typev3.Percent{}

	if model.applications.httpProxy != nil {
		for i := range model.applications.httpProxy.routes {
			healthCheckFilterClusters[fmt.Sprintf("backend_cluster_http_%d", i)] = &envoy_typev3.Percent{Value: 20}
		}
	}
	if model.applications.httpsProxy != nil {
		for i := range model.applications.httpsProxy.routes {
			healthCheckFilterClusters[fmt.Sprintf("backend_cluster_https_%d", i)] = &envoy_typev3.Percent{Value: 20}
		}
	}
	if model.applications.tlsPassthrough != nil {
		for i := range model.applications.tlsPassthrough.routes {
			healthCheckFilterClusters[fmt.Sprintf("backend_cluster_tlspt_%d", i)] = &envoy_typev3.Percent{Value: 20}
		}
	}

	healthCheckFilter := &envoy_health_check_v3.HealthCheck{
		PassThroughMode:              &wrapperspb.BoolValue{Value: false},
		ClusterMinHealthyPercentages: healthCheckFilterClusters,
		Headers: []*envoy_config_route_v3.HeaderMatcher{
			{
				Name: ":path",
				HeaderMatchSpecifier: &envoy_config_route_v3.HeaderMatcher_StringMatch{
					StringMatch: &envoy_matcher_v3.StringMatcher{
						MatchPattern: &envoy_matcher_v3.StringMatcher_Exact{
							Exact: healthCheckHttpPath,
						},
					},
				},
			},
			{
				Name: ":method",
				HeaderMatchSpecifier: &envoy_config_route_v3.HeaderMatcher_StringMatch{
					StringMatch: &envoy_matcher_v3.StringMatcher{
						MatchPattern: &envoy_matcher_v3.StringMatcher_Exact{
							Exact: healthCheckHttpMethod,
						},
					},
				},
			},
			{
				Name: "user-agent",
				HeaderMatchSpecifier: &envoy_config_route_v3.HeaderMatcher_StringMatch{
					StringMatch: &envoy_matcher_v3.StringMatcher{
						MatchPattern: &envoy_matcher_v3.StringMatcher_Prefix{
							Prefix: healthCheckHttpUserAgentPrefix,
						},
					},
				},
			},
		},
	}

	return healthCheckFilter
}

func (r *lbFrontendReconciler) desiredEnvoyClusters(model *lbFrontend) []*envoy_config_cluster_v3.Cluster {
	clusters := []*envoy_config_cluster_v3.Cluster{}

	if model.applications.httpProxy != nil {
		for i, lrh := range model.applications.httpProxy.routes {
			clusters = append(clusters, r.desiredEnvoyCluster(fmt.Sprintf("backend_cluster_http_%d", i), lrh.backend, nil, nil))
		}
	}
	if model.applications.httpsProxy != nil {
		for i, lrh := range model.applications.httpsProxy.routes {
			clusters = append(clusters, r.desiredEnvoyCluster(fmt.Sprintf("backend_cluster_https_%d", i), lrh.backend, nil, nil))
		}
	}
	if model.applications.tlsPassthrough != nil {
		for i, lrh := range model.applications.tlsPassthrough.routes {
			clusters = append(clusters, r.desiredEnvoyCluster(
				fmt.Sprintf("backend_cluster_tlspt_%d", i),
				lrh.backend,
				[]*envoy_config_cluster_v3.Cluster_TransportSocketMatch{
					{
						Name: "healthcheck_tls",
						Match: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								"type": structpb.NewStringValue("tls"),
							},
						},
						TransportSocket: &envoy_corev3.TransportSocket{
							Name: "envoy.transport_sockets.tls",
							ConfigType: &envoy_corev3.TransportSocket_TypedConfig{
								TypedConfig: toAny(&envoy_extensions_transport_sockets_tls_v3.UpstreamTlsContext{}),
							},
						},
					},
				},
				&structpb.Struct{
					Fields: map[string]*structpb.Value{
						"type": structpb.NewStringValue("tls"),
					},
				},
			))
		}
	}

	return clusters
}

func (r *lbFrontendReconciler) desiredEnvoyCluster(name string, b backend, transportSocketMatches []*envoy_config_cluster_v3.Cluster_TransportSocketMatch, hcTransportSocketMatchCriteria *structpb.Struct) *envoy_config_cluster_v3.Cluster {
	return &envoy_config_cluster_v3.Cluster{
		Name: name,
		ClusterDiscoveryType: &envoy_config_cluster_v3.Cluster_Type{
			Type: envoy_config_cluster_v3.Cluster_EDS,
		},
		CommonLbConfig: &envoy_config_cluster_v3.Cluster_CommonLbConfig{
			// disabling panic mode (https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/upstream/load_balancing/panic_threshold)
			HealthyPanicThreshold: &envoy_typev3.Percent{Value: 0.0},
		},
		ConnectTimeout:         &durationpb.Duration{Seconds: 5}, // default
		TransportSocketMatches: transportSocketMatches,
		HealthChecks:           r.toClusterHealthChecks(b.healthCheckConfig, hcTransportSocketMatchCriteria),
		LbPolicy:               mapLbPolicy(b.lbAlgorithm),
		TypedExtensionProtocolOptions: map[string]*anypb.Any{
			"envoy.extensions.upstreams.http.v3.HttpProtocolOptions": r.toClusterHTTPProtocolOptions(b.httpConfig),
		},
		PerConnectionBufferLimitBytes: wrapperspb.UInt32(32768), // 32KiB
	}
}

func (r *lbFrontendReconciler) toClusterHTTPProtocolOptions(httpConfig lbBackendHTTPConfig) *anypb.Any {
	switch {
	case httpConfig.enableHTTP11 && !httpConfig.enableHTTP2:
		return toAny(&envoy_extensions_upstreams_http_v3.HttpProtocolOptions{
			UpstreamProtocolOptions: &envoy_extensions_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig_{
				ExplicitHttpConfig: &envoy_extensions_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig{
					ProtocolConfig: &envoy_extensions_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig_HttpProtocolOptions{},
				},
			},
		})
	case httpConfig.enableHTTP2 && !httpConfig.enableHTTP11:
		return toAny(&envoy_extensions_upstreams_http_v3.HttpProtocolOptions{
			UpstreamProtocolOptions: &envoy_extensions_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig_{
				ExplicitHttpConfig: &envoy_extensions_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig{
					ProtocolConfig: &envoy_extensions_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig_Http2ProtocolOptions{},
				},
			},
		})
	default:
		// use HTTP1.1 if both protocol versions are enabled.
		// The reason is to prevent HTTP/2 issues due to backends that don't support H2C (HTTP2 without TLS).
		// Note: Once we support TLS re-encryption to the backend we can enable AutoConfig to make use of ALPN protocol negotiation.
		return toAny(&envoy_extensions_upstreams_http_v3.HttpProtocolOptions{
			UpstreamProtocolOptions: &envoy_extensions_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig_{
				ExplicitHttpConfig: &envoy_extensions_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig{
					ProtocolConfig: &envoy_extensions_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig_HttpProtocolOptions{},
				},
			},
		})
	}
}

func (r *lbFrontendReconciler) toClusterHealthChecks(healthCheckConfig lbBackendHealthCheckConfig, hcTransportSocketMatchCriteria *structpb.Struct) []*envoy_corev3.HealthCheck {
	healthCheck := &envoy_corev3.HealthCheck{
		Interval:                     &durationpb.Duration{Seconds: int64(healthCheckConfig.intervalSeconds)},
		UnhealthyInterval:            &durationpb.Duration{Seconds: int64(healthCheckConfig.unhealthyIntervalSeconds)},
		UnhealthyEdgeInterval:        &durationpb.Duration{Seconds: int64(healthCheckConfig.unhealthyEdgeIntervalSeconds)},
		NoTrafficInterval:            &durationpb.Duration{Seconds: int64(healthCheckConfig.unhealthyEdgeIntervalSeconds)},
		Timeout:                      &durationpb.Duration{Seconds: int64(healthCheckConfig.timeoutSeconds)},
		HealthyThreshold:             &wrapperspb.UInt32Value{Value: uint32(healthCheckConfig.healthyThreshold)},
		UnhealthyThreshold:           &wrapperspb.UInt32Value{Value: uint32(healthCheckConfig.unhealthyThreshold)},
		TransportSocketMatchCriteria: hcTransportSocketMatchCriteria,
	}

	switch {
	case healthCheckConfig.http != nil:
		healthCheck.HealthChecker = r.toClusterHealthCheckerHTTP(healthCheckConfig)
	case healthCheckConfig.tcp != nil:
		healthCheck.HealthChecker = r.toClusterHealthCheckerTCP(healthCheckConfig)
	default:
		return nil
	}
	return []*envoy_corev3.HealthCheck{
		healthCheck,
	}
}

func (r *lbFrontendReconciler) toClusterHealthCheckerHTTP(healthCheckConfig lbBackendHealthCheckConfig) *envoy_corev3.HealthCheck_HttpHealthCheck_ {
	return &envoy_corev3.HealthCheck_HttpHealthCheck_{
		HttpHealthCheck: &envoy_corev3.HealthCheck_HttpHealthCheck{
			Host: healthCheckConfig.http.host,
			Path: healthCheckConfig.http.path,
		},
	}
}

func (r *lbFrontendReconciler) toClusterHealthCheckerTCP(_ lbBackendHealthCheckConfig) *envoy_corev3.HealthCheck_TcpHealthCheck_ {
	return &envoy_corev3.HealthCheck_TcpHealthCheck_{
		TcpHealthCheck: &envoy_corev3.HealthCheck_TcpHealthCheck{},
	}
}

func (r *lbFrontendReconciler) desiredEnvoyEndpoints(model *lbFrontend) []*envoy_config_endpoint_v3.ClusterLoadAssignment {
	endpoints := []*envoy_config_endpoint_v3.ClusterLoadAssignment{}

	if model.applications.httpProxy != nil {
		for i, lrh := range model.applications.httpProxy.routes {
			endpoints = append(endpoints, r.desiredEnvoyEndpoint(fmt.Sprintf("backend_cluster_http_%d", i), lrh.backend))
		}
	}
	if model.applications.httpsProxy != nil {
		for i, lrh := range model.applications.httpsProxy.routes {
			endpoints = append(endpoints, r.desiredEnvoyEndpoint(fmt.Sprintf("backend_cluster_https_%d", i), lrh.backend))
		}
	}
	if model.applications.tlsPassthrough != nil {
		for i, lrh := range model.applications.tlsPassthrough.routes {
			endpoints = append(endpoints, r.desiredEnvoyEndpoint(fmt.Sprintf("backend_cluster_tlspt_%d", i), lrh.backend))
		}
	}

	return endpoints
}

func (r *lbFrontendReconciler) desiredEnvoyEndpoint(name string, b backend) *envoy_config_endpoint_v3.ClusterLoadAssignment {
	lbEndpoints := make([]*envoy_config_endpoint_v3.LbEndpoint, 0, len(b.ips))

	for _, ipBackends := range b.ips {
		lbEndpoints = append(lbEndpoints, &envoy_config_endpoint_v3.LbEndpoint{
			HostIdentifier: &envoy_config_endpoint_v3.LbEndpoint_Endpoint{Endpoint: &envoy_config_endpoint_v3.Endpoint{
				Address: &envoy_corev3.Address{Address: &envoy_corev3.Address_SocketAddress{SocketAddress: &envoy_corev3.SocketAddress{
					Address:       ipBackends.address,
					PortSpecifier: &envoy_corev3.SocketAddress_PortValue{PortValue: uint32(ipBackends.port)},
				}}},
			}},
		})
	}

	return &envoy_config_endpoint_v3.ClusterLoadAssignment{
		ClusterName: name,
		Endpoints: []*envoy_config_endpoint_v3.LocalityLbEndpoints{
			{
				LbEndpoints: lbEndpoints,
			},
		},
	}
}

func (r *lbFrontendReconciler) ensureCECDeleted(ctx context.Context, model *lbFrontend) error {
	cec := &ciliumv2.CiliumEnvoyConfig{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: model.namespace,
			Name:      model.getOwningResourceName(),
		},
	}
	if err := r.client.Delete(ctx, cec); err != nil {
		if !k8serrors.IsNotFound(err) {
			return err
		}
		// CEC does not exist, which is fine
	}
	return nil
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
