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
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	cilium_proxy_api "github.com/cilium/proxy/go/cilium/api"
	envoy_config_accesslog_v3 "github.com/cilium/proxy/go/envoy/config/accesslog/v3"
	envoy_config_cluster_v3 "github.com/cilium/proxy/go/envoy/config/cluster/v3"
	envoy_config_core_v3 "github.com/cilium/proxy/go/envoy/config/core/v3"
	envoy_config_endpoint_v3 "github.com/cilium/proxy/go/envoy/config/endpoint/v3"
	envoy_config_listener_v3 "github.com/cilium/proxy/go/envoy/config/listener/v3"
	envoy_config_rbac_v3 "github.com/cilium/proxy/go/envoy/config/rbac/v3"
	envoy_config_route_v3 "github.com/cilium/proxy/go/envoy/config/route/v3"
	envoy_extensions_accessloggers_file_v3 "github.com/cilium/proxy/go/envoy/extensions/access_loggers/file/v3"
	envoy_extensions_accessloggers_stream_v3 "github.com/cilium/proxy/go/envoy/extensions/access_loggers/stream/v3"
	envoy_extensions_filters_http_basic_auth_v3 "github.com/cilium/proxy/go/envoy/extensions/filters/http/basic_auth/v3"
	envoy_extensions_filters_http_healthcheck_v3 "github.com/cilium/proxy/go/envoy/extensions/filters/http/health_check/v3"
	envoy_extensions_filters_http_jwt_authn_v3 "github.com/cilium/proxy/go/envoy/extensions/filters/http/jwt_authn/v3"
	envoy_extensions_filters_http_localratelimit_v3 "github.com/cilium/proxy/go/envoy/extensions/filters/http/local_ratelimit/v3"
	envoy_extensions_filters_http_rbac_v3 "github.com/cilium/proxy/go/envoy/extensions/filters/http/rbac/v3"
	envoy_extensions_filters_http_router_v3 "github.com/cilium/proxy/go/envoy/extensions/filters/http/router/v3"
	envoy_extensions_filters_listener_proxy_protocol_v3 "github.com/cilium/proxy/go/envoy/extensions/filters/listener/proxy_protocol/v3"
	envoy_extensions_filters_listener_tlsinspector_v3 "github.com/cilium/proxy/go/envoy/extensions/filters/listener/tls_inspector/v3"
	envoy_extensions_filters_network_hcm_v3 "github.com/cilium/proxy/go/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_extensions_filters_network_localratelimit_v3 "github.com/cilium/proxy/go/envoy/extensions/filters/network/local_ratelimit/v3"
	envoy_extensions_filters_network_rbac_v3 "github.com/cilium/proxy/go/envoy/extensions/filters/network/rbac/v3"
	envoy_extensions_filters_network_tcpproxy_v3 "github.com/cilium/proxy/go/envoy/extensions/filters/network/tcp_proxy/v3"
	envoy_extensions_network_dns_resolver_cares_v3 "github.com/cilium/proxy/go/envoy/extensions/network/dns_resolver/cares/v3"
	envoy_extensions_transportsockets_proxy_protocol_v3 "github.com/cilium/proxy/go/envoy/extensions/transport_sockets/proxy_protocol/v3"
	envoy_extensions_transportsockets_rawbuffer_v3 "github.com/cilium/proxy/go/envoy/extensions/transport_sockets/raw_buffer/v3"
	envoy_extensions_transportsockets_tls_v3 "github.com/cilium/proxy/go/envoy/extensions/transport_sockets/tls/v3"
	envoy_extensions_upstreams_http_v3 "github.com/cilium/proxy/go/envoy/extensions/upstreams/http/v3"
	envoy_type_matcher_v3 "github.com/cilium/proxy/go/envoy/type/matcher/v3"
	envoy_type_v3 "github.com/cilium/proxy/go/envoy/type/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	ossannotation "github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/envoy"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	httpTypeHTTP  = "http"
	httpTypeHTTPS = "https"
)

type lbServiceT2Translator struct {
	logger *slog.Logger
	config reconcilerConfig
}

func (r *lbServiceT2Translator) DesiredCiliumEnvoyConfig(model *lbService) (*ciliumv2.CiliumEnvoyConfig, error) {
	if model.vip.assignedIPv4 == nil || !model.vip.bindStatus.serviceExists || !model.vip.bindStatus.bindSuccessful || model.isTCPProxyT1OnlyMode() || model.isUDPProxyT1OnlyMode() {
		return nil, nil
	}

	envoyResources := []ciliumv2.XDSResource{}

	// Service (with route(s)) -> Envoy Listener & Route(s)

	listener := r.desiredEnvoyListener(model)

	listenerXdsResource, err := r.toXdsResource(listener, envoy.ListenerTypeURL)
	if err != nil {
		return nil, err
	}

	envoyResources = append(envoyResources, listenerXdsResource)

	routeConfigs := r.desiredEnvoyRouteConfigs(model)

	for _, rc := range routeConfigs {
		routeConfigXdsResource, err := r.toXdsResource(rc, envoy.RouteTypeURL)
		if err != nil {
			return nil, err
		}

		envoyResources = append(envoyResources, routeConfigXdsResource)
	}

	// Backend(s)-> Envoy Cluster(s) & Envoy Endpoints (ClusterLoadAssignments)

	clusters := r.desiredEnvoyClusters(model)

	for _, c := range clusters {
		clusterXdsResource, err := r.toXdsResource(c, envoy.ClusterTypeURL)
		if err != nil {
			return nil, err
		}

		envoyResources = append(envoyResources, clusterXdsResource)
	}

	loadAssignments := r.desiredEnvoyClusterLoadAssignments(model)

	for _, la := range loadAssignments {
		endpointXdsResource, err := r.toXdsResource(la, envoy.EndpointTypeURL)
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
					ossannotation.ServiceNodeExposure: lbNodeTypeT2,
				},
			},
			Resources: envoyResources,
		},
	}, nil
}

func (r *lbServiceT2Translator) desiredEnvoyListener(model *lbService) *envoy_config_listener_v3.Listener {
	var accessLoggers []*envoy_config_accesslog_v3.AccessLog

	if r.config.AccessLog.EnableTCP {
		accessLoggers = r.desiredEnvoyAccessLoggers(r.config.AccessLog.FormatTCP, r.config.AccessLog.JSONFormatTCP)
	}

	return &envoy_config_listener_v3.Listener{
		Name: "frontend_listener",
		Address: &envoy_config_core_v3.Address{
			Address: &envoy_config_core_v3.Address_SocketAddress{
				SocketAddress: &envoy_config_core_v3.SocketAddress{
					Address: *model.vip.assignedIPv4,
					PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{
						PortValue: uint32(model.port),
					},
				},
			},
		},
		ListenerFilters:               r.desiredEnvoyListenerFilters(model),
		FilterChains:                  r.desiredEnvoyListenerFilterChains(model),
		AccessLog:                     accessLoggers,
		PerConnectionBufferLimitBytes: wrapperspb.UInt32(32768), // 32KiB
		StatPrefix:                    fmt.Sprintf("%s_%s", model.namespace, model.name),
	}
}

func (r *lbServiceT2Translator) desiredEnvoyListenerFilters(model *lbService) []*envoy_config_listener_v3.ListenerFilter {
	listenerFilters := []*envoy_config_listener_v3.ListenerFilter{}

	listenerFilters = append(listenerFilters, &envoy_config_listener_v3.ListenerFilter{
		Name: "envoy.filters.listener.tls_inspector",
		ConfigType: &envoy_config_listener_v3.ListenerFilter_TypedConfig{
			TypedConfig: toAny(&envoy_extensions_filters_listener_tlsinspector_v3.TlsInspector{}),
		},
	})

	if model.proxyProtocolConfig != nil {
		// Without this filter, Envoy will not be able to parse the Proxy Protocol header
		// and return protocol error
		// Sample error log:
		// 	- application log: http/1.1 protocol error: INVALID_HEADER_NAME_CHARACTER
		//  - access log: http.resp.code.details="http1.codec_error"  response.flags="DPE" response.flags-long="DownstreamProtocolError"
		listenerFilters = append(listenerFilters, &envoy_config_listener_v3.ListenerFilter{
			Name: "envoy.filters.listener.proxy_protocol",
			ConfigType: &envoy_config_listener_v3.ListenerFilter_TypedConfig{
				TypedConfig: toAny(r.toProxyProtocolConfig(model.proxyProtocolConfig)),
			},
		})
	}

	// Explicit configuration of Cilium's BPF Metadata Listener Filter with BPF map lookups
	// disabled. This prevents the CiliumEnvoyConfig parse logic to inject the default one that
	// comes with BPF map lookups enabled.
	listenerFilters = append(listenerFilters, &envoy_config_listener_v3.ListenerFilter{
		Name: "cilium.bpf_metadata",
		ConfigType: &envoy_config_listener_v3.ListenerFilter_TypedConfig{
			TypedConfig: toAny(&cilium_proxy_api.BpfMetadata{
				BpfRoot: "", // disable actual BPF map lookup (no policy enforcement and hubble flows either)
			}),
		},
	})

	return listenerFilters
}

func (r *lbServiceT2Translator) toProxyProtocolConfig(proxyProtocolConfig *lbServiceProxyProtocolConfig) *envoy_extensions_filters_listener_proxy_protocol_v3.ProxyProtocol {
	if proxyProtocolConfig == nil {
		return nil
	}

	var disallowedVersions []envoy_config_core_v3.ProxyProtocolConfig_Version
	for _, v := range proxyProtocolConfig.disallowedVersions {
		switch v {
		case proxyProtocolVersionV1:
			disallowedVersions = append(disallowedVersions, envoy_config_core_v3.ProxyProtocolConfig_V1)
		case proxyProtocolVersionV2:
			disallowedVersions = append(disallowedVersions, envoy_config_core_v3.ProxyProtocolConfig_V2)
		}
	}

	return &envoy_extensions_filters_listener_proxy_protocol_v3.ProxyProtocol{
		// This is to make sure that the listener will not be rejected other kinds of traffic
		AllowRequestsWithoutProxyProtocol: true,
		DisallowedVersions:                disallowedVersions,
		PassThroughTlvs: &envoy_config_core_v3.ProxyProtocolPassThroughTLVs{
			TlvType: proxyProtocolConfig.passThroughTLVs,
		},
	}
}

func (r *lbServiceT2Translator) desiredEnvoyListenerFilterChains(model *lbService) []*envoy_config_listener_v3.FilterChain {
	filterChains := []*envoy_config_listener_v3.FilterChain{}

	healthCheckFilterChain := r.desiredEnvoyListenerHealthCheckHttpFilterChain(model)
	filterChains = append(filterChains, healthCheckFilterChain)

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

	if model.applications.isTLSProxyConfigured() {
		tlsProxyFilterChains := r.desiredEnvoyListenerTLSProxyFilterChains(model)
		filterChains = append(filterChains, tlsProxyFilterChains...)
	}

	return filterChains
}

func (r *lbServiceT2Translator) desiredEnvoyListenerHealthCheckHttpFilterChain(model *lbService) *envoy_config_listener_v3.FilterChain {
	networkFilters := []*envoy_config_listener_v3.Filter{}

	networkFilters = append(networkFilters, &envoy_config_listener_v3.Filter{
		Name: "envoy.filters.network.http_connection_manager",
		ConfigType: &envoy_config_listener_v3.Filter_TypedConfig{
			TypedConfig: toAny(r.desiredEnvoyListenerHealthCheckHTTPHCM(model)),
		},
	})

	return &envoy_config_listener_v3.FilterChain{
		FilterChainMatch: &envoy_config_listener_v3.FilterChainMatch{
			TransportProtocol:        "raw_buffer",
			DirectSourcePrefixRanges: r.t1NodeCIDRRanges(model),
		},
		Filters: networkFilters,
	}
}

func (r *lbServiceT2Translator) t1NodeCIDRRanges(model *lbService) []*envoy_config_core_v3.CidrRange {
	t1NodeCIDRs := []*envoy_config_core_v3.CidrRange{}
	for _, t1NodeIP := range model.t1NodeIPs {
		t1NodeCIDRs = append(t1NodeCIDRs, &envoy_config_core_v3.CidrRange{
			AddressPrefix: t1NodeIP,
			PrefixLen:     wrapperspb.UInt32(32),
		})
	}

	return t1NodeCIDRs
}

func (r *lbServiceT2Translator) desiredEnvoyListenerHttpFilterChain(model *lbService) *envoy_config_listener_v3.FilterChain {
	networkFilters := []*envoy_config_listener_v3.Filter{}

	if model.applications.getHTTPConnectionFiltering() != nil {
		networkFilters = append(networkFilters, &envoy_config_listener_v3.Filter{
			Name: "envoy.filters.network.rbac",
			ConfigType: &envoy_config_listener_v3.Filter_TypedConfig{
				TypedConfig: toAny(r.toHTTPNetworkRBACFilter(model.applications.getHTTPConnectionFiltering(), model.t1NodeIPs, httpTypeHTTP, model.namespace, model.name)),
			},
		})
	}

	if model.applications.getHTTPConnectionRateLimits() != nil {
		networkFilters = append(networkFilters, &envoy_config_listener_v3.Filter{
			Name: "envoy.filters.network.local_ratelimit",
			ConfigType: &envoy_config_listener_v3.Filter_TypedConfig{
				TypedConfig: toAny(r.toNetworkRateLimitFilter(model.applications.getHTTPConnectionRateLimits(), model.namespace, model.name)),
			},
		})
	}

	networkFilters = append(networkFilters, &envoy_config_listener_v3.Filter{
		Name: "envoy.filters.network.http_connection_manager",
		ConfigType: &envoy_config_listener_v3.Filter_TypedConfig{
			TypedConfig: toAny(r.desiredEnvoyListenerHTTPHCM(model)),
		},
	})

	return &envoy_config_listener_v3.FilterChain{
		FilterChainMatch: &envoy_config_listener_v3.FilterChainMatch{
			TransportProtocol: "raw_buffer",
		},
		Filters: networkFilters,
	}
}

func (r *lbServiceT2Translator) desiredEnvoyListenerHealthCheckHTTPHCM(model *lbService) *envoy_extensions_filters_network_hcm_v3.HttpConnectionManager {
	var accessLoggers []*envoy_config_accesslog_v3.AccessLog

	if r.config.AccessLog.EnableHC {
		accessLoggers = r.desiredEnvoyAccessLoggers(r.config.AccessLog.FormatHC, r.config.AccessLog.JSONFormatHC)
	}

	return &envoy_extensions_filters_network_hcm_v3.HttpConnectionManager{
		ServerName:                   r.config.ServerName,
		AccessLog:                    accessLoggers,
		GenerateRequestId:            wrapperspb.Bool(true),
		PreserveExternalRequestId:    false,
		AlwaysSetRequestIdInResponse: false,
		StatPrefix:                   fmt.Sprintf("healthcheck_http_%s_%s", model.namespace, model.name),
		CodecType:                    envoy_extensions_filters_network_hcm_v3.HttpConnectionManager_AUTO,
		NormalizePath:                wrapperspb.Bool(true),
		MergeSlashes:                 true,
		UseRemoteAddress:             wrapperspb.Bool(r.config.OriginalIPDetection.UseRemoteAddress),
		XffNumTrustedHops:            uint32(r.config.OriginalIPDetection.XffNumTrustedHops),
		StripMatchingHostPort:        true,
		HttpFilters:                  r.desiredEnvoyListenerHealthCheckHttpHTTPFilters(model),
		RouteSpecifier:               &envoy_extensions_filters_network_hcm_v3.HttpConnectionManager_RouteConfig{}, // no routes - but specifier required
		CommonHttpProtocolOptions: &envoy_config_core_v3.HttpProtocolOptions{
			HeadersWithUnderscoresAction: envoy_config_core_v3.HttpProtocolOptions_REJECT_REQUEST,
			MaxConnectionDuration:        durationpb.New(time.Hour),
		},
		Http2ProtocolOptions: &envoy_config_core_v3.Http2ProtocolOptions{
			MaxConcurrentStreams:        wrapperspb.UInt32(100),
			InitialStreamWindowSize:     wrapperspb.UInt32(65535),
			InitialConnectionWindowSize: wrapperspb.UInt32(1048576),
		},
	}
}

func (r *lbServiceT2Translator) desiredEnvoyListenerHTTPHCM(model *lbService) *envoy_extensions_filters_network_hcm_v3.HttpConnectionManager {
	return &envoy_extensions_filters_network_hcm_v3.HttpConnectionManager{
		ServerName:                   r.config.ServerName,
		AccessLog:                    r.desiredEnvoyAccessLoggers(r.config.AccessLog.FormatHTTP, r.config.AccessLog.JSONFormatHTTP),
		GenerateRequestId:            wrapperspb.Bool(r.config.RequestID.Generate),
		PreserveExternalRequestId:    r.config.RequestID.Preserve,
		AlwaysSetRequestIdInResponse: r.config.RequestID.Response,
		StatPrefix:                   fmt.Sprintf("http_%s_%s", model.namespace, model.name),
		CodecType:                    r.toCodecType(model.applications.getHTTPHTTPConfig()),
		NormalizePath:                wrapperspb.Bool(true),
		MergeSlashes:                 true,
		UseRemoteAddress:             wrapperspb.Bool(r.config.OriginalIPDetection.UseRemoteAddress),
		XffNumTrustedHops:            uint32(r.config.OriginalIPDetection.XffNumTrustedHops),
		StripMatchingHostPort:        true,
		HttpFilters:                  r.desiredEnvoyListenerHttpHTTPFilters(model),
		RouteSpecifier: &envoy_extensions_filters_network_hcm_v3.HttpConnectionManager_Rds{
			Rds: &envoy_extensions_filters_network_hcm_v3.Rds{
				RouteConfigName: "frontend_routeconfig_http",
			},
		},
		CommonHttpProtocolOptions: &envoy_config_core_v3.HttpProtocolOptions{
			HeadersWithUnderscoresAction: envoy_config_core_v3.HttpProtocolOptions_REJECT_REQUEST,
			MaxConnectionDuration:        durationpb.New(time.Hour),
		},
		Http2ProtocolOptions: &envoy_config_core_v3.Http2ProtocolOptions{
			MaxConcurrentStreams:        wrapperspb.UInt32(100),
			InitialStreamWindowSize:     wrapperspb.UInt32(65535),
			InitialConnectionWindowSize: wrapperspb.UInt32(1048576),
		},
	}
}

func (r *lbServiceT2Translator) desiredEnvoyListenerHealthCheckHttpHTTPFilters(model *lbService) []*envoy_extensions_filters_network_hcm_v3.HttpFilter {
	httpFilters := []*envoy_extensions_filters_network_hcm_v3.HttpFilter{}

	httpFilters = append(httpFilters, &envoy_extensions_filters_network_hcm_v3.HttpFilter{
		Name: "envoy.filters.http.health_check",
		ConfigType: &envoy_extensions_filters_network_hcm_v3.HttpFilter_TypedConfig{
			TypedConfig: toAny(r.desiredHealthCheckFilter(model)),
		},
	})

	// adding router as required terminal filter - even though it's not used in case of health checking (no passthrough mode)
	httpFilters = append(httpFilters, &envoy_extensions_filters_network_hcm_v3.HttpFilter{
		Name: "envoy.filters.http.router",
		ConfigType: &envoy_extensions_filters_network_hcm_v3.HttpFilter_TypedConfig{
			TypedConfig: toAny(r.desiredEnvoyRouterFilter()),
		},
	})

	return httpFilters
}

func (r *lbServiceT2Translator) desiredEnvoyListenerHttpHTTPFilters(model *lbService) []*envoy_extensions_filters_network_hcm_v3.HttpFilter {
	httpFilters := []*envoy_extensions_filters_network_hcm_v3.HttpFilter{}

	if model.usesHTTPRequestFiltering() {
		// Only add the RBAC filter if there's at least one route that is using request filtering.
		// The RBAC filter on the HCM provides support for overriding it per route
		httpFilters = append(httpFilters, &envoy_extensions_filters_network_hcm_v3.HttpFilter{
			Name: "envoy.filters.http.rbac",
			ConfigType: &envoy_extensions_filters_network_hcm_v3.HttpFilter_TypedConfig{
				TypedConfig: toAny(&envoy_extensions_filters_http_rbac_v3.RBAC{}),
			},
		})
	}

	if model.usesHTTPRequestRateLimiting() {
		// Only add the LocalRateLimit filter if there's at least one route that is using request rate limiting.
		// The filter on the HCM provides support for overriding it per route
		httpFilters = append(httpFilters, &envoy_extensions_filters_network_hcm_v3.HttpFilter{
			Name: "envoy.filters.http.local_ratelimit",
			ConfigType: &envoy_extensions_filters_network_hcm_v3.HttpFilter_TypedConfig{
				TypedConfig: toAny(&envoy_extensions_filters_http_localratelimit_v3.LocalRateLimit{
					StatPrefix: fmt.Sprintf("%s_%s", model.namespace, model.name), // required attribute
				}),
			},
		})
	}

	if model.usesHTTPBasicAuth() {
		httpFilters = append(httpFilters, &envoy_extensions_filters_network_hcm_v3.HttpFilter{
			Name: "envoy.filters.http.basic_auth",
			ConfigType: &envoy_extensions_filters_network_hcm_v3.HttpFilter_TypedConfig{
				TypedConfig: toAny(&envoy_extensions_filters_http_basic_auth_v3.BasicAuth{
					Users: &envoy_config_core_v3.DataSource{
						Specifier: &envoy_config_core_v3.DataSource_InlineString{
							InlineString: r.toHTPasswdString(model.applications.httpProxy.auth.basicAuth),
						},
					},
				}),
			},
		})
	}

	if model.usesHTTPJWTAuth() {
		httpFilters = append(httpFilters, &envoy_extensions_filters_network_hcm_v3.HttpFilter{
			Name: "envoy.filters.http.jwt_authn",
			ConfigType: &envoy_extensions_filters_network_hcm_v3.HttpFilter_TypedConfig{
				TypedConfig: toAny(r.toJWTAuthentication(model.namespace, model.name, httpTypeHTTP, model.applications.httpProxy.auth.jwtAuth)),
			},
		})
	}

	httpFilters = append(httpFilters, &envoy_extensions_filters_network_hcm_v3.HttpFilter{
		Name: "envoy.filters.http.router",
		ConfigType: &envoy_extensions_filters_network_hcm_v3.HttpFilter_TypedConfig{
			TypedConfig: toAny(r.desiredEnvoyRouterFilter()),
		},
	})

	return httpFilters
}

func (r *lbServiceT2Translator) toJWTAuthentication(namespace, name, httpType string, auth *lbServiceHTTPJWTAuth) *envoy_extensions_filters_http_jwt_authn_v3.JwtAuthentication {
	providers := map[string]*envoy_extensions_filters_http_jwt_authn_v3.JwtProvider{}
	providerNameRequirements := []*envoy_extensions_filters_http_jwt_authn_v3.JwtRequirement{}
	for _, provider := range auth.providers {
		p := &envoy_extensions_filters_http_jwt_authn_v3.JwtProvider{
			// Forward JWT. The backend application suppose to use
			// JWT for their application specific logic.
			Forward: true,
		}

		if provider.issuer != nil {
			p.Issuer = *provider.issuer
		}

		if len(provider.audiences) != 0 {
			p.Audiences = provider.audiences
		}

		if provider.localJWKS != nil {
			p.JwksSourceSpecifier = &envoy_extensions_filters_http_jwt_authn_v3.JwtProvider_LocalJwks{
				LocalJwks: &envoy_config_core_v3.DataSource{
					Specifier: &envoy_config_core_v3.DataSource_InlineString{
						InlineString: provider.localJWKS.jwksStr,
					},
				},
			}
		}

		if provider.remoteJWKS != nil {
			p.JwksSourceSpecifier = &envoy_extensions_filters_http_jwt_authn_v3.JwtProvider_RemoteJwks{
				RemoteJwks: &envoy_extensions_filters_http_jwt_authn_v3.RemoteJwks{
					HttpUri: &envoy_config_core_v3.HttpUri{
						Uri: provider.remoteJWKS.httpURI,
						HttpUpstreamType: &envoy_config_core_v3.HttpUri_Cluster{
							Cluster: r.jwksClusterNameQualified(namespace, name, httpType, provider.name),
						},
						// The long-enough timeout to fetch the JWKS from the remote store.
						// We can make this configurable as needed.
						Timeout: &durationpb.Duration{Seconds: 3},
					},
				},
			}
		}

		providers[provider.name] = p

		providerNameRequirements = append(providerNameRequirements, &envoy_extensions_filters_http_jwt_authn_v3.JwtRequirement{
			RequiresType: &envoy_extensions_filters_http_jwt_authn_v3.JwtRequirement_ProviderName{
				ProviderName: provider.name,
			},
		})
	}

	var requirement *envoy_extensions_filters_http_jwt_authn_v3.JwtRequirement
	if len(providerNameRequirements) == 1 {
		// Envoy rejects the RequirementAny with a single entry. We
		// need to handle this case separately.
		requirement = providerNameRequirements[0]
	} else {
		requirement = &envoy_extensions_filters_http_jwt_authn_v3.JwtRequirement{
			RequiresType: &envoy_extensions_filters_http_jwt_authn_v3.JwtRequirement_RequiresAny{
				RequiresAny: &envoy_extensions_filters_http_jwt_authn_v3.JwtRequirementOrList{
					Requirements: providerNameRequirements,
				},
			},
		}
	}

	return &envoy_extensions_filters_http_jwt_authn_v3.JwtAuthentication{
		Providers: providers,

		// Accept the requiest if any of the provider matches.
		Rules: []*envoy_extensions_filters_http_jwt_authn_v3.RequirementRule{
			{
				Match: &envoy_config_route_v3.RouteMatch{
					PathSpecifier: &envoy_config_route_v3.RouteMatch_Prefix{
						Prefix: "/",
					},
				},
				RequirementType: &envoy_extensions_filters_http_jwt_authn_v3.RequirementRule_Requires{
					Requires: requirement,
				},
			},
		},
	}
}

// Cilium appends namespace/name to the original Cluster name. However, the
// properties that refers the Cluster doesn't know about it.
func (r *lbServiceT2Translator) jwksClusterNameQualified(namespace, name, httpType, providerName string) string {
	return fmt.Sprintf("%s/%s/jwks_cluster_%s_%s", namespace, getOwningResourceName(name), httpType, providerName)
}

func (r *lbServiceT2Translator) jwksClusterName(httpType, providerName string) string {
	return fmt.Sprintf("jwks_cluster_%s_%s", httpType, providerName)
}

func (r *lbServiceT2Translator) toHTPasswdString(auth *lbServiceHTTPBasicAuth) string {
	htpasswd := ""
	for _, up := range auth.users {
		// Envoy only supports SHA1 hashed passwords as of today.
		hashed := sha1.Sum([]byte(up.password))
		b64Encoded := base64.StdEncoding.EncodeToString(hashed[:])
		htpasswd += fmt.Sprintf("%s:{SHA}%s\n", up.username, b64Encoded)
	}
	return htpasswd
}

func (r *lbServiceT2Translator) toHTTPSServerNames(model *lbService) []string {
	// get all HTTPS hostnames
	httpsDomainNames := []string{}

	if model.applications.httpsProxy != nil {
		httpsDomainNames = append(httpsDomainNames, slices.Collect(maps.Keys(model.applications.httpsProxy.routes))...)
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

func (r *lbServiceT2Translator) toCodecType(httpConfig *lbServiceHTTPConfig) envoy_extensions_filters_network_hcm_v3.HttpConnectionManager_CodecType {
	if httpConfig == nil {
		return envoy_extensions_filters_network_hcm_v3.HttpConnectionManager_AUTO
	}

	if httpConfig.enableHTTP11 && !httpConfig.enableHTTP2 {
		return envoy_extensions_filters_network_hcm_v3.HttpConnectionManager_HTTP1
	}

	if httpConfig.enableHTTP2 && !httpConfig.enableHTTP11 {
		return envoy_extensions_filters_network_hcm_v3.HttpConnectionManager_HTTP2
	}

	return envoy_extensions_filters_network_hcm_v3.HttpConnectionManager_AUTO
}

func (r *lbServiceT2Translator) toAlpnProtocols(model *lbService) []string {
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

func (r *lbServiceT2Translator) toListenerTLSParams(model *lbServiceTLSConfig) *envoy_extensions_transportsockets_tls_v3.TlsParameters {
	if model == nil {
		return nil
	}

	return &envoy_extensions_transportsockets_tls_v3.TlsParameters{
		TlsMinimumProtocolVersion: r.toTLSVersion(model.minTLSVersion),
		TlsMaximumProtocolVersion: r.toTLSVersion(model.maxTLSVersion),
		CipherSuites:              model.allowedCipherSuites,
		EcdhCurves:                model.allowedECDHCurves,
		SignatureAlgorithms:       model.allowedSignatureAlgorithms,
	}
}

func (r *lbServiceT2Translator) toClusterTLSParams(tlsConfig *lbBackendTLSConfig) *envoy_extensions_transportsockets_tls_v3.TlsParameters {
	return &envoy_extensions_transportsockets_tls_v3.TlsParameters{
		TlsMinimumProtocolVersion: r.toTLSVersion(tlsConfig.minTLSVersion),
		TlsMaximumProtocolVersion: r.toTLSVersion(tlsConfig.maxTLSVersion),
		CipherSuites:              tlsConfig.allowedCipherSuites,
		EcdhCurves:                tlsConfig.allowedECDHCurves,
		SignatureAlgorithms:       tlsConfig.allowedSignatureAlgorithms,
	}
}

func (r *lbServiceT2Translator) toTLSVersion(version string) envoy_extensions_transportsockets_tls_v3.TlsParameters_TlsProtocol {
	return envoy_extensions_transportsockets_tls_v3.TlsParameters_TlsProtocol(envoy_extensions_transportsockets_tls_v3.TlsParameters_TlsProtocol_value[version])
}

func (r *lbServiceT2Translator) toTLSServerNames(tlsHostNames []string) []string {
	// remove duplicates and raw '*' that is not allowed by Envoy
	serverNames := []string{}
	for _, dn := range tlsHostNames {
		if dn == "*" {
			continue
		}

		serverNames = append(serverNames, dn)
	}

	slices.Sort(serverNames)
	return slices.Compact(serverNames)
}

func (r *lbServiceT2Translator) toTLSCertificateSdsConfigs(namespace string, tlsConfig *lbServiceTLSConfig) []*envoy_extensions_transportsockets_tls_v3.SdsSecretConfig {
	if tlsConfig == nil {
		return nil
	}

	secrets := []*envoy_extensions_transportsockets_tls_v3.SdsSecretConfig{}

	for _, cs := range tlsConfig.certificateSecrets {
		secrets = append(secrets, &envoy_extensions_transportsockets_tls_v3.SdsSecretConfig{
			Name: fmt.Sprintf("%s/%s-%s", r.config.SecretsNamespace, namespace, cs),
		})
	}

	return secrets
}

func (r *lbServiceT2Translator) toTLSValidationContext(namespace string, model *lbServiceTLSConfig) *envoy_extensions_transportsockets_tls_v3.CommonTlsContext_CombinedValidationContext {
	if len(model.validationContext.trustedCASecretName) == 0 {
		return nil
	}

	defaultValidationContext := &envoy_extensions_transportsockets_tls_v3.CertificateValidationContext{}

	if len(model.validationContext.subjectAlternativeNames) > 0 {
		sanMatchers := []*envoy_extensions_transportsockets_tls_v3.SubjectAltNameMatcher{}
		for _, san := range model.validationContext.subjectAlternativeNames {
			sanMatchers = append(sanMatchers, &envoy_extensions_transportsockets_tls_v3.SubjectAltNameMatcher{
				SanType: envoy_extensions_transportsockets_tls_v3.SubjectAltNameMatcher_DNS,
				Matcher: &envoy_type_matcher_v3.StringMatcher{
					MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{
						Exact: san,
					},
				},
			})
		}
		defaultValidationContext.MatchTypedSubjectAltNames = sanMatchers
	}

	return &envoy_extensions_transportsockets_tls_v3.CommonTlsContext_CombinedValidationContext{
		CombinedValidationContext: &envoy_extensions_transportsockets_tls_v3.CommonTlsContext_CombinedCertificateValidationContext{
			ValidationContextSdsSecretConfig: &envoy_extensions_transportsockets_tls_v3.SdsSecretConfig{
				Name: fmt.Sprintf("%s/%s-%s", r.config.SecretsNamespace, namespace, model.validationContext.trustedCASecretName),
			},
			DefaultValidationContext: defaultValidationContext,
		},
	}
}

func (r *lbServiceT2Translator) requiresClientCertificate(validationContext *envoy_extensions_transportsockets_tls_v3.CommonTlsContext_CombinedValidationContext) *wrapperspb.BoolValue {
	if validationContext == nil {
		return nil
	}

	return wrapperspb.Bool(true)
}

func (r *lbServiceT2Translator) desiredEnvoyListenerHttpsFilterChain(model *lbService) *envoy_config_listener_v3.FilterChain {
	var validationContext *envoy_extensions_transportsockets_tls_v3.CommonTlsContext_CombinedValidationContext
	if model.applications.httpsProxy.tlsConfig != nil {
		validationContext = r.toTLSValidationContext(model.namespace, model.applications.httpsProxy.tlsConfig)
	}

	networkFilters := []*envoy_config_listener_v3.Filter{}

	if model.applications.getHTTPSConnectionFiltering() != nil {
		networkFilters = append(networkFilters, &envoy_config_listener_v3.Filter{
			Name: "envoy.filters.network.rbac",
			ConfigType: &envoy_config_listener_v3.Filter_TypedConfig{
				TypedConfig: toAny(r.toHTTPNetworkRBACFilter(model.applications.getHTTPSConnectionFiltering(), model.t1NodeIPs, httpTypeHTTPS, model.namespace, model.name)),
			},
		})
	}

	if model.applications.getHTTPSConnectionRateLimits() != nil {
		networkFilters = append(networkFilters, &envoy_config_listener_v3.Filter{
			Name: "envoy.filters.network.local_ratelimit",
			ConfigType: &envoy_config_listener_v3.Filter_TypedConfig{
				TypedConfig: toAny(r.toNetworkRateLimitFilter(model.applications.getHTTPSConnectionRateLimits(), model.namespace, model.name)),
			},
		})
	}

	networkFilters = append(networkFilters, &envoy_config_listener_v3.Filter{
		Name: "envoy.filters.network.http_connection_manager",
		ConfigType: &envoy_config_listener_v3.Filter_TypedConfig{
			TypedConfig: toAny(r.desiredEnvoyListenerHTTPSHCM(model)),
		},
	})

	return &envoy_config_listener_v3.FilterChain{
		FilterChainMatch: &envoy_config_listener_v3.FilterChainMatch{
			TransportProtocol: "tls",
			ServerNames:       r.toHTTPSServerNames(model),
		},
		TransportSocket: &envoy_config_core_v3.TransportSocket{
			Name: "envoy.transport_sockets.tls",
			ConfigType: &envoy_config_core_v3.TransportSocket_TypedConfig{
				TypedConfig: toAny(&envoy_extensions_transportsockets_tls_v3.DownstreamTlsContext{
					// Upstream Envoy Secret Sync only supports setting the trusted CA without further verification data.
					// Therefore it's necessary to explicitly enable `require_client_certificate if the validation context isn't nil.
					//
					// https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/transport_sockets/tls/v3/common.proto#extensions-transport-sockets-tls-v3-certificatevalidationcontext
					// By default, a client certificate is optional, unless one of the additional options (require_client_certificate, verify_certificate_spki, verify_certificate_hash, or match_typed_subject_alt_names) is also specified.
					RequireClientCertificate: r.requiresClientCertificate(validationContext),
					CommonTlsContext: &envoy_extensions_transportsockets_tls_v3.CommonTlsContext{
						TlsCertificateSdsSecretConfigs: r.toTLSCertificateSdsConfigs(model.namespace, model.applications.httpsProxy.tlsConfig),
						ValidationContextType:          validationContext,
						AlpnProtocols:                  r.toAlpnProtocols(model),
						TlsParams:                      r.toListenerTLSParams(model.applications.httpsProxy.tlsConfig),
					},
				}),
			},
		},
		Filters: networkFilters,
	}
}

func (r *lbServiceT2Translator) desiredEnvoyListenerHTTPSHCM(model *lbService) *envoy_extensions_filters_network_hcm_v3.HttpConnectionManager {
	return &envoy_extensions_filters_network_hcm_v3.HttpConnectionManager{
		ServerName:                   r.config.ServerName,
		AccessLog:                    r.desiredEnvoyAccessLoggers(r.config.AccessLog.FormatHTTP, r.config.AccessLog.JSONFormatHTTP),
		GenerateRequestId:            wrapperspb.Bool(r.config.RequestID.Generate),
		PreserveExternalRequestId:    r.config.RequestID.Preserve,
		AlwaysSetRequestIdInResponse: r.config.RequestID.Response,
		StatPrefix:                   fmt.Sprintf("https_%s_%s", model.namespace, model.name),
		CodecType:                    r.toCodecType(model.applications.getHTTPSHTTPConfig()),
		NormalizePath:                wrapperspb.Bool(true),
		MergeSlashes:                 true,
		UseRemoteAddress:             wrapperspb.Bool(r.config.OriginalIPDetection.UseRemoteAddress),
		XffNumTrustedHops:            uint32(r.config.OriginalIPDetection.XffNumTrustedHops),
		StripMatchingHostPort:        true,
		HttpFilters:                  r.desiredEnvoyListenerHttpsHTTPFilters(model),
		RouteSpecifier: &envoy_extensions_filters_network_hcm_v3.HttpConnectionManager_Rds{
			Rds: &envoy_extensions_filters_network_hcm_v3.Rds{
				RouteConfigName: "frontend_routeconfig_https",
			},
		},
		CommonHttpProtocolOptions: &envoy_config_core_v3.HttpProtocolOptions{
			HeadersWithUnderscoresAction: envoy_config_core_v3.HttpProtocolOptions_REJECT_REQUEST,
			MaxConnectionDuration:        durationpb.New(time.Hour),
		},
		Http2ProtocolOptions: &envoy_config_core_v3.Http2ProtocolOptions{
			MaxConcurrentStreams:        wrapperspb.UInt32(100),
			InitialStreamWindowSize:     wrapperspb.UInt32(65535),
			InitialConnectionWindowSize: wrapperspb.UInt32(1048576),
		},
	}
}

func (r *lbServiceT2Translator) desiredEnvoyListenerHttpsHTTPFilters(model *lbService) []*envoy_extensions_filters_network_hcm_v3.HttpFilter {
	httpFilters := []*envoy_extensions_filters_network_hcm_v3.HttpFilter{}

	if model.usesHTTPSRequestFiltering() {
		// Only add the RBAC filter if there's at least one route that is using request filtering.
		// The RBAC filter on the HCM provides support for overriding it per route
		httpFilters = append(httpFilters, &envoy_extensions_filters_network_hcm_v3.HttpFilter{
			Name: "envoy.filters.http.rbac",
			ConfigType: &envoy_extensions_filters_network_hcm_v3.HttpFilter_TypedConfig{
				TypedConfig: toAny(&envoy_extensions_filters_http_rbac_v3.RBAC{}),
			},
		})
	}

	if model.usesHTTPSRequestRateLimiting() {
		// Only add the LocalRateLimit filter if there's at least one route that is using request rate limiting.
		// The filter on the HCM provides support for overriding it per route
		httpFilters = append(httpFilters, &envoy_extensions_filters_network_hcm_v3.HttpFilter{
			Name: "envoy.filters.http.local_ratelimit",
			ConfigType: &envoy_extensions_filters_network_hcm_v3.HttpFilter_TypedConfig{
				TypedConfig: toAny(&envoy_extensions_filters_http_localratelimit_v3.LocalRateLimit{
					StatPrefix: fmt.Sprintf("%s_%s", model.namespace, model.name), // required attribute
				}),
			},
		})
	}

	if model.usesHTTPSBasicAuth() {
		httpFilters = append(httpFilters, &envoy_extensions_filters_network_hcm_v3.HttpFilter{
			Name: "envoy.filters.http.basic_auth",
			ConfigType: &envoy_extensions_filters_network_hcm_v3.HttpFilter_TypedConfig{
				TypedConfig: toAny(&envoy_extensions_filters_http_basic_auth_v3.BasicAuth{
					Users: &envoy_config_core_v3.DataSource{
						Specifier: &envoy_config_core_v3.DataSource_InlineString{
							InlineString: r.toHTPasswdString(model.applications.httpsProxy.auth.basicAuth),
						},
					},
				}),
			},
		})
	}

	if model.usesHTTPSJWTAuth() {
		httpFilters = append(httpFilters, &envoy_extensions_filters_network_hcm_v3.HttpFilter{
			Name: "envoy.filters.http.jwt_authn",
			ConfigType: &envoy_extensions_filters_network_hcm_v3.HttpFilter_TypedConfig{
				TypedConfig: toAny(r.toJWTAuthentication(model.namespace, model.name, httpTypeHTTPS, model.applications.httpsProxy.auth.jwtAuth)),
			},
		})
	}

	httpFilters = append(httpFilters, &envoy_extensions_filters_network_hcm_v3.HttpFilter{
		Name: "envoy.filters.http.router",
		ConfigType: &envoy_extensions_filters_network_hcm_v3.HttpFilter_TypedConfig{
			TypedConfig: toAny(r.desiredEnvoyRouterFilter()),
		},
	})

	return httpFilters
}

func (r *lbServiceT2Translator) desiredEnvoyListenerTLSPassthroughFilterChains(model *lbService) []*envoy_config_listener_v3.FilterChain {
	tlsPassthroughFilterChains := []*envoy_config_listener_v3.FilterChain{}

	if model.applications.tlsPassthrough == nil {
		return tlsPassthroughFilterChains
	}

	for i, tr := range model.applications.tlsPassthrough.routes {
		networkFilters := []*envoy_config_listener_v3.Filter{}

		if tr.connectionFiltering != nil {
			networkFilters = append(networkFilters, &envoy_config_listener_v3.Filter{
				Name: "envoy.filters.network.rbac",
				ConfigType: &envoy_config_listener_v3.Filter_TypedConfig{
					TypedConfig: toAny(r.toTLSRouteRBACFilter(tr.connectionFiltering, model.namespace, model.name)),
				},
			})
		}

		if tr.rateLimits != nil {
			networkFilters = append(networkFilters, &envoy_config_listener_v3.Filter{
				Name: "envoy.filters.network.local_ratelimit",
				ConfigType: &envoy_config_listener_v3.Filter_TypedConfig{
					TypedConfig: toAny(r.toNetworkRateLimitFilter(tr.rateLimits, model.namespace, model.name)),
				},
			})
		}

		networkFilters = append(networkFilters, &envoy_config_listener_v3.Filter{
			Name: "envoy.filters.network.tcp_proxy",
			ConfigType: &envoy_config_listener_v3.Filter_TypedConfig{
				TypedConfig: toAny(&envoy_extensions_filters_network_tcpproxy_v3.TcpProxy{
					AccessLog:  r.desiredEnvoyAccessLoggers(r.config.AccessLog.FormatTLS, r.config.AccessLog.JSONFormatTLS),
					StatPrefix: fmt.Sprintf("tls_passthrough_%s_%s_%d", model.namespace, model.name, i),
					HashPolicy: r.toTCPProxyHashpolicy(tr.persistentBackend),
					ClusterSpecifier: &envoy_extensions_filters_network_tcpproxy_v3.TcpProxy_Cluster{
						Cluster: r.getClusterName(tr.backendRef.name),
					},
				}),
			},
		})

		f := &envoy_config_listener_v3.FilterChain{
			FilterChainMatch: &envoy_config_listener_v3.FilterChainMatch{
				TransportProtocol: "tls",
				ServerNames:       r.toTLSServerNames(tr.match.hostNames),
			},
			Filters: networkFilters,
		}

		tlsPassthroughFilterChains = append(tlsPassthroughFilterChains, f)
	}

	return tlsPassthroughFilterChains
}

func (r *lbServiceT2Translator) desiredEnvoyListenerTLSProxyFilterChains(model *lbService) []*envoy_config_listener_v3.FilterChain {
	var validationContext *envoy_extensions_transportsockets_tls_v3.CommonTlsContext_CombinedValidationContext
	if model.applications.tlsProxy.tlsConfig != nil {
		validationContext = r.toTLSValidationContext(model.namespace, model.applications.tlsProxy.tlsConfig)
	}

	tlsProxyFilterChains := []*envoy_config_listener_v3.FilterChain{}
	for i, tr := range model.applications.tlsProxy.routes {
		networkFilters := []*envoy_config_listener_v3.Filter{}

		if tr.connectionFiltering != nil {
			networkFilters = append(networkFilters, &envoy_config_listener_v3.Filter{
				Name: "envoy.filters.network.rbac",
				ConfigType: &envoy_config_listener_v3.Filter_TypedConfig{
					TypedConfig: toAny(r.toTLSRouteRBACFilter(tr.connectionFiltering, model.namespace, model.name)),
				},
			})
		}

		if tr.rateLimits != nil {
			networkFilters = append(networkFilters, &envoy_config_listener_v3.Filter{
				Name: "envoy.filters.network.local_ratelimit",
				ConfigType: &envoy_config_listener_v3.Filter_TypedConfig{
					TypedConfig: toAny(r.toNetworkRateLimitFilter(tr.rateLimits, model.namespace, model.name)),
				},
			})
		}

		networkFilters = append(networkFilters, &envoy_config_listener_v3.Filter{
			Name: "envoy.filters.network.tcp_proxy",
			ConfigType: &envoy_config_listener_v3.Filter_TypedConfig{
				TypedConfig: toAny(&envoy_extensions_filters_network_tcpproxy_v3.TcpProxy{
					AccessLog:  r.desiredEnvoyAccessLoggers(r.config.AccessLog.FormatTLS, r.config.AccessLog.JSONFormatTLS),
					StatPrefix: fmt.Sprintf("tls_proxy_%s_%s_%d", model.namespace, model.name, i),
					HashPolicy: r.toTCPProxyHashpolicy(tr.persistentBackend),
					ClusterSpecifier: &envoy_extensions_filters_network_tcpproxy_v3.TcpProxy_Cluster{
						Cluster: r.getClusterName(tr.backendRef.name),
					},
				}),
			},
		})

		f := &envoy_config_listener_v3.FilterChain{
			FilterChainMatch: &envoy_config_listener_v3.FilterChainMatch{
				TransportProtocol: "tls",
				ServerNames:       r.toTLSServerNames(tr.match.hostNames),
			},
			TransportSocket: &envoy_config_core_v3.TransportSocket{
				Name: "envoy.transport_sockets.tls",
				ConfigType: &envoy_config_core_v3.TransportSocket_TypedConfig{
					TypedConfig: toAny(&envoy_extensions_transportsockets_tls_v3.DownstreamTlsContext{
						// Upstream Envoy Secret Sync only supports setting the trusted CA without further verification data.
						// Therefore it's necessary to explicitly enable `require_client_certificate if the validation context isn't nil.
						//
						// https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/transport_sockets/tls/v3/common.proto#extensions-transport-sockets-tls-v3-certificatevalidationcontext
						// By default, a client certificate is optional, unless one of the additional options (require_client_certificate, verify_certificate_spki, verify_certificate_hash, or match_typed_subject_alt_names) is also specified.
						RequireClientCertificate: r.requiresClientCertificate(validationContext),
						CommonTlsContext: &envoy_extensions_transportsockets_tls_v3.CommonTlsContext{
							TlsCertificateSdsSecretConfigs: r.toTLSCertificateSdsConfigs(model.namespace, model.applications.tlsProxy.tlsConfig),
							ValidationContextType:          validationContext,
							AlpnProtocols:                  r.toAlpnProtocols(model),
							TlsParams:                      r.toListenerTLSParams(model.applications.tlsProxy.tlsConfig),
						},
					}),
				},
			},
			Filters: networkFilters,
		}

		tlsProxyFilterChains = append(tlsProxyFilterChains, f)
	}

	return tlsProxyFilterChains
}

func (r *lbServiceT2Translator) desiredEnvoyAccessLoggers(textFormatString string, jsonFormatString string) []*envoy_config_accesslog_v3.AccessLog {
	accessLoggers := []*envoy_config_accesslog_v3.AccessLog{}

	if r.config.AccessLog.EnableStdOut {
		accessLoggers = append(accessLoggers, &envoy_config_accesslog_v3.AccessLog{
			Name: "stdout",
			ConfigType: &envoy_config_accesslog_v3.AccessLog_TypedConfig{
				TypedConfig: toAny(&envoy_extensions_accessloggers_stream_v3.StdoutAccessLog{
					AccessLogFormat: &envoy_extensions_accessloggers_stream_v3.StdoutAccessLog_LogFormat{
						LogFormat: &envoy_config_core_v3.SubstitutionFormatString{
							Format: &envoy_config_core_v3.SubstitutionFormatString_TextFormatSource{
								TextFormatSource: &envoy_config_core_v3.DataSource{
									Specifier: &envoy_config_core_v3.DataSource_InlineString{
										InlineString: fmt.Sprintf("%s\n", textFormatString),
									},
								},
							},
						},
					},
				}),
			},
		})
	}

	if r.config.AccessLog.FilePath != "" {
		jsonFormatMap := map[string]any{}
		if err := json.Unmarshal([]byte(jsonFormatString), &jsonFormatMap); err != nil {
			r.logger.Error("Failed to unmarshal JSON accesslog format - skipping", "filepath", r.config.AccessLog.FilePath, logfields.Error, err)
			return accessLoggers
		}

		jsonFormatStruct, err := structpb.NewStruct(jsonFormatMap)
		if err != nil {
			r.logger.Error("Failed to create protobuf struct for JSON accesslog format - skipping", "filepath", r.config.AccessLog.FilePath, logfields.Error, err)
			return accessLoggers
		}

		accessLoggers = append(accessLoggers, &envoy_config_accesslog_v3.AccessLog{
			Name: "file",
			ConfigType: &envoy_config_accesslog_v3.AccessLog_TypedConfig{
				TypedConfig: toAny(&envoy_extensions_accessloggers_file_v3.FileAccessLog{
					Path: r.config.AccessLog.FilePath,
					AccessLogFormat: &envoy_extensions_accessloggers_file_v3.FileAccessLog_LogFormat{
						LogFormat: &envoy_config_core_v3.SubstitutionFormatString{
							Format: &envoy_config_core_v3.SubstitutionFormatString_JsonFormat{
								JsonFormat: jsonFormatStruct,
							},
							JsonFormatOptions: &envoy_config_core_v3.JsonFormatOptions{
								SortProperties: true,
							},
						},
					},
				}),
			},
		})
	}

	return accessLoggers
}

func (r *lbServiceT2Translator) desiredEnvoyRouteConfigs(model *lbService) []*envoy_config_route_v3.RouteConfiguration {
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

func (r *lbServiceT2Translator) desiredEnvoyHttpRouteConfig(model *lbService) *envoy_config_route_v3.RouteConfiguration {
	virtualHosts := []*envoy_config_route_v3.VirtualHost{}
	if model.applications.httpProxy != nil {
		virtualHosts = r.desiredEnvoyHttpRouteVirtualHosts(
			model.usesHTTPRequestFiltering(),
			model.usesHTTPRequestRateLimiting(),
			model.usesHTTPBasicAuth(),
			model.usesHTTPJWTAuth(),
			model.applications.httpProxy.routes,
			httpTypeHTTP,
			model.namespace,
			model.name,
		)
	}

	return &envoy_config_route_v3.RouteConfiguration{
		Name:         "frontend_routeconfig_http",
		VirtualHosts: virtualHosts,
	}
}

func (r *lbServiceT2Translator) desiredEnvoyHttpsRouteConfig(model *lbService) *envoy_config_route_v3.RouteConfiguration {
	virtualHosts := []*envoy_config_route_v3.VirtualHost{}
	if model.applications.httpsProxy != nil {
		virtualHosts = r.desiredEnvoyHttpRouteVirtualHosts(
			model.usesHTTPSRequestFiltering(),
			model.usesHTTPSRequestRateLimiting(),
			model.usesHTTPSBasicAuth(),
			model.usesHTTPSJWTAuth(),
			model.applications.httpsProxy.routes,
			httpTypeHTTPS,
			model.namespace,
			model.name,
		)
	}

	return &envoy_config_route_v3.RouteConfiguration{
		Name:         "frontend_routeconfig_https",
		VirtualHosts: virtualHosts,
	}
}

func (r *lbServiceT2Translator) desiredEnvoyHttpRouteVirtualHosts(usesRequestFiltering bool, usesRateLimiting bool, usesBasicAuth bool, usesJWTAuth bool, modelRoutes map[string][]lbRouteHTTP, httpType string, namespace string, name string) []*envoy_config_route_v3.VirtualHost {
	virtualHosts := []*envoy_config_route_v3.VirtualHost{}

	routeHostNamesOrdered := slices.Sorted(maps.Keys(modelRoutes))

	for _, routeHostname := range routeHostNamesOrdered {
		envoyRoutes := []*envoy_config_route_v3.Route{}

		for _, route := range modelRoutes[routeHostname] {
			tpfc := map[string]*anypb.Any{}
			if usesRequestFiltering {
				tpfc["envoy.filters.http.rbac"] = toAny(r.toHTTPRouteRBACFilter(route.requestFiltering))
			}
			if usesRateLimiting {
				tpfc["envoy.filters.http.local_ratelimit"] = toAny(r.toHTTPRateLimitFilter(route.rateLimits, namespace, name))
			}
			if usesBasicAuth && route.auth != nil && route.auth.basicAuth != nil {
				tpfc["envoy.filters.http.basic_auth"] = toAny(r.toHTTPRouteBasicAuthFilter(route.auth.basicAuth))
			}
			if usesJWTAuth && route.auth != nil && route.auth.jwtAuth != nil {
				tpfc["envoy.filters.http.jwt_authn"] = toAny(r.toHTTPRouteJWTAuthFilter(route.auth.jwtAuth))
			}

			envoyRoutes = append(envoyRoutes, &envoy_config_route_v3.Route{
				Match: r.toRouteMatch(route.match),
				Action: &envoy_config_route_v3.Route_Route{
					Route: &envoy_config_route_v3.RouteAction{
						HashPolicy: r.toHTTPRouteHashpolicy(route.persistentBackend),
						ClusterSpecifier: &envoy_config_route_v3.RouteAction_Cluster{
							Cluster: r.getClusterName(route.backendRef.name),
						},
					},
				},
				TypedPerFilterConfig: tpfc,
			})
		}

		cleanedHostName := strings.ReplaceAll(routeHostname, "*", "wildcard")
		cleanedHostName = strings.ReplaceAll(cleanedHostName, ".", "_")

		virtualHosts = append(virtualHosts,
			&envoy_config_route_v3.VirtualHost{
				Name:    fmt.Sprintf("frontend_virtualhost_%s_%s", httpType, cleanedHostName),
				Domains: []string{routeHostname},
				Routes:  envoyRoutes,
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

func (r *lbServiceT2Translator) toRouteMatch(match lbRouteHTTPMatch) *envoy_config_route_v3.RouteMatch {
	switch match.pathType {
	case routePathTypePrefix:
		return &envoy_config_route_v3.RouteMatch{
			PathSpecifier: &envoy_config_route_v3.RouteMatch_Prefix{
				Prefix: match.path,
			},
		}
	case routePathTypeExact:
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

func (r *lbServiceT2Translator) desiredEnvoyRouterFilter() *envoy_extensions_filters_http_router_v3.Router {
	return &envoy_extensions_filters_http_router_v3.Router{
		SuppressEnvoyHeaders: true,
	}
}

func (r *lbServiceT2Translator) desiredHealthCheckFilter(model *lbService) *envoy_extensions_filters_http_healthcheck_v3.HealthCheck {
	healthCheckFilterClusters := map[string]*envoy_type_v3.Percent{}

	minHealthyBackendPercentage := r.config.T1T2HealthCheck.T2ProbeMinHealthyBackendPercentage
	if minHealthyBackendPercentage > 100 {
		minHealthyBackendPercentage = 100
	}

	refBackendNamesSorted := slices.Sorted(maps.Keys(model.referencedBackends))

	for _, bn := range refBackendNamesSorted {
		healthCheckFilterClusters[r.getClusterName(bn)] = &envoy_type_v3.Percent{Value: float64(minHealthyBackendPercentage)}
	}

	healthCheckFilter := &envoy_extensions_filters_http_healthcheck_v3.HealthCheck{
		PassThroughMode:              &wrapperspb.BoolValue{Value: false},
		ClusterMinHealthyPercentages: healthCheckFilterClusters,
		Headers: []*envoy_config_route_v3.HeaderMatcher{
			{
				Name: ":path",
				HeaderMatchSpecifier: &envoy_config_route_v3.HeaderMatcher_StringMatch{
					StringMatch: &envoy_type_matcher_v3.StringMatcher{
						MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{
							Exact: r.config.T1T2HealthCheck.T1ProbeHttpPath,
						},
					},
				},
			},
			{
				Name: ":method",
				HeaderMatchSpecifier: &envoy_config_route_v3.HeaderMatcher_StringMatch{
					StringMatch: &envoy_type_matcher_v3.StringMatcher{
						MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{
							Exact: r.config.T1T2HealthCheck.T1ProbeHttpMethod,
						},
					},
				},
			},
			{
				Name: "user-agent",
				HeaderMatchSpecifier: &envoy_config_route_v3.HeaderMatcher_StringMatch{
					StringMatch: &envoy_type_matcher_v3.StringMatcher{
						MatchPattern: &envoy_type_matcher_v3.StringMatcher_Prefix{
							Prefix: r.config.T1T2HealthCheck.T1ProbeHttpUserAgentPrefix,
						},
					},
				},
			},
		},
	}

	return healthCheckFilter
}

func (r *lbServiceT2Translator) desiredEnvoyClusters(model *lbService) []*envoy_config_cluster_v3.Cluster {
	clusters := []*envoy_config_cluster_v3.Cluster{}

	refBackendNamesSorted := slices.Sorted(maps.Keys(model.referencedBackends))

	for _, bn := range refBackendNamesSorted {
		clusters = append(clusters, r.desiredEnvoyCluster(r.getClusterName(bn), model.referencedBackends[bn]))
	}

	clusters = append(clusters, r.desiredJWKSEnvoyClusters(model)...)

	return clusters
}

func (r *lbServiceT2Translator) desiredJWKSEnvoyClusters(model *lbService) []*envoy_config_cluster_v3.Cluster {
	clusters := []*envoy_config_cluster_v3.Cluster{}

	if model.usesHTTPJWTAuth() {
		for _, provider := range model.applications.httpProxy.auth.jwtAuth.providers {
			if cluster := r.desiredJWKSEnvoyCluster(httpTypeHTTP, provider); cluster != nil {
				clusters = append(clusters, cluster)
			}
		}
	}

	if model.usesHTTPSJWTAuth() {
		for _, provider := range model.applications.httpsProxy.auth.jwtAuth.providers {
			if cluster := r.desiredJWKSEnvoyCluster(httpTypeHTTPS, provider); cluster != nil {
				clusters = append(clusters, cluster)
			}
		}
	}

	return clusters
}

func (r *lbServiceT2Translator) desiredJWKSEnvoyCluster(httpType string, provider jwtProvider) *envoy_config_cluster_v3.Cluster {
	if provider.remoteJWKS == nil {
		return nil
	}

	uri, err := url.ParseRequestURI(provider.remoteJWKS.httpURI)
	if err != nil {
		// The API validation (format=uri) guarantees that the
		// given URI can be parsed with url.ParseRequestURI.
		// So, this shouldn't happen.
		r.logger.Error("BUG: Cannot parse JWKS URI", "uri", provider.remoteJWKS.httpURI)
		return nil
	}

	var port uint32
	if uri.Port() == "" {
		// Port unspecified. Set default values.
		switch uri.Scheme {
		case "http":
			port = 80
		case "https":
			port = 443
		}
	} else {
		// port number is 16bit
		port64, err := strconv.ParseUint(uri.Port(), 10, 16)
		if err != nil {
			return nil
		}
		// Envoy takes port number as uint32
		port = uint32(port64)
	}

	var transportSocket *envoy_config_core_v3.TransportSocket
	if uri.Scheme == "https" {
		transportSocket = &envoy_config_core_v3.TransportSocket{
			Name: "envoy.transport_sockets.tls",
			ConfigType: &envoy_config_core_v3.TransportSocket_TypedConfig{
				TypedConfig: toAny(&envoy_extensions_transportsockets_tls_v3.UpstreamTlsContext{}),
			},
		}
	}

	return &envoy_config_cluster_v3.Cluster{
		Name: r.jwksClusterName(httpType, provider.name),
		ClusterDiscoveryType: &envoy_config_cluster_v3.Cluster_Type{
			Type: envoy_config_cluster_v3.Cluster_STRICT_DNS,
		},
		TransportSocket: transportSocket,
		LoadAssignment: &envoy_config_endpoint_v3.ClusterLoadAssignment{
			ClusterName: r.jwksClusterName(httpType, provider.name),
			Endpoints: []*envoy_config_endpoint_v3.LocalityLbEndpoints{
				{
					LbEndpoints: []*envoy_config_endpoint_v3.LbEndpoint{
						{
							HostIdentifier: &envoy_config_endpoint_v3.LbEndpoint_Endpoint{
								Endpoint: &envoy_config_endpoint_v3.Endpoint{
									Address: &envoy_config_core_v3.Address{
										Address: &envoy_config_core_v3.Address_SocketAddress{
											SocketAddress: &envoy_config_core_v3.SocketAddress{
												Address:       uri.Hostname(),
												PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{PortValue: port},
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
	}
}

func (r *lbServiceT2Translator) toHealthCheckTransportSocketMatches(healthCheckConfig lbBackendHealthCheckConfig) []*envoy_config_cluster_v3.Cluster_TransportSocketMatch {
	return []*envoy_config_cluster_v3.Cluster_TransportSocketMatch{
		{
			Name: "healthcheck",
			Match: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					"type": structpb.NewStringValue("healthcheck"),
				},
			},
			TransportSocket: r.toTransportSocket(healthCheckConfig.tlsConfig, nil),
		},
	}
}

func (r *lbServiceT2Translator) toHealthCheckTransportSocketMatchCriteria(backend backend) *structpb.Struct {
	return &structpb.Struct{
		Fields: map[string]*structpb.Value{
			"type": structpb.NewStringValue("healthcheck"),
		},
	}
}

func (r *lbServiceT2Translator) desiredEnvoyCluster(name string, b backend) *envoy_config_cluster_v3.Cluster {
	cluster := &envoy_config_cluster_v3.Cluster{
		Name: name,
		ClusterDiscoveryType: &envoy_config_cluster_v3.Cluster_Type{
			Type: r.mapClusterType(b.typ),
		},
		CommonLbConfig: &envoy_config_cluster_v3.Cluster_CommonLbConfig{
			// disabling panic mode (https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/upstream/load_balancing/panic_threshold)
			HealthyPanicThreshold: &envoy_type_v3.Percent{Value: 0.0},
		},
		ConnectTimeout:         &durationpb.Duration{Seconds: int64(b.tcpConfig.connectTimeoutSeconds)},
		TransportSocketMatches: r.toHealthCheckTransportSocketMatches(b.healthCheckConfig),
		HealthChecks:           r.toClusterHealthChecks(b.healthCheckConfig, r.toHealthCheckTransportSocketMatchCriteria(b)),
		LbPolicy:               r.mapLbPolicy(b.lbAlgorithm.algorithm),
		TypedExtensionProtocolOptions: map[string]*anypb.Any{
			"envoy.extensions.upstreams.http.v3.HttpProtocolOptions": r.toClusterHTTPProtocolOptions(b.httpConfig),
		},
		PerConnectionBufferLimitBytes: wrapperspb.UInt32(32768), // 32KiB
		TransportSocket:               r.toTransportSocket(b.tlsConfig, b.proxyProtocol),
		IgnoreHealthOnHostRemoval:     true,
	}

	switch cluster.LbPolicy {
	case envoy_config_cluster_v3.Cluster_ROUND_ROBIN:
		cluster.LbConfig = r.toLbConfigRoundRobin()
	case envoy_config_cluster_v3.Cluster_LEAST_REQUEST:
		cluster.LbConfig = r.toLbConfigLeastRequest()
	case envoy_config_cluster_v3.Cluster_MAGLEV:
		cluster.LbConfig = r.toLbConfigMaglev(b.lbAlgorithm)
	}

	if b.typ == lbBackendTypeHostname {
		// For STRICT_DNS cluster, we must specify endpoint inline in the cluster
		cluster.LoadAssignment = r.desiredEnvoyClusterLoadAssignment(name, b)

		// Some fine tuning for DNS resolver. We can expose these settings as needed
		cluster.DnsRefreshRate = &durationpb.Duration{Seconds: 10}
		cluster.DnsFailureRefreshRate = &envoy_config_cluster_v3.Cluster_RefreshRate{
			BaseInterval: &durationpb.Duration{Seconds: 10},
			MaxInterval:  &durationpb.Duration{Seconds: 100},
		}
		cluster.RespectDnsTtl = true

		// We only support IPv4 so far. To avoid unnecessary confusion, we disable IPv6 lookup for now.
		cluster.DnsLookupFamily = envoy_config_cluster_v3.Cluster_V4_ONLY

		// Some additional settings for DNS resolver
		cluster.TypedDnsResolverConfig = &envoy_config_core_v3.TypedExtensionConfig{
			Name:        "envoy.network.dns_resolver.cares",
			TypedConfig: toAny(r.toDNSResolverConfig(b)),
		}
	}

	return cluster
}

func (r *lbServiceT2Translator) toDNSResolverConfig(b backend) *envoy_extensions_network_dns_resolver_cares_v3.CaresDnsResolverConfig {
	resolverConfig := &envoy_extensions_network_dns_resolver_cares_v3.CaresDnsResolverConfig{
		DnsResolverOptions: &envoy_config_core_v3.DnsResolverOptions{
			// For the sake of simplicity, we disable default search domain for now
			NoDefaultSearchDomain: true,
		},
	}

	if b.dnsResolverConfig != nil {
		for _, resolver := range b.dnsResolverConfig.resolvers {
			resolverConfig.Resolvers = append(resolverConfig.Resolvers, &envoy_config_core_v3.Address{
				Address: &envoy_config_core_v3.Address_SocketAddress{
					SocketAddress: &envoy_config_core_v3.SocketAddress{
						Address: resolver.ip,
						PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{
							PortValue: resolver.port,
						},
					},
				},
			})
		}
	}

	return resolverConfig
}

func (r *lbServiceT2Translator) toLbConfigRoundRobin() *envoy_config_cluster_v3.Cluster_RoundRobinLbConfig_ {
	return &envoy_config_cluster_v3.Cluster_RoundRobinLbConfig_{
		RoundRobinLbConfig: &envoy_config_cluster_v3.Cluster_RoundRobinLbConfig{},
	}
}

func (r *lbServiceT2Translator) toLbConfigLeastRequest() *envoy_config_cluster_v3.Cluster_LeastRequestLbConfig_ {
	return &envoy_config_cluster_v3.Cluster_LeastRequestLbConfig_{
		LeastRequestLbConfig: &envoy_config_cluster_v3.Cluster_LeastRequestLbConfig{},
	}
}

func (r *lbServiceT2Translator) toLbConfigMaglev(algorithmConfig lbBackendLBAlgorithm) *envoy_config_cluster_v3.Cluster_MaglevLbConfig_ {
	return &envoy_config_cluster_v3.Cluster_MaglevLbConfig_{
		MaglevLbConfig: &envoy_config_cluster_v3.Cluster_MaglevLbConfig{
			TableSize: wrapperspb.UInt64(uint64(algorithmConfig.consistentHashing.maglevTableSize)),
		},
	}
}

func (r *lbServiceT2Translator) rawTransportSocket() *envoy_config_core_v3.TransportSocket {
	return &envoy_config_core_v3.TransportSocket{
		Name: "envoy.transport_sockets.raw_buffer",
		ConfigType: &envoy_config_core_v3.TransportSocket_TypedConfig{
			TypedConfig: toAny(&envoy_extensions_transportsockets_rawbuffer_v3.RawBuffer{}),
		},
	}
}

func (r *lbServiceT2Translator) wrapWithTLSTransport(tlsConfig *lbBackendTLSConfig) *envoy_config_core_v3.TransportSocket {
	if tlsConfig == nil {
		return r.rawTransportSocket()
	}

	return &envoy_config_core_v3.TransportSocket{
		Name: "envoy.transport_sockets.tls",
		ConfigType: &envoy_config_core_v3.TransportSocket_TypedConfig{
			TypedConfig: toAny(&envoy_extensions_transportsockets_tls_v3.UpstreamTlsContext{
				CommonTlsContext: &envoy_extensions_transportsockets_tls_v3.CommonTlsContext{
					TlsParams: r.toClusterTLSParams(tlsConfig),
				},
			}),
		},
	}
}

func (r *lbServiceT2Translator) wrapWithProxyProtocolTransport(ts *envoy_config_core_v3.TransportSocket, proxyProtocol *lbBackendProxyProtocolConfig) *envoy_config_core_v3.TransportSocket {
	if proxyProtocol == nil {
		return ts
	}

	ppUpstreamTransport := &envoy_extensions_transportsockets_proxy_protocol_v3.ProxyProtocolUpstreamTransport{}
	switch proxyProtocol.version {
	case proxyProtocolVersionV1:
		ppUpstreamTransport.Config = &envoy_config_core_v3.ProxyProtocolConfig{
			Version: envoy_config_core_v3.ProxyProtocolConfig_V1,
			PassThroughTlvs: &envoy_config_core_v3.ProxyProtocolPassThroughTLVs{
				TlvType: proxyProtocol.passthroughTLVs,
			},
		}
	case proxyProtocolVersionV2:
		ppUpstreamTransport.Config = &envoy_config_core_v3.ProxyProtocolConfig{
			Version: envoy_config_core_v3.ProxyProtocolConfig_V2,
		}
	}
	ppUpstreamTransport.TransportSocket = ts

	return &envoy_config_core_v3.TransportSocket{
		Name: "envoy.transport_sockets.proxy_protocol",
		ConfigType: &envoy_config_core_v3.TransportSocket_TypedConfig{
			TypedConfig: toAny(ppUpstreamTransport),
		},
	}
}

func (r *lbServiceT2Translator) toTransportSocket(tlsConfig *lbBackendTLSConfig, proxyProtocol *lbBackendProxyProtocolConfig) *envoy_config_core_v3.TransportSocket {
	return r.wrapWithProxyProtocolTransport(r.wrapWithTLSTransport(tlsConfig), proxyProtocol)
}

func (r *lbServiceT2Translator) toClusterHTTPProtocolOptions(httpConfig lbBackendHTTPConfig) *anypb.Any {
	switch {
	case httpConfig.enableHTTP11 && !httpConfig.enableHTTP2:
		return toAny(&envoy_extensions_upstreams_http_v3.HttpProtocolOptions{
			CommonHttpProtocolOptions: &envoy_config_core_v3.HttpProtocolOptions{
				MaxConnectionDuration: durationpb.New(time.Hour),
			},
			UpstreamProtocolOptions: &envoy_extensions_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig_{
				ExplicitHttpConfig: &envoy_extensions_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig{
					ProtocolConfig: &envoy_extensions_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig_HttpProtocolOptions{},
				},
			},
		})
	case httpConfig.enableHTTP2 && !httpConfig.enableHTTP11:
		return toAny(&envoy_extensions_upstreams_http_v3.HttpProtocolOptions{
			CommonHttpProtocolOptions: &envoy_config_core_v3.HttpProtocolOptions{
				MaxConnectionDuration: durationpb.New(time.Hour),
			},
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
			CommonHttpProtocolOptions: &envoy_config_core_v3.HttpProtocolOptions{
				MaxConnectionDuration: durationpb.New(time.Hour),
			},
			UpstreamProtocolOptions: &envoy_extensions_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig_{
				ExplicitHttpConfig: &envoy_extensions_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig{
					ProtocolConfig: &envoy_extensions_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig_HttpProtocolOptions{},
				},
			},
		})
	}
}

func (r *lbServiceT2Translator) toClusterHealthChecks(healthCheckConfig lbBackendHealthCheckConfig, hcTransportSocketMatchCriteria *structpb.Struct) []*envoy_config_core_v3.HealthCheck {
	healthCheck := &envoy_config_core_v3.HealthCheck{
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
	return []*envoy_config_core_v3.HealthCheck{
		healthCheck,
	}
}

func (r *lbServiceT2Translator) toClusterHealthCheckerHTTP(healthCheckConfig lbBackendHealthCheckConfig) *envoy_config_core_v3.HealthCheck_HttpHealthCheck_ {
	return &envoy_config_core_v3.HealthCheck_HttpHealthCheck_{
		HttpHealthCheck: &envoy_config_core_v3.HealthCheck_HttpHealthCheck{
			Host: healthCheckConfig.http.host,
			Path: healthCheckConfig.http.path,
		},
	}
}

func (r *lbServiceT2Translator) toClusterHealthCheckerTCP(_ lbBackendHealthCheckConfig) *envoy_config_core_v3.HealthCheck_TcpHealthCheck_ {
	return &envoy_config_core_v3.HealthCheck_TcpHealthCheck_{
		TcpHealthCheck: &envoy_config_core_v3.HealthCheck_TcpHealthCheck{},
	}
}

func (r *lbServiceT2Translator) desiredEnvoyClusterLoadAssignments(model *lbService) []*envoy_config_endpoint_v3.ClusterLoadAssignment {
	loadAssignments := []*envoy_config_endpoint_v3.ClusterLoadAssignment{}

	refBackendNamesSorted := slices.Sorted(maps.Keys(model.referencedBackends))

	for _, bn := range refBackendNamesSorted {
		// For STRICT_DNS cluster, we must specify endpoint inline in the cluster
		if b := model.referencedBackends[bn]; b.typ != lbBackendTypeHostname {
			loadAssignments = append(loadAssignments, r.desiredEnvoyClusterLoadAssignment(r.getClusterName(bn), b))
		}
	}

	return loadAssignments
}

func (r *lbServiceT2Translator) desiredEnvoyClusterLoadAssignment(name string, b backend) *envoy_config_endpoint_v3.ClusterLoadAssignment {
	lbEndpoints := []*envoy_config_endpoint_v3.LbEndpoint{}

	for _, lbBackend := range b.lbBackends {
		lbEndpoints = append(lbEndpoints, &envoy_config_endpoint_v3.LbEndpoint{
			LoadBalancingWeight: wrapperspb.UInt32(lbBackend.weight),
			HealthStatus:        r.toHealthStatus(lbBackend.status),
			HostIdentifier: &envoy_config_endpoint_v3.LbEndpoint_Endpoint{Endpoint: &envoy_config_endpoint_v3.Endpoint{
				Address: &envoy_config_core_v3.Address{Address: &envoy_config_core_v3.Address_SocketAddress{SocketAddress: &envoy_config_core_v3.SocketAddress{
					Address:       lbBackend.address,
					PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{PortValue: uint32(lbBackend.port)},
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

func (r *lbServiceT2Translator) toHealthStatus(status lbBackendStatus) envoy_config_core_v3.HealthStatus {
	switch status {
	case lbBackendStatusDraining:
		return envoy_config_core_v3.HealthStatus_DRAINING
	default:
		return envoy_config_core_v3.HealthStatus_UNKNOWN
	}
}

func (r *lbServiceT2Translator) toHTTPRouteHashpolicy(persistentBackendConfig *lbRouteHTTPPersistentBackend) []*envoy_config_route_v3.RouteAction_HashPolicy {
	if persistentBackendConfig == nil {
		return nil
	}

	hashPolicy := []*envoy_config_route_v3.RouteAction_HashPolicy{}

	if persistentBackendConfig.sourceIP {
		hashPolicy = append(hashPolicy, &envoy_config_route_v3.RouteAction_HashPolicy{
			PolicySpecifier: &envoy_config_route_v3.RouteAction_HashPolicy_ConnectionProperties_{
				ConnectionProperties: &envoy_config_route_v3.RouteAction_HashPolicy_ConnectionProperties{
					SourceIp: persistentBackendConfig.sourceIP,
				},
			},
		})
	}

	for _, c := range persistentBackendConfig.cookieNames {
		hashPolicy = append(hashPolicy, &envoy_config_route_v3.RouteAction_HashPolicy{
			PolicySpecifier: &envoy_config_route_v3.RouteAction_HashPolicy_Cookie_{
				Cookie: &envoy_config_route_v3.RouteAction_HashPolicy_Cookie{
					Name: c,
				},
			},
		})
	}

	for _, h := range persistentBackendConfig.headerNames {
		hashPolicy = append(hashPolicy, &envoy_config_route_v3.RouteAction_HashPolicy{
			PolicySpecifier: &envoy_config_route_v3.RouteAction_HashPolicy_Header_{
				Header: &envoy_config_route_v3.RouteAction_HashPolicy_Header{
					HeaderName: h,
				},
			},
		})
	}

	if len(hashPolicy) == 0 {
		return nil
	}

	return hashPolicy
}

func (r *lbServiceT2Translator) toTCPProxyHashpolicy(persistentBackendConfig *lbRouteTLSPersistentBackend) []*envoy_type_v3.HashPolicy {
	if persistentBackendConfig == nil {
		return nil
	}

	hashPolicy := []*envoy_type_v3.HashPolicy{}

	if persistentBackendConfig.sourceIP {
		hashPolicy = append(hashPolicy, &envoy_type_v3.HashPolicy{
			PolicySpecifier: &envoy_type_v3.HashPolicy_SourceIp_{SourceIp: &envoy_type_v3.HashPolicy_SourceIp{}},
		})
	}

	if len(hashPolicy) == 0 {
		return nil
	}

	return hashPolicy
}

func (r *lbServiceT2Translator) mapClusterType(lbBackendType lbBackendType) envoy_config_cluster_v3.Cluster_DiscoveryType {
	switch lbBackendType {
	case lbBackendTypeIP:
		return envoy_config_cluster_v3.Cluster_EDS
	case lbBackendTypeHostname:
		return envoy_config_cluster_v3.Cluster_STRICT_DNS
	default:
		// This shouldn't happen as we should already check in the
		// validation step
		return envoy_config_cluster_v3.Cluster_EDS
	}
}

func (r *lbServiceT2Translator) mapLbPolicy(lbAlgorithm lbAlgorithmType) envoy_config_cluster_v3.Cluster_LbPolicy {
	switch lbAlgorithm {
	case lbAlgorithmRoundRobin:
		return envoy_config_cluster_v3.Cluster_ROUND_ROBIN
	case lbAlgorithmLeastRequest:
		return envoy_config_cluster_v3.Cluster_LEAST_REQUEST
	case lbAlgorithmConsistentHashing:
		return envoy_config_cluster_v3.Cluster_MAGLEV
	default:
		return envoy_config_cluster_v3.Cluster_ROUND_ROBIN
	}
}

func (r *lbServiceT2Translator) toHTTPNetworkRBACFilter(config *lbServiceHTTPConnectionFiltering, t1NodeIPs []string, httpType string, namespace string, name string) *envoy_extensions_filters_network_rbac_v3.RBAC {
	if config == nil {
		return nil
	}

	policies := map[string]*envoy_config_rbac_v3.Policy{}
	action := r.toRBACAction(config.ruleType)

	for i, rr := range config.rules {
		permissions := []*envoy_config_rbac_v3.Permission{}
		principals := []*envoy_config_rbac_v3.Principal{}

		if rr.sourceCIDR != nil {
			principals = append(principals, r.toRBACPrincipalRemoteIP(rr.sourceCIDR))
		}

		if len(principals) == 0 {
			principals = append(principals, r.toRBACPrincipalAny())
		}

		if len(permissions) == 0 {
			permissions = append(permissions, r.toRBACPermissionAny())
		}

		policies[fmt.Sprintf("rule-%d", i)] = &envoy_config_rbac_v3.Policy{
			Permissions: permissions,
			Principals:  principals,
		}
	}

	return &envoy_extensions_filters_network_rbac_v3.RBAC{
		StatPrefix: fmt.Sprintf("%s_%s_%s", httpType, namespace, name),
		Rules: &envoy_config_rbac_v3.RBAC{
			Action:   action,
			Policies: policies,
		},
	}
}

func (r *lbServiceT2Translator) toHTTPRouteRBACFilter(config *lbRouteHTTPRequestFiltering) *envoy_extensions_filters_http_rbac_v3.RBACPerRoute {
	action := envoy_config_rbac_v3.RBAC_DENY
	policies := map[string]*envoy_config_rbac_v3.Policy{}

	rules := []lbRouteHTTPRequestFilteringRule{}

	if config != nil {
		rules = config.rules
		action = r.toRBACAction(config.ruleType)
	}

	for i, rr := range rules {
		permissions := []*envoy_config_rbac_v3.Permission{}
		principals := []*envoy_config_rbac_v3.Principal{}

		if rr.sourceCIDR != nil {
			principals = append(principals, r.toRBACPrincipalRemoteIP(rr.sourceCIDR))
		}

		andPermissions := []*envoy_config_rbac_v3.Permission{}
		if rr.hostname != nil {
			andPermissions = append(andPermissions, r.toRBACPermissionHostName(rr.hostname))
		}

		if rr.path != nil {
			andPermissions = append(andPermissions, r.toRBACPermissionHTTPPath(rr.path))
		}

		if len(andPermissions) > 0 {
			permissions = append(permissions, r.toRBACPermissionAnd(andPermissions...))
		}

		if len(principals) == 0 {
			principals = append(principals, r.toRBACPrincipalAny())
		}

		if len(permissions) == 0 {
			permissions = append(permissions, r.toRBACPermissionAny())
		}

		policies[fmt.Sprintf("rule-%d", i)] = &envoy_config_rbac_v3.Policy{
			Permissions: permissions,
			Principals:  principals,
		}
	}

	return &envoy_extensions_filters_http_rbac_v3.RBACPerRoute{
		Rbac: &envoy_extensions_filters_http_rbac_v3.RBAC{
			Rules: &envoy_config_rbac_v3.RBAC{
				Action:   action,
				Policies: policies,
			},
		},
	}
}

func (r *lbServiceT2Translator) toTLSRouteRBACFilter(config *lbRouteTLSConnectionFiltering, namespace string, name string) *envoy_extensions_filters_network_rbac_v3.RBAC {
	if config == nil {
		return nil
	}

	policies := map[string]*envoy_config_rbac_v3.Policy{}
	action := r.toRBACAction(config.ruleType)

	for i, rr := range config.rules {
		permissions := []*envoy_config_rbac_v3.Permission{}
		principals := []*envoy_config_rbac_v3.Principal{}

		if rr.sourceCIDR != nil {
			principals = append(principals, r.toRBACPrincipalRemoteIP(rr.sourceCIDR))
		}

		if rr.servername != nil {
			permissions = append(permissions, r.toRBACPermissionServerName(*rr.servername))
		}

		if len(principals) == 0 {
			principals = append(principals, r.toRBACPrincipalAny())
		}

		if len(permissions) == 0 {
			permissions = append(permissions, r.toRBACPermissionAny())
		}

		policies[fmt.Sprintf("rule-%d", i)] = &envoy_config_rbac_v3.Policy{
			Permissions: permissions,
			Principals:  principals,
		}
	}

	return &envoy_extensions_filters_network_rbac_v3.RBAC{
		StatPrefix: fmt.Sprintf("tls_%s_%s", namespace, name),
		Rules: &envoy_config_rbac_v3.RBAC{
			Action:   action,
			Policies: policies,
		},
	}
}

func (r *lbServiceT2Translator) toRBACPrincipalRemoteIP(sourceCIDRRule *lbRouteRequestFilteringSourceCIDR) *envoy_config_rbac_v3.Principal {
	return &envoy_config_rbac_v3.Principal{
		Identifier: &envoy_config_rbac_v3.Principal_RemoteIp{
			RemoteIp: &envoy_config_core_v3.CidrRange{
				AddressPrefix: sourceCIDRRule.addressPrefix,
				PrefixLen:     wrapperspb.UInt32(uint32(sourceCIDRRule.prefixLen)),
			},
		},
	}
}

func (r *lbServiceT2Translator) toRBACPermissionHostName(hostnameRule *lbRouteRequestFilteringHostName) *envoy_config_rbac_v3.Permission {
	headerPermRule := &envoy_config_rbac_v3.Permission_Header{
		Header: &envoy_config_route_v3.HeaderMatcher{
			Name: ":authority",
		},
	}

	switch hostnameRule.hostNameType {
	case filterHostnameTypeExact:
		headerPermRule.Header.HeaderMatchSpecifier = &envoy_config_route_v3.HeaderMatcher_ExactMatch{
			ExactMatch: hostnameRule.hostName,
		}
	case filterHostnameTypeSuffix:
		headerPermRule.Header.HeaderMatchSpecifier = &envoy_config_route_v3.HeaderMatcher_SuffixMatch{
			SuffixMatch: hostnameRule.hostName,
		}
	}

	return &envoy_config_rbac_v3.Permission{
		Rule: headerPermRule,
	}
}

func (r *lbServiceT2Translator) toRBACPermissionHTTPPath(httpPathRule *lbRouteRequestFilteringHTTPPath) *envoy_config_rbac_v3.Permission {
	pathMatcherPermRule := &envoy_type_matcher_v3.PathMatcher_Path{
		Path: &envoy_type_matcher_v3.StringMatcher{},
	}

	switch httpPathRule.pathType {
	case filterPathTypeExact:
		pathMatcherPermRule.Path.MatchPattern = &envoy_type_matcher_v3.StringMatcher_Exact{
			Exact: httpPathRule.path,
		}
	case filterPathTypePrefix:
		pathMatcherPermRule.Path.MatchPattern = &envoy_type_matcher_v3.StringMatcher_Prefix{
			Prefix: httpPathRule.path,
		}
	}

	return &envoy_config_rbac_v3.Permission{
		Rule: &envoy_config_rbac_v3.Permission_UrlPath{
			UrlPath: &envoy_type_matcher_v3.PathMatcher{
				Rule: pathMatcherPermRule,
			},
		},
	}
}

func (r *lbServiceT2Translator) toRBACPermissionServerName(serverNameRule lbRouteRequestFilteringHostName) *envoy_config_rbac_v3.Permission {
	serverNameSM := &envoy_type_matcher_v3.StringMatcher{}

	switch serverNameRule.hostNameType {
	case filterHostnameTypeExact:
		serverNameSM.MatchPattern = &envoy_type_matcher_v3.StringMatcher_Exact{
			Exact: serverNameRule.hostName,
		}
	case filterHostnameTypeSuffix:
		serverNameSM.MatchPattern = &envoy_type_matcher_v3.StringMatcher_Suffix{
			Suffix: serverNameRule.hostName,
		}
	}

	return &envoy_config_rbac_v3.Permission{
		Rule: &envoy_config_rbac_v3.Permission_RequestedServerName{
			RequestedServerName: serverNameSM,
		},
	}
}

func (r *lbServiceT2Translator) toRBACPermissionAnd(rules ...*envoy_config_rbac_v3.Permission) *envoy_config_rbac_v3.Permission {
	return &envoy_config_rbac_v3.Permission{
		Rule: &envoy_config_rbac_v3.Permission_AndRules{
			AndRules: &envoy_config_rbac_v3.Permission_Set{
				Rules: rules,
			},
		},
	}
}

func (r *lbServiceT2Translator) toRBACPermissionAny() *envoy_config_rbac_v3.Permission {
	return &envoy_config_rbac_v3.Permission{
		Rule: &envoy_config_rbac_v3.Permission_Any{
			Any: true,
		},
	}
}

func (r *lbServiceT2Translator) toRBACPrincipalAny() *envoy_config_rbac_v3.Principal {
	return &envoy_config_rbac_v3.Principal{
		Identifier: &envoy_config_rbac_v3.Principal_Any{
			Any: true,
		},
	}
}

func (r *lbServiceT2Translator) toRBACAction(ruleType ruleTypeType) envoy_config_rbac_v3.RBAC_Action {
	switch ruleType {
	case ruleTypeAllow:
		return envoy_config_rbac_v3.RBAC_ALLOW
	case ruleTypeDeny:
		return envoy_config_rbac_v3.RBAC_DENY
	default:
		return envoy_config_rbac_v3.RBAC_DENY
	}
}

func (r *lbServiceT2Translator) toNetworkRateLimitFilter(config *lbServiceConnectionRateLimit, namespace string, name string) *envoy_extensions_filters_network_localratelimit_v3.LocalRateLimit {
	if config == nil {
		return nil
	}

	return &envoy_extensions_filters_network_localratelimit_v3.LocalRateLimit{
		StatPrefix: fmt.Sprintf("%s_%s", namespace, name),
		TokenBucket: &envoy_type_v3.TokenBucket{
			MaxTokens:     uint32(config.connections.limit),
			TokensPerFill: wrapperspb.UInt32(uint32(config.connections.limit)),
			FillInterval:  &durationpb.Duration{Seconds: int64(config.connections.timePeriodSeconds)},
		},
	}
}

func (r *lbServiceT2Translator) toHTTPRateLimitFilter(config *lbServiceRequestRateLimit, namespace string, name string) *envoy_extensions_filters_http_localratelimit_v3.LocalRateLimit {
	// We have to provide a ratelimit configuration even if no config available.
	// This is required if the ratelimit is defined as HTTP filter.
	// Also setting to some random defaults (that meet the validation) -
	// the filter won't be enforced in this case.
	tokensPerFill := uint32(100)
	fillIntervalInSeconds := int64(60)
	percentageEnabled := uint32(0)

	if config != nil {
		tokensPerFill = uint32(config.requests.limit)
		fillIntervalInSeconds = int64(config.requests.timePeriodSeconds)
		percentageEnabled = 100
	}

	return &envoy_extensions_filters_http_localratelimit_v3.LocalRateLimit{
		StatPrefix: fmt.Sprintf("%s_%s", namespace, name),
		TokenBucket: &envoy_type_v3.TokenBucket{
			MaxTokens:     tokensPerFill,
			TokensPerFill: wrapperspb.UInt32(tokensPerFill),
			FillInterval:  &durationpb.Duration{Seconds: fillIntervalInSeconds},
		},
		FilterEnabled: &envoy_config_core_v3.RuntimeFractionalPercent{
			DefaultValue: &envoy_type_v3.FractionalPercent{
				Numerator:   percentageEnabled,
				Denominator: envoy_type_v3.FractionalPercent_HUNDRED,
			},
		},
		FilterEnforced: &envoy_config_core_v3.RuntimeFractionalPercent{
			DefaultValue: &envoy_type_v3.FractionalPercent{
				Numerator:   percentageEnabled,
				Denominator: envoy_type_v3.FractionalPercent_HUNDRED,
			},
		},
	}
}

func (r *lbServiceT2Translator) toHTTPRouteBasicAuthFilter(config *lbRouteHTTPBasicAuth) *envoy_config_route_v3.FilterConfig {
	return &envoy_config_route_v3.FilterConfig{
		Disabled: config.disabled,
	}
}

func (r *lbServiceT2Translator) toHTTPRouteJWTAuthFilter(config *lbRouteHTTPJWTAuth) *envoy_extensions_filters_http_jwt_authn_v3.PerRouteConfig {
	return &envoy_extensions_filters_http_jwt_authn_v3.PerRouteConfig{
		RequirementSpecifier: &envoy_extensions_filters_http_jwt_authn_v3.PerRouteConfig_Disabled{
			Disabled: config.disabled,
		},
	}
}

func (r *lbServiceT2Translator) getClusterName(backendName string) string {
	return fmt.Sprintf("backend_cluster_%s", backendName)
}

func (r *lbServiceT2Translator) toXdsResource(m proto.Message, typeUrl string) (ciliumv2.XDSResource, error) {
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
