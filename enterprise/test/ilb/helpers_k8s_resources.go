//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package ilb

import (
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	ossannotation "github.com/cilium/cilium/pkg/annotation"
	ciliumv2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func lbIPPool(name, ipBlock string) *ciliumv2alpha1.CiliumLoadBalancerIPPool {
	return &ciliumv2alpha1.CiliumLoadBalancerIPPool{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: ciliumv2alpha1.CiliumLoadBalancerIPPoolSpec{
			Blocks: []ciliumv2alpha1.CiliumLoadBalancerIPPoolIPBlock{
				{Cidr: ciliumv2alpha1.IPv4orIPv6CIDR(ipBlock)},
			},
		},
	}
}

type httpApplicationOption func(o *isovalentv1alpha1.LBServiceApplicationHTTPProxy)

func withHttpRoute(backendRef string, opts ...httpApplicationRouteOption) httpApplicationOption {
	return func(o *isovalentv1alpha1.LBServiceApplicationHTTPProxy) {
		route := &isovalentv1alpha1.LBServiceHTTPRoute{
			Match: &isovalentv1alpha1.LBServiceHTTPRouteMatch{},
			BackendRef: isovalentv1alpha1.LBServiceBackendRef{
				Name: backendRef,
			},
		}

		for _, opt := range opts {
			opt(route)
		}

		o.Routes = append(o.Routes, *route)
	}
}

type httpApplicationRouteOption func(o *isovalentv1alpha1.LBServiceHTTPRoute)

func withHttpHostname(hostname string) httpApplicationRouteOption {
	return func(o *isovalentv1alpha1.LBServiceHTTPRoute) {
		o.Match.HostNames = []isovalentv1alpha1.LBServiceHostName{isovalentv1alpha1.LBServiceHostName(hostname)}
	}
}

func withHttpPath(path string) httpApplicationRouteOption {
	return func(o *isovalentv1alpha1.LBServiceHTTPRoute) {
		o.Match.Path = &isovalentv1alpha1.LBServiceHTTPPath{
			Exact: &path,
		}
	}
}

func withHttpBackendPersistenceBySourceIP() httpApplicationRouteOption {
	return func(o *isovalentv1alpha1.LBServiceHTTPRoute) {
		o.PersistentBackend = &isovalentv1alpha1.LBServiceHTTPRoutePersistentBackend{
			SourceIP: ptr.To(true),
		}
	}
}

func withHttpBackendPersistenceByCookie(cookieName string) httpApplicationRouteOption {
	return func(o *isovalentv1alpha1.LBServiceHTTPRoute) {
		o.PersistentBackend = &isovalentv1alpha1.LBServiceHTTPRoutePersistentBackend{
			Cookies: []isovalentv1alpha1.LBServiceHTTPRoutePersistentBackendCookie{
				{
					Name: cookieName,
				},
			},
		}
	}
}

func withHttpConnectionFilteringDenyBySourceIP(sourceCIDR string) httpApplicationOption {
	return func(o *isovalentv1alpha1.LBServiceApplicationHTTPProxy) {
		o.ConnectionFiltering = &isovalentv1alpha1.LBServiceHTTPConnectionFiltering{
			RuleType: isovalentv1alpha1.RequestFilteringRuleTypeDeny,
			Rules: []isovalentv1alpha1.LBServiceHTTPConnectionFilteringRule{
				{
					SourceCIDR: &isovalentv1alpha1.LBServiceRequestFilteringRuleSourceCIDR{
						CIDR: sourceCIDR,
					},
				},
			},
		}
	}
}

func withHttpConnectionFilteringAllowBySourceIP(sourceCIDR string) httpApplicationOption {
	return func(o *isovalentv1alpha1.LBServiceApplicationHTTPProxy) {
		o.ConnectionFiltering = &isovalentv1alpha1.LBServiceHTTPConnectionFiltering{
			RuleType: isovalentv1alpha1.RequestFilteringRuleTypeAllow,
			Rules: []isovalentv1alpha1.LBServiceHTTPConnectionFilteringRule{
				{
					SourceCIDR: &isovalentv1alpha1.LBServiceRequestFilteringRuleSourceCIDR{
						CIDR: sourceCIDR,
					},
				},
			},
		}
	}
}

func withHttpsConnectionFilteringDenyBySourceIP(sourceCIDR string) httpsApplicationOption {
	return func(o *isovalentv1alpha1.LBServiceApplicationHTTPSProxy) {
		o.ConnectionFiltering = &isovalentv1alpha1.LBServiceHTTPConnectionFiltering{
			RuleType: isovalentv1alpha1.RequestFilteringRuleTypeDeny,
			Rules: []isovalentv1alpha1.LBServiceHTTPConnectionFilteringRule{
				{
					SourceCIDR: &isovalentv1alpha1.LBServiceRequestFilteringRuleSourceCIDR{
						CIDR: sourceCIDR,
					},
				},
			},
		}
	}
}

func withHttpsConnectionFilteringAllowBySourceIP(sourceCIDR string) httpsApplicationOption {
	return func(o *isovalentv1alpha1.LBServiceApplicationHTTPSProxy) {
		o.ConnectionFiltering = &isovalentv1alpha1.LBServiceHTTPConnectionFiltering{
			RuleType: isovalentv1alpha1.RequestFilteringRuleTypeAllow,
			Rules: []isovalentv1alpha1.LBServiceHTTPConnectionFilteringRule{
				{
					SourceCIDR: &isovalentv1alpha1.LBServiceRequestFilteringRuleSourceCIDR{
						CIDR: sourceCIDR,
					},
				},
			},
		}
	}
}

func withTLSPassthroughConnectionFilteringDenyBySourceIP(sourceCIDR string) tlsPassthroughRouteOption {
	return func(o *isovalentv1alpha1.LBServiceTLSPassthroughRoute) {
		o.ConnectionFiltering = &isovalentv1alpha1.LBServiceTLSRouteConnectionFiltering{
			RuleType: isovalentv1alpha1.RequestFilteringRuleTypeDeny,
			Rules: []isovalentv1alpha1.LBServiceTLSRouteRequestFilteringRule{
				{
					SourceCIDR: &isovalentv1alpha1.LBServiceRequestFilteringRuleSourceCIDR{
						CIDR: sourceCIDR,
					},
				},
			},
		}
	}
}

func withTLSPassthroughConnectionFilteringAllowBySourceIP(sourceCIDR string) tlsPassthroughRouteOption {
	return func(o *isovalentv1alpha1.LBServiceTLSPassthroughRoute) {
		o.ConnectionFiltering = &isovalentv1alpha1.LBServiceTLSRouteConnectionFiltering{
			RuleType: isovalentv1alpha1.RequestFilteringRuleTypeAllow,
			Rules: []isovalentv1alpha1.LBServiceTLSRouteRequestFilteringRule{
				{
					SourceCIDR: &isovalentv1alpha1.LBServiceRequestFilteringRuleSourceCIDR{
						CIDR: sourceCIDR,
					},
				},
			},
		}
	}
}

func withTLSProxyConnectionFilteringDenyBySourceIP(sourceCIDR string) tlsRouteOption {
	return func(o *isovalentv1alpha1.LBServiceTLSRoute) {
		o.ConnectionFiltering = &isovalentv1alpha1.LBServiceTLSRouteConnectionFiltering{
			RuleType: isovalentv1alpha1.RequestFilteringRuleTypeDeny,
			Rules: []isovalentv1alpha1.LBServiceTLSRouteRequestFilteringRule{
				{
					SourceCIDR: &isovalentv1alpha1.LBServiceRequestFilteringRuleSourceCIDR{
						CIDR: sourceCIDR,
					},
				},
			},
		}
	}
}

func withTLSProxyConnectionFilteringAllowBySourceIP(sourceCIDR string) tlsRouteOption {
	return func(o *isovalentv1alpha1.LBServiceTLSRoute) {
		o.ConnectionFiltering = &isovalentv1alpha1.LBServiceTLSRouteConnectionFiltering{
			RuleType: isovalentv1alpha1.RequestFilteringRuleTypeAllow,
			Rules: []isovalentv1alpha1.LBServiceTLSRouteRequestFilteringRule{
				{
					SourceCIDR: &isovalentv1alpha1.LBServiceRequestFilteringRuleSourceCIDR{
						CIDR: sourceCIDR,
					},
				},
			},
		}
	}
}

func withHttpRequestFilteringDenyByExactPath(path string) httpApplicationRouteOption {
	return func(o *isovalentv1alpha1.LBServiceHTTPRoute) {
		o.RequestFiltering = &isovalentv1alpha1.LBServiceHTTPRouteRequestFiltering{
			RuleType: isovalentv1alpha1.RequestFilteringRuleTypeDeny,
			Rules: []isovalentv1alpha1.LBServiceHTTPRouteRequestFilteringRule{
				{
					Path: &isovalentv1alpha1.LBServiceRequestFilteringRuleHTTPPath{
						Exact: &path,
					},
				},
			},
		}
	}
}

func withHttpRequestFilteringDenyByPrefixPath(path string) httpApplicationRouteOption {
	return func(o *isovalentv1alpha1.LBServiceHTTPRoute) {
		o.RequestFiltering = &isovalentv1alpha1.LBServiceHTTPRouteRequestFiltering{
			RuleType: isovalentv1alpha1.RequestFilteringRuleTypeDeny,
			Rules: []isovalentv1alpha1.LBServiceHTTPRouteRequestFilteringRule{
				{
					Path: &isovalentv1alpha1.LBServiceRequestFilteringRuleHTTPPath{
						Prefix: &path,
					},
				},
			},
		}
	}
}

func withHttpRequestFilteringDenyByExactHostname(hostname string) httpApplicationRouteOption {
	return func(o *isovalentv1alpha1.LBServiceHTTPRoute) {
		o.RequestFiltering = &isovalentv1alpha1.LBServiceHTTPRouteRequestFiltering{
			RuleType: isovalentv1alpha1.RequestFilteringRuleTypeDeny,
			Rules: []isovalentv1alpha1.LBServiceHTTPRouteRequestFilteringRule{
				{
					HostName: &isovalentv1alpha1.LBServiceRequestFilteringRuleHTTPHostname{
						Exact: &hostname,
					},
				},
			},
		}
	}
}

func withHttpRequestFilteringDenyBySuffixHostname(hostname string) httpApplicationRouteOption {
	return func(o *isovalentv1alpha1.LBServiceHTTPRoute) {
		o.RequestFiltering = &isovalentv1alpha1.LBServiceHTTPRouteRequestFiltering{
			RuleType: isovalentv1alpha1.RequestFilteringRuleTypeDeny,
			Rules: []isovalentv1alpha1.LBServiceHTTPRouteRequestFilteringRule{
				{
					HostName: &isovalentv1alpha1.LBServiceRequestFilteringRuleHTTPHostname{
						Suffix: &hostname,
					},
				},
			},
		}
	}
}

func withHttpRequestFilteringDenyBySourceIP(sourceCIDR string) httpApplicationRouteOption {
	return func(o *isovalentv1alpha1.LBServiceHTTPRoute) {
		o.RequestFiltering = &isovalentv1alpha1.LBServiceHTTPRouteRequestFiltering{
			RuleType: isovalentv1alpha1.RequestFilteringRuleTypeDeny,
			Rules: []isovalentv1alpha1.LBServiceHTTPRouteRequestFilteringRule{
				{
					SourceCIDR: &isovalentv1alpha1.LBServiceRequestFilteringRuleSourceCIDR{
						CIDR: sourceCIDR,
					},
				},
			},
		}
	}
}

func withHttpRequestFilteringDenyBySourceIPExactHostnameExactPath(sourceCIDR string, hostname string, path string) httpApplicationRouteOption {
	return func(o *isovalentv1alpha1.LBServiceHTTPRoute) {
		o.RequestFiltering = &isovalentv1alpha1.LBServiceHTTPRouteRequestFiltering{
			RuleType: isovalentv1alpha1.RequestFilteringRuleTypeDeny,
			Rules: []isovalentv1alpha1.LBServiceHTTPRouteRequestFilteringRule{
				{
					SourceCIDR: &isovalentv1alpha1.LBServiceRequestFilteringRuleSourceCIDR{
						CIDR: sourceCIDR,
					},
					HostName: &isovalentv1alpha1.LBServiceRequestFilteringRuleHTTPHostname{
						Exact: &hostname,
					},
					Path: &isovalentv1alpha1.LBServiceRequestFilteringRuleHTTPPath{
						Exact: &path,
					},
				},
			},
		}
	}
}

func withHttpRequestFilteringAllowBySourceIPExactHostnameExactPath(sourceCIDR string, hostname string, path string) httpApplicationRouteOption {
	return func(o *isovalentv1alpha1.LBServiceHTTPRoute) {
		o.RequestFiltering = &isovalentv1alpha1.LBServiceHTTPRouteRequestFiltering{
			RuleType: isovalentv1alpha1.RequestFilteringRuleTypeAllow,
			Rules: []isovalentv1alpha1.LBServiceHTTPRouteRequestFilteringRule{
				{
					SourceCIDR: &isovalentv1alpha1.LBServiceRequestFilteringRuleSourceCIDR{
						CIDR: sourceCIDR,
					},
					HostName: &isovalentv1alpha1.LBServiceRequestFilteringRuleHTTPHostname{
						Exact: &hostname,
					},
					Path: &isovalentv1alpha1.LBServiceRequestFilteringRuleHTTPPath{
						Exact: &path,
					},
				},
			},
		}
	}
}

func withHttpConnectionRateLimiting(limit uint, timePeriodSeconds uint) httpApplicationOption {
	return func(o *isovalentv1alpha1.LBServiceApplicationHTTPProxy) {
		o.RateLimits = &isovalentv1alpha1.LBServiceHTTPRateLimits{
			Connections: &isovalentv1alpha1.LBServiceRateLimit{
				Limit:             limit,
				TimePeriodSeconds: timePeriodSeconds,
			},
		}
	}
}

func withHttpRequestRateLimiting(limit uint, timePeriodSeconds uint) httpApplicationRouteOption {
	return func(o *isovalentv1alpha1.LBServiceHTTPRoute) {
		o.RateLimits = &isovalentv1alpha1.LBServiceHTTPRouteRateLimits{
			Requests: &isovalentv1alpha1.LBServiceRateLimit{
				Limit:             limit,
				TimePeriodSeconds: timePeriodSeconds,
			},
		}
	}
}

func withHttpBasicAuth(secretRef string) httpApplicationOption {
	return func(o *isovalentv1alpha1.LBServiceApplicationHTTPProxy) {
		o.Auth = &isovalentv1alpha1.LBServiceHTTPAuth{
			Basic: &isovalentv1alpha1.LBServiceHTTPBasicAuth{
				Users: isovalentv1alpha1.LBServiceHTTPBasicAuthUser{
					SecretRef: isovalentv1alpha1.LBServiceSecretRef{
						Name: secretRef,
					},
				},
			},
		}
	}
}

func withHttpRouteBasicAuth(disabled bool) httpApplicationRouteOption {
	return func(o *isovalentv1alpha1.LBServiceHTTPRoute) {
		o.Auth = &isovalentv1alpha1.LBServiceHTTPRouteAuth{
			Basic: &isovalentv1alpha1.LBServiceHTTPRouteBasicAuth{
				Disabled: disabled,
			},
		}
	}
}

func withHttpJWTAuth(opts ...httpJWTAuthOption) httpApplicationOption {
	return func(o *isovalentv1alpha1.LBServiceApplicationHTTPProxy) {
		o.Auth = &isovalentv1alpha1.LBServiceHTTPAuth{
			JWT: &isovalentv1alpha1.LBServiceHTTPJWTAuth{
				Providers: []isovalentv1alpha1.LBServiceHTTPJWTProvider{},
			},
		}
		for _, opt := range opts {
			opt(o.Auth.JWT)
		}
	}
}

type httpJWTAuthOption func(o *isovalentv1alpha1.LBServiceHTTPJWTAuth)

func withJWTProviderWithLocalJWKS(name string, issuer *string, audiences []string, jwksSecretRef string) httpJWTAuthOption {
	return func(o *isovalentv1alpha1.LBServiceHTTPJWTAuth) {
		o.Providers = append(o.Providers, isovalentv1alpha1.LBServiceHTTPJWTProvider{
			Name:      name,
			Issuer:    issuer,
			Audiences: audiences,
			JWKS: isovalentv1alpha1.LBServiceHTTPJWTAuthJWKS{
				SecretRef: &isovalentv1alpha1.LBServiceSecretRef{
					Name: jwksSecretRef,
				},
			},
		})
	}
}

func withJWTProviderWithRemoteJWKS(name string, issuer *string, audiences []string, uri string) httpJWTAuthOption {
	return func(o *isovalentv1alpha1.LBServiceHTTPJWTAuth) {
		o.Providers = append(o.Providers, isovalentv1alpha1.LBServiceHTTPJWTProvider{
			Name:      name,
			Issuer:    issuer,
			Audiences: audiences,
			JWKS: isovalentv1alpha1.LBServiceHTTPJWTAuthJWKS{
				HTTPURI: &isovalentv1alpha1.LBServiceHTTPURI{
					URI: uri,
				},
			},
		})
	}
}

func withHttpRouteJWTAuth(disabled bool) httpApplicationRouteOption {
	return func(o *isovalentv1alpha1.LBServiceHTTPRoute) {
		o.Auth = &isovalentv1alpha1.LBServiceHTTPRouteAuth{
			JWT: &isovalentv1alpha1.LBServiceHTTPRouteJWTAuth{
				Disabled: disabled,
			},
		}
	}
}

type serviceOption func(o *isovalentv1alpha1.LBService)

func withVIPRef(vipName string) serviceOption {
	return func(o *isovalentv1alpha1.LBService) {
		o.Spec.VIPRef = isovalentv1alpha1.LBServiceVIPRef{
			Name: vipName,
		}
	}
}

func withPort(port int32) serviceOption {
	return func(o *isovalentv1alpha1.LBService) {
		o.Spec.Port = port
	}
}

func withHTTPProxyApplication(opts ...httpApplicationOption) serviceOption {
	return func(o *isovalentv1alpha1.LBService) {
		obj := isovalentv1alpha1.LBServiceApplications{
			HTTPProxy: &isovalentv1alpha1.LBServiceApplicationHTTPProxy{
				Routes: []isovalentv1alpha1.LBServiceHTTPRoute{},
			},
		}

		for _, o := range opts {
			o(obj.HTTPProxy)
		}

		o.Spec.Applications = obj
	}
}

func withProxyProtocol(disallowedVersion []int, tlvs []int) serviceOption {
	return func(o *isovalentv1alpha1.LBService) {
		var dv []isovalentv1alpha1.LBProxyProtocolVersion
		for _, v := range disallowedVersion {
			dv = append(dv, isovalentv1alpha1.LBProxyProtocolVersion(v))
		}

		var pTLVs []isovalentv1alpha1.LBProxyProtocolTLV
		for _, tlv := range tlvs {
			pTLVs = append(pTLVs, isovalentv1alpha1.LBProxyProtocolTLV(tlv))
		}
		o.Spec.ProxyProtocolConfig = &isovalentv1alpha1.LBServiceProxyProtocolConfig{
			DisallowedVersions: dv,
			PassthroughTLVs:    pTLVs,
		}
	}
}

type httpsApplicationOption func(o *isovalentv1alpha1.LBServiceApplicationHTTPSProxy)

func withHttpsRoute(backendRef string, opts ...httpApplicationRouteOption) httpsApplicationOption {
	return func(o *isovalentv1alpha1.LBServiceApplicationHTTPSProxy) {
		route := &isovalentv1alpha1.LBServiceHTTPRoute{
			Match: &isovalentv1alpha1.LBServiceHTTPRouteMatch{},
			BackendRef: isovalentv1alpha1.LBServiceBackendRef{
				Name: backendRef,
			},
		}

		for _, opt := range opts {
			opt(route)
		}

		o.Routes = append(o.Routes, *route)
	}
}

func withCertificate(secretRefName string) httpsApplicationOption {
	return func(o *isovalentv1alpha1.LBServiceApplicationHTTPSProxy) {
		o.TLSConfig.Certificates = append(o.TLSConfig.Certificates, isovalentv1alpha1.LBServiceTLSCertificate{
			SecretRef: isovalentv1alpha1.LBServiceSecretRef{Name: secretRefName},
		})
	}
}

func withHTTPSH2(h2Enabled bool) httpsApplicationOption {
	return func(o *isovalentv1alpha1.LBServiceApplicationHTTPSProxy) {
		o.HTTPConfig.EnableHTTP2 = &h2Enabled
	}
}

func withHTTPSH11(h11Enabled bool) httpsApplicationOption {
	return func(o *isovalentv1alpha1.LBServiceApplicationHTTPSProxy) {
		o.HTTPConfig.EnableHTTP11 = &h11Enabled
	}
}

func withHTTPSProxyApplication(opts ...httpsApplicationOption) serviceOption {
	return func(o *isovalentv1alpha1.LBService) {
		obj := isovalentv1alpha1.LBServiceApplications{
			HTTPSProxy: &isovalentv1alpha1.LBServiceApplicationHTTPSProxy{
				TLSConfig: &isovalentv1alpha1.LBServiceTLSConfig{
					Certificates: []isovalentv1alpha1.LBServiceTLSCertificate{},
				},
				HTTPConfig: &isovalentv1alpha1.LBServiceHTTPConfig{
					EnableHTTP11: ptr.To(true),
					EnableHTTP2:  ptr.To(true),
				},
				Routes: []isovalentv1alpha1.LBServiceHTTPRoute{},
			},
		}

		for _, o := range opts {
			o(obj.HTTPSProxy)
		}

		o.Spec.Applications = obj
	}
}

func withHttpsBasicAuth(secretRef string) httpsApplicationOption {
	return func(o *isovalentv1alpha1.LBServiceApplicationHTTPSProxy) {
		o.Auth = &isovalentv1alpha1.LBServiceHTTPAuth{
			Basic: &isovalentv1alpha1.LBServiceHTTPBasicAuth{
				Users: isovalentv1alpha1.LBServiceHTTPBasicAuthUser{
					SecretRef: isovalentv1alpha1.LBServiceSecretRef{
						Name: secretRef,
					},
				},
			},
		}
	}
}

func withHttpsJWTAuth(opts ...httpJWTAuthOption) httpsApplicationOption {
	return func(o *isovalentv1alpha1.LBServiceApplicationHTTPSProxy) {
		o.Auth = &isovalentv1alpha1.LBServiceHTTPAuth{
			JWT: &isovalentv1alpha1.LBServiceHTTPJWTAuth{
				Providers: []isovalentv1alpha1.LBServiceHTTPJWTProvider{},
			},
		}
		for _, opt := range opts {
			opt(o.Auth.JWT)
		}
	}
}

func withTLSPassthroughApplication(opts ...tlsPassthroughApplicationOption) serviceOption {
	return func(o *isovalentv1alpha1.LBService) {
		app := &isovalentv1alpha1.LBServiceApplicationTLSPassthrough{}

		for _, opt := range opts {
			opt(app)
		}

		o.Spec.Applications = isovalentv1alpha1.LBServiceApplications{
			TLSPassthrough: app,
		}
	}
}

type tlsPassthroughApplicationOption func(o *isovalentv1alpha1.LBServiceApplicationTLSPassthrough)

func withTLSProxyApplication(opts ...tlsProxyApplicationOption) serviceOption {
	return func(o *isovalentv1alpha1.LBService) {
		app := &isovalentv1alpha1.LBServiceApplicationTLSProxy{}

		for _, o := range opts {
			o(app)
		}

		o.Spec.Applications = isovalentv1alpha1.LBServiceApplications{
			TLSProxy: app,
		}
	}
}

type tlsProxyApplicationOption func(o *isovalentv1alpha1.LBServiceApplicationTLSProxy)

func withTLSPassthroughRoute(backendRef string, opts ...tlsPassthroughRouteOption) tlsPassthroughApplicationOption {
	return func(o *isovalentv1alpha1.LBServiceApplicationTLSPassthrough) {
		route := &isovalentv1alpha1.LBServiceTLSPassthroughRoute{
			BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: backendRef},
			Match:      &isovalentv1alpha1.LBServiceTLSPassthroughRouteMatch{},
		}

		for _, o := range opts {
			o(route)
		}

		o.Routes = append(o.Routes, *route)
	}
}

type tlsPassthroughRouteOption func(o *isovalentv1alpha1.LBServiceTLSPassthroughRoute)

func withTLSPassthroughHostname(hostname string) tlsPassthroughRouteOption {
	return func(o *isovalentv1alpha1.LBServiceTLSPassthroughRoute) {
		o.Match.HostNames = []isovalentv1alpha1.LBServiceHostName{
			isovalentv1alpha1.LBServiceHostName(hostname),
		}
	}
}

func withTLSPassthroughConnectionRateLimiting(limit uint, timePeriodSeconds uint) tlsPassthroughRouteOption {
	return func(o *isovalentv1alpha1.LBServiceTLSPassthroughRoute) {
		o.RateLimits = &isovalentv1alpha1.LBServiceTLSRouteRateLimits{
			Connections: &isovalentv1alpha1.LBServiceRateLimit{
				Limit:             limit,
				TimePeriodSeconds: timePeriodSeconds,
			},
		}
	}
}

func withTLSCertificate(secretName string) tlsProxyApplicationOption {
	return func(o *isovalentv1alpha1.LBServiceApplicationTLSProxy) {
		o.TLSConfig = &isovalentv1alpha1.LBServiceTLSConfig{
			Certificates: []isovalentv1alpha1.LBServiceTLSCertificate{
				{SecretRef: isovalentv1alpha1.LBServiceSecretRef{Name: secretName}},
			},
		}
	}
}

func withTLSProxyRoute(backendRef string, opts ...tlsRouteOption) tlsProxyApplicationOption {
	return func(o *isovalentv1alpha1.LBServiceApplicationTLSProxy) {
		route := &isovalentv1alpha1.LBServiceTLSRoute{
			BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: backendRef},
			Match:      &isovalentv1alpha1.LBServiceTLSRouteMatch{},
		}

		for _, o := range opts {
			o(route)
		}

		o.Routes = append(o.Routes, *route)
	}
}

type tlsRouteOption func(o *isovalentv1alpha1.LBServiceTLSRoute)

func withHostname(hostname string) tlsRouteOption {
	return func(o *isovalentv1alpha1.LBServiceTLSRoute) {
		o.Match.HostNames = []isovalentv1alpha1.LBServiceHostName{
			isovalentv1alpha1.LBServiceHostName(hostname),
		}
	}
}

func withTLSProxyConnectionRateLimiting(limit uint, timePeriodSeconds uint) tlsRouteOption {
	return func(o *isovalentv1alpha1.LBServiceTLSRoute) {
		o.RateLimits = &isovalentv1alpha1.LBServiceTLSRouteRateLimits{
			Connections: &isovalentv1alpha1.LBServiceRateLimit{
				Limit:             limit,
				TimePeriodSeconds: timePeriodSeconds,
			},
		}
	}
}

func withTCPProxyApplication(opts ...tcpProxyApplicationOption) serviceOption {
	return func(o *isovalentv1alpha1.LBService) {
		app := &isovalentv1alpha1.LBServiceApplicationTCPProxy{}

		for _, o := range opts {
			o(app)
		}

		o.Spec.Applications = isovalentv1alpha1.LBServiceApplications{
			TCPProxy: app,
		}
	}
}

type tcpProxyApplicationOption func(o *isovalentv1alpha1.LBServiceApplicationTCPProxy)

func withTCPForceDeploymentMode(forceDeploymentMode isovalentv1alpha1.LBTCPProxyForceDeploymentModeType) tcpProxyApplicationOption {
	return func(o *isovalentv1alpha1.LBServiceApplicationTCPProxy) {
		o.ForceDeploymentMode = &forceDeploymentMode
	}
}

func withTCPProxyRoute(backendRef string, opts ...tcpRouteOption) tcpProxyApplicationOption {
	return func(o *isovalentv1alpha1.LBServiceApplicationTCPProxy) {
		route := &isovalentv1alpha1.LBServiceTCPRoute{
			BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: backendRef},
		}

		for _, o := range opts {
			o(route)
		}

		o.Routes = append(o.Routes, *route)
	}
}

type tcpRouteOption func(o *isovalentv1alpha1.LBServiceTCPRoute)

func withUDPProxyApplication(backendRef string, forceDeploymentMode isovalentv1alpha1.LBUDPProxyForceDeploymentModeType) serviceOption {
	return func(o *isovalentv1alpha1.LBService) {
		o.Spec.Applications = isovalentv1alpha1.LBServiceApplications{
			UDPProxy: &isovalentv1alpha1.LBServiceApplicationUDPProxy{
				ForceDeploymentMode: ptr.To(forceDeploymentMode),
				Routes: []isovalentv1alpha1.LBServiceUDPRoute{
					{
						BackendRef: isovalentv1alpha1.LBServiceBackendRef{
							Name: backendRef,
						},
					},
				},
			},
		}
	}
}

func lbService(namespace string, name string, opts ...serviceOption) *isovalentv1alpha1.LBService {
	svc := &isovalentv1alpha1.LBService{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
		Spec: isovalentv1alpha1.LBServiceSpec{
			VIPRef: isovalentv1alpha1.LBServiceVIPRef{
				// use VIP with same name by default
				Name: name,
			},
			Port: 80,
		},
	}

	for _, o := range opts {
		o(svc)
	}

	return svc
}

type backendPoolOption func(o *isovalentv1alpha1.LBBackendPool)

func withIPBackend(ip string, port uint32) backendPoolOption {
	return func(o *isovalentv1alpha1.LBBackendPool) {
		o.Spec.BackendType = isovalentv1alpha1.BackendTypeIP
		o.Spec.Backends = append(o.Spec.Backends, isovalentv1alpha1.Backend{
			IP:     ptr.To(ip),
			Port:   int32(port),
			Weight: ptr.To[uint32](1),
		})
	}
}

func withHostnameBackend(hostname string, port int32) backendPoolOption {
	return func(o *isovalentv1alpha1.LBBackendPool) {
		o.Spec.BackendType = isovalentv1alpha1.BackendTypeHostname
		o.Spec.Backends = append(o.Spec.Backends, isovalentv1alpha1.Backend{
			Host:   ptr.To(hostname),
			Port:   port,
			Weight: ptr.To[uint32](1),
		})
	}
}

func withDNSResolver(ip string, port uint32) backendPoolOption {
	return func(o *isovalentv1alpha1.LBBackendPool) {
		if o.Spec.DNSResolverConfig == nil {
			o.Spec.DNSResolverConfig = &isovalentv1alpha1.DNSResolverConfig{
				Resolvers: []isovalentv1alpha1.DNSResolver{},
			}
		}
		o.Spec.DNSResolverConfig.Resolvers = append(o.Spec.DNSResolverConfig.Resolvers, isovalentv1alpha1.DNSResolver{
			IP:   ip,
			Port: port,
		})
	}
}

func withBackendTLS() backendPoolOption {
	return func(o *isovalentv1alpha1.LBBackendPool) {
		o.Spec.TLSConfig = &isovalentv1alpha1.LBBackendTLSConfig{}
	}
}

func withHealthCheckTLS() backendPoolOption {
	return func(o *isovalentv1alpha1.LBBackendPool) {
		o.Spec.HealthCheck.TLSConfig = &isovalentv1alpha1.LBBackendTLSConfig{}
	}
}

func withProxyProtocolConfig(version int, tlvs []int) backendPoolOption {
	temp := make([]isovalentv1alpha1.LBProxyProtocolTLV, len(tlvs))
	for i, tlv := range tlvs {
		temp[i] = isovalentv1alpha1.LBProxyProtocolTLV(tlv)
	}
	return func(o *isovalentv1alpha1.LBBackendPool) {
		o.Spec.ProxyProtocolConfig = &isovalentv1alpha1.LBBackendPoolProxyProtocolConfig{
			Version:         isovalentv1alpha1.LBProxyProtocolVersion(version),
			PassthroughTLVs: temp,
		}
	}
}

func lbBackendPool(namespace string, name string, opts ...backendPoolOption) *isovalentv1alpha1.LBBackendPool {
	pool := &isovalentv1alpha1.LBBackendPool{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
		Spec: isovalentv1alpha1.LBBackendPoolSpec{
			HealthCheck: isovalentv1alpha1.HealthCheck{
				IntervalSeconds: ptr.To[int32](15),
				HTTP: &isovalentv1alpha1.HealthCheckHTTP{
					Path: ptr.To("/health"),
				},
			},
			Backends: []isovalentv1alpha1.Backend{},
		},
	}

	for _, o := range opts {
		o(pool)
	}

	return pool
}

type vipOption func(o *isovalentv1alpha1.LBVIP)

func withRequestedIPv4(ipv4 string) vipOption {
	return func(o *isovalentv1alpha1.LBVIP) {
		o.Spec.IPv4Request = &ipv4
	}
}

func lbVIP(namespace string, name string, opts ...vipOption) *isovalentv1alpha1.LBVIP {
	obj := &isovalentv1alpha1.LBVIP{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
		Spec: isovalentv1alpha1.LBVIPSpec{},
	}

	for _, o := range opts {
		o(obj)
	}

	return obj
}

func bgpClusterConfig(name string) *isovalentv1alpha1.IsovalentBGPClusterConfig {
	obj := &isovalentv1alpha1.IsovalentBGPClusterConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: isovalentv1alpha1.IsovalentBGPClusterConfigSpec{
			NodeSelector: &slimv1.LabelSelector{
				MatchLabels: map[string]slimv1.MatchLabelsValue{
					ossannotation.ServiceNodeExposure: "t1",
				},
			},
			BGPInstances: []isovalentv1alpha1.IsovalentBGPInstance{
				{
					Name:     "t1",
					LocalASN: ptr.To[int64](64512),
				},
			},
		},
	}

	return obj
}

func tlsSecret(namespace, name string, key, cert []byte) *v1.Secret {
	return &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
		Type: v1.SecretTypeTLS,
		Data: map[string][]byte{
			"tls.key": key,
			"tls.crt": cert,
		},
	}
}

func caSecret(namespace, name string, cert []byte) *v1.Secret {
	return &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
		Type: v1.SecretTypeOpaque,
		Data: map[string][]byte{
			"ca.crt": cert,
		},
	}
}
