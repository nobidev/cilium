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

func lbServiceApplicationsTLSProxy(backendRef, secretName, hostName string) isovalentv1alpha1.LBServiceApplications {
	return isovalentv1alpha1.LBServiceApplications{
		TLSProxy: &isovalentv1alpha1.LBServiceApplicationTLSProxy{
			TLSConfig: &isovalentv1alpha1.LBServiceTLSConfig{
				Certificates: []isovalentv1alpha1.LBServiceTLSCertificate{
					{SecretRef: isovalentv1alpha1.LBServiceSecretRef{Name: secretName}},
				},
			},
			Routes: []isovalentv1alpha1.LBServiceTLSRoute{
				{
					BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: backendRef},
					Match: &isovalentv1alpha1.LBServiceTLSRouteMatch{
						HostNames: []isovalentv1alpha1.LBServiceHostName{
							isovalentv1alpha1.LBServiceHostName(hostName),
						},
					},
				},
			},
		},
	}
}

func lbServiceApplicationsTLSPassthrough(routes []isovalentv1alpha1.LBServiceTLSPassthroughRoute) isovalentv1alpha1.LBServiceApplications {
	return isovalentv1alpha1.LBServiceApplications{
		TLSPassthrough: &isovalentv1alpha1.LBServiceApplicationTLSPassthrough{
			Routes: routes,
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

func withTLSPassthroughApplication(routes []isovalentv1alpha1.LBServiceTLSPassthroughRoute) serviceOption {
	return func(o *isovalentv1alpha1.LBService) {
		o.Spec.Applications = lbServiceApplicationsTLSPassthrough(routes)
	}
}

func withTLSProxyApplication(backendRef, secretName, hostName string) serviceOption {
	return func(o *isovalentv1alpha1.LBService) {
		o.Spec.Applications = lbServiceApplicationsTLSProxy(backendRef, secretName, hostName)
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

func lbBackendPool(namespace string, name string, opts ...backendPoolOption) *isovalentv1alpha1.LBBackendPool {
	pool := &isovalentv1alpha1.LBBackendPool{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
		Spec: isovalentv1alpha1.LBBackendPoolSpec{
			HealthCheck: isovalentv1alpha1.HealthCheck{
				IntervalSeconds: ptr.To[int32](5),
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

func bgpPeerConfig(name string) *isovalentv1alpha1.IsovalentBGPPeerConfig {
	obj := &isovalentv1alpha1.IsovalentBGPPeerConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: isovalentv1alpha1.IsovalentBGPPeerConfigSpec{
			CiliumBGPPeerConfigSpec: ciliumv2alpha1.CiliumBGPPeerConfigSpec{
				Families: []ciliumv2alpha1.CiliumBGPFamilyWithAdverts{
					{
						CiliumBGPFamily: ciliumv2alpha1.CiliumBGPFamily{
							Afi:  "ipv4",
							Safi: "unicast",
						},
						Advertisements: &slimv1.LabelSelector{
							MatchLabels: map[string]slimv1.MatchLabelsValue{
								"advertise": "bgp-" + name,
							},
						},
					},
				},
				Timers: &ciliumv2alpha1.CiliumBGPTimers{
					ConnectRetryTimeSeconds: ptr.To(int32(1)),
				},
			},
			BFDProfileRef: &name,
		},
	}

	return obj
}

func bgpAdvertisement(name string, vips []string) *isovalentv1alpha1.IsovalentBGPAdvertisement {
	obj := &isovalentv1alpha1.IsovalentBGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				"advertise": "bgp-" + name,
			},
		},
		Spec: isovalentv1alpha1.IsovalentBGPAdvertisementSpec{
			Advertisements: []isovalentv1alpha1.BGPAdvertisement{
				{
					AdvertisementType: isovalentv1alpha1.BGPServiceAdvert,
					Service: &ciliumv2alpha1.BGPServiceOptions{
						Addresses: []ciliumv2alpha1.BGPServiceAddressType{
							ciliumv2alpha1.BGPLoadBalancerIPAddr,
						},
					},
					Selector: &slimv1.LabelSelector{
						MatchExpressions: []slimv1.LabelSelectorRequirement{
							{
								Key:      "loadbalancer.isovalent.com/vip-name",
								Operator: slimv1.LabelSelectorOpIn,
								Values:   vips,
							},
						},
					},
				},
			},
		},
	}

	return obj
}

func bfdProfile(name string) *isovalentv1alpha1.IsovalentBFDProfile {
	detectMultiplier := int32(3)
	receiveIntervalMilliseconds := int32(300)
	transmitIntervalMilliseconds := int32(300)

	return &isovalentv1alpha1.IsovalentBFDProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: isovalentv1alpha1.BFDProfileSpec{
			DetectMultiplier:             &detectMultiplier,
			ReceiveIntervalMilliseconds:  &receiveIntervalMilliseconds,
			TransmitIntervalMilliseconds: &transmitIntervalMilliseconds,
		},
	}
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
