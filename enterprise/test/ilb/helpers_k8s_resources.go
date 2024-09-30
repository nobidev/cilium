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

func lbServiceApplicationsHTTPSProxy(backendRef, secretName, hostName string, opts ...httpsApplicationOption) isovalentv1alpha1.LBServiceApplications {
	obj := isovalentv1alpha1.LBServiceApplications{
		HTTPSProxy: &isovalentv1alpha1.LBServiceApplicationHTTPSProxy{
			TLSConfig: &isovalentv1alpha1.LBServiceTLSConfig{
				Certificates: []isovalentv1alpha1.LBServiceTLSCertificate{
					{SecretRef: isovalentv1alpha1.LBServiceSecretRef{Name: secretName}},
				},
			},
			HTTPConfig: &isovalentv1alpha1.LBServiceHTTPConfig{
				EnableHTTP11: ptr.To(true),
				EnableHTTP2:  ptr.To(true),
			},
			Routes: []isovalentv1alpha1.LBServiceHTTPRoute{
				{
					BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: backendRef},
					Match: &isovalentv1alpha1.LBServiceHTTPRouteMatch{
						HostNames: []isovalentv1alpha1.LBServiceHostName{
							isovalentv1alpha1.LBServiceHostName(hostName),
						},
					},
				},
			},
		},
	}

	for _, o := range opts {
		o(obj.HTTPSProxy)
	}

	return obj
}

type httpApplicationOption func(o *isovalentv1alpha1.LBServiceApplicationHTTPProxy)

func withHttpHostname(hostname string) httpApplicationOption {
	return func(o *isovalentv1alpha1.LBServiceApplicationHTTPProxy) {
		o.Routes[0].Match = &isovalentv1alpha1.LBServiceHTTPRouteMatch{
			HostNames: []isovalentv1alpha1.LBServiceHostName{isovalentv1alpha1.LBServiceHostName(hostname)},
		}
	}
}

func withHttpPath(path string) httpApplicationOption {
	return func(o *isovalentv1alpha1.LBServiceApplicationHTTPProxy) {
		o.Routes[0].Match.Path = &isovalentv1alpha1.LBServiceHTTPPath{
			Exact: &path,
		}
	}
}

func withHttpBackendPersistenceBySourceIP() httpApplicationOption {
	return func(o *isovalentv1alpha1.LBServiceApplicationHTTPProxy) {
		o.Routes[0].PersistentBackend = &isovalentv1alpha1.LBServiceHTTPRoutePersistentBackend{
			SourceIP: ptr.To(true),
		}
	}
}

func withHttpBackendPersistenceByCookie(cookieName string) httpApplicationOption {
	return func(o *isovalentv1alpha1.LBServiceApplicationHTTPProxy) {
		o.Routes[0].PersistentBackend = &isovalentv1alpha1.LBServiceHTTPRoutePersistentBackend{
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

func withHttpRequestFilteringDenyByExactPath(path string) httpApplicationOption {
	return func(o *isovalentv1alpha1.LBServiceApplicationHTTPProxy) {
		o.Routes[0].RequestFiltering = &isovalentv1alpha1.LBServiceHTTPRouteRequestFiltering{
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

func withHttpRequestFilteringDenyByPrefixPath(path string) httpApplicationOption {
	return func(o *isovalentv1alpha1.LBServiceApplicationHTTPProxy) {
		o.Routes[0].RequestFiltering = &isovalentv1alpha1.LBServiceHTTPRouteRequestFiltering{
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

func withHttpRequestFilteringDenyByExactHostname(hostname string) httpApplicationOption {
	return func(o *isovalentv1alpha1.LBServiceApplicationHTTPProxy) {
		o.Routes[0].RequestFiltering = &isovalentv1alpha1.LBServiceHTTPRouteRequestFiltering{
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

func withHttpRequestFilteringDenyBySuffixHostname(hostname string) httpApplicationOption {
	return func(o *isovalentv1alpha1.LBServiceApplicationHTTPProxy) {
		o.Routes[0].RequestFiltering = &isovalentv1alpha1.LBServiceHTTPRouteRequestFiltering{
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

func withHttpRequestFilteringDenyBySourceIP(sourceCIDR string) httpApplicationOption {
	return func(o *isovalentv1alpha1.LBServiceApplicationHTTPProxy) {
		o.Routes[0].RequestFiltering = &isovalentv1alpha1.LBServiceHTTPRouteRequestFiltering{
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

func withHttpRequestFilteringDenyBySourceIPExactHostnameExactPath(sourceCIDR string, hostname string, path string) httpApplicationOption {
	return func(o *isovalentv1alpha1.LBServiceApplicationHTTPProxy) {
		o.Routes[0].RequestFiltering = &isovalentv1alpha1.LBServiceHTTPRouteRequestFiltering{
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

func withHttpRequestFilteringAllowBySourceIPExactHostnameExactPath(sourceCIDR string, hostname string, path string) httpApplicationOption {
	return func(o *isovalentv1alpha1.LBServiceApplicationHTTPProxy) {
		o.Routes[0].RequestFiltering = &isovalentv1alpha1.LBServiceHTTPRouteRequestFiltering{
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

func lbServiceApplicationsHTTPProxy(backendRef string, opts ...httpApplicationOption) isovalentv1alpha1.LBServiceApplications {
	obj := isovalentv1alpha1.LBServiceApplications{
		HTTPProxy: &isovalentv1alpha1.LBServiceApplicationHTTPProxy{
			Routes: []isovalentv1alpha1.LBServiceHTTPRoute{
				{
					BackendRef: isovalentv1alpha1.LBServiceBackendRef{
						Name: backendRef,
					},
				},
			},
		},
	}

	for _, o := range opts {
		o(obj.HTTPProxy)
	}

	return obj
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

func withHTTPProxyApplication(backendRef string, opts ...httpApplicationOption) serviceOption {
	return func(o *isovalentv1alpha1.LBService) {
		o.Spec.Applications = lbServiceApplicationsHTTPProxy(backendRef, opts...)
	}
}

type httpsApplicationOption func(o *isovalentv1alpha1.LBServiceApplicationHTTPSProxy)

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

func withHTTPSProxyApplication(backendRef, secretName, hostName string, opts ...httpsApplicationOption) serviceOption {
	return func(o *isovalentv1alpha1.LBService) {
		o.Spec.Applications = lbServiceApplicationsHTTPSProxy(backendRef, secretName, hostName, opts...)
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

func withBackend(ip string, port int32) backendPoolOption {
	return func(o *isovalentv1alpha1.LBBackendPool) {
		o.Spec.Backends = append(o.Spec.Backends, isovalentv1alpha1.Backend{
			IP:     ip,
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

func bgpPeeringPolicy(name string) *ciliumv2alpha1.CiliumBGPPeeringPolicy {
	obj := &ciliumv2alpha1.CiliumBGPPeeringPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: ciliumv2alpha1.CiliumBGPPeeringPolicySpec{
			NodeSelector: &slimv1.LabelSelector{
				MatchLabels: map[string]slimv1.MatchLabelsValue{
					ossannotation.ServiceNodeExposure: "t1",
				},
			},
			VirtualRouters: []ciliumv2alpha1.CiliumBGPVirtualRouter{
				{
					LocalASN: 64512,
					ServiceSelector: &slimv1.LabelSelector{
						MatchExpressions: []slimv1.LabelSelectorRequirement{
							{
								Key:      "somekey",
								Operator: slimv1.LabelSelectorOpNotIn,
								Values:   []string{"never-used-value"},
							},
						},
					},
					Neighbors: []ciliumv2alpha1.CiliumBGPNeighbor{
						// Create a dummy neighbor until we switch to BGPv2
						{
							PeerAddress:             "0.0.0.0/0",
							ConnectRetryTimeSeconds: ptr.To(int32(1)),
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
