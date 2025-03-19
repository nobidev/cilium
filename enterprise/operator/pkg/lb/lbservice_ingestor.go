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
	"math/big"
	"net"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

type ingestor struct{}

func (r *ingestor) ingest(vip *isovalentv1alpha1.LBVIP, lbsvc *isovalentv1alpha1.LBService, backends []*isovalentv1alpha1.LBBackendPool, t1Service *corev1.Service, t1NodeIPs []string, t2NodeIPs []string, referencedSecrets map[string]*corev1.Secret) *lbService {
	referencedBackends := r.toReferencedBackends(backends)

	return &lbService{
		namespace: lbsvc.Namespace,
		name:      lbsvc.Name,
		vip: lbVIP{
			name:         lbsvc.Spec.VIPRef.Name,
			assignedIPv4: getAssignedIP(vip),
			bindStatus:   getVIPBindStatus(t1Service),
		},
		port:                lbsvc.Spec.Port,
		proxyProtocolConfig: r.toServiceProxyProtocolConfig(lbsvc.Spec.ProxyProtocolConfig),
		applications:        r.toApplications(lbsvc, referencedBackends, referencedSecrets),
		referencedBackends:  referencedBackends,
		t1NodeIPs:           t1NodeIPs,
		t2NodeIPs:           t2NodeIPs,
	}
}

func (*ingestor) toHTTPConfig(httpConfig *isovalentv1alpha1.LBServiceHTTPConfig) *lbServiceHTTPConfig {
	http11Enabled := true
	http2Enabled := true

	if httpConfig != nil && httpConfig.EnableHTTP11 != nil {
		http11Enabled = *httpConfig.EnableHTTP11
	}

	if httpConfig != nil && httpConfig.EnableHTTP2 != nil {
		http2Enabled = *httpConfig.EnableHTTP2
	}

	return &lbServiceHTTPConfig{
		enableHTTP11: http11Enabled,
		enableHTTP2:  http2Enabled,
	}
}

func (*ingestor) toTLSConfig(tlsConfig isovalentv1alpha1.LBServiceTLSConfig) lbServiceTLSConfig {
	certificateSecretNames := []string{}
	for _, c := range tlsConfig.Certificates {
		certificateSecretNames = append(certificateSecretNames, c.SecretRef.Name)
	}

	validationContextSecret := ""
	validationContextSubjectAlternativeNames := []string{}

	if tlsConfig.Validation != nil {
		validationContextSecret = tlsConfig.Validation.SecretRef.Name

		for _, san := range tlsConfig.Validation.SubjectAlternativeNames {
			validationContextSubjectAlternativeNames = append(validationContextSubjectAlternativeNames, san.Exact)
		}
	}

	minTLSVersion := ""
	if tlsConfig.MinTLSVersion != nil {
		minTLSVersion = string(*tlsConfig.MinTLSVersion)
	}

	maxTLSVersion := ""
	if tlsConfig.MaxTLSVersion != nil {
		maxTLSVersion = string(*tlsConfig.MaxTLSVersion)
	}

	allowedCipherSuites := []string{}
	for _, cs := range tlsConfig.AllowedCipherSuites {
		allowedCipherSuites = append(allowedCipherSuites, string(cs))
	}

	allowedECDHCurves := []string{}
	for _, ec := range tlsConfig.AllowedECDHCurves {
		allowedECDHCurves = append(allowedECDHCurves, string(ec))
	}

	allowedSignatureAlgorithms := []string{}
	for _, sa := range tlsConfig.AllowedSignatureAlgorithms {
		allowedSignatureAlgorithms = append(allowedSignatureAlgorithms, string(sa))
	}

	return lbServiceTLSConfig{
		certificateSecrets: certificateSecretNames,
		validationContext: lbServiceTLSConfigValidationContext{
			trustedCASecretName:     validationContextSecret,
			subjectAlternativeNames: validationContextSubjectAlternativeNames,
		},
		minTLSVersion:              minTLSVersion,
		maxTLSVersion:              maxTLSVersion,
		allowedCipherSuites:        allowedCipherSuites,
		allowedECDHCurves:          allowedECDHCurves,
		allowedSignatureAlgorithms: allowedSignatureAlgorithms,
	}
}

func (r *ingestor) toReferencedBackends(backends []*isovalentv1alpha1.LBBackendPool) map[string]backend {
	referencedBackends := map[string]backend{}

	for _, b := range backends {
		referencedBackends[b.Name] = backend{
			name:        b.Name,
			typ:         r.toBackendType(b.Spec.BackendType),
			lbBackends:  r.toBackends(b.Spec.BackendType, b.Spec.Backends),
			lbAlgorithm: r.toLBBackendAlgorithm(b.Spec.Loadbalancing),
			healthCheckConfig: lbBackendHealthCheckConfig{
				http:                         r.toHTTPHealthCheck(&b.Spec.HealthCheck),
				tcp:                          r.toTCPHealthCheck(&b.Spec.HealthCheck),
				tlsConfig:                    r.toBackendTLSConfig(b.Spec.HealthCheck.TLSConfig),
				intervalSeconds:              int(*b.Spec.HealthCheck.IntervalSeconds),
				timeoutSeconds:               int(*b.Spec.HealthCheck.TimeoutSeconds),
				healthyThreshold:             int(*b.Spec.HealthCheck.HealthyThreshold),
				unhealthyThreshold:           int(*b.Spec.HealthCheck.UnhealthyThreshold),
				unhealthyEdgeIntervalSeconds: int(*b.Spec.HealthCheck.IntervalSeconds),
				unhealthyIntervalSeconds:     int(*b.Spec.HealthCheck.IntervalSeconds),
			},
			tcpConfig:         r.toBackendTCPConfig(b.Spec.TCPConfig),
			tlsConfig:         r.toBackendTLSConfig(b.Spec.TLSConfig),
			httpConfig:        r.toBackendHTTPConfig(b.Spec.HTTPConfig),
			dnsResolverConfig: r.toDNSResolverConfig(b.Spec.DNSResolverConfig),
			proxyProtocol:     r.toBackendProxyProtocolConfig(b.Spec.ProxyProtocolConfig),
		}
	}

	return referencedBackends
}

func (r *ingestor) toApplications(lbsvc *isovalentv1alpha1.LBService, referencedBackends map[string]backend, referencedSecrets map[string]*corev1.Secret) lbApplications {
	return lbApplications{
		httpProxy:      r.toApplicationHTTP(lbsvc, referencedBackends, referencedSecrets),
		httpsProxy:     r.toApplicationHTTPS(lbsvc, referencedBackends, referencedSecrets),
		tlsPassthrough: r.toApplicationTLSPassthrough(lbsvc, referencedBackends),
		tlsProxy:       r.toApplicationTLSProxy(lbsvc, referencedBackends),
		tcpProxy:       r.toApplicationTCPProxy(lbsvc, referencedBackends),
		udpProxy:       r.toApplicationUDPProxy(lbsvc, referencedBackends),
	}
}

func (r *ingestor) toApplicationHTTP(lbsvc *isovalentv1alpha1.LBService, referencedBackends map[string]backend, referencedSecrets map[string]*corev1.Secret) *lbApplicationHTTPProxy {
	if lbsvc.Spec.Applications.HTTPProxy == nil {
		return nil
	}

	routes := map[string][]lbRouteHTTP{}

	for _, lr := range lbsvc.Spec.Applications.HTTPProxy.Routes {
		if _, ok := referencedBackends[lr.BackendRef.Name]; !ok {
			// backend not present yet
			continue
		}

		pathType, path := toPath(lr.Match)

		httpRoute := lbRouteHTTP{
			match: lbRouteHTTPMatch{
				pathType: pathType,
				path:     path,
			},
			backendRef:        backendRef{name: lr.BackendRef.Name},
			persistentBackend: r.toHTTPPersistentBackendConfig(lr.PersistentBackend),
			requestFiltering:  r.toHTTPRouteRequestFilteringConfig(lr.RequestFiltering),
			rateLimits:        r.toHTTPRouteRateLimits(lr.RateLimits),
			auth:              r.toHTTPRouteAuth(lr.Auth),
		}

		if lr.Match == nil || len(lr.Match.HostNames) == 0 {
			routes["*"] = append(routes["*"], httpRoute)
			continue
		}

		// assigning the route to all hostnames
		for _, h := range lr.Match.HostNames {
			routes[string(h)] = append(routes[string(h)], httpRoute)
		}
	}

	return &lbApplicationHTTPProxy{
		httpConfig:          r.toHTTPConfig(lbsvc.Spec.Applications.HTTPProxy.HTTPConfig),
		connectionFiltering: r.toHTTPConnectionFilteringConfig(lbsvc.Spec.Applications.HTTPProxy.ConnectionFiltering),
		rateLimits:          r.toHTTPRateLimits(lbsvc.Spec.Applications.HTTPProxy.RateLimits),
		auth:                r.toHTTPAuth(lbsvc.Spec.Applications.HTTPProxy.Auth, referencedSecrets),
		routes:              routes,
	}
}

func (r *ingestor) toApplicationHTTPS(lbsvc *isovalentv1alpha1.LBService, referencedBackends map[string]backend, referencedSecrets map[string]*corev1.Secret) *lbApplicationHTTPSProxy {
	if lbsvc.Spec.Applications.HTTPSProxy == nil {
		return nil
	}

	routes := map[string][]lbRouteHTTP{}

	for _, lr := range lbsvc.Spec.Applications.HTTPSProxy.Routes {
		if _, ok := referencedBackends[lr.BackendRef.Name]; !ok {
			// backend not present yet
			continue
		}

		pathType, path := toPath(lr.Match)

		httpRoute := lbRouteHTTP{
			match: lbRouteHTTPMatch{
				pathType: pathType,
				path:     path,
			},
			backendRef:        backendRef{name: lr.BackendRef.Name},
			persistentBackend: r.toHTTPPersistentBackendConfig(lr.PersistentBackend),
			requestFiltering:  r.toHTTPRouteRequestFilteringConfig(lr.RequestFiltering),
			rateLimits:        r.toHTTPRouteRateLimits(lr.RateLimits),
			auth:              r.toHTTPRouteAuth(lr.Auth),
		}

		if lr.Match == nil || len(lr.Match.HostNames) == 0 {
			routes["*"] = append(routes["*"], httpRoute)
			continue
		}

		// assigning the route to all hostnames
		for _, h := range lr.Match.HostNames {
			routes[string(h)] = append(routes[string(h)], httpRoute)
		}
	}

	return &lbApplicationHTTPSProxy{
		httpConfig:          r.toHTTPConfig(lbsvc.Spec.Applications.HTTPSProxy.HTTPConfig),
		tlsConfig:           r.toTLSConfig(lbsvc.Spec.Applications.HTTPSProxy.TLSConfig),
		connectionFiltering: r.toHTTPConnectionFilteringConfig(lbsvc.Spec.Applications.HTTPSProxy.ConnectionFiltering),
		rateLimits:          r.toHTTPRateLimits(lbsvc.Spec.Applications.HTTPSProxy.RateLimits),
		auth:                r.toHTTPAuth(lbsvc.Spec.Applications.HTTPSProxy.Auth, referencedSecrets),
		routes:              routes,
	}
}

func toPath(match *isovalentv1alpha1.LBServiceHTTPRouteMatch) (routePathTypeType, string) {
	pathType := routePathTypePrefix
	path := "/"

	if match != nil && match.Path != nil {
		if match.Path.Prefix != nil {
			pathType = routePathTypePrefix
			path = *match.Path.Prefix
		} else if match.Path.Exact != nil {
			pathType = routePathTypeExact
			path = *match.Path.Exact
		}
	}

	return pathType, path
}

func (r *ingestor) toApplicationTLSPassthrough(lbsvc *isovalentv1alpha1.LBService, referencedBackends map[string]backend) *lbApplicationTLSPassthrough {
	if lbsvc.Spec.Applications.TLSPassthrough == nil {
		return nil
	}

	routes := []lbRouteTLSPassthrough{}

	for _, lr := range lbsvc.Spec.Applications.TLSPassthrough.Routes {
		if _, ok := referencedBackends[lr.BackendRef.Name]; !ok {
			// backend not present yet
			continue
		}

		routes = append(routes, lbRouteTLSPassthrough{
			match: lbRouteTLSPassthroughMatch{
				hostNames: r.toTLSPassthroughHostNames(lr.Match),
			},
			backendRef:          backendRef{name: lr.BackendRef.Name},
			persistentBackend:   r.toTLSPersistentBackendConfig(lr.PersistentBackend),
			connectionFiltering: r.toTLSRequestFilteringConfig(lr.ConnectionFiltering),
			rateLimits:          r.toTLSRateLimits(lr.RateLimits),
		})
	}

	return &lbApplicationTLSPassthrough{
		routes: routes,
	}
}

func (r *ingestor) toApplicationTLSProxy(lbsvc *isovalentv1alpha1.LBService, referencedBackends map[string]backend) *lbApplicationTLSProxy {
	app := lbsvc.Spec.Applications.TLSProxy
	if app == nil {
		return nil
	}

	routes := []lbRouteTLSProxy{}
	for _, lr := range app.Routes {
		if _, ok := referencedBackends[lr.BackendRef.Name]; !ok {
			// backend not present yet
			continue
		}

		routes = append(routes, lbRouteTLSProxy{
			match: lbRouteTLSProxyMatch{
				hostNames: r.toTLSProxyHostNames(lr.Match),
			},
			backendRef:          backendRef{name: lr.BackendRef.Name},
			persistentBackend:   r.toTLSPersistentBackendConfig(lr.PersistentBackend),
			connectionFiltering: r.toTLSRequestFilteringConfig(lr.ConnectionFiltering),
			rateLimits:          r.toTLSRateLimits(lr.RateLimits),
		})
	}
	return &lbApplicationTLSProxy{
		tlsConfig: r.toTLSConfig(app.TLSConfig),
		routes:    routes,
	}
}

func (r *ingestor) toApplicationTCPProxy(lbsvc *isovalentv1alpha1.LBService, referencedBackends map[string]backend) *lbApplicationTCPProxy {
	app := lbsvc.Spec.Applications.TCPProxy
	if app == nil {
		return nil
	}

	routes := []lbRouteTCPProxy{}
	for _, lr := range app.Routes {
		if _, ok := referencedBackends[lr.BackendRef.Name]; !ok {
			// backend not present yet
			continue
		}

		routes = append(routes, lbRouteTCPProxy{
			backendRef:          backendRef{name: lr.BackendRef.Name},
			persistentBackend:   r.toTCPPersistentBackendConfig(lr.PersistentBackend),
			connectionFiltering: r.toTCPRequestFilteringConfig(lr.ConnectionFiltering),
			rateLimits:          r.toTCPRateLimits(lr.RateLimits),
		})
	}

	return &lbApplicationTCPProxy{
		tierMode: r.mapTCPProxyTierMode(app, referencedBackends),
		routes:   routes,
	}
}

func (r *ingestor) toApplicationUDPProxy(lbsvc *isovalentv1alpha1.LBService, referencedBackends map[string]backend) *lbApplicationUDPProxy {
	app := lbsvc.Spec.Applications.UDPProxy
	if app == nil {
		return nil
	}

	routes := []lbRouteUDPProxy{}
	for _, lr := range app.Routes {
		if _, ok := referencedBackends[lr.BackendRef.Name]; !ok {
			// backend not present yet
			continue
		}

		routes = append(routes, lbRouteUDPProxy{
			backendRef:          backendRef{name: lr.BackendRef.Name},
			persistentBackend:   r.toUDPPersistentBackendConfig(lr.PersistentBackend),
			connectionFiltering: r.toUDPRequestFilteringConfig(lr.ConnectionFiltering),
		})
	}

	return &lbApplicationUDPProxy{
		tierMode: r.mapUDPProxyTierMode(app, referencedBackends),
		routes:   routes,
	}
}

func (r *ingestor) toHTTPHealthCheck(hc *isovalentv1alpha1.HealthCheck) *lbBackendHealthCheckHTTPConfig {
	if hc.HTTP == nil {
		return nil
	}

	return &lbBackendHealthCheckHTTPConfig{
		host: *hc.HTTP.Host,
		path: *hc.HTTP.Path,
	}
}

func (r *ingestor) toTCPHealthCheck(hc *isovalentv1alpha1.HealthCheck) *lbBackendHealthCheckTCPConfig {
	if hc.TCP == nil {
		return nil
	}

	return &lbBackendHealthCheckTCPConfig{}
}

func (r *ingestor) toBackendType(backendType isovalentv1alpha1.BackendType) lbBackendType {
	switch backendType {
	case isovalentv1alpha1.BackendTypeIP:
		return lbBackendTypeIP
	case isovalentv1alpha1.BackendTypeHostname:
		return lbBackendTypeHostname
	default:
		return lbBackendTypeIP
	}
}

func (r *ingestor) toBackends(typ isovalentv1alpha1.BackendType, backends []isovalentv1alpha1.Backend) []lbBackend {
	ret := []lbBackend{}

	for _, backend := range backends {
		weight := uint32(1)
		if backend.Weight != nil {
			weight = *backend.Weight
		}

		status := lbBackendStatusHealthChecking
		if backend.Status != nil && *backend.Status == isovalentv1alpha1.BackendStatusDraining {
			status = lbBackendStatusDraining
		}

		var address string
		switch typ {
		case isovalentv1alpha1.BackendTypeIP:
			address = *backend.IP
		case isovalentv1alpha1.BackendTypeHostname:
			address = *backend.Host
			// FIXME: This is a workaround for the issue that no_default_search_domain
			// of Envoy is broken (https://github.com/envoyproxy/envoy/issues/33138).
			// This leads to the situation that the default search domain is mistakenly
			// appended to the hostname. This workaround is to append a dot to the hostname
			// make it fully qualified.
			if !strings.HasSuffix(address, ".") {
				address = address + "."
			}
		default:
			address = *backend.IP
		}

		ret = append(ret, lbBackend{
			address: address,
			port:    uint32(backend.Port),
			weight:  weight,
			status:  status,
		})
	}

	return ret
}

func (r *ingestor) toLBBackendAlgorithm(loadbalancing *isovalentv1alpha1.Loadbalancing) lbBackendLBAlgorithm {
	switch {
	case loadbalancing == nil:
		return lbBackendLBAlgorithm{algorithm: lbAlgorithmRoundRobin}
	case loadbalancing.Algorithm.RoundRobin != nil:
		return lbBackendLBAlgorithm{algorithm: lbAlgorithmRoundRobin}
	case loadbalancing.Algorithm.LeastRequest != nil:
		return lbBackendLBAlgorithm{algorithm: lbAlgorithmLeastRequest}
	case loadbalancing.Algorithm.ConsistentHashing != nil:
		maglevTableSize := uint32(65537)

		if loadbalancing.Algorithm.ConsistentHashing.Algorithm != nil && loadbalancing.Algorithm.ConsistentHashing.Algorithm.Maglev.TableSize != nil {
			desiredMaglevTableSize := *loadbalancing.Algorithm.ConsistentHashing.Algorithm.Maglev.TableSize
			if big.NewInt(int64(desiredMaglevTableSize)).ProbablyPrime(1) {
				maglevTableSize = desiredMaglevTableSize
			}
		}

		return lbBackendLBAlgorithm{
			algorithm: lbAlgorithmConsistentHashing,
			consistentHashing: &lbBackendLBAlgorithmConsistentHashing{
				maglevTableSize: maglevTableSize,
			},
		}
	}

	return lbBackendLBAlgorithm{algorithm: lbAlgorithmRoundRobin}
}

func (r *ingestor) toTLSPassthroughHostNames(match *isovalentv1alpha1.LBServiceTLSPassthroughRouteMatch) []string {
	if match == nil || len(match.HostNames) == 0 {
		return []string{"*"}
	}

	hostNames := []string{}
	for _, h := range match.HostNames {
		hostNames = append(hostNames, string(h))
	}

	return hostNames
}

func (r *ingestor) toTLSProxyHostNames(match *isovalentv1alpha1.LBServiceTLSRouteMatch) []string {
	if match == nil || len(match.HostNames) == 0 {
		return []string{"*"}
	}

	hostNames := []string{}
	for _, h := range match.HostNames {
		hostNames = append(hostNames, string(h))
	}

	return hostNames
}

// getAssignedIP evaluates and returns the actually assigned loadbalancer IP from the LBVIP resource.
// If there's no assigned loadbalancer IP assigned yet, nil is returned instead.
func getAssignedIP(vip *isovalentv1alpha1.LBVIP) *string {
	if vip != nil {
		return vip.Status.Addresses.IPv4
	}

	return nil
}

func getVIPBindStatus(t1Service *corev1.Service) lbVIPBindStatus {
	if t1Service == nil {
		return lbVIPBindStatus{
			serviceExists:  false,
			bindSuccessful: false,
		}
	}

	for _, cond := range t1Service.Status.Conditions {
		// Map LBIPAM conditions to LBVIP conditions
		if cond.Type == "cilium.io/IPAMRequestSatisfied" {
			switch cond.Status {
			case metav1.ConditionUnknown:
				return lbVIPBindStatus{
					serviceExists:  true,
					bindSuccessful: false,
					bindIssue:      "No LB IPAM condition present yet",
				}
			case metav1.ConditionTrue:
				return lbVIPBindStatus{
					serviceExists:  true,
					bindSuccessful: true,
				}
			case metav1.ConditionFalse:
				switch cond.Reason {
				case "already_allocated_incompatible_service":
					// Special handling for the case where an IP & port combination might
					// already be used by another service.
					return lbVIPBindStatus{
						serviceExists:  true,
						bindSuccessful: false,
						bindIssue:      cond.Message,
					}
				default:
					// Pass through the message of LB IPAM.
					// Assuming users will file an issue if
					// they see this message. Most of these
					// cases should already be covered by LB IP
					// assignment to LBVIP service.
					return lbVIPBindStatus{
						serviceExists:  true,
						bindSuccessful: false,
						bindIssue:      "Unexpected condition: " + cond.Message,
					}
				}
			}
		}
	}

	return lbVIPBindStatus{
		bindSuccessful: false,
		bindIssue:      "No LB IPAM condition present yet",
	}
}

func (*ingestor) toBackendTCPConfig(tcpConfig *isovalentv1alpha1.LBBackendTCPConfig) *lbBackendTCPConfig {
	connectTimeout := int32(5)
	if tcpConfig != nil && tcpConfig.ConnectTimeoutSeconds != nil {
		connectTimeout = *tcpConfig.ConnectTimeoutSeconds
	}

	return &lbBackendTCPConfig{
		connectTimeoutSeconds: connectTimeout,
	}
}

func (*ingestor) toBackendTLSConfig(tlsConfig *isovalentv1alpha1.LBBackendTLSConfig) *lbBackendTLSConfig {
	if tlsConfig == nil {
		return nil
	}

	minTLSVersion := ""
	if tlsConfig.MinTLSVersion != nil {
		minTLSVersion = string(*tlsConfig.MinTLSVersion)
	}

	maxTLSVersion := ""
	if tlsConfig.MaxTLSVersion != nil {
		maxTLSVersion = string(*tlsConfig.MaxTLSVersion)
	}

	allowedCipherSuites := []string{}
	for _, cs := range tlsConfig.AllowedCipherSuites {
		allowedCipherSuites = append(allowedCipherSuites, string(cs))
	}

	allowedECDHCurves := []string{}
	for _, ec := range tlsConfig.AllowedECDHCurves {
		allowedECDHCurves = append(allowedECDHCurves, string(ec))
	}

	allowedSignatureAlgorithms := []string{}
	for _, sa := range tlsConfig.AllowedSignatureAlgorithms {
		allowedSignatureAlgorithms = append(allowedSignatureAlgorithms, string(sa))
	}

	return &lbBackendTLSConfig{
		minTLSVersion:              minTLSVersion,
		maxTLSVersion:              maxTLSVersion,
		allowedCipherSuites:        allowedCipherSuites,
		allowedECDHCurves:          allowedECDHCurves,
		allowedSignatureAlgorithms: allowedSignatureAlgorithms,
	}
}

func (*ingestor) toBackendHTTPConfig(httpConfig *isovalentv1alpha1.LBBackendHTTPConfig) lbBackendHTTPConfig {
	http11Enabled := true
	http2Enabled := true

	if httpConfig != nil && httpConfig.EnableHTTP11 != nil {
		http11Enabled = *httpConfig.EnableHTTP11
	}

	if httpConfig != nil && httpConfig.EnableHTTP2 != nil {
		http2Enabled = *httpConfig.EnableHTTP2
	}

	return lbBackendHTTPConfig{
		enableHTTP11: http11Enabled,
		enableHTTP2:  http2Enabled,
	}
}

func (*ingestor) toHTTPPersistentBackendConfig(persistentBackendConfig *isovalentv1alpha1.LBServiceHTTPRoutePersistentBackend) *lbRouteHTTPPersistentBackend {
	if persistentBackendConfig == nil {
		return nil
	}

	sourceIP := false
	if persistentBackendConfig.SourceIP != nil {
		sourceIP = *persistentBackendConfig.SourceIP
	}

	cookieNames := []string{}
	for _, c := range persistentBackendConfig.Cookies {
		cookieNames = append(cookieNames, c.Name)
	}

	headerNames := []string{}
	for _, h := range persistentBackendConfig.Headers {
		headerNames = append(headerNames, h.Name)
	}

	return &lbRouteHTTPPersistentBackend{
		sourceIP:    sourceIP,
		cookieNames: cookieNames,
		headerNames: headerNames,
	}
}

func (*ingestor) toTLSPersistentBackendConfig(persistentBackendConfig *isovalentv1alpha1.LBServiceTLSRoutePersistentBackend) *lbRouteTLSPersistentBackend {
	if persistentBackendConfig == nil {
		return nil
	}

	sourceIP := false
	if persistentBackendConfig.SourceIP != nil {
		sourceIP = *persistentBackendConfig.SourceIP
	}

	return &lbRouteTLSPersistentBackend{
		sourceIP: sourceIP,
	}
}

func (r *ingestor) toHTTPConnectionFilteringConfig(config *isovalentv1alpha1.LBServiceHTTPConnectionFiltering) *lbServiceHTTPConnectionFiltering {
	if config == nil {
		return nil
	}

	rules := []lbServiceHTTPConnectionFilteringRule{}

	for _, ir := range config.Rules {

		var sourceCIDR *lbRouteRequestFilteringSourceCIDR

		if ir.SourceCIDR != nil {
			sourceCIDR = r.toSourceCIDR(ir.SourceCIDR.CIDR)
		}

		rules = append(rules, lbServiceHTTPConnectionFilteringRule{
			sourceCIDR: sourceCIDR,
		})
	}

	return &lbServiceHTTPConnectionFiltering{
		ruleType: r.mapRuleType(config.RuleType),
		rules:    rules,
	}
}

func (*ingestor) toTCPPersistentBackendConfig(persistentBackendConfig *isovalentv1alpha1.LBServiceTCPRoutePersistentBackend) *lbRouteTCPPersistentBackend {
	if persistentBackendConfig == nil {
		return nil
	}

	sourceIP := false
	if persistentBackendConfig.SourceIP != nil {
		sourceIP = *persistentBackendConfig.SourceIP
	}

	return &lbRouteTCPPersistentBackend{
		sourceIP: sourceIP,
	}
}

func (r *ingestor) toTCPRequestFilteringConfig(config *isovalentv1alpha1.LBServiceTCPRouteConnectionFiltering) *lbRouteTCPConnectionFiltering {
	if config == nil {
		return nil
	}

	rules := []lbRouteTCPConnectionFilteringRule{}

	for _, ir := range config.Rules {
		var sourceCIDR *lbRouteRequestFilteringSourceCIDR

		if ir.SourceCIDR != nil {
			sourceCIDR = r.toSourceCIDR(ir.SourceCIDR.CIDR)
		}

		rules = append(rules, lbRouteTCPConnectionFilteringRule{
			sourceCIDR: sourceCIDR,
		})
	}

	return &lbRouteTCPConnectionFiltering{
		ruleType: r.mapRuleType(config.RuleType),
		rules:    rules,
	}
}

func (*ingestor) toUDPPersistentBackendConfig(persistentBackendConfig *isovalentv1alpha1.LBServiceUDPRoutePersistentBackend) *lbRouteUDPPersistentBackend {
	if persistentBackendConfig == nil {
		return nil
	}

	sourceIP := false
	if persistentBackendConfig.SourceIP != nil {
		sourceIP = *persistentBackendConfig.SourceIP
	}

	return &lbRouteUDPPersistentBackend{
		sourceIP: sourceIP,
	}
}

func (r *ingestor) toUDPRequestFilteringConfig(config *isovalentv1alpha1.LBServiceUDPRouteConnectionFiltering) *lbRouteUDPConnectionFiltering {
	if config == nil {
		return nil
	}

	rules := []lbRouteUDPConnectionFilteringRule{}

	for _, ir := range config.Rules {
		var sourceCIDR *lbRouteRequestFilteringSourceCIDR

		if ir.SourceCIDR != nil {
			sourceCIDR = r.toSourceCIDR(ir.SourceCIDR.CIDR)
		}

		rules = append(rules, lbRouteUDPConnectionFilteringRule{
			sourceCIDR: sourceCIDR,
		})
	}

	return &lbRouteUDPConnectionFiltering{
		ruleType: r.mapRuleType(config.RuleType),
		rules:    rules,
	}
}

func (r *ingestor) toHTTPRouteRequestFilteringConfig(config *isovalentv1alpha1.LBServiceHTTPRouteRequestFiltering) *lbRouteHTTPRequestFiltering {
	if config == nil {
		return nil
	}

	rules := []lbRouteHTTPRequestFilteringRule{}

	for _, ir := range config.Rules {

		var sourceCIDR *lbRouteRequestFilteringSourceCIDR
		var hostname *lbRouteRequestFilteringHostName
		var path *lbRouteRequestFilteringHTTPPath

		if ir.SourceCIDR != nil {
			sourceCIDR = r.toSourceCIDR(ir.SourceCIDR.CIDR)
		}

		if ir.HostName != nil {
			var hostName string
			var hostNameType filterHostnameTypeType

			if ir.HostName.Exact != nil {
				hostName = *ir.HostName.Exact
				hostNameType = filterHostnameTypeExact
			} else if ir.HostName.Suffix != nil {
				hostName = *ir.HostName.Suffix
				hostNameType = filterHostnameTypeSuffix
			}

			hostname = &lbRouteRequestFilteringHostName{
				hostName:     hostName,
				hostNameType: hostNameType,
			}
		}

		if ir.Path != nil {
			var p string
			var pType filterPathTypeType

			if ir.Path.Exact != nil {
				p = *ir.Path.Exact
				pType = filterPathTypeExact
			} else if ir.Path.Prefix != nil {
				p = *ir.Path.Prefix
				pType = filterPathTypePrefix
			}

			path = &lbRouteRequestFilteringHTTPPath{
				path:     p,
				pathType: pType,
			}
		}

		rules = append(rules, lbRouteHTTPRequestFilteringRule{
			sourceCIDR: sourceCIDR,
			hostname:   hostname,
			path:       path,
		})
	}

	return &lbRouteHTTPRequestFiltering{
		ruleType: r.mapRuleType(config.RuleType),
		rules:    rules,
	}
}

func (r *ingestor) toSourceCIDR(cidr string) *lbRouteRequestFilteringSourceCIDR {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		// return nil as this should already be covered by CRD field validation
		return nil
	}

	prefixLen, _ := ipNet.Mask.Size()
	return &lbRouteRequestFilteringSourceCIDR{
		addressPrefix: ipNet.IP.String(),
		prefixLen:     uint32(prefixLen),
	}
}

func (r *ingestor) toTLSRequestFilteringConfig(config *isovalentv1alpha1.LBServiceTLSRouteConnectionFiltering) *lbRouteTLSConnectionFiltering {
	if config == nil {
		return nil
	}

	rules := []lbRouteTLSConnectionFilteringRule{}

	for _, ir := range config.Rules {

		var sourceCIDR *lbRouteRequestFilteringSourceCIDR
		var servername *lbRouteRequestFilteringHostName

		if ir.SourceCIDR != nil {
			sourceCIDR = r.toSourceCIDR(ir.SourceCIDR.CIDR)
		}

		if ir.ServerName != nil {
			var serverName string
			var serverNameType filterHostnameTypeType

			if ir.ServerName.Exact != nil {
				serverName = *ir.ServerName.Exact
				serverNameType = filterHostnameTypeExact
			} else if ir.ServerName.Suffix != nil {
				serverName = *ir.ServerName.Suffix
				serverNameType = filterHostnameTypeSuffix
			}

			servername = &lbRouteRequestFilteringHostName{
				hostName:     serverName,
				hostNameType: serverNameType,
			}
		}

		rules = append(rules, lbRouteTLSConnectionFilteringRule{
			sourceCIDR: sourceCIDR,
			servername: servername,
		})
	}

	return &lbRouteTLSConnectionFiltering{
		ruleType: r.mapRuleType(config.RuleType),
		rules:    rules,
	}
}

func (*ingestor) mapRuleType(ruleType isovalentv1alpha1.RequestFilteringRuleType) ruleTypeType {
	switch ruleType {
	case isovalentv1alpha1.RequestFilteringRuleTypeAllow:
		return ruleTypeAllow
	case isovalentv1alpha1.RequestFilteringRuleTypeDeny:
		return ruleTypeDeny
	}

	return ruleTypeDeny
}

func (*ingestor) toHTTPRateLimits(rateLimits *isovalentv1alpha1.LBServiceHTTPRateLimits) *lbServiceConnectionRateLimit {
	if rateLimits == nil {
		return nil
	}

	return &lbServiceConnectionRateLimit{
		connections: lbServiceRateLimit{
			limit:             rateLimits.Connections.Limit,
			timePeriodSeconds: rateLimits.Connections.TimePeriodSeconds,
		},
	}
}

func (*ingestor) toHTTPRouteRateLimits(rateLimits *isovalentv1alpha1.LBServiceHTTPRouteRateLimits) *lbServiceRequestRateLimit {
	if rateLimits == nil {
		return nil
	}

	return &lbServiceRequestRateLimit{
		requests: lbServiceRateLimit{
			limit:             rateLimits.Requests.Limit,
			timePeriodSeconds: rateLimits.Requests.TimePeriodSeconds,
		},
	}
}

func (*ingestor) toTLSRateLimits(rateLimits *isovalentv1alpha1.LBServiceTLSRouteRateLimits) *lbServiceConnectionRateLimit {
	if rateLimits == nil {
		return nil
	}

	return &lbServiceConnectionRateLimit{
		connections: lbServiceRateLimit{
			limit:             rateLimits.Connections.Limit,
			timePeriodSeconds: rateLimits.Connections.TimePeriodSeconds,
		},
	}
}

func (*ingestor) toTCPRateLimits(rateLimits *isovalentv1alpha1.LBServiceTCPRouteRateLimits) *lbServiceConnectionRateLimit {
	if rateLimits == nil {
		return nil
	}

	return &lbServiceConnectionRateLimit{
		connections: lbServiceRateLimit{
			limit:             rateLimits.Connections.Limit,
			timePeriodSeconds: rateLimits.Connections.TimePeriodSeconds,
		},
	}
}

func (r *ingestor) mapTCPProxyTierMode(app *isovalentv1alpha1.LBServiceApplicationTCPProxy, referencedBackends map[string]backend) tierModeType {
	forceDeploymentMode := isovalentv1alpha1.LBTCPProxyForceDeploymentModeAuto

	if app.ForceDeploymentMode != nil {
		forceDeploymentMode = *app.ForceDeploymentMode
	}

	switch forceDeploymentMode {
	case isovalentv1alpha1.LBTCPProxyForceDeploymentModeAuto:
		return r.evaluateTCPProxyAutoTierMode(app, referencedBackends)
	case isovalentv1alpha1.LBTCPProxyForceDeploymentModeT1:
		return tierModeT1
	case isovalentv1alpha1.LBTCPProxyForceDeploymentModeT2:
		return tierModeT2
	default:
		return r.evaluateTCPProxyAutoTierMode(app, referencedBackends)
	}
}

func (r *ingestor) evaluateTCPProxyAutoTierMode(app *isovalentv1alpha1.LBServiceApplicationTCPProxy, referencedBackends map[string]backend) tierModeType {
	for _, ar := range app.Routes {
		if ar.RateLimits != nil || ar.PersistentBackend != nil || referencedBackends[ar.BackendRef.Name].typ == lbBackendTypeHostname {
			return tierModeT2
		}

		// backends with different ports aren't supported by t1-only mode
		port := uint32(0)
		for _, be := range referencedBackends[ar.BackendRef.Name].lbBackends {
			if port == 0 {
				port = be.port
			}

			if port != be.port {
				return tierModeT2
			}
		}
	}

	return tierModeT1
}

func (r *ingestor) mapUDPProxyTierMode(app *isovalentv1alpha1.LBServiceApplicationUDPProxy, referencedBackends map[string]backend) tierModeType {
	forceDeploymentMode := isovalentv1alpha1.LBUDPProxyForceDeploymentModeAuto

	if app.ForceDeploymentMode != nil {
		forceDeploymentMode = *app.ForceDeploymentMode
	}

	switch forceDeploymentMode {
	case isovalentv1alpha1.LBUDPProxyForceDeploymentModeAuto:
		return r.evaluateUDPProxyAutoTierMode(app, referencedBackends)
	case isovalentv1alpha1.LBUDPProxyForceDeploymentModeT1:
		return tierModeT1
	case isovalentv1alpha1.LBUDPProxyForceDeploymentModeT2:
		return tierModeT2
	default:
		return r.evaluateUDPProxyAutoTierMode(app, referencedBackends)
	}
}

func (r *ingestor) evaluateUDPProxyAutoTierMode(app *isovalentv1alpha1.LBServiceApplicationUDPProxy, referencedBackends map[string]backend) tierModeType {
	for _, ar := range app.Routes {
		if referencedBackends[ar.BackendRef.Name].typ == lbBackendTypeHostname {
			return tierModeT2
		}

		// backends with different ports aren't supported by t1-only mode
		port := uint32(0)
		for _, be := range referencedBackends[ar.BackendRef.Name].lbBackends {
			if port == 0 {
				port = be.port
			}

			if port != be.port {
				return tierModeT2
			}
		}
	}

	return tierModeT1
}

func (r *ingestor) toDNSResolverConfig(config *isovalentv1alpha1.DNSResolverConfig) *lbBackendDNSResolverConfig {
	if config == nil {
		return nil
	}

	ret := &lbBackendDNSResolverConfig{
		resolvers: []lbBackendDNSResolver{},
	}

	for _, resolver := range config.Resolvers {
		ret.resolvers = append(ret.resolvers, lbBackendDNSResolver{
			ip:   resolver.IP,
			port: resolver.Port,
		})
	}

	return ret
}

func (r *ingestor) toHTTPAuth(auth *isovalentv1alpha1.LBServiceHTTPAuth, referencedSecrets map[string]*corev1.Secret) *lbServiceHTTPAuth {
	if auth == nil {
		return nil
	}
	return &lbServiceHTTPAuth{
		basicAuth: r.toHTTPBasicAuth(auth.Basic, referencedSecrets),
		jwtAuth:   r.toHTTPJWTAuth(auth.JWT, referencedSecrets),
	}
}

func (r *ingestor) toHTTPBasicAuth(basicAuth *isovalentv1alpha1.LBServiceHTTPBasicAuth, referencedSecrets map[string]*corev1.Secret) *lbServiceHTTPBasicAuth {
	if basicAuth == nil {
		return nil
	}

	ba := &lbServiceHTTPBasicAuth{
		users: []lbServiceUserPassword{},
	}

	secret, ok := referencedSecrets[basicAuth.Users.SecretRef.Name]
	if !ok {
		return nil
	}

	// Extract clear text credentials from secret
	for username, password := range secret.Data {
		ba.users = append(ba.users, lbServiceUserPassword{
			username: username,
			password: password,
		})
	}

	// Sort by username for deterministic output
	slices.SortStableFunc(ba.users, func(a, b lbServiceUserPassword) int {
		return strings.Compare(a.username, b.username)
	})

	return ba
}

func (r *ingestor) toHTTPJWTAuth(jwtAuth *isovalentv1alpha1.LBServiceHTTPJWTAuth, referencedSecrets map[string]*corev1.Secret) *lbServiceHTTPJWTAuth {
	if jwtAuth == nil {
		return nil
	}

	ja := &lbServiceHTTPJWTAuth{
		providers: []jwtProvider{},
	}

	for _, provider := range jwtAuth.Providers {
		p := jwtProvider{
			name:      provider.Name,
			issuer:    provider.Issuer,
			audiences: provider.Audiences,
		}
		switch {
		case provider.JWKS.SecretRef != nil:
			secret, ok := referencedSecrets[provider.JWKS.SecretRef.Name]
			if !ok {
				continue
			}

			jwksStr, ok := secret.Data[isovalentv1alpha1.LBServiceJWKSSecretKey]
			if !ok {
				continue
			}

			p.localJWKS = &localJWKS{
				jwksStr: string(jwksStr),
			}
		case provider.JWKS.HTTPURI != nil:
			p.remoteJWKS = &remoteJWKS{
				httpURI: provider.JWKS.HTTPURI.URI,
			}
		}
		ja.providers = append(ja.providers, p)
	}

	return ja
}

func (r *ingestor) toHTTPRouteAuth(auth *isovalentv1alpha1.LBServiceHTTPRouteAuth) *lbRouteHTTPAuth {
	if auth == nil {
		return nil
	}

	return &lbRouteHTTPAuth{
		basicAuth: r.toHTTPRouteBasicAuth(auth.Basic),
		jwtAuth:   r.toHTTPRouteJWTAuth(auth.JWT),
	}
}

func (r *ingestor) toHTTPRouteBasicAuth(basicAuth *isovalentv1alpha1.LBServiceHTTPRouteBasicAuth) *lbRouteHTTPBasicAuth {
	if basicAuth == nil {
		return nil
	}
	return &lbRouteHTTPBasicAuth{
		disabled: basicAuth.Disabled,
	}
}

func (r *ingestor) toServiceProxyProtocolConfig(protocol *isovalentv1alpha1.LBServiceProxyProtocolConfig) *lbServiceProxyProtocolConfig {
	if protocol == nil {
		return nil
	}

	var dVersions []int
	for _, v := range protocol.DisallowedVersions {
		dVersions = append(dVersions, int(v))
	}

	var tlvs []uint32
	for _, tlv := range protocol.PassthroughTLVs {
		tlvs = append(tlvs, uint32(tlv))
	}

	return &lbServiceProxyProtocolConfig{
		disallowedVersions: dVersions,
		passThroughTLVs:    tlvs,
	}
}

func (r *ingestor) toBackendProxyProtocolConfig(protocol *isovalentv1alpha1.LBBackendPoolProxyProtocolConfig) *lbBackendProxyProtocolConfig {
	if protocol == nil {
		return nil
	}

	var tlvs []uint32
	for _, tlv := range protocol.PassthroughTLVs {
		tlvs = append(tlvs, uint32(tlv))
	}

	return &lbBackendProxyProtocolConfig{
		version:         int(protocol.Version),
		passthroughTLVs: tlvs,
	}
}

func (r *ingestor) toHTTPRouteJWTAuth(jwtAuth *isovalentv1alpha1.LBServiceHTTPRouteJWTAuth) *lbRouteHTTPJWTAuth {
	if jwtAuth == nil {
		return nil
	}
	return &lbRouteHTTPJWTAuth{
		disabled: jwtAuth.Disabled,
	}
}
