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
	"math/big"
	"net"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

type ingestor struct{}

func (r *ingestor) ingest(vip *isovalentv1alpha1.LBVIP, lbsvc *isovalentv1alpha1.LBService, backends []*isovalentv1alpha1.LBBackendPool, t1Service *corev1.Service, t1NodeIPs []string, t2NodeIPs []string) (*lbService, error) {
	applications, err := r.toApplications(lbsvc, backends)
	if err != nil {
		return nil, fmt.Errorf("failed to ingest applications: %w", err)
	}

	return &lbService{
		namespace: lbsvc.Namespace,
		name:      lbsvc.Name,
		vip: lbVIP{
			name:         lbsvc.Spec.VIPRef.Name,
			assignedIPv4: getAssignedIP(vip),
			bindStatus:   getVIPBindStatus(t1Service),
		},
		port:         lbsvc.Spec.Port,
		applications: applications,
		t1NodeIPs:    t1NodeIPs,
		t2NodeIPs:    t2NodeIPs,
	}, nil
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

func (*ingestor) toTLSConfig(tlsConfig *isovalentv1alpha1.LBServiceTLSConfig) *lbServiceTLSConfig {
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

	return &lbServiceTLSConfig{
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

func (r *ingestor) toApplications(lbsvc *isovalentv1alpha1.LBService, backends []*isovalentv1alpha1.LBBackendPool) (lbApplications, error) {
	return lbApplications{
		httpProxy:      r.toApplicationHTTP(lbsvc, backends),
		httpsProxy:     r.toApplicationHTTPS(lbsvc, backends),
		tlsPassthrough: r.toApplicationTLSPassthrough(lbsvc, backends),
		tlsProxy:       r.toApplicationTLSProxy(lbsvc, backends),
	}, nil
}

func (r *ingestor) toApplicationHTTP(lbsvc *isovalentv1alpha1.LBService, backends []*isovalentv1alpha1.LBBackendPool) *lbApplicationHTTPProxy {
	if lbsvc.Spec.Applications.HTTPProxy == nil {
		return nil
	}

	backendIndex := map[string]*isovalentv1alpha1.LBBackendPool{}
	for _, b := range backends {
		backendIndex[b.Name] = b
	}

	routes := map[string][]lbRouteHTTP{}

	for i, lr := range lbsvc.Spec.Applications.HTTPProxy.Routes {
		routeBackend, ok := backendIndex[lr.BackendRef.Name]
		if !ok {
			// backend not present yet
			continue
		}

		pathType, path := toPath(lr.Match)

		httpRoute := lbRouteHTTP{
			match: lbRouteHTTPMatch{
				pathType: pathType,
				path:     path,
			},
			backend: backend{
				routeIndex:  i,
				ips:         r.toIPBackends(routeBackend.Spec.Backends),
				hostnames:   []lbBackend{},
				lbAlgorithm: r.toLBBackendAlgorithm(routeBackend.Spec.Loadbalancing),
				healthCheckConfig: lbBackendHealthCheckConfig{
					http:                         r.toHTTPHealthCheck(&routeBackend.Spec.HealthCheck),
					tcp:                          r.toTCPHealthCheck(&routeBackend.Spec.HealthCheck),
					intervalSeconds:              int(*routeBackend.Spec.HealthCheck.IntervalSeconds),
					timeoutSeconds:               int(*routeBackend.Spec.HealthCheck.TimeoutSeconds),
					healthyThreshold:             int(*routeBackend.Spec.HealthCheck.HealthyThreshold),
					unhealthyThreshold:           int(*routeBackend.Spec.HealthCheck.UnhealthyThreshold),
					unhealthyEdgeIntervalSeconds: int(*routeBackend.Spec.HealthCheck.IntervalSeconds),
					unhealthyIntervalSeconds:     int(*routeBackend.Spec.HealthCheck.IntervalSeconds),
				},
				tcpConfig:  r.toBackendTCPConfig(routeBackend.Spec.TCPConfig),
				tlsConfig:  r.toBackendTLSConfig(routeBackend.Spec.TLSConfig),
				httpConfig: r.toBackendHTTPConfig(routeBackend.Spec.HTTPConfig),
			},
			persistentBackend: r.toHTTPPersistentBackendConfig(lr.PersistentBackend),
			requestFiltering:  r.toHTTPRouteRequestFilteringConfig(lr.RequestFiltering),
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
		routes:              routes,
	}
}

func (r *ingestor) toApplicationHTTPS(lbsvc *isovalentv1alpha1.LBService, backends []*isovalentv1alpha1.LBBackendPool) *lbApplicationHTTPSProxy {
	if lbsvc.Spec.Applications.HTTPSProxy == nil {
		return nil
	}

	backendIndex := map[string]*isovalentv1alpha1.LBBackendPool{}
	for _, b := range backends {
		backendIndex[b.Name] = b
	}

	routes := map[string][]lbRouteHTTP{}

	for i, lr := range lbsvc.Spec.Applications.HTTPSProxy.Routes {
		routeBackend, ok := backendIndex[lr.BackendRef.Name]
		if !ok {
			// backend not present yet
			continue
		}

		pathType, path := toPath(lr.Match)

		httpRoute := lbRouteHTTP{
			match: lbRouteHTTPMatch{
				pathType: pathType,
				path:     path,
			},
			backend: backend{
				routeIndex:  i,
				ips:         r.toIPBackends(routeBackend.Spec.Backends),
				hostnames:   []lbBackend{},
				lbAlgorithm: r.toLBBackendAlgorithm(routeBackend.Spec.Loadbalancing),
				healthCheckConfig: lbBackendHealthCheckConfig{
					http:                         r.toHTTPHealthCheck(&routeBackend.Spec.HealthCheck),
					tcp:                          r.toTCPHealthCheck(&routeBackend.Spec.HealthCheck),
					intervalSeconds:              int(*routeBackend.Spec.HealthCheck.IntervalSeconds),
					timeoutSeconds:               int(*routeBackend.Spec.HealthCheck.TimeoutSeconds),
					healthyThreshold:             int(*routeBackend.Spec.HealthCheck.HealthyThreshold),
					unhealthyThreshold:           int(*routeBackend.Spec.HealthCheck.UnhealthyThreshold),
					unhealthyEdgeIntervalSeconds: int(*routeBackend.Spec.HealthCheck.IntervalSeconds),
					unhealthyIntervalSeconds:     int(*routeBackend.Spec.HealthCheck.IntervalSeconds),
				},
				tcpConfig:  r.toBackendTCPConfig(routeBackend.Spec.TCPConfig),
				tlsConfig:  r.toBackendTLSConfig(routeBackend.Spec.TLSConfig),
				httpConfig: r.toBackendHTTPConfig(routeBackend.Spec.HTTPConfig),
			},
			persistentBackend: r.toHTTPPersistentBackendConfig(lr.PersistentBackend),
			requestFiltering:  r.toHTTPRouteRequestFilteringConfig(lr.RequestFiltering),
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

	var tlsConfig *lbServiceTLSConfig
	if lbsvc.Spec.Applications.HTTPSProxy.TLSConfig != nil {
		tlsConfig = r.toTLSConfig(lbsvc.Spec.Applications.HTTPSProxy.TLSConfig)
	}

	return &lbApplicationHTTPSProxy{
		httpConfig:          r.toHTTPConfig(lbsvc.Spec.Applications.HTTPSProxy.HTTPConfig),
		tlsConfig:           tlsConfig,
		connectionFiltering: r.toHTTPConnectionFilteringConfig(lbsvc.Spec.Applications.HTTPSProxy.ConnectionFiltering),
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

func (r *ingestor) toApplicationTLSPassthrough(lbsvc *isovalentv1alpha1.LBService, backends []*isovalentv1alpha1.LBBackendPool) *lbApplicationTLSPassthrough {
	if lbsvc.Spec.Applications.TLSPassthrough == nil {
		return nil
	}

	backendIndex := map[string]*isovalentv1alpha1.LBBackendPool{}
	for _, b := range backends {
		backendIndex[b.Name] = b
	}

	routes := []lbRouteTLSPassthrough{}

	for i, lr := range lbsvc.Spec.Applications.TLSPassthrough.Routes {
		routeBackend, ok := backendIndex[lr.BackendRef.Name]
		if !ok {
			// backend not present yet
			continue
		}

		routes = append(routes, lbRouteTLSPassthrough{
			match: lbRouteTLSPassthroughMatch{
				hostNames: r.toTLSPassthroughHostNames(lr.Match),
			},
			backend: backend{
				routeIndex:  i,
				ips:         r.toIPBackends(routeBackend.Spec.Backends),
				hostnames:   []lbBackend{},
				lbAlgorithm: r.toLBBackendAlgorithm(routeBackend.Spec.Loadbalancing),
				healthCheckConfig: lbBackendHealthCheckConfig{
					http:                         r.toHTTPHealthCheck(&routeBackend.Spec.HealthCheck),
					tcp:                          r.toTCPHealthCheck(&routeBackend.Spec.HealthCheck),
					intervalSeconds:              int(*routeBackend.Spec.HealthCheck.IntervalSeconds),
					timeoutSeconds:               int(*routeBackend.Spec.HealthCheck.TimeoutSeconds),
					healthyThreshold:             int(*routeBackend.Spec.HealthCheck.HealthyThreshold),
					unhealthyThreshold:           int(*routeBackend.Spec.HealthCheck.UnhealthyThreshold),
					unhealthyEdgeIntervalSeconds: int(*routeBackend.Spec.HealthCheck.IntervalSeconds),
					unhealthyIntervalSeconds:     int(*routeBackend.Spec.HealthCheck.IntervalSeconds),
				},
				tcpConfig:  r.toBackendTCPConfig(routeBackend.Spec.TCPConfig),
				tlsConfig:  r.toBackendTLSConfig(routeBackend.Spec.TLSConfig),
				httpConfig: r.toBackendHTTPConfig(routeBackend.Spec.HTTPConfig),
			},
			persistentBackend:   r.toTLSPersistentBackendConfig(lr.PersistentBackend),
			connectionFiltering: r.toTLSRequestFilteringConfig(lr.ConnectionFiltering),
		})
	}

	return &lbApplicationTLSPassthrough{
		routes: routes,
	}
}

func (r *ingestor) toApplicationTLSProxy(lbsvc *isovalentv1alpha1.LBService, backends []*isovalentv1alpha1.LBBackendPool) *lbApplicationTLSProxy {
	app := lbsvc.Spec.Applications.TLSProxy
	if app == nil {
		return nil
	}

	backendIndex := map[string]*isovalentv1alpha1.LBBackendPool{}
	for _, b := range backends {
		backendIndex[b.Name] = b
	}

	routes := []lbRouteTLSProxy{}
	for i, lr := range app.Routes {
		routeBackend, ok := backendIndex[lr.BackendRef.Name]
		if !ok {
			// backend not present yet
			continue
		}

		routes = append(routes, lbRouteTLSProxy{
			match: lbRouteTLSProxyMatch{
				hostNames: r.toTLSProxyHostNames(lr.Match),
			},
			backend: backend{
				routeIndex:  i,
				ips:         r.toIPBackends(routeBackend.Spec.Backends),
				hostnames:   []lbBackend{},
				lbAlgorithm: r.toLBBackendAlgorithm(routeBackend.Spec.Loadbalancing),
				healthCheckConfig: lbBackendHealthCheckConfig{
					http:                         r.toHTTPHealthCheck(&routeBackend.Spec.HealthCheck),
					tcp:                          r.toTCPHealthCheck(&routeBackend.Spec.HealthCheck),
					intervalSeconds:              int(*routeBackend.Spec.HealthCheck.IntervalSeconds),
					timeoutSeconds:               int(*routeBackend.Spec.HealthCheck.TimeoutSeconds),
					healthyThreshold:             int(*routeBackend.Spec.HealthCheck.HealthyThreshold),
					unhealthyThreshold:           int(*routeBackend.Spec.HealthCheck.UnhealthyThreshold),
					unhealthyEdgeIntervalSeconds: int(*routeBackend.Spec.HealthCheck.IntervalSeconds),
					unhealthyIntervalSeconds:     int(*routeBackend.Spec.HealthCheck.IntervalSeconds),
				},
				tcpConfig:  r.toBackendTCPConfig(routeBackend.Spec.TCPConfig),
				tlsConfig:  r.toBackendTLSConfig(routeBackend.Spec.TLSConfig),
				httpConfig: r.toBackendHTTPConfig(routeBackend.Spec.HTTPConfig),
			},
			persistentBackend:   r.toTLSPersistentBackendConfig(lr.PersistentBackend),
			connectionFiltering: r.toTLSRequestFilteringConfig(lr.ConnectionFiltering),
		})
	}

	var tlsConfig *lbServiceTLSConfig
	if app.TLSConfig != nil {
		tlsConfig = r.toTLSConfig(app.TLSConfig)
	}

	return &lbApplicationTLSProxy{
		tlsConfig: tlsConfig,
		routes:    routes,
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

func (r *ingestor) toIPBackends(addresses []isovalentv1alpha1.Backend) []lbBackend {
	ipBackends := []lbBackend{}
	for _, ipAddress := range addresses {
		weight := uint32(1)
		if ipAddress.Weight != nil {
			weight = *ipAddress.Weight
		}

		status := lbBackendStatusHealthChecking
		if ipAddress.Status != nil && *ipAddress.Status == isovalentv1alpha1.BackendStatusDraining {
			status = lbBackendStatusDraining
		}

		ipBackends = append(ipBackends, lbBackend{
			address: ipAddress.IP,
			port:    uint32(ipAddress.Port),
			weight:  weight,
			status:  status,
		})
	}

	return ipBackends
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
