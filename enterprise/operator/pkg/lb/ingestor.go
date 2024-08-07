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

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

type ingestor struct{}

func (r *ingestor) ingest(vip *isovalentv1alpha1.LBVIP, frontend *isovalentv1alpha1.LBFrontend, backends []*isovalentv1alpha1.LBBackendPool) (*lbFrontend, error) {
	applications, err := r.toApplications(frontend, backends)
	if err != nil {
		return nil, fmt.Errorf("failed to ingest applications: %w", err)
	}

	return &lbFrontend{
		namespace: frontend.Namespace,
		name:      frontend.Name,
		vip: lbVIP{
			name:         frontend.Spec.VIPRef.Name,
			assignedIPv4: getAssignedIP(vip),
		},
		port:         frontend.Spec.Port,
		applications: applications,
	}, nil
}

func (*ingestor) toHTTPConfig(httpConfig *isovalentv1alpha1.LBFrontendHTTPConfig) *lbFrontendHTTPConfig {
	http11Enabled := true
	http2Enabled := true

	if httpConfig != nil && httpConfig.EnableHTTP11 != nil {
		http11Enabled = *httpConfig.EnableHTTP11
	}

	if httpConfig != nil && httpConfig.EnableHTTP2 != nil {
		http2Enabled = *httpConfig.EnableHTTP2
	}

	return &lbFrontendHTTPConfig{
		enableHTTP11: http11Enabled,
		enableHTTP2:  http2Enabled,
	}
}

func (*ingestor) toTLSConfig(frontend *isovalentv1alpha1.LBFrontend) *lbFrontendTLSConfig {
	if frontend.Spec.Applications.HTTPSProxy == nil || frontend.Spec.Applications.HTTPSProxy.TLSConfig == nil {
		return nil
	}

	certificateSecretNames := []string{}

	for _, c := range frontend.Spec.Applications.HTTPSProxy.TLSConfig.Certificates {
		certificateSecretNames = append(certificateSecretNames, c.SecretName)
	}

	minTLSVersion := ""
	if frontend.Spec.Applications.HTTPSProxy.TLSConfig.MinTLSVersion != nil {
		minTLSVersion = string(*frontend.Spec.Applications.HTTPSProxy.TLSConfig.MinTLSVersion)
	}

	maxTLSVersion := ""
	if frontend.Spec.Applications.HTTPSProxy.TLSConfig.MaxTLSVersion != nil {
		maxTLSVersion = string(*frontend.Spec.Applications.HTTPSProxy.TLSConfig.MaxTLSVersion)
	}

	allowedCipherSuites := []string{}
	for _, cs := range frontend.Spec.Applications.HTTPSProxy.TLSConfig.AllowedCipherSuites {
		allowedCipherSuites = append(allowedCipherSuites, string(cs))
	}

	allowedECDHCurves := []string{}
	for _, ec := range frontend.Spec.Applications.HTTPSProxy.TLSConfig.AllowedECDHCurves {
		allowedECDHCurves = append(allowedECDHCurves, string(ec))
	}

	allowedSignatureAlgorithms := []string{}
	for _, sa := range frontend.Spec.Applications.HTTPSProxy.TLSConfig.AllowedSignatureAlgorithms {
		allowedSignatureAlgorithms = append(allowedSignatureAlgorithms, string(sa))
	}

	return &lbFrontendTLSConfig{
		certificateSecrets:         certificateSecretNames,
		MinTLSVersion:              minTLSVersion,
		MaxTLSVersion:              maxTLSVersion,
		AllowedCipherSuites:        allowedCipherSuites,
		AllowedECDHCurves:          allowedECDHCurves,
		AllowedSignatureAlgorithms: allowedSignatureAlgorithms,
	}
}

func (r *ingestor) toApplications(frontend *isovalentv1alpha1.LBFrontend, backends []*isovalentv1alpha1.LBBackendPool) (lbApplications, error) {
	return lbApplications{
		httpProxy:      r.toApplicationHTTP(frontend, backends),
		httpsProxy:     r.toApplicationHTTPS(frontend, backends),
		tlsPassthrough: r.toApplicationTLSPassthrough(frontend, backends),
	}, nil
}

func (r *ingestor) toApplicationHTTP(frontend *isovalentv1alpha1.LBFrontend, backends []*isovalentv1alpha1.LBBackendPool) *lbApplicationHTTPProxy {
	if frontend.Spec.Applications.HTTPProxy == nil {
		return nil
	}

	backendIndex := map[string]*isovalentv1alpha1.LBBackendPool{}
	for _, b := range backends {
		backendIndex[b.Name] = b
	}

	routes := []lbRouteHTTP{}

	for _, lr := range frontend.Spec.Applications.HTTPProxy.Routes {
		routeBackend, ok := backendIndex[lr.BackendRef.Name]
		if !ok {
			// backend not present yet
			continue
		}

		pathType, path := toPath(lr.Match)

		routes = append(routes, lbRouteHTTP{
			match: lbRouteHTTPMatch{
				hostNames: r.toHTTPHostNames(lr.Match),
				pathType:  pathType,
				path:      path,
			},
			backend: backend{
				ips:         r.toIPBackends(routeBackend.Spec.Backends),
				hostnames:   []lbBackend{},
				lbAlgorithm: lbAlgorithmRoundRobin,
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
				tlsConfig:  r.toBackendTLSConfig(routeBackend.Spec.TLSConfig),
				httpConfig: r.toBackendHTTPConfig(routeBackend.Spec.HTTPConfig),
			},
		})
	}

	return &lbApplicationHTTPProxy{
		httpConfig: r.toHTTPConfig(frontend.Spec.Applications.HTTPProxy.HTTPConfig),
		routes:     routes,
	}
}

func (r *ingestor) toApplicationHTTPS(frontend *isovalentv1alpha1.LBFrontend, backends []*isovalentv1alpha1.LBBackendPool) *lbApplicationHTTPSProxy {
	if frontend.Spec.Applications.HTTPSProxy == nil {
		return nil
	}

	backendIndex := map[string]*isovalentv1alpha1.LBBackendPool{}
	for _, b := range backends {
		backendIndex[b.Name] = b
	}

	routes := []lbRouteHTTPS{}

	for _, lr := range frontend.Spec.Applications.HTTPSProxy.Routes {
		routeBackend, ok := backendIndex[lr.BackendRef.Name]
		if !ok {
			// backend not present yet
			continue
		}

		pathType, path := toPath(lr.Match)

		routes = append(routes, lbRouteHTTPS{
			match: lbRouteHTTPMatch{
				hostNames: r.toHTTPHostNames(lr.Match),
				pathType:  pathType,
				path:      path,
			},
			backend: backend{
				ips:         r.toIPBackends(routeBackend.Spec.Backends),
				hostnames:   []lbBackend{},
				lbAlgorithm: lbAlgorithmRoundRobin,
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
				tlsConfig:  r.toBackendTLSConfig(routeBackend.Spec.TLSConfig),
				httpConfig: r.toBackendHTTPConfig(routeBackend.Spec.HTTPConfig),
			},
		})
	}

	return &lbApplicationHTTPSProxy{
		httpConfig: r.toHTTPConfig(frontend.Spec.Applications.HTTPSProxy.HTTPConfig),
		tlsConfig:  r.toTLSConfig(frontend),
		routes:     routes,
	}
}

func toPath(match *isovalentv1alpha1.LBFrontendHTTPRouteMatch) (pathTypeType, string) {
	pathType := pathTypePrefix
	path := "/"

	if match != nil && match.Path != nil {
		if match.Path.Prefix != nil {
			pathType = pathTypePrefix
			path = *match.Path.Prefix
		} else if match.Path.Exact != nil {
			pathType = pathTypeExact
			path = *match.Path.Exact
		}
	}

	return pathType, path
}

func (r *ingestor) toApplicationTLSPassthrough(frontend *isovalentv1alpha1.LBFrontend, backends []*isovalentv1alpha1.LBBackendPool) *lbApplicationTLSPassthrough {
	if frontend.Spec.Applications.TLSPassthrough == nil {
		return nil
	}

	backendIndex := map[string]*isovalentv1alpha1.LBBackendPool{}
	for _, b := range backends {
		backendIndex[b.Name] = b
	}

	routes := []lbRouteTLSPassthrough{}

	for _, lr := range frontend.Spec.Applications.TLSPassthrough.Routes {
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
				ips:         r.toIPBackends(routeBackend.Spec.Backends),
				hostnames:   []lbBackend{},
				lbAlgorithm: lbAlgorithmRoundRobin,
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
				tlsConfig:  r.toBackendTLSConfig(routeBackend.Spec.TLSConfig),
				httpConfig: r.toBackendHTTPConfig(routeBackend.Spec.HTTPConfig),
			},
		})
	}

	return &lbApplicationTLSPassthrough{
		routes: routes,
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
		ipBackends = append(ipBackends, lbBackend{
			address: ipAddress.IP,
			port:    uint32(ipAddress.Port),
		})
	}

	return ipBackends
}

func (r *ingestor) toHTTPHostNames(match *isovalentv1alpha1.LBFrontendHTTPRouteMatch) []string {
	if match == nil || len(match.HostNames) == 0 {
		return []string{"*"}
	}

	hostNames := []string{}
	for _, h := range match.HostNames {
		hostNames = append(hostNames, string(h))
	}

	return hostNames
}

func (r *ingestor) toTLSPassthroughHostNames(match *isovalentv1alpha1.LBFrontendTLSPassthroughRouteMatch) []string {
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

func (*ingestor) toBackendTLSConfig(tlsConfig *isovalentv1alpha1.LBBackendTLSConfig) *lbBackendTLSConfig {
	if tlsConfig == nil {
		return nil
	}

	return &lbBackendTLSConfig{}
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
