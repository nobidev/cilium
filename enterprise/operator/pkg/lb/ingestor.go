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

func (r *ingestor) ingest(vip *isovalentv1alpha1.LBVIP, frontend *isovalentv1alpha1.LBFrontend, backends []*isovalentv1alpha1.LBBackend) (*lbFrontend, error) {
	applications, err := r.toApplications(frontend, backends)
	if err != nil {
		return nil, fmt.Errorf("failed to ingest applications: %w", err)
	}

	return &lbFrontend{
		namespace: frontend.Namespace,
		name:      frontend.Name,
		vip: lbVIP{
			name:          frontend.Spec.VIPRef.Name,
			requestedIPv4: getRequestedIP(vip),
			assignedIPv4:  getAssignedIP(vip),
		},
		port:         frontend.Spec.Port,
		applications: applications,
	}, nil
}

func (*ingestor) toTLS(frontend *isovalentv1alpha1.LBFrontend) *lbFrontendTLSConfig {
	if frontend.Spec.Applications.HTTPSProxy == nil || frontend.Spec.Applications.HTTPSProxy.TLSConfig == nil {
		return nil
	}

	certificateSecretNames := []string{}

	for _, c := range frontend.Spec.Applications.HTTPSProxy.TLSConfig.Certificates {
		certificateSecretNames = append(certificateSecretNames, c.SecretName)
	}

	return &lbFrontendTLSConfig{
		certificateSecrets: certificateSecretNames,
	}
}

func (r *ingestor) toApplications(frontend *isovalentv1alpha1.LBFrontend, backends []*isovalentv1alpha1.LBBackend) (lbApplications, error) {
	return lbApplications{
		httpProxy:      r.toApplicationHTTP(frontend, backends),
		httpsProxy:     r.toApplicationHTTPS(frontend, backends),
		tlsPassthrough: r.toApplicationTLSPassthrough(frontend, backends),
	}, nil
}

func (r *ingestor) toApplicationHTTP(frontend *isovalentv1alpha1.LBFrontend, backends []*isovalentv1alpha1.LBBackend) *lbApplicationHTTPProxy {
	if frontend.Spec.Applications.HTTPProxy == nil {
		return nil
	}

	backendIndex := map[string]*isovalentv1alpha1.LBBackend{}
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

		pathType, path := toPath(lr)

		routes = append(routes, lbRouteHTTP{
			hostNames: r.toHostNames(lr.HostNames),
			pathType:  pathType,
			path:      path,
			backend: backend{
				ips:         r.toIPBackends(routeBackend.Spec.Addresses),
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
			},
		})
	}

	return &lbApplicationHTTPProxy{
		routes: routes,
	}
}

func (r *ingestor) toApplicationHTTPS(frontend *isovalentv1alpha1.LBFrontend, backends []*isovalentv1alpha1.LBBackend) *lbApplicationHTTPSProxy {
	if frontend.Spec.Applications.HTTPSProxy == nil {
		return nil
	}

	backendIndex := map[string]*isovalentv1alpha1.LBBackend{}
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

		pathType, path := toPath(lr)

		routes = append(routes, lbRouteHTTPS{
			hostNames: r.toHostNames(lr.HostNames),
			pathType:  pathType,
			path:      path,
			backend: backend{
				ips:         r.toIPBackends(routeBackend.Spec.Addresses),
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
			},
		})
	}

	return &lbApplicationHTTPSProxy{
		tlsConfig: r.toTLS(frontend),
		routes:    routes,
	}
}

func toPath(lr isovalentv1alpha1.LBFrontendHTTPRoute) (pathTypeType, string) {
	pathType := pathTypePrefix
	path := "/"

	if lr.Path != nil {
		if lr.Path.Prefix != nil {
			pathType = pathTypePrefix
			path = *lr.Path.Prefix
		} else if lr.Path.Exact != nil {
			pathType = pathTypeExact
			path = *lr.Path.Exact
		}
	}

	return pathType, path
}

func (r *ingestor) toApplicationTLSPassthrough(frontend *isovalentv1alpha1.LBFrontend, backends []*isovalentv1alpha1.LBBackend) *lbApplicationTLSPassthrough {
	if frontend.Spec.Applications.TLSPassthrough == nil {
		return nil
	}

	backendIndex := map[string]*isovalentv1alpha1.LBBackend{}
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
			hostNames: r.toHostNames(lr.HostNames),
			backend: backend{
				ips:         r.toIPBackends(routeBackend.Spec.Addresses),
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

func (r *ingestor) toIPBackends(addresses []isovalentv1alpha1.Address) []lbBackend {
	ipBackends := []lbBackend{}
	for _, ipAddress := range addresses {
		ipBackends = append(ipBackends, lbBackend{
			address: ipAddress.IP,
			port:    uint32(ipAddress.Port),
		})
	}

	return ipBackends
}

func (r *ingestor) toHostNames(crdHostnames []isovalentv1alpha1.LBFrontendHostName) []string {
	if len(crdHostnames) == 0 {
		return []string{"*"}
	}

	hostNames := []string{}
	for _, h := range crdHostnames {
		hostNames = append(hostNames, string(h))
	}

	return hostNames
}

func getRequestedIP(vip *isovalentv1alpha1.LBVIP) *string {
	if vip == nil {
		return nil
	}
	return vip.Spec.IPv4Request
}

// getAssignedIP evaluates and returns the actually assigned loadbalancer IP from the LBVIP resource.
// If there's no assigned loadbalancer IP assigned yet, nil is returned instead.
func getAssignedIP(vip *isovalentv1alpha1.LBVIP) *string {
	if vip != nil && vip.Status.Addresses.IPv4 != "" {
		return &vip.Status.Addresses.IPv4
	}

	return nil
}
