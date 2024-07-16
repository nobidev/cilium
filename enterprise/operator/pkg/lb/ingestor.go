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

	corev1 "k8s.io/api/core/v1"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/time"
)

type ingestor struct{}

func (r *ingestor) ingest(frontend *isovalentv1alpha1.LBFrontend, backends []*isovalentv1alpha1.LBBackend, t1Service *corev1.Service) (*lbFrontend, error) {
	applications, err := r.toApplications(frontend, backends)
	if err != nil {
		return nil, fmt.Errorf("failed to ingest applications: %w", err)
	}

	return &lbFrontend{
		namespace:    frontend.Namespace,
		name:         frontend.Name,
		staticIP:     frontend.Spec.VIP,
		assignedIP:   getAssignedIP(t1Service),
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
	http, err := r.toApplicationHTTP(frontend, backends)
	if err != nil {
		return lbApplications{}, err
	}

	https, err := r.toApplicationHTTPS(frontend, backends)
	if err != nil {
		return lbApplications{}, err
	}

	tlsPassthrough, err := r.toApplicationTLSPassthrough(frontend, backends)
	if err != nil {
		return lbApplications{}, err
	}

	return lbApplications{
		httpProxy:      http,
		httpsProxy:     https,
		tlsPassthrough: tlsPassthrough,
	}, nil
}

func (r *ingestor) toApplicationHTTP(frontend *isovalentv1alpha1.LBFrontend, backends []*isovalentv1alpha1.LBBackend) (*lbApplicationHTTPProxy, error) {
	if frontend.Spec.Applications.HTTPProxy == nil {
		return nil, nil
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

		intervalDuration, err := time.ParseDuration(routeBackend.Spec.Healthcheck.Interval)
		if err != nil {
			return nil, fmt.Errorf("failed to parse HC interval: %w", err)
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
					http: &lbBackendHealthCheckHTTPConfig{
						host: "envoy",
						path: "/health",
					},
					tcp:                          nil,
					intervalSeconds:              int(intervalDuration.Seconds()),
					timeoutSeconds:               5,
					healthyThreshold:             2,
					unhealthyThreshold:           2,
					unhealthyEdgeIntervalSeconds: 30,
					unhealthyIntervalSeconds:     int(intervalDuration.Seconds()),
				},
			},
		})
	}

	return &lbApplicationHTTPProxy{
		routes: routes,
	}, nil
}

func (r *ingestor) toApplicationHTTPS(frontend *isovalentv1alpha1.LBFrontend, backends []*isovalentv1alpha1.LBBackend) (*lbApplicationHTTPSProxy, error) {
	if frontend.Spec.Applications.HTTPSProxy == nil {
		return nil, nil
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

		intervalDuration, err := time.ParseDuration(routeBackend.Spec.Healthcheck.Interval)
		if err != nil {
			return nil, fmt.Errorf("failed to parse HC interval: %w", err)
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
					http: &lbBackendHealthCheckHTTPConfig{
						host: "envoy",
						path: "/health",
					},
					tcp:                          nil,
					intervalSeconds:              int(intervalDuration.Seconds()),
					timeoutSeconds:               5,
					healthyThreshold:             2,
					unhealthyThreshold:           2,
					unhealthyEdgeIntervalSeconds: 30,
					unhealthyIntervalSeconds:     int(intervalDuration.Seconds()),
				},
			},
		})
	}

	return &lbApplicationHTTPSProxy{
		tlsConfig: r.toTLS(frontend),
		routes:    routes,
	}, nil
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

func (r *ingestor) toApplicationTLSPassthrough(frontend *isovalentv1alpha1.LBFrontend, backends []*isovalentv1alpha1.LBBackend) (*lbApplicationTLSPassthrough, error) {
	if frontend.Spec.Applications.TLSPassthrough == nil {
		return nil, nil
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

		intervalDuration, err := time.ParseDuration(routeBackend.Spec.Healthcheck.Interval)
		if err != nil {
			return nil, fmt.Errorf("failed to parse HC interval: %w", err)
		}

		routes = append(routes, lbRouteTLSPassthrough{
			hostNames: r.toHostNames(lr.HostNames),
			backend: backend{
				ips:         r.toIPBackends(routeBackend.Spec.Addresses),
				hostnames:   []lbBackend{},
				lbAlgorithm: lbAlgorithmRoundRobin,
				healthCheckConfig: lbBackendHealthCheckConfig{
					http: &lbBackendHealthCheckHTTPConfig{
						host: "envoy",
						path: "/health",
					},
					tcp:                          nil,
					intervalSeconds:              int(intervalDuration.Seconds()),
					timeoutSeconds:               5,
					healthyThreshold:             2,
					unhealthyThreshold:           2,
					unhealthyEdgeIntervalSeconds: 30,
					unhealthyIntervalSeconds:     int(intervalDuration.Seconds()),
				},
			},
		})
	}

	return &lbApplicationTLSPassthrough{
		routes: routes,
	}, nil
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
	hostNames := []string{}
	for _, h := range crdHostnames {
		hostNames = append(hostNames, string(h))
	}

	return hostNames
}

// getAssignedIP evaluates and returns the actually assigned loadbalancer IP from the T1 Service.
// If there's no assigned loadbalancer IP assigned yet, nil is returned instead.
func getAssignedIP(t1Service *corev1.Service) *string {
	if t1Service != nil && len(t1Service.Status.LoadBalancer.Ingress) > 0 && t1Service.Status.LoadBalancer.Ingress[0].IP != "" {
		return &t1Service.Status.LoadBalancer.Ingress[0].IP
	}

	return nil
}
