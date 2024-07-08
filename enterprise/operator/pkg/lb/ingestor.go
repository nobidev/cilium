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
	routes, err := r.toRoutes(frontend, backends)
	if err != nil {
		return nil, fmt.Errorf("failed to ingest routes: %w", err)
	}

	return &lbFrontend{
		namespace:  frontend.Namespace,
		name:       frontend.Name,
		staticIP:   frontend.Spec.VIP,
		assignedIP: getAssignedIP(t1Service),
		port:       frontend.Spec.Port,
		tls:        r.toTLS(frontend),
		routes:     routes,
	}, nil
}

func (*ingestor) toTLS(frontend *isovalentv1alpha1.LBFrontend) *lbFrontendTLS {
	if frontend.Spec.TLS == nil {
		return nil
	}

	certificateSecretNames := []string{}

	for _, c := range frontend.Spec.TLS.Certificates {
		certificateSecretNames = append(certificateSecretNames, c.SecretName)
	}

	return &lbFrontendTLS{
		certificateSecrets: certificateSecretNames,
	}
}

func (r *ingestor) toRoutes(frontend *isovalentv1alpha1.LBFrontend, backends []*isovalentv1alpha1.LBBackend) ([]lbRoute, error) {
	backendIndex := map[string]*isovalentv1alpha1.LBBackend{}
	for _, b := range backends {
		backendIndex[b.Name] = b
	}

	routes := []lbRoute{}

	for _, lr := range frontend.Spec.Routes {
		if lr.HTTP != nil {
			routeBackend, ok := backendIndex[lr.HTTP.Backend]
			if !ok {
				// backend not present yet
				continue
			}

			intervalDuration, err := time.ParseDuration(routeBackend.Spec.Healthcheck.Interval)
			if err != nil {
				return nil, fmt.Errorf("failed to parse HC interval: %w", err)
			}

			routes = append(routes, lbRoute{
				http: &lbRouteHTTP{
					hostNames: r.toHostNames(lr.HTTP.HostNames),
					path:      "/",
					pathType:  pathTypePrefix,
				},
				https:          nil,
				tlsPassthrough: nil,
				tcp:            nil,
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
		} else if lr.HTTPS != nil {
			routeBackend, ok := backendIndex[lr.HTTPS.Backend]
			if !ok {
				// backend not present yet
				continue
			}

			intervalDuration, err := time.ParseDuration(routeBackend.Spec.Healthcheck.Interval)
			if err != nil {
				return nil, fmt.Errorf("failed to parse HC interval: %w", err)
			}

			routes = append(routes, lbRoute{
				http: nil,
				https: &lbRouteHTTPS{
					hostNames: r.toHostNames(lr.HTTPS.HostNames),
					path:      "/",
					pathType:  pathTypePrefix,
				},
				tlsPassthrough: nil,
				tcp:            nil,
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
	}

	return routes, nil
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
