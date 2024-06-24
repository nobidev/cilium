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

func (r *ingestor) ingest(frontend *isovalentv1alpha1.LBFrontend, t1Service *corev1.Service) (*lbFrontend, error) {
	ipBackends := []lbBackend{}
	for _, ipb := range frontend.Spec.Backends {
		ipBackends = append(ipBackends, lbBackend{
			address: ipb.IP,
			port:    uint32(ipb.Port),
		})
	}

	intervalDuration, err := time.ParseDuration(frontend.Spec.Healthcheck.Interval)
	if err != nil {
		return nil, fmt.Errorf("failed to parse HC interval: %w", err)
	}

	return &lbFrontend{
		namespace:  frontend.Namespace,
		name:       frontend.Name,
		staticIP:   frontend.Spec.VIP,
		assignedIP: getAssignedIP(t1Service),
		port:       frontend.Spec.Port,
		routes: []lbRoute{
			{
				http: &lbRouteHttp{
					tls:      nil,
					hostname: "*",
					path:     "/",
					pathType: pathTypePrefix,
				},
				tls: nil,
				tcp: nil,
				backendGroup: lbBackendGroup{
					ips:         ipBackends,
					hostnames:   []lbBackend{},
					lbAlgorithm: lbAlgorithmRoundRobin,
					healthCheckConfig: lbBackendHealthCheckConfig{
						http: &lbBackendHealthCheckHttpConfig{
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
			},
		},
	}, nil
}

// getAssignedIP evaluates and returns the actually assigned loadbalancer IP from the T1 Service.
// If there's no assigned loadbalancer IP assigned yet, nil is returned instead.
func getAssignedIP(t1Service *corev1.Service) *string {
	if t1Service != nil && len(t1Service.Status.LoadBalancer.Ingress) > 0 && t1Service.Status.LoadBalancer.Ingress[0].IP != "" {
		return &t1Service.Status.LoadBalancer.Ingress[0].IP
	}

	return nil
}
