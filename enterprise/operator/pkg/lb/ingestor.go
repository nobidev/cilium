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
	"github.com/cilium/cilium/pkg/time"
)

type ingestor struct{}

func (r *ingestor) ingest(lb *isovalentv1alpha1.IsovalentLB) (*lbFrontend, error) {
	ipBackends := []lbBackend{}
	for _, ipb := range lb.Spec.Backends {
		ipBackends = append(ipBackends, lbBackend{
			address: ipb.IP,
			port:    uint32(ipb.Port),
		})
	}

	intervalDuration, err := time.ParseDuration(lb.Spec.Healthcheck.Interval)
	if err != nil {
		return nil, fmt.Errorf("failed to parse HC interval: %w", err)
	}

	return &lbFrontend{
		namespace: lb.Namespace,
		name:      lb.Name,
		ip:        lb.Spec.VIP,
		port:      lb.Spec.Port,
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
