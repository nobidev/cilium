//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package metrics

import (
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

type Metrics struct {
	UnhealthyBgpPeers              metric.Vec[metric.Gauge]
	UnhealthyBgpNodes              metric.Vec[metric.Gauge]
	UnhealthyT1Nodes               metric.Vec[metric.Gauge]
	UnhealthyT2Healthchecks        metric.Vec[metric.Gauge]
	UnhealthyT2Nodes               metric.Vec[metric.Gauge]
	UnhealthyT2BackendHealthchecks metric.Vec[metric.Gauge]
	UnhealthyBackendpools          metric.Vec[metric.Gauge]
}

func MetricsProvider() Metrics {
	return Metrics{
		UnhealthyBgpPeers: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: "loadbalancer_controlplane",
			Help:      "Number of unhealthy BGP peers",
			Name:      "unhealthy_bgp_peers",
		}, []string{"service"}),
		UnhealthyBgpNodes: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: "loadbalancer_controlplane",
			Help:      "Number of unhealthy BGP nodes",
			Name:      "unhealthy_bgp_nodes",
		}, []string{"service"}),
		UnhealthyT1Nodes: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: "loadbalancer_controlplane",
			Help:      "Number of unhealthy T1 nodes",
			Name:      "unhealthy_t1_nodes",
		}, []string{"service"}),
		UnhealthyT2Healthchecks: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: "loadbalancer_controlplane",
			Help:      "Number of unhealthy T2 healthchecks",
			Name:      "unhealthy_t2_healthchecks",
		}, []string{"service"}),
		UnhealthyT2Nodes: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: "loadbalancer_controlplane",
			Help:      "Number of unhealthy T2 nodes",
			Name:      "unhealthy_t2_nodes",
		}, []string{"service"}),
		UnhealthyT2BackendHealthchecks: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: "loadbalancer_controlplane",
			Help:      "Number of unhealthy T2 backend healthchecks",
			Name:      "unhealthy_t2_backend_healthchecks",
		}, []string{"service"}),
		UnhealthyBackendpools: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: "loadbalancer_controlplane",
			Help:      "Number of unhealthy backend pools",
			Name:      "unhealthy_backend_pools",
		}, []string{"service", "group"}),
	}
}
