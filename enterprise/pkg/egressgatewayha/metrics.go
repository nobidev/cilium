//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package egressgatewayha

import (
	ciliumMetrics "github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

const (
	subsystemEGWHA = "egressgatewayha"

	labelPolicy = "policy"
	labelAZ     = "az"
	labelScope  = "scope"

	labelValueScopeLocal  = "local"
	labelValueScopeRemote = "remote"
)

type Metrics struct {
	ActiveGateways     metric.DeletableVec[metric.Gauge]
	ActiveGatewaysByAZ metric.DeletableVec[metric.Gauge]
	HealthyGateways    metric.DeletableVec[metric.Gauge]
}

func newMetrics() *Metrics {
	return &Metrics{
		ActiveGateways: metric.NewGaugeVecWithLabels(metric.GaugeOpts{
			Help:      "Number of active gateways selected for this policy.",
			Namespace: ciliumMetrics.CiliumOperatorNamespace,
			Subsystem: subsystemEGWHA,
			Name:      "active_gateways",
		}, metric.Labels{
			{Name: labelPolicy},
		}),
		ActiveGatewaysByAZ: metric.NewGaugeVecWithLabels(metric.GaugeOpts{
			Help:      "Number of active gateways available to serve traffic from the given AZ; split by scope=local (gateway in the same AZ) and scope=remote (gateway selected from a different AZ).",
			Namespace: ciliumMetrics.CiliumOperatorNamespace,
			Subsystem: subsystemEGWHA,
			Name:      "active_gateways_by_az",
		}, metric.Labels{
			{Name: labelPolicy},
			{Name: labelAZ},
			{Name: labelScope, Values: metric.NewValues(labelValueScopeLocal, labelValueScopeRemote)},
		}),
		HealthyGateways: metric.NewGaugeVecWithLabels(metric.GaugeOpts{
			Help:      "Number of healthy gateways for this policy.",
			Namespace: ciliumMetrics.CiliumOperatorNamespace,
			Subsystem: subsystemEGWHA,
			Name:      "healthy_gateways",
		}, metric.Labels{
			{Name: labelPolicy},
		}),
	}
}
