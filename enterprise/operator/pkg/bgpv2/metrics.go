// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bgpv2

import (
	"github.com/cilium/cilium/enterprise/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

// OperatorMetrics contains metrics of the BGP operator.
type OperatorMetrics struct {
	// ReconcileErrorsTotal is the number of errors during reconciliation of the BGP configuration.
	ReconcileErrorsTotal metric.Vec[metric.Counter]

	// ReconcileRunDuration measures the duration of the reconciliation run. Histogram can
	// be used to observe the total number of reconciliation runs and distribution of the run duration.
	ReconcileRunDuration metric.Vec[metric.Observer]
}

// newBGPOperatorMetrics returns a new OperatorMetrics with all metrics initialized.
func newBGPOperatorMetrics() *OperatorMetrics {
	return &OperatorMetrics{
		ReconcileErrorsTotal: metric.NewCounterVec(metric.CounterOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Subsystem: types.MetricsSubsystem,
			Name:      types.MetricReconcileErrorsTotal,
			Help:      "The number of errors during reconciliation of BGP configuration",
		}, []string{types.LabelResourceKind}),
		ReconcileRunDuration: metric.NewHistogramVec(metric.HistogramOpts{
			Namespace: metrics.Namespace,
			Subsystem: types.MetricsSubsystem,
			Name:      types.MetricReconcileRunDuration,
			Help:      "The duration of the BGP reconciliation run",
		}, nil),
	}
}
