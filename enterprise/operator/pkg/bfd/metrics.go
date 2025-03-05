// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bfd

import (
	"github.com/cilium/cilium/enterprise/pkg/bfd/types"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

// OperatorMetrics contains metrics of the BFD operator.
type OperatorMetrics struct {
	// ReconcileErrorsTotal is the number of errors during reconciliation of the BFD configuration.
	ReconcileErrorsTotal metric.Vec[metric.Counter]

	// ReconcileRunDuration measures the duration of the reconciliation run. Histogram can
	// be used to observe the total number of reconciliation runs and distribution of the run duration.
	ReconcileRunDuration metric.Vec[metric.Observer]
}

// newBFDOperatorMetrics returns a new OperatorMetrics with all metrics initialized.
func newBFDOperatorMetrics() *OperatorMetrics {
	return &OperatorMetrics{
		ReconcileErrorsTotal: metric.NewCounterVec(metric.CounterOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Subsystem: types.MetricsSubsystem,
			Name:      types.MetricReconcileErrorsTotal,
			Help:      "The number of errors during reconciliation of BFD configuration",
		}, []string{types.LabelResourceKind, types.LabelResourceName}),
		ReconcileRunDuration: metric.NewHistogramVec(metric.HistogramOpts{
			Namespace: metrics.Namespace,
			Subsystem: types.MetricsSubsystem,
			Name:      types.MetricReconcileRunDuration,
			Help:      "The duration of the BFD reconciliation run",
		}, nil),
	}
}
