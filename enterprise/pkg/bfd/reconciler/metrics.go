//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package reconciler

import (
	"github.com/cilium/cilium/enterprise/pkg/bfd/types"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

type BFDMetrics struct {
	// SessionState contains the current state of the BFD session with the peer.
	SessionState metric.Vec[metric.Gauge]

	// ReconcileErrorCount is the number of errors during reconciliation of the BFD configuration.
	ReconcileErrorCount metric.Vec[metric.Counter]

	// ReconcileRunDuration measures the duration of the reconciliation run. Histogram can
	// be used to observe the total number of reconciliation runs and distribution of the run duration.
	ReconcileRunDuration metric.Vec[metric.Observer]
}

func newBFDMetrics() *BFDMetrics {
	return &BFDMetrics{
		SessionState: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: types.MetricsSubsystem,
			Name:      types.MetricSessionState,
			Help:      "Current state of the BFD session with the peer, Up = 1 or Down = 0",
		}, []string{types.LabelPeerIP, types.LabelInterface}),
		ReconcileErrorCount: metric.NewCounterVec(metric.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: types.MetricsSubsystem,
			Name:      types.MetricReconcileErrorCount,
			Help:      "The number of errors during reconciliation of BFD configuration",
		}, []string{types.LabelPeerName}),
		ReconcileRunDuration: metric.NewHistogramVec(metric.HistogramOpts{
			Namespace: metrics.Namespace,
			Subsystem: types.MetricsSubsystem,
			Name:      types.MetricReconcileRunDuration,
			Help:      "The duration of the BFD reconciliation run",
		}, nil),
	}
}
