//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package diagnostics

import (
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

type diagnosticMetrics struct {
	// Number of failing conditions.
	ConditionFailures metric.Gauge

	// Histogram of how long the evaluation of conditions took
	ControllerDuration metric.Histogram
}

func newMetrics() diagnosticMetrics {
	return diagnosticMetrics{
		ConditionFailures: metric.NewGauge(metric.GaugeOpts{
			Namespace:  metrics.Namespace,
			Subsystem:  "diagnostics",
			Name:       "condition_failures",
			ConfigName: metrics.Namespace + "_diagnostics_condition_failures",
			Help:       "Gauge of failures",
			Disabled:   true,
		}),
		ControllerDuration: metric.NewHistogram(metric.HistogramOpts{
			Namespace:  metrics.Namespace,
			ConfigName: metrics.Namespace + "_diagnostics_controller_duration_seconds",
			Subsystem:  "diagnostics",
			Name:       "controller_duration_seconds",
			Help:       "Histogram of diagnostic evaluation times",
			Disabled:   true,
			// Use buckets in the 0.5ms-1.0s range.
			Buckets: []float64{.0005, .001, .0025, .005, .01, .025, .05, 0.1, 0.25, 0.5, 1.0},
		}),
	}
}
