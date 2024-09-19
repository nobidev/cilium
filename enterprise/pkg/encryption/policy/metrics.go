//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package policy

import (
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
	"github.com/cilium/cilium/pkg/time"
)

type encryptionPolicyMetrics struct {
	EncryptionPolicyRules     metric.Gauge
	PolicyComputationRuns     metric.Vec[metric.Counter]
	PolicyComputationDuration metric.Vec[metric.Observer]
}

const (
	reasonPolicyUpdate   = "policy-update"
	reasonIdentityUpdate = "identity-update"
)

func newEncryptionPolicyMetrics() *encryptionPolicyMetrics {
	return &encryptionPolicyMetrics{
		EncryptionPolicyRules: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: "encryption_policy",
			Name:      "rules",
			Help:      "Number of implemented encryption policy rules",
		}),
		PolicyComputationRuns: metric.NewCounterVec(metric.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "encryption_policy",
			Name:      "computation_runs_total",
			Help:      "Number of times the encryption policy engine performed a recomputation",
		}, []string{"reason"}),
		PolicyComputationDuration: metric.NewHistogramVec(metric.HistogramOpts{
			Namespace: metrics.Namespace,
			Subsystem: "encryption_policy",
			Name:      "computation_runs_duration_seconds",
			Help:      "Histogram of per-operation duration during encryption policy computation",
		}, []string{"reason"}),
	}
}

func (e *encryptionPolicyMetrics) JobError(name string, err error) {
	// no-op
}

func (e *encryptionPolicyMetrics) OneShotRunDuration(name string, duration time.Duration) {
	// no-op
}

func (e *encryptionPolicyMetrics) TimerRunDuration(name string, duration time.Duration) {
	// no-op
}

func (e *encryptionPolicyMetrics) TimerTriggerStats(name string, latency time.Duration, folds int) {
	// no-op
}

func (e *encryptionPolicyMetrics) ObserverRunDuration(name string, duration time.Duration) {
	switch name {
	case identityUpdateObserver:
		e.PolicyComputationRuns.WithLabelValues(reasonIdentityUpdate).Inc()
		e.PolicyComputationDuration.WithLabelValues(reasonIdentityUpdate).Observe(duration.Seconds())
	case policyUpdateObserver:
		e.PolicyComputationRuns.WithLabelValues(reasonPolicyUpdate).Inc()
		e.PolicyComputationDuration.WithLabelValues(reasonPolicyUpdate).Observe(duration.Seconds())
	}
}
