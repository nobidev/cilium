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
	"fmt"
	"strings"

	"github.com/cilium/cilium/enterprise/pkg/diagnostics"
	"github.com/cilium/cilium/pkg/metrics"
)

// The user constants that can be overridden with --diagnostics-constants.
const (
	// policyImplementationDelayMultiplierKey is the key for setting the threshold for policy implementation latency, e.g.
	// how many times the 24h average latency should the latency be before the condition fails.
	policyImplementationDelayMultiplierKey = "policy_impl_delay_multiplier"

	// defaultPolicyImplementationDelayMultiplier is the default threshold multiplier, e.g. if the current average latency
	// (average latency since the last evaluation) multiplied by this multiplier is above the 24h average then
	// the condition is marked failed.
	defaultPolicyImplementationDelayMultiplier = 3.0
)

func registerPolicyDiagnosticConditions(reg *diagnostics.Registry) error {
	return reg.Register(
		diagnostics.Condition{
			ID:          "policy_implementation",
			SubSystem:   "Policy",
			Description: "Enforcing policy updates from control plane is taking longer than expected.",
			Evaluator:   evalPolicyImplmentationDelay,
		},
		diagnostics.Condition{
			ID:          "policy_identity_updates",
			SubSystem:   "Policy",
			Description: "Propagation of identity updates to endpoint policy state is taking longer than expected.",
			Evaluator:   evalPolicyIncrementalUpdateLatency,
		},
	)
}

// TODO: Add support for sampling counter metrics as rate/increase stats in diagnostics module.
// Support diagnostic condition for counter metrics:
// * `cilium_policy_change_total{outcome="failure"}` - Policy parsing failures
// * `cilium_xds_events_count{status="nack"}` - Envoy config update failures

func evalPolicyImplmentationDelay(env diagnostics.Environment) (msg string, severity diagnostics.Severity) {
	metricName := metrics.PolicyImplementationDelay.Opts().ConfigName
	policyImplementationDelayMetrics, err := env.MetricsMatchingLabels(metricName, nil)
	if err != nil {
		return err.Error(), diagnostics.OK
	}

	var (
		overallAverage    float64
		failingConditions []string
	)
	multiplier := env.UserConstant(policyImplementationDelayMultiplierKey, defaultPolicyImplementationDelayMultiplier)
	for _, m := range policyImplementationDelayMetrics {
		stats, err := env.Histogram(metricName, m.Labels())
		if err != nil || stats.Avg_Latest == 0.0 {
			continue
		}

		overallAverage = (overallAverage + stats.Avg_Latest) / 2
		threshold := multiplier * stats.Avg_24h
		if stats.Avg_24h > 0.0 && stats.Avg_Latest > threshold {
			failingConditions = append(failingConditions,
				fmt.Sprintf("%s: %.1fs > %.1fs", m.LabelsString(), stats.Avg_Latest, threshold))
		}
	}

	if len(failingConditions) > 0 {
		return fmt.Sprintf("High policy implementation latency(latest average >%.1fx of 24 hour average): [%s]", multiplier, strings.Join(failingConditions, ", ")), diagnostics.Minor
	}

	return fmt.Sprintf("Policy implementation latency OK (average %.2fs)", overallAverage), diagnostics.OK
}

func evalPolicyIncrementalUpdateLatency(env diagnostics.Environment) (msg string, severity diagnostics.Severity) {
	metricName := metrics.PolicyIncrementalUpdateDuration.Opts().ConfigName
	stats, err := env.Histogram(metricName, map[string]string{
		metrics.LabelScope: "global",
	})
	if err != nil {
		return err.Error(), diagnostics.OK
	}

	// Incremental policy update latency indicates the delay in propagating identity updates to policy maps.
	// Use same constants as that of policy implementation delay.
	multiplier := env.UserConstant(policyImplementationDelayMultiplierKey, defaultPolicyImplementationDelayMultiplier)
	if stats.Avg_24h > 0.0 && stats.Avg_Latest > multiplier*stats.Avg_24h {
		return fmt.Sprintf("Current average policy identity update propagation latency %.1fs is >%.1fx the 24 hour average of %.1fs",
			stats.Avg_Latest, multiplier, stats.Avg_24h), diagnostics.Minor
	}
	return fmt.Sprintf("%.2fs OK", stats.Avg_Latest), diagnostics.OK
}
