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
	"sync/atomic"
)

// newInternalConditions registers conditions internal to the diagnostics
// subsystem.
func newInternalConditions(m diagnosticMetrics, reg *Registry) (*internalConditions, error) {
	ic := &internalConditions{m: m}
	err := reg.Register(
		Condition{
			ID:          "diagnostics_evaluation_duration",
			SubSystem:   "Agent",
			Description: "The evaluation of diagnostics conditions is taking longer than expected.",
			Evaluator:   ic.checkEvaluationDuration,
		},
		Condition{
			ID:          "diagnostics_simulated_failure",
			SubSystem:   "Agent",
			Description: "This is a simulated failure toggled by the 'diagnostics/toggle-fail' shell command.",
			Evaluator:   ic.checkSimulatedFailure,
		},
	)
	return ic, err
}

const evaluationThresholdSeconds = 5.0

type internalConditions struct {
	m diagnosticMetrics

	simulatedFailure atomic.Bool
}

func (ic *internalConditions) checkEvaluationDuration(env Environment) (Message, Severity) {
	stats, err := env.Histogram(
		ic.m.ControllerDuration.Opts().ConfigName,
		nil,
	)
	if err != nil {
		return err.Error(), Debug
	}

	// Worse than 3x the 24 hour average?
	if stats.Avg_24h > 0.0 && stats.Avg_Latest > 3*stats.Avg_24h {
		return fmt.Sprintf("Diagnostics evaluation taking %.2fs which is 3x the 24h average (%.2fs)",
			stats.Avg_Latest,
			stats.Avg_24h), Debug
	}

	// Worse than the fixed threshold?
	if stats.Avg_Latest > evaluationThresholdSeconds {
		return fmt.Sprintf("Diagnostic evaluation taking %.2fs (threshold %f)", stats.Avg_Latest, evaluationThresholdSeconds),
			Debug
	}

	return "OK", OK
}

func (ic *internalConditions) checkSimulatedFailure(env Environment) (Message, Severity) {
	if ic.simulatedFailure.Load() {
		return "Simulated failure triggered", Debug
	}
	return "OK", OK
}
