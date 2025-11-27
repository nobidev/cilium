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
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/enterprise/pkg/diagnostics"
)

func TestPolicyImplementationLatencyConditions(t *testing.T) {
	fakeEnv := &diagnostics.FakeEnvironment{
		FakeMetricsMatchingLabels: []diagnostics.Metric{{}},
	}

	msg, sev := evalPolicyImplmentationDelay(fakeEnv)
	assert.Contains(t, msg, "OK")
	assert.Equal(t, diagnostics.OK, sev)

	msg, sev = evalPolicyIncrementalUpdateLatency(fakeEnv)
	assert.Contains(t, msg, "OK")
	assert.Equal(t, diagnostics.OK, sev)

	fakeEnv.FakeHistogram = diagnostics.HistogramStats{
		Avg_24h:    3.0,
		Avg_Latest: 10.0,
	}

	_, sev = evalPolicyImplmentationDelay(fakeEnv)
	assert.Equal(t, diagnostics.Minor, sev)

	msg, sev = evalPolicyIncrementalUpdateLatency(fakeEnv)
	assert.Contains(t, msg, "10.0s is >3.0x the 24 hour average of 3.0s")
	assert.Equal(t, diagnostics.Minor, sev)

	fakeEnv.FakeHistogram.Avg_24h = 4.0

	msg, sev = evalPolicyImplmentationDelay(fakeEnv)
	assert.Contains(t, msg, "OK")
	assert.Equal(t, diagnostics.OK, sev)

	msg, sev = evalPolicyIncrementalUpdateLatency(fakeEnv)
	assert.Contains(t, msg, "OK")
	assert.Equal(t, diagnostics.OK, sev)

	fakeEnv.FakeUserConstants = map[string]float64{
		policyImplementationDelayMultiplierKey: 2,
	}

	_, sev = evalPolicyImplmentationDelay(fakeEnv)
	assert.Equal(t, diagnostics.Minor, sev)

	msg, sev = evalPolicyIncrementalUpdateLatency(fakeEnv)
	assert.Contains(t, msg, "10.0s is >2.0x the 24 hour average of 4.0s")
	assert.Equal(t, diagnostics.Minor, sev)
}
