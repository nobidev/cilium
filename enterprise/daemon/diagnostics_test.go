//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package main

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/statedb"
	dto "github.com/prometheus/client_model/go"

	"github.com/cilium/cilium/enterprise/pkg/diagnostics"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/health"
	"github.com/cilium/cilium/pkg/hive/health/types"
)

func TestEndpointRegenCondition(t *testing.T) {
	fakeEnv := &diagnostics.FakeEnvironment{}

	msg, sev := evalEndpointRegeneration(fakeEnv)
	assert.Contains(t, msg, "OK")
	assert.Equal(t, diagnostics.OK, sev)

	fakeEnv.FakeHistogram = diagnostics.HistogramStats{
		Avg_24h:    1.0,
		Avg_Latest: 10.0,
	}

	msg, sev = evalEndpointRegeneration(fakeEnv)
	assert.Contains(t, msg, "10.0s is >3.0x the 24 hour average of 1.0s")
	assert.Equal(t, diagnostics.Minor, sev)

	fakeEnv.FakeUserConstants = map[string]float64{
		keyEndpointRegenMultiplier: 2.5,
	}

	msg, sev = evalEndpointRegeneration(fakeEnv)
	assert.Contains(t, msg, "10.0s is >2.5x the 24 hour average of 1.0s")
	assert.Equal(t, diagnostics.Minor, sev)
}

func TestHiveHealthCondition(t *testing.T) {
	fakeEnv := &diagnostics.FakeEnvironment{}
	db := statedb.New()
	healthTable, err := newHealthTable(db)
	require.NoError(t, err, "newHealthTable")
	eval := evalHiveHealth(db, healthTable)

	msg, sev := eval(fakeEnv)
	assert.Empty(t, msg)
	assert.Equal(t, diagnostics.OK, sev)

	wtxn := db.WriteTxn(healthTable)
	healthTable.Insert(wtxn,
		types.Status{
			ID: types.Identifier{
				Module:    []string{"foo"},
				Component: []string{"bar"},
			},
			Level: types.LevelDegraded,
		})
	wtxn.Commit()

	msg, sev = eval(fakeEnv)
	assert.Contains(t, msg, "Degraded modules: foo.bar")
	assert.Equal(t, diagnostics.Debug, sev)
}

func newHealthTable(db *statedb.DB) (statedb.RWTable[types.Status], error) {
	return statedb.NewTable(
		db,
		health.TableName,
		health.PrimaryIndex,
		health.LevelIndex)
}

func TestStateDBCondition_WriteTxn(t *testing.T) {
	statedbMetrics := hive.NewStateDBMetrics()
	fakeEnv := &diagnostics.FakeEnvironment{}
	strp := func(s string) *string { return &s }
	eval := evalStateDB(statedb.New(), statedbMetrics)

	// Evaluate without any matching metrics
	msg, sev := eval(fakeEnv)
	assert.Contains(t, msg, "OK")
	assert.Equal(t, diagnostics.OK, sev)

	fakeEnv.FakeMetricsMatchingLabels = []diagnostics.Metric{
		{
			Name: statedbMetrics.WriteTxnDuration.Opts().GetConfigName(),
			Raw: &dto.Metric{
				Label: []*dto.LabelPair{{
					Name:  strp("handle"),
					Value: strp("foo"),
				}},
			},
		},
	}
	fakeEnv.FakeHistogram.Avg_Latest = defaultStateDBWriteTxnThresholdSeconds / 2

	// Evaluate with a matching metric but below the threshold
	msg, sev = eval(fakeEnv)
	assert.Equal(t, fmt.Sprintf("WriteTxn OK (max %.1fs), Graveyard OK", fakeEnv.FakeHistogram.Avg_Latest), msg)
	assert.Equal(t, diagnostics.OK, sev, "Succeed with metric below threshold")

	// Set the metrics above the threshold
	fakeEnv.FakeHistogram.Avg_Latest = defaultStateDBWriteTxnThresholdSeconds * 2

	// Evaluate with metric above the threshold
	msg, sev = eval(fakeEnv)
	assert.Equal(t, fmt.Sprintf("WriteTxn latency >%.1fs for [handle=foo], Graveyard OK", defaultStateDBWriteTxnThresholdSeconds), msg)
	assert.Equal(t, diagnostics.Debug, sev, "Fail with metric above threshold")

	// Test with a custom user constant
	fakeEnv.FakeUserConstants = map[string]float64{
		keyStateDBWriteTxnThreshold: 2.0,
	}
	fakeEnv.FakeHistogram.Avg_Latest = 1.5
	_, sev = eval(fakeEnv)
	assert.Equal(t, diagnostics.OK, sev)
	fakeEnv.FakeHistogram.Avg_Latest = 2.5
	_, sev = eval(fakeEnv)
	assert.Equal(t, diagnostics.Debug, sev)
}

func TestStateDBCondition_Graveyard(t *testing.T) {
	statedbMetrics := hive.NewStateDBMetrics()
	fakeEnv := &diagnostics.FakeEnvironment{}
	strp := func(s string) *string { return &s }
	eval := evalStateDB(statedb.New(), statedbMetrics)

	fakeEnv.FakeMetricsMatchingLabels = []diagnostics.Metric{
		{
			Name: statedbMetrics.TableGraveyardObjectCount.Opts().GetConfigName(),
			Raw: &dto.Metric{
				Label: []*dto.LabelPair{{
					Name:  strp("table"),
					Value: strp("foo"),
				}},
			},
		},
	}
	fakeEnv.FakeGauge.Avg_1h = 0.1

	// Evaluate with a matching metric but below the threshold
	msg, sev := eval(fakeEnv)
	assert.Regexp(t, `WriteTxn OK.*Graveyard OK`, msg)
	assert.Equal(t, diagnostics.OK, sev, "Succeed with metric below threshold")

	// Set the metrics above the threshold
	fakeEnv.FakeGauge.Avg_1h = 2.0

	// Evaluate with metric above the threshold
	msg, sev = eval(fakeEnv)
	assert.Regexp(t, `WriteTxn OK.*Graveyard: Potentially stuck.*for \[table=foo\]`, msg)
	assert.Equal(t, diagnostics.Debug, sev, "Fail with metric above threshold")
}

func TestStateDBCondition_PendingInitializers(t *testing.T) {
	db := statedb.New()
	healthTable, err := newHealthTable(db)
	require.NoError(t, err)
	wtxn := db.WriteTxn(healthTable)
	init := healthTable.RegisterInitializer(wtxn, "test")
	wtxn.Commit()

	eval := evalStateDBPendingInitializers(db)
	fakeEnv := &diagnostics.FakeEnvironment{}

	fakeEnv.FakeNow = time.Now()

	// The pending initializer exists, but not enough time has passed.
	msg, fail := eval(fakeEnv)
	assert.False(t, fail)
	assert.Empty(t, msg)

	// Try again after we've exceeded the threshold
	fakeEnv.FakeNow = fakeEnv.FakeNow.Add(2 * pendingInitializersThresholdDuration)
	msg, fail = eval(fakeEnv)
	assert.True(t, fail)
	assert.Equal(t, `Table "health" still waiting for initializers: [test]`, msg)

	// Marking the table initialized clears the condition
	wtxn = db.WriteTxn(healthTable)
	init(wtxn)
	wtxn.Commit()

	msg, fail = eval(fakeEnv)
	assert.False(t, fail)
	assert.Empty(t, msg)
}
