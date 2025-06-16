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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/statedb"

	"github.com/cilium/cilium/enterprise/pkg/diagnostics"
	"github.com/cilium/cilium/pkg/hive/health"
	"github.com/cilium/cilium/pkg/hive/health/types"
)

func TestEndpointRegenCondition(t *testing.T) {
	fakeEnv := &diagnostics.FakeEnvironment{}

	msg, fail := evalEndpointRegeneration(fakeEnv)
	assert.Contains(t, msg, "OK")
	assert.False(t, fail)

	fakeEnv.FakeHistogram = diagnostics.HistogramStats{
		Avg_24h:    1.0,
		Avg_Latest: 10.0,
	}

	msg, fail = evalEndpointRegeneration(fakeEnv)
	assert.Contains(t, msg, "10.0s is >3.0x the 24 hour average of 1.0s")
	assert.True(t, fail)

	fakeEnv.FakeUserConstants = map[string]float64{
		keyEndpointRegenMultiplier: 2.5,
	}

	msg, fail = evalEndpointRegeneration(fakeEnv)
	assert.Contains(t, msg, "10.0s is >2.5x the 24 hour average of 1.0s")
	assert.True(t, fail)
}

func TestHiveHealthCondition(t *testing.T) {
	fakeEnv := &diagnostics.FakeEnvironment{}
	db := statedb.New()
	healthTable, err := newHealthTable(db)
	require.NoError(t, err, "newHealthTable")
	eval := evalHiveHealth(db, healthTable)

	msg, fail := eval(fakeEnv)
	assert.Empty(t, msg)
	assert.False(t, fail)

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

	msg, fail = eval(fakeEnv)
	assert.Contains(t, msg, "Degraded modules: foo.bar")
	assert.True(t, fail)
}

func newHealthTable(db *statedb.DB) (statedb.RWTable[types.Status], error) {
	statusTable, err := statedb.NewTable(health.TableName,
		health.PrimaryIndex,
		health.LevelIndex)
	if err != nil {
		return nil, err
	}
	if err := db.RegisterTable(statusTable); err != nil {
		return nil, err
	}
	return statusTable, nil
}
