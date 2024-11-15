// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package chain

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	aggregationpb "github.com/cilium/cilium/enterprise/pkg/hubble/aggregation/api/aggregation"
	"github.com/cilium/cilium/enterprise/pkg/hubble/aggregation/internal/aggregation/types"
	"github.com/cilium/cilium/enterprise/pkg/hubble/aggregation/internal/testflow"
)

type trueAggregator struct{}

func (a *trueAggregator) Aggregate(_ types.AggregatableFlow) *types.Result {
	return &types.Result{StateChange: aggregationpb.StateChange_new}
}

func (a *trueAggregator) Start(context.Context) {}

func (a *trueAggregator) String() string { return "trueAggreator" }

type falseAggregator struct{}

func (a *falseAggregator) Aggregate(_ types.AggregatableFlow) *types.Result {
	return &types.Result{}
}

func (a *falseAggregator) Start(context.Context) {}

func (a *falseAggregator) String() string { return "falseAggreator" }

func TestAggregationChain(t *testing.T) {
	af := NewAggregationChain([]types.Aggregator{})
	if af == nil {
		panic("Aggregation chain is nil")
	}

	assert.Equal(t, "[]", af.String())
	assert.Nil(t, af.Aggregate(&testflow.Flow{}))

	af.Add(&trueAggregator{})
	assert.NotEqual(t, "[]", af.String())
	assert.Equal(t, aggregationpb.StateChange_new, af.Aggregate(&testflow.Flow{}).StateChange)

	af = NewAggregationChain([]types.Aggregator{
		&trueAggregator{}, &trueAggregator{},
	})
	if af == nil {
		panic("Aggregation chain is nil")
	}

	assert.NotEqual(t, "[]", af.String())
	assert.Equal(t, aggregationpb.StateChange_new, af.Aggregate(&testflow.Flow{}).StateChange)

	af = NewAggregationChain([]types.Aggregator{
		&trueAggregator{}, &falseAggregator{},
	})
	if af == nil {
		panic("Aggregation chain is nil")
	}

	// Latest result wins
	assert.Equal(t, aggregationpb.StateChange_unspec, af.Aggregate(&testflow.Flow{}).StateChange)

	af = NewAggregationChain([]types.Aggregator{
		&falseAggregator{}, &falseAggregator{},
	})
	if af == nil {
		panic("Aggregation chain is nil")
	}

	assert.Equal(t, aggregationpb.StateChange_unspec, af.Aggregate(&testflow.Flow{}).StateChange)
}
