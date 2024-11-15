// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package aggregator

import (
	"context"
	"testing"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"

	aggregationpb "github.com/cilium/cilium/enterprise/pkg/hubble/aggregation/api/aggregation"
)

func Test_flowAggregation_OnFlowDelivery(t *testing.T) {
	p := &flowAggregation{}
	stop, err := p.OnFlowDelivery(context.TODO(), nil)
	assert.NoError(t, err)
	assert.False(t, stop)
}

func TestConfigureAggregator(t *testing.T) {
	clock := clockwork.NewFakeClock()
	a, err := ConfigureAggregator(clock, []*aggregationpb.Aggregator{})
	assert.NoError(t, err)
	assert.Nil(t, a)

	a, err = ConfigureAggregator(clock, []*aggregationpb.Aggregator{{Type: 10000}})
	assert.Error(t, err)
	assert.Nil(t, a)

	a, err = ConfigureAggregator(clock, []*aggregationpb.Aggregator{{Type: aggregationpb.AggregatorType_identity}})
	assert.NoError(t, err)
	assert.Equal(t, "compare", a.String())

	a, err = ConfigureAggregator(clock, []*aggregationpb.Aggregator{{Type: aggregationpb.AggregatorType_identity}, {Type: aggregationpb.AggregatorType_connection}})
	assert.NoError(t, err)
	assert.EqualValues(t, '[', a.String()[0])
}
