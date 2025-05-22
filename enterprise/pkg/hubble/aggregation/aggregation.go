// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package aggregation

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jonboulle/clockwork"

	"github.com/cilium/cilium/enterprise/pkg/hubble/aggregation/aggregator"
	"github.com/cilium/cilium/enterprise/pkg/hubble/aggregation/api/aggregation"
	"github.com/cilium/cilium/enterprise/pkg/hubble/aggregation/internal/aggregation/types"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/exporter"
)

var _ exporter.OnExportEvent = (*EnterpriseAggregator)(nil)

type EnterpriseAggregator struct {
	flowAggregator    aggregator.FlowAggregator
	aggregationFilter *aggregation.Aggregation
	aggregators       types.Aggregator
}

func NewEnterpriseAggregator(aggFilter *aggregation.Aggregation, logger *slog.Logger) (*EnterpriseAggregator, error) {
	if len(aggFilter.Aggregators) == 0 {
		return nil, errors.New("no aggregator filters provided")
	}
	clock := clockwork.NewRealClock()
	flowAggregator := aggregator.NewFlowAggregator(clock, logger)
	aggregators, err := aggregator.ConfigureAggregator(clock, aggFilter.Aggregators)
	if err != nil {
		return nil, fmt.Errorf("could not create flow aggregator chain: %w", err)
	}

	return &EnterpriseAggregator{
		flowAggregator:    flowAggregator,
		aggregationFilter: aggFilter,
		aggregators:       aggregators,
	}, nil
}

// OnExportEvent implements exporter.OnExportEvent.
func (e *EnterpriseAggregator) OnExportEvent(ctx context.Context, ev *v1.Event, encoder exporter.Encoder) (stop bool, err error) {
	flow := ev.GetFlow()
	if flow == nil {
		// we only care about flow events
		return false, nil
	}

	ctx = e.flowAggregator.NewContext(ctx, e.aggregators, e.aggregationFilter)
	return e.flowAggregator.OnFlowDelivery(ctx, flow)
}

func (e *EnterpriseAggregator) Start(ctx context.Context) {
	e.aggregators.Start(ctx)
}
