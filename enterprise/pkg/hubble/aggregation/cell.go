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
	"github.com/cilium/hive/cell"
	"github.com/jonboulle/clockwork"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/enterprise/pkg/hubble/aggregation/aggregator"
	"github.com/cilium/cilium/pkg/hubble/observer/observeroption"
)

var Cell = cell.Module(
	"enterprise-hubble-aggregator",
	"Hubble Enterprise Observer Flow Aggregator",

	cell.Provide(newObserverFlowAggregator),
)

type observerFlowAggregatorOut struct {
	cell.Out

	ObserverOptions []observeroption.Option `group:"hubble-observer-options,flatten"`
}

func newObserverFlowAggregator(logger logrus.FieldLogger) (observerFlowAggregatorOut, error) {
	clock := clockwork.NewRealClock()
	flowAggregator := aggregator.NewFlowAggregator(clock, logger)
	options := []observeroption.Option{
		// responsible for injecting aggregatorCtx used by all future flows
		observeroption.WithOnGetFlows(flowAggregator),
		// responsible for extracting aggregatorCtx for each flow and call Aggregate()
		observeroption.WithOnFlowDelivery(flowAggregator),
	}
	return observerFlowAggregatorOut{ObserverOptions: options}, nil
}
