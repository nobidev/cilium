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
	"fmt"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/jonboulle/clockwork"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/enterprise/pkg/hubble/aggregation/aggregator"
	"github.com/cilium/cilium/enterprise/pkg/hubble/aggregation/api/aggregation"
	"github.com/cilium/cilium/enterprise/pkg/hubble/aggregation/internal/aggregation/types"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/exporter"
	"github.com/cilium/cilium/pkg/hubble/observer/observeroption"
	"github.com/cilium/cilium/pkg/time"
)

var Cell = cell.Module(
	"enterprise-hubble-aggregation",
	"Hubble Enterprise Flow Aggregation",

	cell.Provide(newHubbleEnterpriseAggregator),
	cell.Config(defaultConfig),
)

type config struct {
	Aggregations                 []string      `mapstructure:"export-aggregation"`
	AggregationIgnoreSourcePort  bool          `mapstructure:"export-aggregation-ignore-source-port"`
	AggregationRenewTTL          bool          `mapstructure:"export-aggregation-renew-ttl"`
	AggregationStateChangeFilter []string      `mapstructure:"export-aggregation-state-filter"`
	AggregationTtl               time.Duration `mapstructure:"export-aggregation-ttl"`
}

var defaultConfig = config{
	Aggregations:                 []string{},
	AggregationIgnoreSourcePort:  true,
	AggregationRenewTTL:          true,
	AggregationStateChangeFilter: []string{"new", "error", "closed"},
	AggregationTtl:               30 * time.Second,
}

func (def config) Flags(flags *pflag.FlagSet) {
	flags.StringSlice("export-aggregation", def.Aggregations, "Perform aggregation pre-storage ('connection', 'identity')")
	flags.Bool("export-aggregation-ignore-source-port", def.AggregationIgnoreSourcePort, "Ignore source port during aggregation")
	flags.Bool("export-aggregation-renew-ttl", def.AggregationRenewTTL, "Renew flow TTL when a new flow is observed")
	flags.StringSlice("export-aggregation-state-filter", def.AggregationStateChangeFilter, "The state changes to include while aggregating ('new', 'established', 'first_error', 'error', 'closed')")
	flags.Duration("export-aggregation-ttl", def.AggregationTtl, "TTL for flow aggregation")
}

type hubbleEnterpriseAggregatorParams struct {
	cell.In

	JobGroup job.Group
	Config   config

	// TODO: replace by slog
	Logger logrus.FieldLogger
}

type hubbleEnterpriseAggregatorOut struct {
	cell.Out

	Aggregator      *EnterpriseAggregator
	ObserverOptions []observeroption.Option `group:"hubble-observer-options,flatten"`
}

func newHubbleEnterpriseAggregator(params hubbleEnterpriseAggregatorParams) (hubbleEnterpriseAggregatorOut, error) {
	aggregator, err := newEnterpriseAggregator(params.Config, params.Logger)
	if err != nil {
		return hubbleEnterpriseAggregatorOut{}, fmt.Errorf("failed to create enterprise aggregator: %w", err)
	}

	aggregator.initializeJobs(params.JobGroup)
	options := aggregator.observerOptions()

	return hubbleEnterpriseAggregatorOut{Aggregator: aggregator, ObserverOptions: options}, nil
}

var _ exporter.OnExportEvent = (*EnterpriseAggregator)(nil)

type EnterpriseAggregator struct {
	flowAggregator aggregator.FlowAggregator
	aggregation    *aggregation.Aggregation
	aggregators    types.Aggregator
}

func newEnterpriseAggregator(conf config, logger logrus.FieldLogger) (*EnterpriseAggregator, error) {
	clock := clockwork.NewRealClock()
	flowAggregator := aggregator.NewFlowAggregator(clock, logger)

	aggregation, err := aggregator.NewAggregation(
		conf.Aggregations,
		conf.AggregationStateChangeFilter,
		conf.AggregationIgnoreSourcePort,
		conf.AggregationTtl,
		conf.AggregationRenewTTL,
	)
	if err != nil {
		return nil, fmt.Errorf("could not create flow aggregation filter: %w", err)
	}

	aggregators, err := aggregator.ConfigureAggregator(clock, aggregation.Aggregators)
	if err != nil {
		return nil, fmt.Errorf("could not create flow aggregator chain: %w", err)
	}

	return &EnterpriseAggregator{
		flowAggregator: flowAggregator,
		aggregation:    aggregation,
		aggregators:    aggregators,
	}, nil
}

// OnExportEvent implements the exporter.OnExportEvent interface.
func (e *EnterpriseAggregator) OnExportEvent(ctx context.Context, ev *v1.Event, encoder exporter.Encoder) (stop bool, err error) {
	if e.aggregators == nil {
		// no aggregators configured
		return false, nil
	}
	flow := ev.GetFlow()
	if flow == nil {
		// we only care about flow events
		return false, nil
	}

	ctx = e.flowAggregator.NewContext(ctx, e.aggregators, e.aggregation)
	return e.flowAggregator.OnFlowDelivery(ctx, flow)
}

func (e *EnterpriseAggregator) initializeJobs(jobGroup job.Group) {
	if e.aggregators == nil {
		// no aggregators configured
		return
	}
	jobGroup.Add(job.OneShot("hubble-flow-aggregator", func(ctx context.Context, _ cell.Health) error {
		e.aggregators.Start(ctx)
		return nil
	}))
}

func (e *EnterpriseAggregator) observerOptions() []observeroption.Option {
	return []observeroption.Option{
		// inject aggregatorCtx used by all future flows
		observeroption.WithOnGetFlows(e.flowAggregator),
		// extract aggregatorCtx for each flow and call Aggregate()
		observeroption.WithOnFlowDelivery(e.flowAggregator),
	}
}
