//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package metrics

import (
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/loadbalancer"
	lbmaps "github.com/cilium/cilium/pkg/loadbalancer/maps"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

var Cell = cell.Module(
	"loadbalancer-metrics",
	"LoadBalancer metrics",

	//exhaustruct:ignore
	cell.Config(Config{}),
	cell.Invoke(registerCollector),
	metrics.Metric(newLBMetrics),
)

type Config struct {
	LoadBalancerMetricsEnabled            bool
	LoadBalancerMetricsCollectionInterval time.Duration
}

func (cfg Config) Flags(flags *pflag.FlagSet) {
	flags.Bool("loadbalancer-metrics-enabled", false, "Whether or not LoadBalancer metrics collection is enabled.")
	flags.Duration("loadbalancer-metrics-collection-interval", 5*time.Second, "Refresh interval for LoadBalancer metrics.")
}

type collectorParams struct {
	cell.In

	Metrics   *lbMetrics
	Config    Config
	JobGroup  job.Group
	Lifecycle cell.Lifecycle
	Logger    *slog.Logger
	LBMaps    lbmaps.LBMaps
	CTGC      ctmap.GCRunner

	DB        *statedb.DB
	Frontends statedb.Table[*loadbalancer.Frontend]
}

func registerCollector(params collectorParams) {
	if !option.Config.EnableIPv4 {
		return
	}

	if !params.Config.LoadBalancerMetricsEnabled {
		return
	}

	var ctMaps []ctmap.CtMap
	for _, m := range ctmap.Maps(true, false) {
		ctMaps = append(ctMaps, m)
	}

	mc := newLBMetricsCollector(params, ctMaps)

	params.JobGroup.Add(
		job.Timer(
			"loadbalancer metrics collector",
			mc.fetchMetrics,
			params.Config.LoadBalancerMetricsCollectionInterval,
		),
		job.Observer("ctmap-gc", mc.handleCTGCEvent, params.CTGC.Observe4()),
	)
}
