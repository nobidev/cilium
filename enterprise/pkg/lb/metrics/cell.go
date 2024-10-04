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
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
)

var Cell = cell.Module(
	"loadbalancer-metrics",
	"LoadBalancer metrics",

	//exhaustruct:ignore
	cell.Config(Config{}),
	cell.Invoke(registerCollector),
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

	Config    Config
	JobGroup  job.Group
	Lifecycle cell.Lifecycle
	Logger    logrus.FieldLogger

	Services resource.Resource[*slim_corev1.Service]
}

func registerCollector(params collectorParams) {
	if !option.Config.EnableIPv4 {
		return
	}

	if !params.Config.LoadBalancerMetricsEnabled {
		return
	}

	mc := newLBMetricsCollector(params)
	if err := metrics.Register(mc); err != nil {
		params.Logger.WithError(err).
			Error("Failed to register LB collector to Prometheus registry. LB metrics will not be collected")
		return
	}

	params.Lifecycle.Append(cell.Hook{
		OnStart: func(hc cell.HookContext) error {
			params.JobGroup.Add(job.Observer("loadbalancer metrics service cache", mc.lbServiceCacheUpdater, params.Services))
			params.JobGroup.Add(job.Timer("loadbalancer metrics collector", mc.fetchMetrics, params.Config.LoadBalancerMetricsCollectionInterval))

			return nil
		},
		OnStop: func(hc cell.HookContext) error {
			return nil
		},
	})
}
