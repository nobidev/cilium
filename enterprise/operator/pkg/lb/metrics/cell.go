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
	"time"

	"github.com/cilium/cilium/pkg/metrics"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
)

var Cell = cell.Module(
	"loadbalancer-metrics",
	"LoadBalancer metrics",

	//exhaustruct:ignore
	cell.Config(Config{}),
	cell.Invoke(registerCollector),
	metrics.Metric(MetricsProvider),
)

type Config struct {
	LoadBalancerMetricsEnabled            bool
	LoadBalancerMetricsCollectionInterval time.Duration
}

func (cfg Config) Flags(flags *pflag.FlagSet) {
	flags.Bool("loadbalancer-metrics-enabled", false, "Whether or not LoadBalancer metrics collection is enabled.")
	flags.Duration("loadbalancer-metrics-collection-interval", 5*time.Second, "Refresh interval for LoadBalancer metrics.")
}
