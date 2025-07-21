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
	"context"
	"fmt"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	"github.com/cilium/cilium/enterprise/pkg/fqdnha/tables"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/gops"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/pprof"
	"github.com/cilium/cilium/pkg/version"
)

var (
	FQDNProxy = cell.Module(
		"fqdnha-proxy",
		"Cilium FQDN-HA Proxy",

		cell.Config(defaultConfig),

		cell.Provide(newAgentClient),
		cell.Provide(newNotifier),
		cell.Provide(newRulesWatcher),

		cell.Provide(tables.NewAgentStateTable, tables.NewRemoteProxyStateTable),
		cell.Provide(newStateManager),
		cell.Invoke(func(_ *stateManager) {}),

		gops.Cell(defaults.EnableGops, DefaultGopsPort),
		pprof.Cell(pprofConfig),
		cell.Invoke(runDNSProxy),
	)

	Hive = hive.New(
		FQDNProxy,
		Metrics,
	)

	Metrics = cell.Module("metrics", "Metrics",
		cell.ProvidePrivate(func() *option.DaemonConfig {
			return &option.DaemonConfig{}
		}),
		cell.Provide(metrics.NewRegistry),
		cell.Provide(func(cfg Config) metrics.RegistryConfig {
			if !cfg.ExposePrometheusMetrics {
				return metrics.RegistryConfig{
					PrometheusServeAddr: "",
				}
			}
			return metrics.RegistryConfig{
				PrometheusServeAddr: fmt.Sprintf(":%d", cfg.PrometheusPort),
			}
		}),
		metrics.Metric(newProxyMetrics),
		cell.Invoke(setVersion),
	)
)

type proxyMetrics struct {
	Version metric.Vec[metric.Gauge]
}

const metricsNamespace = "isovalent"

func newProxyMetrics() *proxyMetrics {
	return &proxyMetrics{
		Version: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "version",
			Help:      "FQDN Proxy version",
		}, []string{"version"}),
	}
}

func setVersion(m *proxyMetrics, _ *metrics.Registry) {
	m.Version.WithLabelValues(version.GetCiliumVersion().Version).Set(1)
}

func runDNSProxy(jg job.Group, params runParams) {
	jg.Add(job.OneShot("fqdnha-proxy", func(ctx context.Context, health cell.Health) error {
		return run(ctx, params)
	}, job.WithShutdown()))
}
