// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package export

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"slices"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/lumberjack/v2"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/enterprise/pkg/hubble/aggregation"
	"github.com/cilium/cilium/enterprise/pkg/hubble/aggregation/aggregator"
	"github.com/cilium/cilium/pkg/hubble"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/exporter"
	exportercell "github.com/cilium/cilium/pkg/hubble/exporter/cell"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

const formatVersionV1 = "v1"

var Cell = cell.Module(
	"enterprise-hubble-exporter",
	"Hubble Enterprise flow log exporter",

	timescapeExporterCell,

	cell.ProvidePrivate(newMetricsHandler),
	cell.ProvidePrivate(newMergedConfig),
	cell.Provide(newHubbleEnterpriseExporter),
	cell.Provide(newHubbleEnterpriseDynamicExporter),
	cell.Config(defaultConfig),
	cell.Config(defaultLegacyConfig),
)

func newMetricsHandler() *metricsHandler {
	metricsHandler := &metricsHandler{}
	registerMetricsHandler(metricsHandler)
	return metricsHandler
}

// config represents the EE static exporter configuration.
//
// These are colocated with the OSS static exporter options in the helm chart
// under the `hubble.export.static` field.
type config struct {
	FileRotationInterval         time.Duration `mapstructure:"hubble-export-file-rotation-interval"`
	FormatVersion                string        `mapstructure:"hubble-export-format-version"`
	RateLimit                    int           `mapstructure:"hubble-export-rate-limit"`
	NodeName                     string        `mapstructure:"hubble-export-node-name"`
	Aggregations                 []string      `mapstructure:"hubble-export-aggregation"`
	AggregationIgnoreSourcePort  bool          `mapstructure:"hubble-export-aggregation-ignore-source-port"`
	AggregationRenewTTL          bool          `mapstructure:"hubble-export-aggregation-renew-ttl"`
	AggregationStateChangeFilter []string      `mapstructure:"hubble-export-aggregation-state-filter"`
	AggregationTTL               time.Duration `mapstructure:"hubble-export-aggregation-ttl"`
}

var defaultConfig = config{
	FileRotationInterval:         0,
	FormatVersion:                formatVersionV1,
	RateLimit:                    -1,
	NodeName:                     "",
	Aggregations:                 []string{},
	AggregationIgnoreSourcePort:  true,
	AggregationRenewTTL:          true,
	AggregationStateChangeFilter: []string{"new", "error", "closed"},
	AggregationTTL:               30 * time.Second,
}

func (def config) Flags(flags *pflag.FlagSet) {
	flags.Duration("hubble-export-file-rotation-interval", def.FileRotationInterval, "Interval at which to rotate JSON export files in addition to rotating them by size")
	flags.String("hubble-export-format-version", def.FormatVersion, "Default to v1 format. Set to '' to use the legacy format")
	flags.Int("hubble-export-rate-limit", def.RateLimit, "Rate limit (per minute) for flow exports. Set to -1 to disable")
	flags.String("hubble-export-node-name", def.NodeName, "Override the node_name field in exported flows")
	flags.StringSlice("hubble-export-aggregation", def.Aggregations, "Perform aggregation pre-storage ('connection', 'identity')")
	flags.Bool("hubble-export-aggregation-ignore-source-port", def.AggregationIgnoreSourcePort, "Ignore source port during aggregation")
	flags.Bool("hubble-export-aggregation-renew-ttl", def.AggregationRenewTTL, "Renew flow TTL when a new flow is observed")
	flags.StringSlice("hubble-export-aggregation-state-filter", def.AggregationStateChangeFilter, "The state changes to include while aggregating ('new', 'established', 'first_error', 'error', 'closed')")
	flags.Duration("hubble-export-aggregation-ttl", def.AggregationTTL, "TTL for flow aggregation")
}

// legacyConfig represents the `deprecated` EE static exporter configuration used by Cilium <1.18.0.
//
// These are sourced in the helm chart from the `extraConfig` free-form field and are
// superseded by native configuration merged with the OSS exporter values under:
// `hubble.export.static`.
//
// Starting with v1.19, we trimmed down the legacy config to only include
// fields required to set default values when Integrated Timescape is enabled.
type legacyConfig struct {
	FilePath                     string   `mapstructure:"export-file-path"`
	Aggregations                 []string `mapstructure:"export-aggregation"`
	AggregationRenewTTL          bool     `mapstructure:"export-aggregation-renew-ttl"`
	AggregationStateChangeFilter []string `mapstructure:"export-aggregation-state-filter"`
}

var defaultLegacyConfig = legacyConfig{
	FilePath:                     "",
	Aggregations:                 []string{},
	AggregationRenewTTL:          true,
	AggregationStateChangeFilter: []string{"new", "error", "closed"},
}

func (def legacyConfig) Flags(flags *pflag.FlagSet) {
	flags.String("export-file-path", def.FilePath, "Absolute path of the export file location. An empty string disables the flow export")
	flags.StringSlice("export-aggregation", def.Aggregations, "Perform aggregation pre-storage ('connection', 'identity')")
	flags.Bool("export-aggregation-renew-ttl", def.AggregationRenewTTL, "Renew flow TTL when a new flow is observed")
	flags.StringSlice("export-aggregation-state-filter", def.AggregationStateChangeFilter, "The state changes to include while aggregating ('new', 'established', 'first_error', 'error', 'closed')")
}

// mergedConfig depends on OSS and EE configs and merges them together.
type mergedConfig struct {
	oss exportercell.ValidatedConfig
	ee  config
}

func newMergedConfig(oss exportercell.ValidatedConfig, eeLegacy legacyConfig, ee config) mergedConfig {
	// merge oss with eeLegacy (OSS takes precedence)
	ossDefault := exportercell.DefaultConfig
	if oss.ExportFilePath == ossDefault.ExportFilePath {
		oss.ExportFilePath = eeLegacy.FilePath
	}

	// merge ee with eeLegacy (EE takes precedence)
	if slices.Equal(ee.Aggregations, defaultConfig.Aggregations) {
		ee.Aggregations = eeLegacy.Aggregations
	}
	if ee.AggregationRenewTTL == defaultConfig.AggregationRenewTTL {
		ee.AggregationRenewTTL = eeLegacy.AggregationRenewTTL
	}
	if slices.Equal(ee.AggregationStateChangeFilter, defaultConfig.AggregationStateChangeFilter) {
		ee.AggregationStateChangeFilter = eeLegacy.AggregationStateChangeFilter
	}

	return mergedConfig{oss: oss, ee: ee}
}

type hubbleEnterpriseExporterParams struct {
	cell.In

	JobGroup  job.Group
	Lifecycle cell.Lifecycle
	Config    mergedConfig
	Metrics   *metricsHandler

	Logger *slog.Logger
}

type HubbleEnterpriseExporterOut struct {
	cell.Out

	ExporterBuilders []*exportercell.FlowLogExporterBuilder `group:"hubble-exporter-builders,flatten"`
}

func newHubbleEnterpriseExporter(params hubbleEnterpriseExporterParams) (HubbleEnterpriseExporterOut, error) {
	if params.Config.oss.ExportFilePath == "" {
		params.Logger.Info("The Hubble EE static exporter is disabled")
		return HubbleEnterpriseExporterOut{}, nil
	}

	builder := &exportercell.FlowLogExporterBuilder{
		Name:     "static-ee-exporter",
		Replaces: "static-exporter",
		Build: func() (exporter.FlowLogExporter, error) {
			params.Logger.Info("Building the Hubble EE static exporter", logfields.Config, fmt.Sprintf("%+v", params.Config))

			allowList, err := hubble.ParseFlowFilters(params.Config.oss.ExportAllowlist)
			if err != nil {
				return nil, fmt.Errorf("failed to parse allowlist: %w", err)
			}
			denyList, err := hubble.ParseFlowFilters(params.Config.oss.ExportDenylist)
			if err != nil {
				return nil, fmt.Errorf("failed to parse denylist: %w", err)
			}

			// create file writer
			writer := &lumberjack.Logger{
				Filename:   params.Config.oss.ExportFilePath,
				MaxSize:    params.Config.oss.ExportFileMaxSizeMB,
				MaxBackups: params.Config.oss.ExportFileMaxBackups,
				Compress:   params.Config.oss.ExportFileCompress,
			}

			metricsHandlerNameLabel := "static"

			// setup exporter options
			exporterOpts := []exporter.Option{
				exporter.WithAllowList(params.Logger, allowList),
				exporter.WithDenyList(params.Logger, denyList),
				exporter.WithNewWriterFunc(func() (io.WriteCloser, error) {
					var writer io.WriteCloser = writer
					writer = params.Metrics.WrapWriter(writer, metricsHandlerNameLabel)
					return writer, nil
				}),
				exporter.WithNewEncoderFunc(func(writer io.Writer) (exporter.Encoder, error) {
					return newJsonEncoderFromStaticConfig(params.Config.ee, writer), nil
				}),
				exporter.WithOnExportEventFunc(func(_ context.Context, ev *v1.Event, _ exporter.Encoder) (bool, error) {
					// stop export pipeline for non-flow events
					stop := ev.GetFlow() == nil
					return stop, nil
				}),
			}

			// create aggregator
			if len(params.Config.ee.Aggregations) > 0 {
				aggregator, err := newAggregatorFromStaticConfig(params.Config.ee, params.Logger)
				if err != nil {
					return nil, fmt.Errorf("failed to create enterprise aggregator: %w", err)
				}
				exporterOpts = append(exporterOpts, exporter.WithOnExportEvent(aggregator))
				params.JobGroup.Add(job.OneShot("hubble-flow-aggregator", func(ctx context.Context, _ cell.Health) error {
					aggregator.Start(ctx)
					return nil
				}))
			}

			// setup rate-limiting
			if params.Config.ee.RateLimit >= 0 {
				ratelimiter, err := newRateLimiterFromStaticConfig(params.Config.ee, params.Logger)
				if err != nil {
					// non-fatal failure, log and continue
					params.Logger.Warn("Failed to create flow export rate limiter", logfields.Error, err)
				} else {
					exporterOpts = append(exporterOpts, exporter.WithOnExportEvent(ratelimiter))
				}
			}

			// setup flow metrics reporting
			//
			// NOTE: make sure this is always the last exporter option so it remains accurate
			// when aggregation/rate-limiting is performed
			exporterOpts = append(exporterOpts, exporter.WithOnExportEventFunc(func(ctx context.Context, ev *v1.Event, encoder exporter.Encoder) (bool, error) {
				flow := ev.GetFlow()
				if flow == nil {
					// we only care about flow events
					return false, nil
				}
				err := params.Metrics.UpdateFlowMetrics(ctx, flow, metricsHandlerNameLabel)
				if err != nil {
					return false, fmt.Errorf("failed to update flow metrics: %w", err)
				}
				return false, nil
			}))

			staticExporter, err := exporter.NewExporter(params.Logger, exporterOpts...)
			if err != nil {
				// non-fatal failure, log and continue
				params.Logger.Error("Failed to configure Hubble static exporter", logfields.Error, err)
				return nil, nil
			}

			if params.Config.ee.FileRotationInterval != 0 {
				params.Logger.Info("Periodically rotating JSON export file", logfields.Interval, params.Config.ee.FileRotationInterval)
				params.JobGroup.Add(job.OneShot("hubble-exporter-file-rotate", func(ctx context.Context, health cell.Health) error {
					ticker := time.NewTicker(params.Config.ee.FileRotationInterval)
					for {
						select {
						case <-ctx.Done():
							return nil
						case <-ticker.C:
							if err := writer.Rotate(); err != nil {
								params.Logger.Warn("Failed to rotate JSON export file",
									logfields.Error, err,
									logfields.FilePath, params.Config.oss.ExportFilePath,
								)
							}
						}
					}
				}))
			}

			params.Lifecycle.Append(cell.Hook{
				OnStop: func(hc cell.HookContext) error {
					return staticExporter.Stop()
				},
			})

			return staticExporter, nil
		},
	}

	return HubbleEnterpriseExporterOut{
		ExporterBuilders: []*exportercell.FlowLogExporterBuilder{builder},
	}, nil
}

type hubbleEnterpriseDynamicExporterParams struct {
	cell.In

	JobGroup  job.Group
	Lifecycle cell.Lifecycle
	// depend on OSS config so we can re-use the hubble-flowlogs-config-path flag.
	Config  exportercell.ValidatedConfig
	Metrics *metricsHandler

	Logger *slog.Logger
}

func newHubbleEnterpriseDynamicExporter(params hubbleEnterpriseDynamicExporterParams) (HubbleEnterpriseExporterOut, error) {
	if params.Config.FlowlogsConfigFilePath == "" {
		params.Logger.Info("The Hubble EE dynamic exporter is disabled")
		return HubbleEnterpriseExporterOut{}, nil
	}

	builder := &exportercell.FlowLogExporterBuilder{
		Name:     "dynamic-ee-exporter",
		Replaces: "dynamic-exporter",
		Build: func() (exporter.FlowLogExporter, error) {
			params.Logger.Info("Building the Hubble EE dynamic exporter", logfields.ConfigPath, params.Config.FlowlogsConfigFilePath)

			// dynamic exporter
			exporterFactory := &exporterFactory{logger: params.Logger, jobGroup: params.JobGroup, metricsHandler: params.Metrics}
			exporterConfigParser := &exporterConfigParser{params.Logger}
			dynamicExporter := exporter.NewDynamicExporter(params.Logger, params.Config.FlowlogsConfigFilePath, exporterFactory, exporterConfigParser)

			params.JobGroup.Add(job.OneShot("hubble-dynamic-exporter", func(ctx context.Context, _ cell.Health) error {
				return dynamicExporter.Watch(ctx)
			}))
			params.Lifecycle.Append(cell.Hook{
				OnStop: func(hc cell.HookContext) error {
					return dynamicExporter.Stop()
				},
			})

			return dynamicExporter, nil
		},
	}

	return HubbleEnterpriseExporterOut{
		ExporterBuilders: []*exportercell.FlowLogExporterBuilder{builder},
	}, nil
}

func newAggregatorFromStaticConfig(config config, logger *slog.Logger) (*aggregation.EnterpriseAggregator, error) {
	aggFilter, err := aggregator.NewAggregation(
		config.Aggregations,
		config.AggregationStateChangeFilter,
		config.AggregationIgnoreSourcePort,
		config.AggregationTTL,
		config.AggregationRenewTTL,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create flow aggregation filter: %w", err)
	}
	return aggregation.NewEnterpriseAggregator(aggFilter, logger)
}
