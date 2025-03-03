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

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/lumberjack/v2"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/enterprise/pkg/hubble/aggregation"
	"github.com/cilium/cilium/enterprise/pkg/hubble/aggregation/aggregator"
	"github.com/cilium/cilium/pkg/hubble"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/exporter"
	exportercell "github.com/cilium/cilium/pkg/hubble/exporter/cell"
	"github.com/cilium/cilium/pkg/time"
)

const formatVersionV1 = "v1"

var Cell = cell.Module(
	"enterprise-hubble-exporter",
	"Hubble Enterprise flow log exporter",

	cell.Provide(newHubbleEnterpriseExporter),
	cell.Config(defaultConfig),
)

type config struct {
	FilePath                     string        `mapstructure:"export-file-path"`
	FileMaxSize                  int           `mapstructure:"export-file-max-size"`
	FileRotationInterval         time.Duration `mapstructure:"export-file-rotation-interval"`
	FileMaxBackups               int           `mapstructure:"export-file-max-backups"`
	FileCompress                 bool          `mapstructure:"export-file-compress"`
	FlowWhitelist                string        `mapstructure:"export-flow-whitelist"`
	FlowBlacklist                string        `mapstructure:"export-flow-blacklist"`
	FlowAllowlist                string        `mapstructure:"export-flow-allowlist"`
	FlowDenylist                 string        `mapstructure:"export-flow-denylist"`
	FormatVersion                string        `mapstructure:"export-format-version"`
	RateLimit                    int           `mapstructure:"export-rate-limit"`
	NodeName                     string        `mapstructure:"export-node-name"`
	Aggregations                 []string      `mapstructure:"export-aggregation"`
	AggregationIgnoreSourcePort  bool          `mapstructure:"export-aggregation-ignore-source-port"`
	AggregationRenewTTL          bool          `mapstructure:"export-aggregation-renew-ttl"`
	AggregationStateChangeFilter []string      `mapstructure:"export-aggregation-state-filter"`
	AggregationTtl               time.Duration `mapstructure:"export-aggregation-ttl"`
}

var defaultConfig = config{
	FilePath:                     "",
	FileMaxSize:                  100,
	FileRotationInterval:         0,
	FileMaxBackups:               3,
	FileCompress:                 true,
	FlowWhitelist:                "",
	FlowBlacklist:                "",
	FlowAllowlist:                "",
	FlowDenylist:                 "",
	FormatVersion:                formatVersionV1,
	RateLimit:                    -1,
	NodeName:                     "",
	Aggregations:                 []string{},
	AggregationIgnoreSourcePort:  true,
	AggregationRenewTTL:          true,
	AggregationStateChangeFilter: []string{"new", "error", "closed"},
	AggregationTtl:               30 * time.Second,
}

func (def config) Flags(flags *pflag.FlagSet) {
	flags.String("export-file-path", def.FilePath, "Absolute path of the export file location. An empty string disables the flow export")
	flags.Int("export-file-max-size", def.FileMaxSize, "Maximum size of the file in megabytes")
	flags.Duration("export-file-rotation-interval", def.FileRotationInterval, "Interval at which to rotate JSON export files in addition to rotating them by size")
	flags.Int("export-file-max-backups", def.FileMaxBackups, "Number of rotated files to keep")
	flags.Bool("export-file-compress", def.FileCompress, "Compress rotated files")
	flags.String("export-flow-whitelist", "", "Whitelist filters for flows")
	flags.String("export-flow-blacklist", "", "Blacklist filters for flows")
	flags.MarkHidden("export-flow-whitelist")
	flags.MarkHidden("export-flow-blacklist")
	flags.String("export-flow-allowlist", "", "Allowlist filters for flows")
	flags.String("export-flow-denylist", "", "Denylist filters for flows")
	flags.String("export-format-version", formatVersionV1, "Default to v1 format. Set to '' to use the legacy format")
	flags.Int("export-rate-limit", def.RateLimit, "Rate limit (per minute) for flow exports. Set to -1 to disable")
	flags.String("export-node-name", def.NodeName, "Override the node_name field in exported flows")
	flags.StringSlice("export-aggregation", def.Aggregations, "Perform aggregation pre-storage ('connection', 'identity')")
	flags.Bool("export-aggregation-ignore-source-port", def.AggregationIgnoreSourcePort, "Ignore source port during aggregation")
	flags.Bool("export-aggregation-renew-ttl", def.AggregationRenewTTL, "Renew flow TTL when a new flow is observed")
	flags.StringSlice("export-aggregation-state-filter", def.AggregationStateChangeFilter, "The state changes to include while aggregating ('new', 'established', 'first_error', 'error', 'closed')")
	flags.Duration("export-aggregation-ttl", def.AggregationTtl, "TTL for flow aggregation")
}

type hubbleEnterpriseExporterParams struct {
	cell.In

	JobGroup  job.Group
	Lifecycle cell.Lifecycle
	Config    config

	// TODO: replace by slog
	Logger logrus.FieldLogger
}

type HubbleEnterpriseExporterOut struct {
	cell.Out

	ExporterBuilders []*exportercell.FlowLogExporterBuilder `group:"hubble-exporter-builders,flatten"`
}

func newHubbleEnterpriseExporter(params hubbleEnterpriseExporterParams) (HubbleEnterpriseExporterOut, error) {
	if params.Config.FilePath == "" {
		params.Logger.Info("The Hubble EE static exporter is disabled")
		return HubbleEnterpriseExporterOut{}, nil
	}

	builder := &exportercell.FlowLogExporterBuilder{
		Name: "static-ee-exporter",
		Build: func() (exporter.FlowLogExporter, error) {
			params.Logger.WithField("config", fmt.Sprintf("%+v", params.Config)).Info("Building the Hubble EE static exporter")

			// keep support for deprecated flags
			allowlistFlag := params.Config.FlowAllowlist
			if allowlistFlag == "" {
				allowlistFlag = params.Config.FlowWhitelist
			}
			denylistFlag := params.Config.FlowDenylist
			if denylistFlag == "" {
				denylistFlag = params.Config.FlowBlacklist
			}

			allowList, err := hubble.ParseFlowFilters(allowlistFlag)
			if err != nil {
				return nil, fmt.Errorf("failed to parse allowlist: %w", err)
			}
			denyList, err := hubble.ParseFlowFilters(denylistFlag)
			if err != nil {
				return nil, fmt.Errorf("failed to parse denylist: %w", err)
			}

			// create file writer
			writer := &lumberjack.Logger{
				Filename:   params.Config.FilePath,
				MaxSize:    params.Config.FileMaxSize,
				MaxBackups: params.Config.FileMaxBackups,
				Compress:   params.Config.FileCompress,
			}

			// register flow metrics
			metricsHandler := &metricsHandler{}
			registerMetricsHandler(metricsHandler)

			// setup exporter options
			exporterOpts := []exporter.Option{
				exporter.WithAllowList(params.Logger, allowList),
				exporter.WithDenyList(params.Logger, denyList),
				exporter.WithNewWriterFunc(func() (io.WriteCloser, error) {
					var writer io.WriteCloser = writer
					writer = metricsHandler.WrapWriter(writer)
					return writer, nil
				}),
				exporter.WithNewEncoderFunc(func(writer io.Writer) (exporter.Encoder, error) {
					return newEnterpriseJsonEncoder(params.Config, writer), nil
				}),
				exporter.WithOnExportEventFunc(func(_ context.Context, ev *v1.Event, _ exporter.Encoder) (bool, error) {
					// stop export pipeline for non-flow events
					stop := ev.GetFlow() == nil
					return stop, nil
				}),
			}

			// create aggregator
			if len(params.Config.Aggregations) > 0 {
				aggregator, err := newHubbleEnterpriseAggregator(params.Config, params.Logger)
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
			if params.Config.RateLimit >= 0 {
				ratelimiter, err := newEnterpriseRateLimiter(params.Config, params.Logger)
				if err != nil {
					// non-fatal failure, log and continue
					params.Logger.WithError(err).Warn("Failed to create flow export rate limiter")
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
				err := metricsHandler.UpdateMetrics(ctx, flow)
				if err != nil {
					return false, fmt.Errorf("failed to update flow metrics: %w", err)
				}
				return false, nil
			}))

			staticExporter, err := exporter.NewExporter(params.Logger, exporterOpts...)
			if err != nil {
				// non-fatal failure, log and continue
				params.Logger.WithError(err).Error("Failed to configure Hubble static exporter")
				return nil, nil
			}

			if params.Config.FileRotationInterval != 0 {
				params.Logger.WithField("interval", params.Config.FileRotationInterval).Info("Periodically rotating JSON export file")
				params.JobGroup.Add(job.OneShot("hubble-exporter-file-rotate", func(ctx context.Context, health cell.Health) error {
					ticker := time.NewTicker(params.Config.FileRotationInterval)
					for {
						select {
						case <-ctx.Done():
							return nil
						case <-ticker.C:
							if err := writer.Rotate(); err != nil {
								params.Logger.WithError(err).
									WithField("filename", params.Config.FilePath).
									Warn("Failed to rotate JSON export file")
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

func newHubbleEnterpriseAggregator(config config, logger logrus.FieldLogger) (*aggregation.EnterpriseAggregator, error) {
	aggFilter, err := aggregator.NewAggregation(
		config.Aggregations,
		config.AggregationStateChangeFilter,
		config.AggregationIgnoreSourcePort,
		config.AggregationTtl,
		config.AggregationRenewTTL,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create flow aggregation filter: %w", err)
	}
	return aggregation.NewEnterpriseAggregator(aggFilter, logger)
}
