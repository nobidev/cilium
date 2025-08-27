// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package connectionlog

import (
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/hubble/exporter"
	"github.com/cilium/cilium/pkg/time"
)

// Config is the Hubble Enterprise ConnectionLog configuration.
//
// NOTE: no config path, allow/deny lists, although they could make sense at
// some point and are already part of the exporter options since they are
// shared with flow exporters. Some other exporter configuration are missing
// e.g. fieldmask which doesn't apply for the IPA ConnectionLog format.
type Config struct {
	// Enabled controls whether the Hubble ConnLogger should be running.
	Enabled bool `mapstructure:"hubble-connectionlog-export-enabled"`
	// ExportInterval is the time between two export cycles. If too long
	// then the exported data won't have enough granularity, if too short then
	// we're exporting a lot of data causing unnecessary overhead (producing,
	// storing, and processing).
	ExportInterval time.Duration `mapstructure:"hubble-connectionlog-export-interval"`
	// ExportFilePath specifies the filepath to write ConnectionLog messages
	// to, e.g. "/var/run/cilium/hubble/connectionlog.log".
	ExportFilePath string `mapstructure:"hubble-connectionlog-export-file-path"`
	// ExportFileMaxSizeMB specifies the file size in MB at which to rotate the
	// ConnectionLog export file.
	ExportFileMaxSizeMB int `mapstructure:"hubble-connectionlog-export-file-max-size-mb"`
	// ExportFileMaxBackups specifies the number of rotated files to keep.
	ExportFileMaxBackups int `mapstructure:"hubble-connectionlog-export-file-max-backups"`
	// ExportFileCompress specifies whether rotated files are compressed.
	ExportFileCompress bool `mapstructure:"hubble-connectionlog-export-file-compress"`
}

var DefaultConfig = Config{
	Enabled:              false,
	ExportInterval:       DefaultExportInterval,
	ExportFilePath:       DefaultExportFilePath,
	ExportFileMaxSizeMB:  exporter.DefaultFileMaxSizeMB,
	ExportFileMaxBackups: exporter.DefaultFileMaxBackups,
	ExportFileCompress:   false,
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Bool("hubble-connectionlog-export-enabled", def.Enabled, "Enable the ConnectionLog exporter")
	flags.Duration("hubble-connectionlog-export-interval", def.ExportInterval, "Interval at which the ConnectionLog events are collected and written.")
	flags.String("hubble-connectionlog-export-file-path", def.ExportFilePath, "Filepath to write ConnectionLogs to. By specifying `stdout` the connection logs are logged instead of written to a rotated file.")
	flags.Int("hubble-connectionlog-export-file-max-size-mb", def.ExportFileMaxSizeMB, "Size in MB at which to rotate ConnectionLog export file.")
	flags.Int("hubble-connectionlog-export-file-max-backups", def.ExportFileMaxBackups, "Number of rotated ConnectionLog export files to keep.")
	flags.Bool("hubble-connectionlog-export-file-compress", def.ExportFileCompress, "Compress rotated ConnectionLog export files.")
}

// XXX: do we need a ValidatedConfig pattern like we have for other Hubble
// exporters?
