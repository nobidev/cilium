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
	"io"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/lumberjack/v2"

	"github.com/cilium/cilium/pkg/hubble/exporter"
	"github.com/cilium/cilium/pkg/hubble/observer/observeroption"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// enterprise-hubble-connectionlog hook into Hubble OnDecodedFlow() aggregating
// the flows information in a "database" which is exported on disk every so
// often in the IPA graphV1 format.
var Cell = cell.Module(
	"enterprise-hubble-connectionlog",
	"Hubble Enterprise ConnectionLog exporter",

	cell.Provide(newHubbleEnterpriseConnLogger),
	cell.Config(DefaultConfig),
)

type HubbleEnterpriseConnLoggerParams struct {
	cell.In
	Config    Config
	Lifecycle cell.Lifecycle
	Logger    *slog.Logger
}

type HubbleEnterpriseConnLoggerOut struct {
	cell.Out
	ObserverOptions []observeroption.Option `group:"hubble-observer-options,flatten"`
}

func newHubbleEnterpriseConnLogger(params HubbleEnterpriseConnLoggerParams) (HubbleEnterpriseConnLoggerOut, error) {
	logger := params.Logger.With(logfields.LogSubsys, "hubble-connectionlog")
	if !params.Config.Enabled {
		logger.Info("Hubble ConnectionLog exporter disabled")
		return HubbleEnterpriseConnLoggerOut{}, nil
	}

	// db setup.
	db := newConnLogDB()

	// connection logger setup.
	cl := newConnLogger(db)

	// exporter setup.
	writer := &lumberjack.Logger{
		Filename:   params.Config.ExportFilePath,
		MaxSize:    params.Config.ExportFileMaxSizeMB,
		MaxBackups: params.Config.ExportFileMaxBackups,
		Compress:   params.Config.ExportFileCompress,
	}
	opts := []exporter.Option{
		exporter.WithNewWriterFunc(func() (io.WriteCloser, error) {
			return writer, nil
		}),
	}
	exp, err := newExporter(logger, db, params.Config.ExportInterval, opts...)
	if err != nil {
		return HubbleEnterpriseConnLoggerOut{}, err
	}
	params.Lifecycle.Append(exp)

	// hook the connlogger into the observer OnDecodedFlow.
	opt := observeroption.WithOnDecodedFlow(cl)
	return HubbleEnterpriseConnLoggerOut{
		ObserverOptions: []observeroption.Option{opt},
	}, nil
}
