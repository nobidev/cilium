//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package config

import (
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/pkg/crypto/certloader"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/promise"
)

type (
	ServerConfigPromise promise.Promise[*certloader.WatchedServerConfig]
	ClientConfigPromise promise.Promise[*certloader.WatchedClientConfig]
)

var (
	Cell = cell.Group(
		cell.Config(defaultConfig),
		cell.ProvidePrivate(
			newWatchedClientConfigPromise,
			newWatchedServerConfigPromise,
		),
	)

	defaultConfig = Config{
		Port: defaults.ClusterHealthPort - 1,

		TLSEnabled: false,

		TLSServerCertFile: "",
		TLSServerKeyFile:  "",
		TLSClientCertFile: "",
		TLSClientKeyFile:  "",
		TLSCAFiles:        []string{},
	}
)

type Config struct {
	// Port is the port used for the privnet gRPC server.
	Port uint16 `mapstructure:"private-networks-api-port"`

	TLSEnabled bool `mapstructure:"private-networks-api-tls-enabled"`

	TLSServerCertFile string   `mapstructure:"private-networks-api-tls-server-cert-file"`
	TLSServerKeyFile  string   `mapstructure:"private-networks-api-tls-server-key-file"`
	TLSClientCertFile string   `mapstructure:"private-networks-api-tls-client-cert-file"`
	TLSClientKeyFile  string   `mapstructure:"private-networks-api-tls-client-key-file"`
	TLSCAFiles        []string `mapstructure:"private-networks-api-tls-ca-files"`
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Uint16("private-networks-api-port", def.Port,
		fmt.Sprintf("The TCP port the privnet gRPC server listens to, in %s mode. Otherwise, it represents the fallback port to connect to a candidate INB if not explicitly advertised by the candidate INB itself.",
			config.ModeBridge))
	flags.Bool("private-networks-api-tls-enabled", def.TLSEnabled,
		"Enable TLS for the private networks gRPC server and clients")
	flags.String("private-networks-api-tls-server-cert-file", def.TLSServerCertFile,
		"Path to the private networks gRPC server certificate file in PEM format")
	flags.String("private-networks-api-tls-server-key-file", def.TLSServerKeyFile,
		"Path to the private networks gRPC server private key file in PEM format")
	flags.String("private-networks-api-tls-client-cert-file", def.TLSClientCertFile,
		"Path to the private networks gRPC client certificate file in PEM format")
	flags.String("private-networks-api-tls-client-key-file", def.TLSClientKeyFile,
		"Path to the private networks gRPC client private key file in PEM format")
	flags.StringSlice("private-networks-api-tls-ca-files", def.TLSCAFiles,
		"Paths to one or more CA certificate files trusted by private networks gRPC peers")
}

func newWatchedServerConfigPromise(lc cell.Lifecycle, jobGroup job.Group, log *slog.Logger, cfg Config) (ServerConfigPromise, error) {
	return certloader.NewWatchedServerConfigPromise(lc, jobGroup, log, certloader.Config{
		TLS:              cfg.TLSEnabled,
		TLSCertFile:      cfg.TLSServerCertFile,
		TLSKeyFile:       cfg.TLSServerKeyFile,
		TLSClientCAFiles: cfg.TLSCAFiles,
	})
}

func newWatchedClientConfigPromise(lc cell.Lifecycle, jobGroup job.Group, log *slog.Logger, cfg Config) (ClientConfigPromise, error) {
	return certloader.NewWatchedClientConfigPromise(lc, jobGroup, log, certloader.Config{
		TLS:              cfg.TLSEnabled,
		TLSCertFile:      cfg.TLSClientCertFile,
		TLSKeyFile:       cfg.TLSClientKeyFile,
		TLSClientCAFiles: cfg.TLSCAFiles,
	})
}
