// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package config

import (
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/enterprise/pkg/privnet/config"
)

var (
	// Cell registers the private networks configuration.
	Cell = cell.Config(defaultConfig)

	defaultConfig = Config{
		Common: config.DefaultCommon,

		NADIntegration: NADIntegrationConfig{
			Enabled: false,
		},
	}
)

type Config struct {
	config.Common `mapstructure:",squash"`

	NADIntegration NADIntegrationConfig `mapstructure:",squash"`
}

type NADIntegrationConfig struct {
	Enabled bool `mapstructure:"private-networks-nad-integration-enabled"`
}

func (def Config) Flags(flags *pflag.FlagSet) {
	def.Common.Flags(flags)
	def.NADIntegration.Flags(flags)
}

func (def NADIntegrationConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool("private-networks-nad-integration-enabled", def.Enabled,
		"Enable the private networks integration with Multus network attachment definitions")
}

// EnabledWithNADIntegration returns whether private networking is enabled, with
// support for Multus network attachment definitions.
func (cfg Config) EnabledWithNADIntegration() bool {
	return cfg.Enabled && cfg.NADIntegration.Enabled
}
