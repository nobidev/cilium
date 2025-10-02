//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package evpn

import "github.com/spf13/pflag"

// CommonConfig is the configuration shared between the agent and the operator
type CommonConfig struct {
	Enabled bool `mapstructure:"enable-evpn"`
}

func (c CommonConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-evpn", false, "Enable EVPN")
}

// Config is the configuration specific to the agent
type Config struct {
	CommonConfig `mapstructure:",squash"`
}

// defaultConfig is the default configuration of the agent
var defaultConfig = Config{
	CommonConfig: CommonConfig{
		Enabled: false,
	},
}
