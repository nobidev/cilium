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

	"github.com/spf13/pflag"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/time"
)

var (
	Cell = cell.Group(
		cell.Config(defaultConfig),
		cell.Invoke(Config.validate),
	)

	defaultConfig = Config{
		Port:     defaults.ClusterHealthPort - 1,
		Interval: 2 * time.Second,
		Timeout:  5 * time.Second,
	}
)

type Config struct {
	// Port is the port used for the health checking API.
	Port uint16 `mapstructure:"private-networks-health-check-port"`

	// Interval is the interval for sending health probes.
	Interval time.Duration `mapstructure:"private-networks-health-check-interval"`

	// Timeout is the timeout after which a candidate INB is considered unhealthy.
	Timeout time.Duration `mapstructure:"private-networks-health-check-timeout"`
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Uint16("private-networks-health-check-port", def.Port, "The TCP port used for health checks")
	flags.Duration("private-networks-health-check-interval", def.Interval,
		fmt.Sprintf("The interval for performing health checks against candidate INBs. Ignored in %s mode.", config.ModeBridge))
	flags.Duration("private-networks-health-check-timeout", def.Timeout,
		fmt.Sprintf("The timeout after which a candidate INB is considered unhealthy if no health check response is received. Ignored in %s mode.", config.ModeBridge))
}

func (cfg Config) validate() error {
	if cfg.Timeout < cfg.Interval*3/2 {
		return fmt.Errorf("private-networks-health-check-timeout must be at least 50%% higher than interval (got interval=%s, timeout=%s)",
			cfg.Interval, cfg.Timeout)
	}

	return nil
}
