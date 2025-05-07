// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package healthchecker

import (
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/service"
)

// Cell provides service health checker functionality.
var Cell = cell.Module(
	"service-health-checker",
	"Service Health Checker",

	//exhaustruct:ignore
	cell.Config(Config{}),
	cell.Provide(registerActiveHealthChecker),
)

type Config struct {
	EnableActiveLbHealthChecking bool
}

func (r Config) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-active-lb-health-checking", false, "Enable active health checking on loadbalancer services")
}

func registerActiveHealthChecker(
	lifecycle cell.Lifecycle,
	logger *slog.Logger,
	cfg Config,
	lbConfig lb.Config,
) healthCheckerResult {
	if !cfg.EnableActiveLbHealthChecking || lbConfig.EnableExperimentalLB {
		return healthCheckerResult{}
	}

	activeHealthChecker := newHealthChecker(logger)

	lifecycle.Append(cell.Hook{
		OnStart: func(hookContext cell.HookContext) error {
			go activeHealthChecker.run()
			return nil
		},
		OnStop: func(cell.HookContext) error {
			activeHealthChecker.Stop()
			return nil
		},
	})

	return healthCheckerResult{
		HealthChecker: activeHealthChecker,
	}
}

type healthCheckerResult struct {
	cell.Out

	HealthChecker service.HealthChecker `group:"healthCheckers"`
}
