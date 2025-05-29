//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package rib

import (
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/time"
)

var Cell = cell.Module(
	"rib",
	"Routing Information Base",
	cell.Provide(
		New,
		ribReadCommands,
	),
	cell.ProvidePrivate(
		func(cfg Config) gcChFn {
			return func() <-chan time.Time {
				return time.After(cfg.InitialGCDelay)
			}
		},
	),
	cell.Invoke(
		scheduleInitialGC,
	),
	cell.Config(defaultConfig),
)

var NopDataPlaneCell = cell.Module(
	"nop-dataplane",
	"An empty dataplane implementation for testing purposes",
	cell.Provide(
		newNopDataPlane,
	),
)

var defaultConfig = Config{
	// InitialGCDelay is the delay before the initial garbage collection of
	// the RIB. This value is chosen to be long enough to allow the route
	// owners to write their routes to the RIB. For example, the default
	// connect retry time of BGP CPlane is 120s, so this timeout allows BGP
	// connection to fail twice (takes 240s to establish) and has 60s to
	// install all routes.
	InitialGCDelay: time.Minute * 5,
}

type Config struct {
	InitialGCDelay time.Duration `mapstructure:"rib-initial-gc-delay"`
}

func (cfg Config) Flags(flags *pflag.FlagSet) {
	// Adjusting this flag is not recommended and once we get rid of the
	// timeout based approach, we'll remove this. Still, leave this knob as
	// an escape hatch.
	flags.Duration("rib-initial-gc-delay", cfg.InitialGCDelay, "Delay before the initial garbage collection of the RIB")
	flags.MarkHidden("rib-initial-gc-delay")
}
