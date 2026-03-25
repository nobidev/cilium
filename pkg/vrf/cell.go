// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package vrf

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/vrf/config"
)

var Cell = cell.Module(
	"vrf",
	"virtual routing and forwarding control-plane components",
	cell.Config(config.DefaultConfig),
	cell.Provide(NewVRFTableAndReflector),
	cell.Invoke(registerController),
)
