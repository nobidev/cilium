// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdevicesmap

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bpf"
)

// Cell initializes and manages the network devices map.
var Cell = cell.Module(
	"network-devices-map",
	"eBPF map contains information about network devices for Cilium datapath",

	cell.Provide(newMap),
)

func newMap(lifecycle cell.Lifecycle) bpf.MapOut[Map] {
	networkDevicesMap := newNetworkDeviceMap()

	lifecycle.Append(cell.Hook{
		OnStart: func(startCtx cell.HookContext) error {
			return networkDevicesMap.init()
		},
		OnStop: func(stopCtx cell.HookContext) error {
			return networkDevicesMap.close()
		},
	})

	return bpf.NewMapOut(Map(networkDevicesMap))
}
