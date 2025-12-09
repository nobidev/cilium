// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package privnet

import (
	"fmt"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/datapath/linux/config/defines"
)

var Cell = cell.Module(
	"private-networks-maps",
	"Private Networks eBPF Maps",

	cell.Config(defaultConfig),

	cell.Provide(
		newPIP,
		newFIB,
		newWatchdog,
		Config.nodeDefs,
	),
)

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Uint32("bpf-privnet-pip-fib-map-max", def.MapSize, "Maximum number of entries in the private network PIP and FIB BPF maps.")
}

type Config struct {
	// MapSize is the maximum number of entries in the private network PIP and FIB BPF maps.
	MapSize uint32 `mapstructure:"bpf-privnet-pip-fib-map-max"`
}

var defaultConfig = Config{
	// The default value matches the size of the ipcache.
	MapSize: 512000,
}

func (c Config) nodeDefs() defines.NodeOut {
	return defines.NodeOut{
		NodeDefines: map[string]string{
			"PRIVNET_PIP_FIB_MAP_SIZE": fmt.Sprint(c.MapSize),
		},
	}
}
