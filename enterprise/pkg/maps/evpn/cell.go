// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package evpn

import (
	"fmt"
	"math"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/datapath/linux/config/defines"
)

var Cell = cell.Module(
	"evpn-maps",
	"EVPN BPF Map",

	cell.Config(defaultConfig),

	cell.Provide(
		Config.nodeDefs,
		newFIB,
	),
)

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Uint32("bpf-evpn-fib-map-max", def.FIBMapSize, "Maximum number of entries in the FIB BPF map.")
}

type Config struct {
	// FIBMapSize is the maximum number of entries in the EVPN FIB BPF maps.
	FIBMapSize uint32 `mapstructure:"bpf-evpn-fib-map-max"`
}

var defaultConfig = Config{
	FIBMapSize: math.MaxUint16 + 1,
}

func (c Config) nodeDefs() defines.NodeOut {
	return defines.NodeOut{
		NodeDefines: map[string]string{
			"EVPN_FIB_MAP_SIZE": fmt.Sprint(c.FIBMapSize),
		},
	}
}
