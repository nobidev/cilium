// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package vni

import (
	"fmt"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/pkg/datapath/linux/config/defines"
)

var Cell = cell.Module(
	"vni-maps",
	"VNI BPF Map",

	cell.Config(defaultConfig),

	cell.Provide(
		newVNI,
		Config.nodeDefs,
	),
)

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Uint32("bpf-vni-map-max", def.MapSize, "Maximum number of entries in the VNI BPF map.")
}

type Config struct {
	// MapSize is the maximum number of entries in the VNI BPF maps.
	MapSize uint32 `mapstructure:"bpf-vni-map-max"`
}

var defaultConfig = Config{
	// The default value is maximum number of net-ids
	MapSize: uint32(tables.NetworkIDMax) + 1,
}

func (c Config) nodeDefs() defines.NodeOut {
	return defines.NodeOut{
		NodeDefines: map[string]string{
			"VNI_MAP_SIZE": fmt.Sprint(c.MapSize),
		},
	}
}
