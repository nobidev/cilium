//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package grpc

import (
	"fmt"

	"github.com/spf13/pflag"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/pkg/defaults"
)

var (
	Cell = cell.Group(
		cell.Config(defaultConfig),
	)

	defaultConfig = Config{
		Port: defaults.ClusterHealthPort - 1,
	}
)

type Config struct {
	// Port is the port used for the privnet gRPC server.
	Port uint16 `mapstructure:"private-networks-api-port"`
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Uint16("private-networks-api-port", def.Port,
		fmt.Sprintf("The TCP port the privnet gRPC server listens to, in %s mode. Otherwise, it represents the fallback port to connect to a candidate INB if not explicitly advertised by the candidate INB itself.",
			config.ModeBridge))
}
