// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package config

import (
	"fmt"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	opncfg "github.com/cilium/cilium/enterprise/operator/pkg/privnet/config"
)

var (
	Cell = cell.Group(
		cell.Config(defaultConfig),
		cell.Invoke(Config.validate),
	)

	defaultConfig = Config{
		Enabled:     false,
		HostPort:    ":11443",
		TLSKeyFile:  "/var/lib/cilium/privnet/webhook/tls/server.key",
		TLSCertFile: "/var/lib/cilium/privnet/webhook/tls/server.crt",

		NetworkBinding: "",
	}
)

type Config struct {
	Enabled     bool   `mapstructure:"private-networks-webhook-enabled"`
	HostPort    string `mapstructure:"private-networks-webhook-hostport"`
	TLSKeyFile  string `mapstructure:"private-networks-webhook-tls-key-file"`
	TLSCertFile string `mapstructure:"private-networks-webhook-tls-cert-file"`

	NetworkBinding string `mapstructure:"private-networks-webhook-network-binding"`
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Bool("private-networks-webhook-enabled", def.Enabled,
		"Enable the private networks webhook")
	flags.String("private-networks-webhook-hostport", def.HostPort,
		"The address and port the private networks webhook listens to")
	flags.String("private-networks-webhook-tls-key-file", def.TLSKeyFile,
		"The path to the webhook TLS key for the private networks webhook")
	flags.String("private-networks-webhook-tls-cert-file", def.TLSCertFile,
		"The path to the webhook TLS certificate for the private networks webhook")

	flags.String("private-networks-webhook-network-binding", def.NetworkBinding,
		"The name of the KubeVirt network binding plugin enforced on mutated VMs",
	)
}

func (cfg Config) validate(ocfg opncfg.Config) error {
	if cfg.Enabled && !ocfg.Enabled {
		return fmt.Errorf("cannot enable the private networks webhook if private networks is disabled")
	}

	if cfg.Enabled && !ocfg.NADIntegration.Enabled {
		return fmt.Errorf("cannot enable the private networks webhook if the integration with Multus NADs is disabled")
	}

	if cfg.Enabled && cfg.NetworkBinding == "" {
		return fmt.Errorf("cannot enable the private networks webhook if the network binding is unspecified")
	}

	return nil
}
