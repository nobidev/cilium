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

	"github.com/cilium/cilium/pkg/healthconfig"
	"github.com/cilium/cilium/pkg/option"
)

type Config struct {
	EnableIPv4StandaloneEgressGateway bool
	StandaloneEgressGatewayInterface  string
}

func (def Config) IsEnabled() bool {
	return def.EnableIPv4StandaloneEgressGateway
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-ipv4-standalone-egress-gateway", def.EnableIPv4StandaloneEgressGateway, "Enable standalone egress gateway for IPv4")
	flags.String("standalone-egress-gateway-interface", def.StandaloneEgressGatewayInterface,
		"Name of the egress interface for the standalone gateway; if empty, it automatically selects the interface with the default route")
}

func (cfg Config) Validate(dcfg *option.DaemonConfig, healthConfig healthconfig.CiliumHealthConfig) error {
	if !cfg.EnableIPv4StandaloneEgressGateway {
		return nil
	}

	if dcfg.EnableIPv4EgressGatewayHA {
		return fmt.Errorf("standalone egress gateway cannot be enabled in combination with egress gateway HA")
	}

	if !dcfg.MasqueradingEnabled() || !dcfg.EnableBPFMasquerade {
		return fmt.Errorf("standalone egress gateway requires --%s=\"true\" and --%s=\"true\"", option.EnableIPv4Masquerade, option.EnableBPFMasquerade)
	}

	if !healthConfig.IsHealthCheckingEnabled() {
		return fmt.Errorf("standalone egress gateway requires healthchecking to be enabled")
	}

	return nil
}
