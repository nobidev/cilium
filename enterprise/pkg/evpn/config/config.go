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

	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/defaults"
)

const (
	DefaultEVPNEnabled     = false
	DefaultEVPNVxlanDevice = "cilium_evpn"
	DefaultEVPNVxlanPort   = 4789
)

const (
	FlagEvpnEnabled      = "enable-evpn"
	FlagEvpnTunnelDevice = "evpn-vxlan-device"
	FlagEvpnTunnelPort   = "evpn-vxlan-port"
)

// CommonConfig is the configuration shared between the agent and the operator
type CommonConfig struct {
	Enabled bool `mapstructure:"enable-evpn"`
}

func (c CommonConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool(FlagEvpnEnabled, c.Enabled, "Enable EVPN")
}

// Config is the configuration specific to the agent
type Config struct {
	CommonConfig `mapstructure:",squash"`

	VxlanDevice string `mapstructure:"evpn-vxlan-device"`
	VxlanPort   uint16 `mapstructure:"evpn-vxlan-port"`
}

func (c Config) Flags(flags *pflag.FlagSet) {
	c.CommonConfig.Flags(flags)

	flags.String(FlagEvpnTunnelDevice, c.VxlanDevice, "Vxlan device setup and used for EVPN")
	flags.Uint16(FlagEvpnTunnelPort, c.VxlanPort, "UDP port used for EVPN vxlan tunnel")
}

func (c Config) validate(tcfg tunnel.Config) error {
	if !c.Enabled {
		return nil
	}
	if tcfg.EncapProtocol() == tunnel.VXLAN {
		if tcfg.Port() == c.VxlanPort {
			return fmt.Errorf("EVPN vxlan port %d conflicts with Cilium vxlan tunnel port", c.VxlanPort)
		}

		if defaults.VxlanDevice == c.VxlanDevice {
			return fmt.Errorf("EVPN vxlan device %s conflicts with Cilium vxlan tunnel device", c.VxlanDevice)
		}
	}
	return nil
}

// defaultConfig is the default configuration of the agent
var defaultConfig = Config{
	CommonConfig: CommonConfig{
		Enabled: DefaultEVPNEnabled,
	},
	VxlanDevice: DefaultEVPNVxlanDevice,
	VxlanPort:   DefaultEVPNVxlanPort,
}
