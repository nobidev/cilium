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

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/time"
)

const (
	// FlagEnable is the flag to enable private networking.
	FlagEnable = "private-networks-enabled"

	// DHCPInterfaceName is the name of the host dummy interface used to
	// receive DHCP packets redirected from BPF.
	DHCPInterfaceName = "cilium_dhcp"

	// FlagMode is the flag to configure the private networking mode.
	FlagMode = "private-networks-mode"

	// FlagBridgeGneighInterval is the flag to configure the interval at which workload cluster
	// endpoints are announced via gratuitous ARP/ND in bridge mode.
	FlagBridgeGneighInterval = "private-networks-bridge-gneigh-interval"

	// FlagHostReachability is the flag to allow (remote) host traffic into privnet.
	FlagHostReachability = "private-networks-host-reachability"

	// ModeDefault configures private networks to operate in default mode.
	ModeDefault = "default"

	// ModeLocalAccess configures the private network to operate in local access mode.
	ModeLocalAccess = "local-access"

	// ModeBridge configures private networks to operate in bridge mode,
	// that is providing connectivity between cilium-managed endpoints and
	// external endpoints that belong to the same private network.
	ModeBridge = "bridge"
)

var (
	// Cell registers the private networking configuration, and performs validation.
	Cell = cell.Group(
		cell.Config(defaultConfig),
		cell.Invoke(Config.validate),
	)

	DefaultCommon = Common{
		Enabled: false,
	}

	defaultConfig = Config{
		Common:               DefaultCommon,
		Mode:                 ModeDefault,
		BridgeGneighInterval: 1 * time.Minute,
		HostReachability:     true,
	}
)

// Common represents the basic configuration to enable private networking. It is
// extracted into a separate type so that it can be reused by other components,
// such as the Cilium operator or the clustermesh-apiserver.
type Common struct {
	Enabled bool `mapstructure:"private-networks-enabled"`
}

func (def Common) Flags(flags *pflag.FlagSet) {
	flags.Bool(FlagEnable, def.Enabled, "Enable support for private networks")
}

// Config groups the private networking configuration.
type Config struct {
	Common `mapstructure:",squash"`

	Mode                 string        `mapstructure:"private-networks-mode"`
	BridgeGneighInterval time.Duration `mapstructure:"private-networks-bridge-gneigh-interval"`
	HostReachability     bool          `mapstructure:"private-networks-host-reachability"`
}

func (def Config) Flags(flags *pflag.FlagSet) {
	def.Common.Flags(flags)

	flags.String(FlagMode, def.Mode, fmt.Sprintf("The private networks mode (%q, %q or %q)", ModeDefault, ModeLocalAccess, ModeBridge))

	flags.Duration(FlagBridgeGneighInterval, def.BridgeGneighInterval,
		fmt.Sprintf("Interval at which workload cluster endpoints are announced using gratuitous ARP/ND in %s or %s mode. Ignored in %s mode.", ModeBridge, ModeLocalAccess, ModeDefault))

	flags.Bool(FlagHostReachability, def.HostReachability, "Allow (remote) host traffic into privnet")
	flags.MarkHidden(FlagHostReachability)
}

// EnabledAsBridge returns whether private networking is enabled, and configured in bridge mode.
func (cfg Config) EnabledAsBridge() bool {
	return cfg.Enabled && cfg.Mode == ModeBridge
}

// EnabledAsLocalAccess returns whether private networking is enabled, and configured in local access mode.
func (cfg Config) EnabledAsLocalAccess() bool {
	return cfg.Enabled && cfg.Mode == ModeLocalAccess
}

// IsLocallyConnected returns whether private networking is enabled, and configured in local access or
// bridge mode. It signifies that the private network can egress via a local device configured on
// the node. Currently, INB or a K8s cluster in local access mode can egress via local device.
func (cfg Config) IsLocallyConnected() bool {
	return cfg.Enabled && (cfg.Mode == ModeBridge || cfg.Mode == ModeLocalAccess)
}

func (cfg Config) validate() error {
	switch cfg.Mode {
	case ModeDefault, ModeBridge, ModeLocalAccess:
	default:
		return fmt.Errorf("invalid private networks mode %q, should be one of: %q, %q, %q",
			cfg.Mode, ModeDefault, ModeBridge, ModeLocalAccess)
	}

	return nil
}
