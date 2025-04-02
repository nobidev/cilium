// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/time"
)

const (
	CECPolicyModeDedicated = "dedicated"
	CECPolicyModeGlobal    = "global"
)

// CECPolicyConfig is the configuration to enable CiliumEnvoyConfig identity feature.
// Ideally, this should be in the enterprise package, but it is here so that we can use in CEC parser component.
type CECPolicyConfig struct {
	Mode          string        `mapstructure:"envoy-config-policy-mode"`
	RegenInterval time.Duration `mapstructure:"envoy-config-policy-regen-interval"`
}

func (r CECPolicyConfig) Flags(flags *pflag.FlagSet) {
	flags.String("envoy-config-policy-mode", r.Mode, "Enable a dedicated identity for each CiliumEnvoyConfig instead of using the global reserved:ingress identity")
	flags.Duration("envoy-config-policy-regen-interval", r.RegenInterval, "Ingress Policy Regeneration Interval")
}

var DefaultConfig = CECPolicyConfig{
	Mode:          CECPolicyModeGlobal,
	RegenInterval: 30 * time.Second,
}
