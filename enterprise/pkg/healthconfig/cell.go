/*
 * // Copyright 2021 Authors of Cilium
 * //
 * // Licensed under the Apache License, Version 2.0 (the "License");
 * // you may not use this file except in compliance with the License.
 * // You may obtain a copy of the License at
 * //
 * //     http://www.apache.org/licenses/LICENSE-2.0
 * //
 * // Unless required by applicable law or agreed to in writing, software
 * // distributed under the License is distributed on an "AS IS" BASIS,
 * // WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * // See the License for the specific language governing permissions and
 * // limitations under the License.
 *
 */

package healthconfig

import (
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/healthconfig"
)

// Cell provides the Cilium health config.
var Cell = cell.Module(
	"enterprise-cilium-health-config",
	"Cilium enterprise health config",
	cell.Config(defaultConfig),
	cell.DecorateAll(func(hc healthconfig.CiliumHealthConfig, ec EnterpriseConfig) healthconfig.CiliumHealthConfig {
		return EnterpriseCiliumHealthConfig{
			CiliumHealthConfig:                    hc,
			EnableHealthServerWithoutActiveChecks: ec.EnableHealthServer,
		}
	}),
)

const (
	EnableHealthServerName = "enable-health-server-without-active-checks"
)

type EnterpriseConfig struct {
	EnableHealthServer bool `mapstructure:"enable-health-server-without-active-checks"`
}

// EnterpriseCiliumHealthConfig extends the CiliumHealthConfig with Enterprise health configurations.
type EnterpriseCiliumHealthConfig struct {
	healthconfig.CiliumHealthConfig
	EnableHealthServerWithoutActiveChecks bool
}

var defaultConfig = EnterpriseConfig{
	EnableHealthServer: false,
}

func (c EnterpriseCiliumHealthConfig) IsHealthCheckingEnabled() bool {
	return c.CiliumHealthConfig.IsHealthCheckingEnabled() || c.EnableHealthServerWithoutActiveChecks
}

func (c EnterpriseCiliumHealthConfig) IsEndpointHealthCheckingEnabled() bool {
	return c.CiliumHealthConfig.IsEndpointHealthCheckingEnabled()
}

func (c EnterpriseCiliumHealthConfig) IsActiveHealthCheckingEnabled() bool {
	return !c.EnableHealthServerWithoutActiveChecks
}

func (c EnterpriseConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool(EnableHealthServerName, false, "Enable health server without active health checks")
}
