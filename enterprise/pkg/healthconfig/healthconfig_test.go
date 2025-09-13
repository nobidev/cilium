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
	"context"
	"testing"

	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/healthconfig"
)

func Test_enterprise_healthconfig(t *testing.T) {
	var got healthconfig.CiliumHealthConfig
	h := hive.New(healthconfig.Cell,
		Cell,
		cell.Invoke(func(hc healthconfig.CiliumHealthConfig) {
			got = hc
		}))
	flags := pflag.NewFlagSet("", pflag.ContinueOnError)
	h.RegisterFlags(flags)
	flags.Set(healthconfig.EnableHealthCheckingName, "false")
	flags.Set(healthconfig.EnableEndpointHealthCheckingName, "false")
	flags.Set(EnableHealthServerName, "true")

	tlog := hivetest.Logger(t)
	err := h.Start(tlog, context.Background())
	defer t.Cleanup(func() {
		h.Stop(tlog, context.Background())
	})

	require.NoError(t, err)
	require.True(t, got.IsHealthCheckingEnabled())
	require.False(t, got.IsEndpointHealthCheckingEnabled())
	require.False(t, got.IsActiveHealthCheckingEnabled())
}
