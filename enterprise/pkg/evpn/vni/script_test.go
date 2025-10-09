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
	"context"
	"maps"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/script"
	"github.com/cilium/hive/script/scripttest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	evpnConfig "github.com/cilium/cilium/enterprise/pkg/evpn/config"
	privnetConfig "github.com/cilium/cilium/enterprise/pkg/privnet/config"
	privnetTables "github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/hive"
)

func TestScript(t *testing.T) {
	log := hivetest.Logger(t)

	scripttest.Test(t,
		t.Context(),
		func(t testing.TB, args []string) *script.Engine {
			h := hive.New(
				privnetConfig.Cell,
				evpnConfig.Cell,
				mockVNIMapCell,

				cell.Provide(
					privnetTables.NewPrivateNetworksTable,
					statedb.RWTable[privnetTables.PrivateNetwork].ToTable,

					newVNIMappingTable,
					newVNIMappings,

					func() tunnel.Config {
						return tunnel.NewTestConfig(tunnel.VXLAN)
					},
					regeneration.NewFence,
				),
				cell.Invoke(
					(*VNIMappings).registerReconciler,
				),
			)
			hive.AddConfigOverride(h, func(c *evpnConfig.Config) {
				c.CommonConfig.Enabled = true
			})
			hive.AddConfigOverride(h, func(c *privnetConfig.Config) {
				c.Enabled = true
			})
			t.Cleanup(func() {
				assert.NoError(t, h.Stop(log, context.Background()))
			})
			cmds, err := h.ScriptCommands(log)
			require.NoError(t, err, "ScriptCommands")
			maps.Insert(cmds, maps.All(script.DefaultCmds()))

			return &script.Engine{
				Cmds: cmds,
			}
		}, []string{}, "testdata/*.txtar")
}
