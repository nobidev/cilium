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
	"fmt"
	"iter"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"

	uhive "github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/script"
	"github.com/cilium/hive/script/scripttest"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	evpnConfig "github.com/cilium/cilium/enterprise/pkg/evpn/config"
	vniMaps "github.com/cilium/cilium/enterprise/pkg/maps/vni"
	privnetConfig "github.com/cilium/cilium/enterprise/pkg/privnet/config"
	privnetTables "github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/lock"
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
					registerMapReconciler,
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

var mockVNIMapCell = cell.Group(
	cell.Provide(
		func() *mockVNIMap {
			return &mockVNIMap{}
		},
		func(m *mockVNIMap) reconciler.Operations[*vniMaps.VNIKeyVal] {
			return m
		},
	),
	cell.Provide(func(m *mockVNIMap) uhive.ScriptCmdsOut {
		return uhive.NewScriptCmds(map[string]script.Cmd{
			"vni/map-dump": vniMapDump(m),
		})
	}),
)

func vniMapDump(m *mockVNIMap) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "dump the content of the (in-memory) VNI map",
			Args:    "<file>",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			return func(s *script.State) (stdout string, stderr string, err error) {
				output := m.Dump()
				if len(args) == 0 {
					return output, "", nil
				}
				err = os.WriteFile(s.Path(args[0]), []byte(output), 0644)
				return "", "", err
			}, nil
		},
	)
}

type mockVNIMap struct {
	vals lock.Map[string, *vniMaps.VNIKeyVal]
}

// Delete implements reconciler.Operations.
func (m *mockVNIMap) Delete(_ context.Context, _ statedb.ReadTxn, _ uint64, obj *vniMaps.VNIKeyVal) error {
	m.vals.Delete(obj.Key.String())
	return nil
}

// Prune implements reconciler.Operations.
func (m *mockVNIMap) Prune(ctx context.Context, txn statedb.ReadTxn, objects iter.Seq2[*vniMaps.VNIKeyVal, uint64]) error {
	m.vals.Range(func(key string, _ *vniMaps.VNIKeyVal) bool {
		m.vals.Delete(key)
		return true
	})
	for obj := range objects {
		m.vals.Store(obj.Key.String(), obj)
	}
	return nil
}

// Update implements reconciler.Operations.
func (m *mockVNIMap) Update(_ context.Context, _ statedb.ReadTxn, _ uint64, obj *vniMaps.VNIKeyVal) error {
	m.vals.Store(obj.Key.String(), obj)
	return nil
}

// Dump returns a string representation of the contents of the map
func (m *mockVNIMap) Dump() string {
	var out []string
	m.vals.Range(func(_ string, val *vniMaps.VNIKeyVal) bool {
		out = append(out, fmt.Sprintf("%s -> %s\n", val.Key.String(), val.Val.String()))
		return true
	})
	slices.Sort(out)
	return strings.Join(out, "")
}
