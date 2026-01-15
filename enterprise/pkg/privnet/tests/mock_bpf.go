// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package tests

import (
	"context"
	"fmt"
	"iter"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/script"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"

	pnmaps "github.com/cilium/cilium/enterprise/pkg/maps/privnet"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/types"
)

func mockBPFMapCell(t testing.TB) cell.Cell {
	t.Helper()

	return cell.Group(
		cell.Provide(
			newFakeBPFMapRegistry,
			registerFakeBPFMap(
				"cilium_privnet_pip", 512000,
				&pnmaps.PIPKeyVal{
					Key: pnmaps.NewPIPKey(netip.MustParsePrefix("172.16.1.1/32")),
					Val: pnmaps.NewPIPVal(0xff, netip.MustParseAddr("172.16.2.1"), types.MACAddr{}, 0x1f),
				},
			),
			registerFakeBPFMap(
				"cilium_privnet_fib", 512000,
				&pnmaps.FIBKeyVal{
					Key: pnmaps.NewFIBKey(5, netip.MustParsePrefix("172.16.2.1/32")),
					Val: pnmaps.NewFIBVal(netip.MustParseAddr("172.16.1.1"), 0x0),
				},
			),
		),

		cell.Provide(func(f *fakeBPFMapRegistry) hive.ScriptCmdsOut {
			return hive.NewScriptCmds(map[string]script.Cmd{
				"privnet/maps-dump": f.dumpMaps(),
			})
		}),
	)
}

type fakeBPFMapInspector interface {
	Dump() iter.Seq2[bpf.MapKey, bpf.MapValue]
}

type fakeBPFMapRegistry struct {
	maps map[string]fakeBPFMapInspector
}

func newFakeBPFMapRegistry() *fakeBPFMapRegistry {
	return &fakeBPFMapRegistry{
		maps: make(map[string]fakeBPFMapInspector),
	}
}

type fakeBPFMap[Obj pnmaps.KeyValue] struct {
	name       string
	maxEntries uint32
	entries    lock.Map[string, Obj]
}

func registerFakeBPFMap[Obj pnmaps.KeyValue](
	name string,
	maxEntries uint32,
	existing ...Obj,
) func(registry *fakeBPFMapRegistry) pnmaps.Map[Obj] {
	m := &fakeBPFMap[Obj]{
		name:       name,
		maxEntries: maxEntries,
		entries:    lock.Map[string, Obj]{},
	}
	for _, obj := range existing {
		m.entries.Store(obj.MapKey().String(), obj)
	}
	return func(registry *fakeBPFMapRegistry) pnmaps.Map[Obj] {
		registry.maps[m.NonPrefixedName()] = m
		return m
	}
}

// IsOpen implements pnmaps.Map[Obj]
func (f *fakeBPFMap[Obj]) IsOpen() bool {
	return true
}

// NonPrefixedName implements pnmaps.Map[Obj]
func (f *fakeBPFMap[Obj]) NonPrefixedName() string {
	return strings.TrimPrefix(f.name, "cilium_")
}

// MaxEntries implements pnmaps.Map[Obj]
func (f *fakeBPFMap[Obj]) MaxEntries() uint32 {
	return f.maxEntries
}

// Ops implements pnmaps.Map[Obj]
func (f *fakeBPFMap[Obj]) Ops() reconciler.Operations[Obj] {
	return f
}

// Delete implements reconciler.Operations.
func (f *fakeBPFMap[Obj]) Delete(_ context.Context, _ statedb.ReadTxn, _ statedb.Revision, obj Obj) error {
	f.entries.Delete(obj.MapKey().String())
	return nil
}

// Prune implements reconciler.Operations.
func (f *fakeBPFMap[Obj]) Prune(ctx context.Context, txn statedb.ReadTxn, objects iter.Seq2[Obj, statedb.Revision]) error {
	f.entries.Range(func(key string, _ Obj) bool {
		f.entries.Delete(key)
		return true
	})
	for obj := range objects {
		f.entries.Store(obj.MapKey().String(), obj)
	}
	return nil
}

// Update implements reconciler.Operations.
func (f *fakeBPFMap[Obj]) Update(_ context.Context, _ statedb.ReadTxn, _ statedb.Revision, obj Obj) error {
	f.entries.Store(obj.MapKey().String(), obj)
	return nil
}

// Dump implements fakeBPFMapInspecter
func (f *fakeBPFMap[Obj]) Dump() iter.Seq2[bpf.MapKey, bpf.MapValue] {
	return func(yield func(bpf.MapKey, bpf.MapValue) bool) {
		f.entries.Range(func(_ string, obj Obj) bool {
			return yield(obj.MapKey(), obj.MapValue())
		})
	}
}

func (f *fakeBPFMapRegistry) dumpMaps() script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "dump the content of the (in-memory) private networks BPF maps",
			Args:    "<map> <file>",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) < 1 {
				return nil, fmt.Errorf("%w: expected map name", script.ErrUsage)
			}

			return func(s *script.State) (stdout string, stderr string, err error) {
				m, ok := f.maps[args[0]]
				if !ok {
					return "", "", fmt.Errorf("%w: unexpected map name %q", script.ErrUsage, args[0])
				}

				var lines []string
				for k, v := range m.Dump() {
					lines = append(lines, fmt.Sprintf("%s -> %s\n", k, v))
				}
				slices.Sort(lines)
				output := strings.Join(lines, "")

				if len(args) == 1 {
					return output, "", nil
				}
				err = os.WriteFile(s.Path(args[1]), []byte(output), 0644)
				return "", "", err
			}, nil
		},
	)
}
