//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package tests

import (
	"log/slog"
	"path"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"

	daemonk8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/enterprise/pkg/privnet"
	"github.com/cilium/cilium/enterprise/pkg/privnet/reconcilers/idpool"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	dptables "github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/hive"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
)

func NewTestHive(t testing.TB) *hive.Hive {
	return hive.New(
		k8sClient.FakeClientCell(),

		cell.Config(cmtypes.DefaultClusterInfo),

		daemonk8s.ResourcesCell,
		daemonk8s.TablesCell,

		mockEndpointCell(t),
		mockLocalCiliumNodeCell(t),
		mockGneigh(t),
		mockBPFMapCell(t),

		cell.Provide(
			dptables.NewDeviceTable,
			statedb.RWTable[*dptables.Device].ToTable,

			func() promise.Promise[synced.CRDSync] {
				r, p := promise.New[synced.CRDSync]()
				r.Resolve(synced.CRDSync{})
				return p
			},

			func() tunnel.Config {
				return tunnel.NewTestConfig(tunnel.VXLAN)
			},

			func() *option.DaemonConfig {
				return &option.DaemonConfig{
					// Set StateDir to match the script test directory.
					StateDir: path.Join(path.Dir(t.TempDir()), "001"),
				}
			},
		),

		// Make privnet ID predictable
		withOverride(idpool.NewIDPool(slog.Default(), 1, tables.NetworkIDMax)),

		ClusterMeshObservers,
		Health(t.TempDir()),

		privnet.Cell,
	)
}

func withOverride[T any](override T) cell.Cell {
	return cell.DecorateAll(func(T) T {
		return override
	})
}
