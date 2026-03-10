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
	"github.com/spf13/pflag"

	daemonk8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/enterprise/pkg/privnet"
	"github.com/cilium/cilium/enterprise/pkg/privnet/dhcp"
	"github.com/cilium/cilium/enterprise/pkg/privnet/reconcilers"
	"github.com/cilium/cilium/enterprise/pkg/privnet/reconcilers/idpool"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	dptables "github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/hive"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/time"
)

type dhcpTestConfig struct {
	StaticRelay bool `mapstructure:"privnet-test-dhcp-static-relay"`
}

func (def dhcpTestConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool("privnet-test-dhcp-static-relay", def.StaticRelay, "Use a static DHCP relay in privnet script tests")
}

func NewTestHive(t testing.TB) *hive.Hive {
	extra := cell.Group()
	if testutils.IsPrivileged() {
		// Create a new network namespace for the privileged test cases.
		ns, err := netns.New()
		if err != nil {
			t.Fatalf("failed to create netns: %v", err)
		}
		t.Cleanup(func() {
			_ = ns.Close()
		})

		cfg := &dhcp.TestConfig{
			NetNS:              ns,
			LeaseSweepInterval: 100 * time.Millisecond,
		}
		extra = cell.Group(
			cell.Provide(func() *dhcp.TestConfig { return cfg }),
			cell.Provide(func() *netns.NetNS { return ns }),
		)
	}

	return hive.New(
		k8sClient.FakeClientCell(),

		cell.Config(cmtypes.DefaultClusterInfo),
		cell.Config(metrics.RegistryConfig{}),
		cell.Config(dhcpTestConfig{StaticRelay: true}),

		daemonk8s.ResourcesCell,
		daemonk8s.TablesCell,
		node.LocalNodeStoreTestCell,

		mockEndpointCell(t),
		mockLocalCiliumNodeCell(t),
		mockGneigh(t),
		mockBPFMapCell(t),
		mockK8sCell(t),
		mockPolicyCell(t),
		mockDeviceManagerCell(t),

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

			metrics.NewRegistry,
		),

		cell.Invoke(func(localNodeStore *node.LocalNodeStore) {
			// Prepopulate local node name and labels for nodeattachment test which
			// requires modifying the local node labels.
			localNodeStore.Update(func(n *node.LocalNode) {
				n.Labels["node"] = "node1"
			})
		}),

		// Make privnet ID predictable
		withOverride(idpool.NewIDPool[tables.NetworkName, tables.NetworkID](slog.Default(), 1, tables.NetworkIDMax)),
		// Make subnet ID predictable
		withOverride(reconcilers.SubnetIDPoolFactory(func() *idpool.SubnetIDPool {
			return idpool.NewIDPool[tables.SubnetName, tables.SubnetID](slog.Default(), 1, tables.SubnetIDMax)
		})),

		ClusterMeshObservers,
		Health(t.TempDir()),

		dhcpScriptCmdsCell(),

		privnet.Cell,
		extra,
	)
}

func withOverride[T any](override T) cell.Cell {
	return cell.DecorateAll(func(T) T {
		return override
	})
}
