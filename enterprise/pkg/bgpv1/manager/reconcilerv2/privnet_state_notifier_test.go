// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package reconcilerv2

import (
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	"github.com/cilium/cilium/enterprise/pkg/evpn"
	pnCfg "github.com/cilium/cilium/enterprise/pkg/privnet/config"
	privnetTables "github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/pkg/bgpv1/agent"
	"github.com/cilium/cilium/pkg/bgpv1/agent/mode"
	"github.com/cilium/cilium/pkg/bgpv1/manager"
	bgpTables "github.com/cilium/cilium/pkg/bgpv1/manager/tables"
	"github.com/cilium/cilium/pkg/hive"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

func TestPrivnetStateNotifier(t *testing.T) {
	// This simple test ensures that the update to the private network
	// table triggers the state reconciliation of all BGP instances.
	var (
		sr           *mockStatusReconciler
		mgr          agent.BGPRouterManager
		db           *statedb.DB
		privnetTable statedb.RWTable[privnetTables.PrivateNetwork]
	)
	h := hive.New(
		cell.Module(
			"test",
			"test module",
			cell.Provide(
				newMockStatusReconciler,
				privnetTables.NewPrivateNetworksTable,
				statedb.RWTable[privnetTables.PrivateNetwork].ToTable,
				manager.NewBGPRouterManager,
				mode.NewConfigMode,
				manager.NewBGPManagerMetrics,
				bgpTables.NewBGPReconcileErrorTable,
				func() *option.DaemonConfig {
					return &option.DaemonConfig{
						EnableBGPControlPlane: true,
					}
				},
			),
			cell.Invoke(func(
				s *mockStatusReconciler,
				m agent.BGPRouterManager,
				d *statedb.DB,
				t statedb.RWTable[privnetTables.PrivateNetwork],
				mod *mode.ConfigMode,
			) {
				sr = s
				mgr = m
				db = d
				privnetTable = t
				mod.Set(mode.BGPv2)
			}),
		),
	)

	hive.AddConfigOverride(h, func(c *evpn.Config) {
		c.Enabled = true
	})
	hive.AddConfigOverride(h, func(c *config.Config) {
		c.Enabled = true
	})
	hive.AddConfigOverride(h, func(c *pnCfg.Config) {
		c.Enabled = true
	})

	err := h.Start(hivetest.Logger(t), t.Context())
	require.NoError(t, err)
	t.Cleanup(func() {
		h.Stop(hivetest.Logger(t), t.Context())
	})

	// Create BGP instances
	err = mgr.ReconcileInstances(
		t.Context(),
		&v2.CiliumBGPNodeConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test",
			},
			Spec: v2.CiliumBGPNodeSpec{
				BGPInstances: []v2.CiliumBGPNodeInstance{
					{
						Name:     "instance0",
						LocalASN: ptr.To[int64](65000),
						RouterID: ptr.To("10.0.0.1"),
					},
					{
						Name:     "instance1",
						LocalASN: ptr.To[int64](65001),
						RouterID: ptr.To("10.0.0.2"),
					},
				},
			},
		},
		&v2.CiliumNode{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test",
			},
		},
	)
	require.NoError(t, err)

	// Insert a private network to trigger the notifier
	wtxn := db.WriteTxn(privnetTable)
	_, _, err = privnetTable.Insert(wtxn, privnetTables.PrivateNetwork{
		Name: "test",
	})
	wtxn.Commit()
	require.NoError(t, err)

	// The update to the private network should trigger the reconciliation
	// for all instances.
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		sr.Lock()
		if !assert.Equal(ct, 1, sr.countPerInstance["instance0"]) {
			return
		}
		if !assert.Equal(ct, 1, sr.countPerInstance["instance1"]) {
			return
		}
		sr.Unlock()
	}, time.Second*3, time.Millisecond*100)
}
