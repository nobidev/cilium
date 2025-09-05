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
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/job"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	daemon_k8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	"github.com/cilium/cilium/pkg/bgpv1/agent/signaler"
	"github.com/cilium/cilium/pkg/bgpv1/manager/instance"
	"github.com/cilium/cilium/pkg/bgpv1/manager/reconcilerv2"
	"github.com/cilium/cilium/pkg/bgpv1/manager/store"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/k8s"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	k8sclient "github.com/cilium/cilium/pkg/k8s/client"
	k8sfake "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/utils"
)

func TestReconcileParamsUpgrader(t *testing.T) {
	var (
		up paramUpgrader
		cs k8sclient.Clientset
	)

	ossNode := &v2.CiliumBGPNodeConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node0",
		},
		Spec: v2.CiliumBGPNodeSpec{
			BGPInstances: []v2.CiliumBGPNodeInstance{
				{
					Name: "instance0",
					Peers: []v2.CiliumBGPNodePeer{
						{
							Name:        "peer1",
							PeerAddress: ptr.To("10.10.10.10"),
						},
						{
							Name:        "peer2-unnumbered",
							PeerAddress: ptr.To("fe80::aabb:1234"), // normally set by LinkLocalReconciler for unnumbered peers
						},
					},
				},
			},
		},
	}

	ceeNode := &v1.IsovalentBGPNodeConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node0",
		},
		Spec: v1.IsovalentBGPNodeSpec{
			BGPInstances: []v1.IsovalentBGPNodeInstance{
				{
					Name: ossNode.Spec.BGPInstances[0].Name,
					Peers: []v1.IsovalentBGPNodePeer{
						{
							Name:        ossNode.Spec.BGPInstances[0].Peers[0].Name,
							PeerAddress: ossNode.Spec.BGPInstances[0].Peers[0].PeerAddress,
						},
						{
							Name: ossNode.Spec.BGPInstances[0].Peers[1].Name,
							AutoDiscovery: &v1.BGPAutoDiscovery{
								Mode: v1.BGPADUnnumbered,
								Unnumbered: &v1.BGPUnnumbered{
									Interface: "eth0", // should cause copying PeerAddress from oss NodeConfig
								},
							},
						},
					},
				},
			},
		},
	}

	h := hive.New(
		job.Cell,
		cell.Provide(
			newReconcileParamsUpgrader,
			k8sfake.NewFakeClientset,
			k8s.CiliumBGPNodeConfigResource,
			k8s.IsovalentBGPNodeConfigResource,
			signaler.NewBGPCPSignaler,
			cell.NewSimpleHealth,
			func() store.BGPCPResourceStore[*v1.IsovalentBGPNodeConfig] {
				return store.InitMockStore([]*v1.IsovalentBGPNodeConfig{ceeNode})
			},
			func(r job.Registry, lc cell.Lifecycle, health cell.Health) job.Group {
				return r.NewGroup(health, lc)
			},
			// enterprise bgp is enabled
			func() config.Config {
				return config.Config{
					Enabled:             true,
					StatusReportEnabled: true,
				}
			},
		),

		cell.Provide(func(lc cell.Lifecycle, c k8sclient.Clientset) daemon_k8s.LocalCiliumNodeResource {
			return resource.New[*v2.CiliumNode](
				lc, utils.ListerWatcherFromTyped[*v2.CiliumNodeList](
					c.CiliumV2().CiliumNodes(),
				), nil,
			)
		}),

		cell.Invoke(func(u paramUpgrader, c k8sclient.Clientset, j job.Group) {
			up = u
			cs = c
		}),
	)

	logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))
	err := h.Start(logger, context.Background())
	require.NoError(t, err)
	t.Cleanup(func() {
		h.Stop(logger, context.Background())
	})

	// insert a node
	_, err = cs.CiliumV2().CiliumNodes().Create(
		context.Background(),
		&v2.CiliumNode{
			ObjectMeta: metav1.ObjectMeta{
				Name: "node0",
			},
		},
		metav1.CreateOptions{},
	)
	require.NoError(t, err)

	ossParams := reconcilerv2.ReconcileParams{
		BGPInstance: &instance.BGPInstance{
			Config: &ossNode.Spec.BGPInstances[0],
			Router: types.NewFakeRouter(),
		},
		DesiredConfig: &ossNode.Spec.BGPInstances[0],
		CiliumNode: &v2.CiliumNode{
			ObjectMeta: metav1.ObjectMeta{
				Name: "node0",
			},
		},
	}

	var ceeParams EnterpriseReconcileParams
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		ceeParams, err = up.upgrade(ossParams)
		if !assert.NoError(ct, err) {
			return
		}
	}, time.Second*3, time.Millisecond*100)

	require.Equal(t,
		// Pointer equality
		ceeParams.BGPInstance.Router, ossParams.BGPInstance.Router,
		"CEE router doesn't point to the same router instance as OSS",
	)

	require.Equal(t,
		ceeParams.BGPInstance.Name, ossParams.BGPInstance.Name,
		"CEE instance name doesn't match OSS instance name",
	)

	require.Same(t,
		// Pointer equality
		ceeParams.CiliumNode, ossParams.CiliumNode,
		"CEE CiliumNode doesn't point to the same router instance as OSS",
	)

	require.Len(t, ossParams.DesiredConfig.Peers, len(ceeParams.DesiredConfig.Peers))
	for _, ceePeer := range ceeParams.DesiredConfig.Peers {
		ossPeer, err := getOSSNodePeerByName(ossParams.DesiredConfig, ceePeer.Name)
		require.NoError(t, err)
		require.Equal(t, ceePeer.PeerAddress, ossPeer.PeerAddress)
	}
}
