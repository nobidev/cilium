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

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	"github.com/cilium/cilium/pkg/bgpv1/agent/signaler"
	"github.com/cilium/cilium/pkg/hive"
	k8sfake "github.com/cilium/cilium/pkg/k8s/client/testutils"
	slimcorev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slimmetav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	corev1client "github.com/cilium/cilium/pkg/k8s/slim/k8s/client/clientset/versioned/typed/core/v1"
	nodetypes "github.com/cilium/cilium/pkg/node/types"
)

const (
	nodeStatusTestNodeName = "test-node"
	nodeStatusTestTimeout  = time.Second * 5
)

type nodeStatusTestFixture struct {
	hive        *hive.Hive
	nsProvider  NodeStatusProvider
	bgpSignaler *signaler.BGPCPSignaler
	nodeClient  corev1client.NodeInterface
}

func newNodeStatusTestFixture() *nodeStatusTestFixture {
	f := &nodeStatusTestFixture{}

	f.hive = hive.New(
		cell.Module("node-status-test", "BGP node status test",
			k8s.LocalNodeCell,

			cell.Config(config.Config{
				Enabled: true,
			}),
			cell.Config(Config{
				MaintenanceGracefulShutdownEnabled: true,
				MaintenanceWithdrawTime:            1 * time.Second,
			}),

			cell.Provide(
				NewNodeStatusReconciler,
				signaler.NewBGPCPSignaler,
				k8sfake.NewFakeClientset,
			),

			cell.Invoke(func() {
				nodetypes.SetName(nodeStatusTestNodeName)
			}),
			cell.Invoke(func(provider NodeStatusProvider) {
				f.nsProvider = provider
			}),
			cell.Invoke(func(sig *signaler.BGPCPSignaler) {
				f.bgpSignaler = sig
			}),
			cell.Invoke(func(c *k8sfake.FakeClientset) {
				f.nodeClient = c.SlimFakeClientset.CoreV1().Nodes()
			}),
		),
	)
	return f
}

func TestNodeStatus(t *testing.T) {
	var table = []struct {
		name         string
		localNode    *slimcorev1.Node
		expectSignal bool
		expectStatus NodeStatus
	}{
		{
			name:         "local node resource not yet present - assume maintenance mode",
			expectSignal: false,
			expectStatus: NodeMaintenanceTimeExpired,
		},
		{
			name: "local node running - node ready",
			localNode: &slimcorev1.Node{
				ObjectMeta: slimmetav1.ObjectMeta{
					Name: nodeStatusTestNodeName,
				},
				Spec: slimcorev1.NodeSpec{},
			},
			expectSignal: true,
			expectStatus: NodeReady,
		},
		{
			name: "local node tainted - maintenance mode",
			localNode: &slimcorev1.Node{
				ObjectMeta: slimmetav1.ObjectMeta{
					Name: nodeStatusTestNodeName,
				},
				Spec: slimcorev1.NodeSpec{
					Taints: []slimcorev1.Taint{
						{
							Key:    corev1.TaintNodeUnschedulable,
							Effect: slimcorev1.TaintEffectNoSchedule,
						},
					},
				},
			},
			expectSignal: true,
			expectStatus: NodeMaintenance,
		},
		{
			name:         "local node tainted - maintenance time expired",
			localNode:    nil,
			expectSignal: true,
			expectStatus: NodeMaintenanceTimeExpired,
		},
		{
			name: "local node running again - node read",
			localNode: &slimcorev1.Node{
				ObjectMeta: slimmetav1.ObjectMeta{
					Name: nodeStatusTestNodeName,
				},
				Spec: slimcorev1.NodeSpec{},
			},
			expectSignal: true,
			expectStatus: NodeReady,
		},
	}

	// setup test environment
	req := require.New(t)
	f := newNodeStatusTestFixture()
	log := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))
	testCtx, cancel := context.WithTimeout(t.Context(), nodeStatusTestTimeout)
	t.Cleanup(func() {
		cancel()
	})

	// start test hive
	err := f.hive.Start(log, t.Context())
	req.NoError(err)
	t.Cleanup(func() {
		f.hive.Stop(log, t.Context())
	})

	created := false
	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {

			if tt.localNode != nil {
				// create / update local node
				if !created {
					_, err = f.nodeClient.Create(t.Context(), tt.localNode, metav1.CreateOptions{})
					created = true
				} else {
					_, err = f.nodeClient.Update(t.Context(), tt.localNode, metav1.UpdateOptions{})
				}
				req.NoError(err)

				// verify BGP signal
				if tt.expectSignal {
					select {
					case <-f.bgpSignaler.Sig:
					case <-testCtx.Done():
						t.Fatalf("missed expected BGP reconciliation signal")
					}
				} else {
					require.Empty(t, f.bgpSignaler.Sig, "unexpected BGP reconciliation signal")
				}

				// verify node state
				req.Equal(tt.expectStatus, f.nsProvider.GetNodeStatus())
			}
		})
	}
}
