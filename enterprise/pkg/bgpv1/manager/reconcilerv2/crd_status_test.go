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
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/job"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	daemon_k8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	"github.com/cilium/cilium/pkg/hive"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	k8s_client "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/node"
	nodetypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/time"
)

const (
	TestTimeout = time.Second * 5
)

func TestDisableStatusReport(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()

	logger := hivetest.Logger(t)

	var cs k8s_client.Clientset
	hive := hive.New(cell.Module("test", "test",
		daemon_k8s.LocalNodeCell,
		cell.Provide(
			func() *config.Config {
				return &config.Config{
					Enabled:             true,
					StatusReportEnabled: false,
				}
			},
			k8s_client.NewFakeClientset,
		),
		cell.Provide(func() *node.LocalNodeStore {
			return node.NewTestLocalNodeStore(node.LocalNode{
				Node: nodetypes.Node{
					Name: "node0",
				},
			})
		}),
		cell.Invoke(func(jg job.Group, ln *node.LocalNodeStore, _cs k8s_client.Clientset) {
			cs = _cs

			// Create a LocalNode to obtain local node name
			_, err := cs.CiliumV2().CiliumNodes().Create(
				ctx,
				&v2.CiliumNode{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node0",
					},
				},
				metav1.CreateOptions{},
			)
			require.NoError(t, err)

			// Create a NodeConfig for this node
			_, err = cs.IsovalentV1().IsovalentBGPNodeConfigs().Create(
				ctx,
				&v1.IsovalentBGPNodeConfig{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node0",
					},
					// Spec can be empty for this test
					Spec: v1.IsovalentBGPNodeSpec{},
					// Fill with some dummy status
					Status: v1.IsovalentBGPNodeStatus{
						BGPInstances: []v1.IsovalentBGPNodeInstanceStatus{
							{
								CiliumBGPNodeInstanceStatus: v2alpha1.CiliumBGPNodeInstanceStatus{
									Name: "foo",
								},
							},
						},
					},
				},

				metav1.CreateOptions{},
			)
			require.NoError(t, err)

			// Ensure the status is not empty at this point
			nc, err := cs.IsovalentV1().IsovalentBGPNodeConfigs().Get(ctx, "node0", metav1.GetOptions{})
			require.NoError(t, err)
			require.False(t, nc.Status.DeepEqual(&v1.IsovalentBGPNodeStatus{}), "Status is already empty before cleanup job")

			// Register cleanup job. This should cleanup the status of the NodeConfig above.
			r := &StatusReconciler{
				LocalNodeStore: ln,
				ClientSet:      cs,
			}
			jg.Add(job.OneShot("cleanup-status", r.cleanupStatus))
		}),
	))

	require.NoError(t, hive.Start(logger, ctx))
	t.Cleanup(func() {
		hive.Stop(logger, ctx)
	})

	// Wait for status to be cleared
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		nc, err := cs.IsovalentV1().IsovalentBGPNodeConfigs().Get(ctx, "node0", metav1.GetOptions{})
		if !assert.NoError(ct, err) {
			return
		}
		// The status should be cleared to empty
		assert.True(ct, nc.Status.DeepEqual(&v1.IsovalentBGPNodeStatus{}), "Status is not empty")
	}, time.Second*5, time.Millisecond*100)
}
