// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package bgpv2

import (
	"context"
	"maps"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/utils/ptr"

	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	slim_meta_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/time"
)

func Test_ClusterConfigSteps(t *testing.T) {
	steps := []struct {
		name                   string
		clusterConfig          *v1alpha1.IsovalentBGPClusterConfig
		nodeConfigOverride     *v1alpha1.IsovalentBGPNodeConfigOverride
		nodes                  []*cilium_v2.CiliumNode
		expectedNodeConfigs    []*v1alpha1.IsovalentBGPNodeConfig
		expectedTrueConditions []string
	}{
		{
			name:          "initial node setup",
			clusterConfig: nil,
			nodes: []*cilium_v2.CiliumNode{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-1",
						Labels: map[string]string{
							"bgp": "rack1",
						},
					},
				},
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-2",
						Labels: map[string]string{
							"bgp": "rack1",
						},
					},
				},
			},
			expectedNodeConfigs: nil,
		},
		{
			name:          "initial cluster configuration",
			clusterConfig: isoClusterConfig,
			expectedNodeConfigs: []*v1alpha1.IsovalentBGPNodeConfig{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-1",
					},
					Spec: v1alpha1.IsovalentBGPNodeSpec{
						BGPInstances: []v1alpha1.IsovalentBGPNodeInstance{isoNodeConfigSpec},
					},
				},
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-2",
					},
					Spec: v1alpha1.IsovalentBGPNodeSpec{
						BGPInstances: []v1alpha1.IsovalentBGPNodeInstance{isoNodeConfigSpec},
					},
				},
			},
		},
		{
			name:          "add new node",
			clusterConfig: isoClusterConfig,
			nodes: []*cilium_v2.CiliumNode{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-3",
						Labels: map[string]string{
							"bgp": "rack1",
						},
					},
				},
			},
			expectedNodeConfigs: []*v1alpha1.IsovalentBGPNodeConfig{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-1",
					},
					Spec: v1alpha1.IsovalentBGPNodeSpec{
						BGPInstances: []v1alpha1.IsovalentBGPNodeInstance{isoNodeConfigSpec},
					},
				},
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-2",
					},
					Spec: v1alpha1.IsovalentBGPNodeSpec{
						BGPInstances: []v1alpha1.IsovalentBGPNodeInstance{isoNodeConfigSpec},
					},
				},
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-3",
					},
					Spec: v1alpha1.IsovalentBGPNodeSpec{
						BGPInstances: []v1alpha1.IsovalentBGPNodeInstance{isoNodeConfigSpec},
					},
				},
			},
		},
		{
			name:          "add node config override",
			clusterConfig: isoClusterConfig,
			nodeConfigOverride: &v1alpha1.IsovalentBGPNodeConfigOverride{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: "node-3",
				},
				Spec: v1alpha1.IsovalentBGPNodeConfigOverrideSpec{
					BGPInstances: []v1alpha1.IsovalentBGPNodeConfigInstanceOverride{
						{
							Name:          "instance-1",
							SRv6Responder: ptr.To[bool](true),
						},
					},
				},
			},
			nodes: []*cilium_v2.CiliumNode{},
			expectedNodeConfigs: []*v1alpha1.IsovalentBGPNodeConfig{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-1",
					},
					Spec: v1alpha1.IsovalentBGPNodeSpec{
						BGPInstances: []v1alpha1.IsovalentBGPNodeInstance{isoNodeConfigSpec},
					},
				},
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-2",
					},
					Spec: v1alpha1.IsovalentBGPNodeSpec{
						BGPInstances: []v1alpha1.IsovalentBGPNodeInstance{isoNodeConfigSpec},
					},
				},
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-3",
					},
					Spec: v1alpha1.IsovalentBGPNodeSpec{
						BGPInstances: []v1alpha1.IsovalentBGPNodeInstance{isoNodeConfigSpecWithResponder()},
					},
				},
			},
		},
		{
			name:          "remove node labels",
			clusterConfig: isoClusterConfig,
			nodes: []*cilium_v2.CiliumNode{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-1",
					},
				},
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-2",
					},
				},
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node-3",
					},
				},
			},
			expectedNodeConfigs: nil,
			expectedTrueConditions: []string{
				v1alpha1.BGPClusterConfigConditionNoMatchingNode,
			},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()

	f, watchersReady := newFixture(ctx, require.New(t))

	tlog := hivetest.Logger(t)
	f.hive.Start(tlog, ctx)
	defer f.hive.Stop(tlog, ctx)

	watchersReady()

	for _, step := range steps {
		t.Run(step.name, func(t *testing.T) {
			req := require.New(t)

			// setup nodes
			for _, node := range step.nodes {
				upsertNode(req, ctx, f, node)
			}

			// upsert BGP cluster config
			upsertIsoBGPCC(req, ctx, f, step.clusterConfig)

			// upsert BGP node config override
			upsertIsoBGPNodeConfigOR(req, ctx, f, step.nodeConfigOverride)

			// validate node configs
			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				runningIsoNodeConfigs, err := f.isoBGPNodeConfClient.List(ctx, meta_v1.ListOptions{})
				if err != nil {
					assert.NoError(c, err)
					return
				}
				assert.Equal(c, len(step.expectedNodeConfigs), len(runningIsoNodeConfigs.Items))

				for _, expectedNodeConfig := range step.expectedNodeConfigs {
					isoNodeConfig, err := f.isoBGPNodeConfClient.Get(ctx, expectedNodeConfig.Name, meta_v1.GetOptions{})
					if err != nil {
						assert.NoError(c, err)
						return
					}
					assert.Equal(c, expectedNodeConfig.Spec, isoNodeConfig.Spec)
				}

			}, TestTimeout, 50*time.Millisecond)

			// Condition checks. Assuming the cluster config already exists on the API server.
			if len(step.expectedTrueConditions) > 0 {
				bgpcc, err := f.isoClusterClient.Get(ctx, isoClusterConfig.Name, meta_v1.GetOptions{})
				req.NoError(err)

				trueConditions := sets.New[string]()
				for _, cond := range bgpcc.Status.Conditions {
					trueConditions.Insert(cond.Type)
				}

				for _, cond := range step.expectedTrueConditions {
					req.True(trueConditions.Has(cond), "Condition missing or not true: %s", cond)
				}
			}
		})
	}
}

func TestClusterConfigConditions(t *testing.T) {
	clusterConfigName := "cluster-config0"
	peerConfigName := "peer-config0"

	node := cilium_v2.CiliumNode{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "node-1",
			Labels: map[string]string{
				"bgp": "rack1",
			},
		},
	}

	peerConfig := v1alpha1.IsovalentBGPPeerConfig{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: peerConfigName,
		},
	}

	tests := []struct {
		name                    string
		clusterConfig           *v1alpha1.IsovalentBGPClusterConfig
		expectedConditionStatus map[string]meta_v1.ConditionStatus
	}{
		{
			name: "NoMatchingNode False",
			clusterConfig: &v1alpha1.IsovalentBGPClusterConfig{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: clusterConfigName,
				},
				Spec: v1alpha1.IsovalentBGPClusterConfigSpec{
					NodeSelector: &slim_meta_v1.LabelSelector{
						MatchLabels: map[string]string{
							"bgp": "rack1",
						},
					},
				},
			},
			expectedConditionStatus: map[string]meta_v1.ConditionStatus{
				v1alpha1.BGPClusterConfigConditionNoMatchingNode: meta_v1.ConditionFalse,
			},
		},
		{
			name: "NoMatchingNode False Nil Selector",
			clusterConfig: &v1alpha1.IsovalentBGPClusterConfig{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: clusterConfigName,
				},
				Spec: v1alpha1.IsovalentBGPClusterConfigSpec{
					NodeSelector: nil,
				},
			},
			expectedConditionStatus: map[string]meta_v1.ConditionStatus{
				v1alpha1.BGPClusterConfigConditionNoMatchingNode: meta_v1.ConditionFalse,
			},
		},
		{
			name: "NoMatchingNode True",
			clusterConfig: &v1alpha1.IsovalentBGPClusterConfig{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: clusterConfigName,
				},
				Spec: v1alpha1.IsovalentBGPClusterConfigSpec{
					NodeSelector: &slim_meta_v1.LabelSelector{
						MatchLabels: map[string]string{
							"bgp": "rack2",
						},
					},
				},
			},
			expectedConditionStatus: map[string]meta_v1.ConditionStatus{
				v1alpha1.BGPClusterConfigConditionNoMatchingNode: meta_v1.ConditionTrue,
			},
		},
		{
			name: "MissingPeerConfig False",
			clusterConfig: &v1alpha1.IsovalentBGPClusterConfig{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: clusterConfigName,
				},
				Spec: v1alpha1.IsovalentBGPClusterConfigSpec{
					NodeSelector: nil,
					BGPInstances: []v1alpha1.IsovalentBGPInstance{
						{
							Peers: []v1alpha1.IsovalentBGPPeer{
								{
									Name: "peer0",
									PeerConfigRef: &v1alpha1.PeerConfigReference{
										Name: peerConfigName,
									},
								},
							},
						},
					},
				},
			},
			expectedConditionStatus: map[string]meta_v1.ConditionStatus{
				v1alpha1.BGPClusterConfigConditionMissingPeerConfigs: meta_v1.ConditionFalse,
			},
		},
		{
			name: "MissingPeerConfig False nil PeerConfigRef",
			clusterConfig: &v1alpha1.IsovalentBGPClusterConfig{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: clusterConfigName,
				},
				Spec: v1alpha1.IsovalentBGPClusterConfigSpec{
					NodeSelector: nil,
					BGPInstances: []v1alpha1.IsovalentBGPInstance{
						{
							Peers: []v1alpha1.IsovalentBGPPeer{
								{
									Name: "peer0",
								},
							},
						},
					},
				},
			},
			expectedConditionStatus: map[string]meta_v1.ConditionStatus{
				v1alpha1.BGPClusterConfigConditionMissingPeerConfigs: meta_v1.ConditionFalse,
			},
		},
		{
			name: "MissingPeerConfig True",
			clusterConfig: &v1alpha1.IsovalentBGPClusterConfig{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: clusterConfigName,
				},
				Spec: v1alpha1.IsovalentBGPClusterConfigSpec{
					NodeSelector: nil,
					BGPInstances: []v1alpha1.IsovalentBGPInstance{
						{
							Peers: []v1alpha1.IsovalentBGPPeer{
								{
									Name: "peer0",
									PeerConfigRef: &v1alpha1.PeerConfigReference{
										Name: peerConfigName + "-foo",
									},
								},
							},
						},
					},
				},
			},
			expectedConditionStatus: map[string]meta_v1.ConditionStatus{
				v1alpha1.BGPClusterConfigConditionMissingPeerConfigs: meta_v1.ConditionTrue,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := require.New(t)

			ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
			defer cancel()

			f, watchersReady := newFixture(ctx, require.New(t))

			tlog := hivetest.Logger(t)
			f.hive.Start(tlog, ctx)
			defer f.hive.Stop(tlog, ctx)

			watchersReady()

			// Setup resources
			upsertNode(req, ctx, f, &node)
			upsertIsoBGPCC(req, ctx, f, tt.clusterConfig)
			upsertIsoBGPPC(req, ctx, f, &peerConfig)

			require.EventuallyWithT(t, func(ct *assert.CollectT) {
				// Check conditions
				cc, err := f.isoClusterClient.Get(ctx, clusterConfigName, meta_v1.GetOptions{})
				if !assert.NoError(ct, err, "Cannot get cluster config") {
					return
				}

				// Check if the expected condition exists and has an intended values
				missing := maps.Clone(tt.expectedConditionStatus)
				for condType, status := range tt.expectedConditionStatus {
					for _, cond := range cc.Status.Conditions {
						if cond.Type == condType {
							if !assert.Equal(ct, status, cond.Status) {
								return
							}
							delete(missing, cond.Type)
						}
					}
				}

				assert.Empty(ct, missing, "Missing conditions: %v", missing)
			}, time.Second*3, time.Millisecond*100)
		})
	}
}

func upsertNode(req *require.Assertions, ctx context.Context, f *fixture, node *cilium_v2.CiliumNode) {
	_, err := f.nodeClient.Get(ctx, node.Name, meta_v1.GetOptions{})
	if err != nil && k8sErrors.IsNotFound(err) {
		_, err = f.nodeClient.Create(ctx, node, meta_v1.CreateOptions{})
	} else if err != nil {
		req.Fail(err.Error())
	} else {
		_, err = f.nodeClient.Update(ctx, node, meta_v1.UpdateOptions{})
	}
	req.NoError(err)
}
