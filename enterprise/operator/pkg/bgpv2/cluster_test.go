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
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/uuid"
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

	f, watchersReady := newFixture(ctx, require.New(t), fixtureConfig{enableStatusReport: true})

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
				assert.EventuallyWithT(t, func(c *assert.CollectT) {
					bgpcc, err := f.isoClusterClient.Get(ctx, isoClusterConfig.Name, meta_v1.GetOptions{})
					if err != nil {
						assert.NoError(c, err)
						return
					}

					trueConditions := sets.New[string]()
					for _, cond := range bgpcc.Status.Conditions {
						trueConditions.Insert(cond.Type)
					}

					for _, cond := range step.expectedTrueConditions {
						assert.True(c, trueConditions.Has(cond), "Condition missing or not true: %s", cond)
					}
				}, TestTimeout, 50*time.Millisecond)
			}
		})
	}
}

func TestClusterConfigConditions(t *testing.T) {
	clusterConfigName := "cluster-config0"
	peerConfigName := "peer-config0"
	vrfName := "vrf0"
	bgpVrfConfigName := "vrf0-bgp-config"

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

	vrf := v1alpha1.IsovalentVRF{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: vrfName,
		},
	}

	bgpVrfConfig := v1alpha1.IsovalentBGPVRFConfig{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: bgpVrfConfigName,
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
		{
			name: "MissingVRF and MissingVRFConfig False",
			clusterConfig: &v1alpha1.IsovalentBGPClusterConfig{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: clusterConfigName,
				},
				Spec: v1alpha1.IsovalentBGPClusterConfigSpec{
					BGPInstances: []v1alpha1.IsovalentBGPInstance{
						{
							VRFs: []v1alpha1.BGPVRF{
								{
									VRFRef:    vrfName,
									ConfigRef: ptr.To[string](bgpVrfConfigName),
								},
							},
						},
					},
				},
			},
			expectedConditionStatus: map[string]meta_v1.ConditionStatus{
				v1alpha1.BGPClusterConfigConditionMissingVRFs:       meta_v1.ConditionFalse,
				v1alpha1.BGPClusterConfigConditionMissingVRFConfigs: meta_v1.ConditionFalse,
			},
		},
		{
			name: "MissingVRF True, MissingVRFConfig False",
			clusterConfig: &v1alpha1.IsovalentBGPClusterConfig{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: clusterConfigName,
				},
				Spec: v1alpha1.IsovalentBGPClusterConfigSpec{
					BGPInstances: []v1alpha1.IsovalentBGPInstance{
						{
							VRFs: []v1alpha1.BGPVRF{
								{
									VRFRef:    "foo",
									ConfigRef: ptr.To[string](bgpVrfConfigName),
								},
							},
						},
					},
				},
			},
			expectedConditionStatus: map[string]meta_v1.ConditionStatus{
				v1alpha1.BGPClusterConfigConditionMissingVRFs:       meta_v1.ConditionTrue,
				v1alpha1.BGPClusterConfigConditionMissingVRFConfigs: meta_v1.ConditionFalse,
			},
		},
		{
			name: "MissingVRF True, MissingVRFConfig True",
			clusterConfig: &v1alpha1.IsovalentBGPClusterConfig{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: clusterConfigName,
				},
				Spec: v1alpha1.IsovalentBGPClusterConfigSpec{
					BGPInstances: []v1alpha1.IsovalentBGPInstance{
						{
							VRFs: []v1alpha1.BGPVRF{
								{
									VRFRef:    "foo",
									ConfigRef: ptr.To[string]("bar"),
								},
							},
						},
					},
				},
			},
			expectedConditionStatus: map[string]meta_v1.ConditionStatus{
				v1alpha1.BGPClusterConfigConditionMissingVRFs:       meta_v1.ConditionTrue,
				v1alpha1.BGPClusterConfigConditionMissingVRFConfigs: meta_v1.ConditionTrue,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := require.New(t)

			ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
			defer cancel()

			f, watchersReady := newFixture(ctx, require.New(t), fixtureConfig{enableStatusReport: true})

			tlog := hivetest.Logger(t)
			f.hive.Start(tlog, ctx)
			defer f.hive.Stop(tlog, ctx)

			watchersReady()

			// Setup resources
			upsertNode(req, ctx, f, &node)
			upsertIsoBGPCC(req, ctx, f, tt.clusterConfig)
			upsertIsoBGPPC(req, ctx, f, &peerConfig)
			upsertIsoVrf(req, ctx, f, &vrf)
			upsertIsoBGPVrfConfig(req, ctx, f, &bgpVrfConfig)

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

func TestConflictingClusterConfigCondition(t *testing.T) {
	nodes := []*cilium_v2.CiliumNode{
		{
			ObjectMeta: meta_v1.ObjectMeta{
				Name: "node-0",
				Labels: map[string]string{
					"rack":             "rack0",
					"complete-overlap": "true",
					"partial-overlap0": "true",
				},
			},
		},
		{
			ObjectMeta: meta_v1.ObjectMeta{
				Name: "node-1",
				Labels: map[string]string{
					"rack":             "rack1",
					"complete-overlap": "true",
					"partial-overlap0": "true",
					"partial-overlap1": "true",
				},
			},
		},
		{
			ObjectMeta: meta_v1.ObjectMeta{
				Name: "node-2",
				Labels: map[string]string{
					"rack":             "rack2",
					"complete-overlap": "true",
					"partial-overlap1": "true",
				},
			},
		},
	}

	type clusterConfig struct {
		name     string
		selector *slim_meta_v1.LabelSelector
	}

	// sortRelation sorts the relation in a deterministic way.
	sortRelation := func(a, b [2]string) int {
		slices.Sort(a[:])
		slices.Sort(b[:])
		return strings.Compare(a[0]+a[1], b[0]+b[1])
	}

	tests := []struct {
		name           string
		clusterConfigs []clusterConfig

		// conflictingRelations is a list of pairs of cluster config
		// names that are expected to have a conflict.
		conflictingRelations [][2]string
	}{
		{
			name: "ConflictingClusterConfig False",
			clusterConfigs: []clusterConfig{
				{
					name: "cluster-config-0",
					selector: &slim_meta_v1.LabelSelector{
						MatchLabels: map[string]string{
							"rack": "rack0",
						},
					},
				},
				{
					name: "cluster-config-1",
					selector: &slim_meta_v1.LabelSelector{
						MatchLabels: map[string]string{
							"rack": "rack1",
						},
					},
				},
				{
					name: "cluster-config-2",
					selector: &slim_meta_v1.LabelSelector{
						MatchLabels: map[string]string{
							"rack": "rack2",
						},
					},
				},
			},
			conflictingRelations: [][2]string{},
		},
		{
			name: "ConflictingClusterConfig True complete overlap",
			clusterConfigs: []clusterConfig{
				{
					name: "cluster-config-0",
					selector: &slim_meta_v1.LabelSelector{
						MatchLabels: map[string]string{
							"complete-overlap": "true",
						},
					},
				},
				{
					name: "cluster-config-1",
					selector: &slim_meta_v1.LabelSelector{
						MatchLabels: map[string]string{
							"complete-overlap": "true",
						},
					},
				},
			},
			conflictingRelations: [][2]string{
				{"cluster-config-0", "cluster-config-1"},
			},
		},
		{
			name: "ConflictingClusterConfig True complete overlap with nil",
			clusterConfigs: []clusterConfig{
				{
					name:     "cluster-config-0",
					selector: nil,
				},
				{
					name:     "cluster-config-1",
					selector: nil,
				},
			},
			conflictingRelations: [][2]string{
				{"cluster-config-0", "cluster-config-1"},
			},
		},
		{
			name: "ConflictingClusterConfig True partial overlap",
			clusterConfigs: []clusterConfig{
				{
					name: "cluster-config-0",
					selector: &slim_meta_v1.LabelSelector{
						MatchLabels: map[string]string{
							"partial-overlap0": "true",
						},
					},
				},
				{
					name: "cluster-config-1",
					selector: &slim_meta_v1.LabelSelector{
						MatchLabels: map[string]string{
							"partial-overlap1": "true",
						},
					},
				},
			},
			conflictingRelations: [][2]string{
				{"cluster-config-0", "cluster-config-1"},
			},
		},
		{
			name: "ConflictingClusterConfig True partial overlap of four configs",
			clusterConfigs: []clusterConfig{
				{
					name: "cluster-config-0",
					selector: &slim_meta_v1.LabelSelector{
						MatchLabels: map[string]string{
							"partial-overlap0": "true",
						},
					},
				},
				{
					name: "cluster-config-1",
					selector: &slim_meta_v1.LabelSelector{
						MatchLabels: map[string]string{
							"rack": "rack0",
						},
					},
				},
				{
					name: "cluster-config-2",
					selector: &slim_meta_v1.LabelSelector{
						MatchLabels: map[string]string{
							"rack": "rack1",
						},
					},
				},
				{
					name: "cluster-config-3",
					selector: &slim_meta_v1.LabelSelector{
						MatchLabels: map[string]string{
							"rack": "rack2",
						},
					},
				},
			},
			conflictingRelations: [][2]string{
				{"cluster-config-0", "cluster-config-1"},
				{"cluster-config-0", "cluster-config-2"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := require.New(t)

			ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
			defer cancel()

			f, watchersReady := newFixture(ctx, require.New(t), fixtureConfig{enableStatusReport: true})

			tlog := hivetest.Logger(t)
			f.hive.Start(tlog, ctx)
			defer f.hive.Stop(tlog, ctx)

			watchersReady()

			// Setup resources
			for _, node := range nodes {
				upsertNode(req, ctx, f, node)
			}

			for _, config := range tt.clusterConfigs {
				clusterConfig := &v1alpha1.IsovalentBGPClusterConfig{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: config.name,
						// Fake client doesn't set UID. Assign it manually.
						UID: uuid.NewUUID(),
					},
					Spec: v1alpha1.IsovalentBGPClusterConfigSpec{
						NodeSelector: config.selector,
						BGPInstances: []v1alpha1.IsovalentBGPInstance{
							{
								Peers: []v1alpha1.IsovalentBGPPeer{},
							},
						},
					},
				}
				upsertIsoBGPCC(req, ctx, f, clusterConfig)
			}

			require.EventuallyWithT(t, func(ct *assert.CollectT) {
				configs, err := f.isoClusterClient.List(ctx, meta_v1.ListOptions{})
				if !assert.NoError(ct, err, "Cannot list cluster configs") {
					return
				}

				// Here we collect all conflicting configs from all cluster configs.
				// Since we detect the conflict by checking the owner reference of
				// the node config, the cluster config observes the conflict depends
				// on the node config creation order. So we need to check all cluster
				// configs to get the entire view of the conflicts.
				conflictingRelations := [][2]string{}
				for _, config := range configs.Items {
					cond := meta.FindStatusCondition(
						config.Status.Conditions,
						v1alpha1.BGPClusterConfigConditionConflictingClusterConfigs,
					)
					if !assert.NotNil(ct, cond, "Condition not found") {
						return
					}

					if len(tt.conflictingRelations) == 0 {
						if !assert.Equal(ct, meta_v1.ConditionFalse, cond.Status, "Expected condition to be false") {
							return
						}
						return
					}

					if cond.Status == meta_v1.ConditionFalse {
						continue
					}

					expr, err := regexp.Compile(
						`Selecting the same node\(s\) with ClusterConfig\(s\): \[(.*)\]`,
					)
					if !assert.NoError(ct, err, "Error during regexp match") {
						return
					}

					match := expr.FindSubmatch([]byte(cond.Message))
					if !assert.Len(ct, match, 2, "Invalid number of match") {
						return
					}

					for _, conflictingConfig := range strings.Split(string(match[1]), " ") {
						relation := [2]string{config.Name, conflictingConfig}
						conflictingRelations = append(conflictingRelations, relation)
					}
				}

				// Short circuit if the number of conflict relations is not the same.
				if !assert.Len(ct, conflictingRelations, len(tt.conflictingRelations), "Exexpected number of conflicts") {
					return
				}

				// Sort the conflicting relations to make the comparison deterministic.
				slices.SortFunc(conflictingRelations, sortRelation)
				slices.SortFunc(tt.conflictingRelations, sortRelation)

				// Compare the conflicting relations.
				for i := 0; i < len(tt.conflictingRelations); i++ {
					if !assert.ElementsMatch(ct, tt.conflictingRelations[i], conflictingRelations[i]) {
						return
					}
				}
			}, time.Second*3, time.Millisecond*100)
		})
	}
}

func TestDisableClusterConfigStatusReport(t *testing.T) {
	req := require.New(t)
	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	t.Cleanup(func() {
		cancel()
	})

	f, ready := newFixture(ctx, req, fixtureConfig{enableStatusReport: false})

	logger := hivetest.Logger(t)

	f.hive.Start(logger, ctx)
	t.Cleanup(func() {
		f.hive.Stop(logger, ctx)
	})

	ready()

	clusterConfig := &v1alpha1.IsovalentBGPClusterConfig{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "config0",
		},
		Spec: v1alpha1.IsovalentBGPClusterConfigSpec{},
		Status: v1alpha1.IsovalentBGPClusterConfigStatus{
			Conditions: []meta_v1.Condition{},
		},
	}

	// Fill with all known conditions
	for _, cond := range v1alpha1.AllBGPClusterConfigConditions {
		clusterConfig.Status.Conditions = append(clusterConfig.Status.Conditions, meta_v1.Condition{
			Type: cond,
		})
	}
	upsertIsoBGPCC(req, ctx, f, clusterConfig)

	// Wait for status to be cleared
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		// Check conditions
		cc, err := f.isoClusterClient.Get(ctx, clusterConfig.Name, meta_v1.GetOptions{})
		if !assert.NoError(ct, err, "Cannot get cluster config") {
			return
		}

		assert.Empty(ct, cc.Status.Conditions, "Conditions are not cleared")
	}, time.Second*3, time.Millisecond*100)
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
