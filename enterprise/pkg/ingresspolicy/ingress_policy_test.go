//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package ingresspolicy

import (
	"context"
	"log/slog"
	"sync"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/container/set"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache/types"
	ciliumio "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	policyUtils "github.com/cilium/cilium/pkg/policy/utils"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
	testpolicy "github.com/cilium/cilium/pkg/testutils/policy"
)

func newMockPolicyRepository(t *testing.T) *policy.Repository {
	repo := policy.NewPolicyRepository(hivetest.Logger(t), nil, nil, nil, nil, testpolicy.NewPolicyMetricsNoop())
	repo.GetSelectorCache().SetLocalIdentityNotifier(testidentity.NewDummyIdentityNotifier())
	return repo
}

var identityMap = map[identity.NumericIdentity]labels.LabelArray{
	16777216: {
		labels.NewLabel(LabelNameIngress, "cec", LabelSourceIngress),
		labels.NewLabel(ciliumio.PodNamespaceLabel, "default", labels.LabelSourceK8s),
		labels.NewLabel(labels.IDNameIngress, "", labels.LabelSourceReserved),
	},
}

func Test_ingressPolicyManager_EnsureIngressPolicy(t *testing.T) {
	err := labelsfilter.ParseLabelPrefixCfg(hivetest.Logger(t), nil, nil, "")
	require.NoError(t, err)

	t.Run("no associated identity", func(t *testing.T) {
		mockSDSServer := newMockXdsServer()
		m := &ingressPolicyManager{
			logger:                 hivetest.Logger(t),
			cacheIdentityAllocator: testidentity.NewMockIdentityAllocator(map[identity.NumericIdentity]labels.LabelArray{}),
			policyRepository:       newMockPolicyRepository(t),
			xdsServer:              mockSDSServer,
			ingressIdentities:      make(map[resource.Key]*identity.Identity),
			ingressPolicies:        make(map[resource.Key]*IngressPolicy),
		}

		err := m.EnsureIngressPolicy(context.Background(), resource.Key{Name: "cec", Namespace: "default"}, nil)
		require.NoError(t, err)
		require.Len(t, m.cacheIdentityAllocator.GetIdentities(), 1)
		require.Equal(t, 1, mockSDSServer.nrOfUpdates)
		require.Contains(t, mockSDSServer.policies, "default/cec")

		policy := m.ingressPolicies[resource.Key{Name: "cec", Namespace: "default"}]
		require.NotNil(t, policy)
		require.False(t, policy.desiredPolicy.VersionHandle.IsValid())
	})

	t.Run("successfully reconcile policy with existing identity", func(t *testing.T) {
		mockSDSServer := newMockXdsServer()
		m := &ingressPolicyManager{
			logger:                 hivetest.Logger(t),
			cacheIdentityAllocator: testidentity.NewMockIdentityAllocator(identityMap),
			policyRepository:       newMockPolicyRepository(t),
			xdsServer:              mockSDSServer,

			ingressIdentities: make(map[resource.Key]*identity.Identity),
			ingressPolicies:   make(map[resource.Key]*IngressPolicy),
		}

		err := m.EnsureIngressPolicy(context.Background(), resource.Key{Name: "cec", Namespace: "default"}, nil)
		require.NoError(t, err)
		require.Len(t, m.cacheIdentityAllocator.GetIdentities(), 1)
		require.Equal(t, 1, mockSDSServer.nrOfUpdates)
		require.Contains(t, mockSDSServer.policies, "default/cec")

		policy := m.ingressPolicies[resource.Key{Name: "cec", Namespace: "default"}]
		require.NotNil(t, policy)
		require.False(t, policy.desiredPolicy.VersionHandle.IsValid())
	})

	t.Run("successfully reconcile policy with different identity", func(t *testing.T) {
		mockSDSServer := newMockXdsServer()
		m := &ingressPolicyManager{
			logger:                 hivetest.Logger(t),
			cacheIdentityAllocator: testidentity.NewMockIdentityAllocator(identityMap),
			policyRepository:       newMockPolicyRepository(t),
			xdsServer:              mockSDSServer,

			ingressIdentities: make(map[resource.Key]*identity.Identity),
			ingressPolicies: map[resource.Key]*IngressPolicy{
				{Name: "cec", Namespace: "default"}: {id: 16777217}, // other identity allocated before
			},
		}

		err := m.EnsureIngressPolicy(context.Background(), resource.Key{Name: "cec", Namespace: "default"}, map[string]string{
			"foo": "bar",
		})
		require.NoError(t, err)
		require.Len(t, m.cacheIdentityAllocator.GetIdentities(), 1)
		require.Equal(t, 1, mockSDSServer.nrOfUpdates)
		require.Equal(t, 1, mockSDSServer.nrOfDeletions)
		require.Contains(t, mockSDSServer.policies, "default/cec")

		policy := m.ingressPolicies[resource.Key{Name: "cec", Namespace: "default"}]
		require.NotNil(t, policy)
		require.False(t, policy.desiredPolicy.VersionHandle.IsValid())
	})
}

func Test_ingressPolicyManager_DeleteIngressPolicy(t *testing.T) {
	err := labelsfilter.ParseLabelPrefixCfg(hivetest.Logger(t), nil, nil, "")
	require.NoError(t, err)

	t.Run("no associated identity", func(t *testing.T) {
		m := &ingressPolicyManager{
			logger:                 hivetest.Logger(t),
			cacheIdentityAllocator: testidentity.NewMockIdentityAllocator(map[identity.NumericIdentity]labels.LabelArray{}),
			policyRepository:       newMockPolicyRepository(t),
			xdsServer:              newMockXdsServer(),
			ingressIdentities:      make(map[resource.Key]*identity.Identity),
			ingressPolicies:        make(map[resource.Key]*IngressPolicy),
		}

		err := m.DeleteIngressPolicy(context.Background(), resource.Key{Name: "cec", Namespace: "default"}, nil)
		require.NoError(t, err)
	})

	t.Run("successfully remove existing policy", func(t *testing.T) {
		mockSDSServer := newMockXdsServer()
		m := &ingressPolicyManager{
			logger:                 hivetest.Logger(t),
			cacheIdentityAllocator: testidentity.NewMockIdentityAllocator(identityMap),
			policyRepository:       newMockPolicyRepository(t),
			xdsServer:              mockSDSServer,

			ingressIdentities: make(map[resource.Key]*identity.Identity),
			ingressPolicies:   make(map[resource.Key]*IngressPolicy),
		}

		err := m.EnsureIngressPolicy(context.Background(), resource.Key{Name: "cec", Namespace: "default"}, nil)
		require.NoError(t, err)
		require.Equal(t, 1, mockSDSServer.nrOfUpdates)
		require.Contains(t, mockSDSServer.policies, "default/cec")

		policy := m.ingressPolicies[resource.Key{Name: "cec", Namespace: "default"}]
		require.NotNil(t, policy)
		require.False(t, policy.desiredPolicy.VersionHandle.IsValid())

		err = m.DeleteIngressPolicy(context.Background(), resource.Key{Name: "cec", Namespace: "default"}, nil)
		require.NoError(t, err)
		require.Equal(t, 1, mockSDSServer.nrOfDeletions)
		require.Empty(t, mockSDSServer.policies)

		policy = m.ingressPolicies[resource.Key{Name: "cec", Namespace: "default"}]
		require.Nil(t, policy)
	})
}

func Test_ingressPolicyManager_IncrementalPolicyUpdate(t *testing.T) {
	err := labelsfilter.ParseLabelPrefixCfg(hivetest.Logger(t), nil, nil, "")
	require.NoError(t, err)

	t.Run("successfully reconcile policy with existing identity", func(t *testing.T) {
		mockSDSServer := newMockXdsServer()
		m := &ingressPolicyManager{
			logger:                 hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug)),
			cacheIdentityAllocator: testidentity.NewMockIdentityAllocator(identityMap),
			policyRepository:       newMockPolicyRepository(t),
			xdsServer:              mockSDSServer,

			ingressIdentities: make(map[resource.Key]*identity.Identity),
			ingressPolicies:   make(map[resource.Key]*IngressPolicy),
		}

		repo := m.policyRepository
		sc := repo.GetSelectorCache()

		resourceLabels := map[string]string{"id": "foo"}
		err := m.EnsureIngressPolicy(context.Background(), resource.Key{Name: "cec", Namespace: "default"}, resourceLabels)
		require.NoError(t, err)
		require.Len(t, m.cacheIdentityAllocator.GetIdentities(), 1)

		nid := identity.NumericIdentity(m.cacheIdentityAllocator.GetIdentities()[0].ID)
		require.NotZero(t, nid)
		idMap := m.cacheIdentityAllocator.GetIdentityCache()
		require.NotNil(t, idMap)
		idLabels := idMap[nid]
		require.NotEmpty(t, idLabels)

		require.Equal(t, 1, mockSDSServer.nrOfUpdates)
		require.Contains(t, mockSDSServer.policies, "default/cec")

		policy := m.ingressPolicies[resource.Key{Name: "cec", Namespace: "default"}]
		require.NotNil(t, policy)
		require.False(t, policy.desiredPolicy.VersionHandle.IsValid())

		// add a policy applicable to "default/cec"
		selFoo := api.NewESFromLabels(labels.ParseSelectLabel("k8s:id=foo"))
		ruleLabel := labels.ParseLabelArray("rule-foo-allow-port-80")

		rule := &api.Rule{
			EndpointSelector: selFoo,
			Labels:           ruleLabel,
			Ingress: []api.IngressRule{
				{
					IngressCommonRule: api.IngressCommonRule{
						FromEndpoints: []api.EndpointSelector{
							{
								LabelSelector: &slim_metav1.LabelSelector{
									MatchLabels: map[string]string{
										"app": "test",
									},
								},
							},
						},
					},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
						Rules: &api.L7Rules{},
					}},
				},
			},
		}

		rules := api.Rules{rule}
		for i := range rules {
			err := rules[i].Sanitize()
			require.NoError(t, err)
		}

		rID1 := types.NewResourceID(types.ResourceKindCNP, "default", "my-policy")
		affectedIDs, rev, oldRuleCnt := repo.ReplaceByResource(policyUtils.RulesToPolicyEntries(rules), rID1)
		require.False(t, affectedIDs.Empty())
		require.True(t, affectedIDs.Has(nid))
		require.Equal(t, uint64(2), rev)
		require.Zero(t, oldRuleCnt)

		idSet := set.NewSet(nid)

		// trigger policy update for a new policy
		m.policyUpdateCallback(&idSet, false)
		require.Equal(t, 2, mockSDSServer.nrOfUpdates)

		policy = m.ingressPolicies[resource.Key{Name: "cec", Namespace: "default"}]
		require.NotNil(t, policy)
		require.False(t, policy.desiredPolicy.VersionHandle.IsValid())

		// make sure the to-be-added identity is not found before incremental update
		found := false
		for k, v := range policy.desiredPolicy.UpdatedMap(nil) {
			if k.Identity == identity.NumericIdentity(1234) && k.DestPort == 80 && !v.IsDeny() {
				found = true
			}
		}
		require.False(t, found)

		// Add some identities to the selector cache
		wg := &sync.WaitGroup{}
		sc.UpdateIdentities(identity.IdentityMap{
			1234: labels.Labels{"app": labels.NewLabel("app", "test", labels.LabelSourceK8s),
				ciliumio.PodNamespaceLabel: labels.NewLabel(ciliumio.PodNamespaceLabel, "default", labels.LabelSourceK8s)}.LabelArray(),
			2345: labels.Labels{"app": labels.NewLabel("app", "test2", labels.LabelSourceK8s)}.LabelArray(),
		}, nil, wg)
		wg.Wait()

		// trigger incremental policy update for the new IDs
		m.policyUpdateCallback(&idSet, true)
		require.Equal(t, 3, mockSDSServer.nrOfUpdates)

		policy = m.ingressPolicies[resource.Key{Name: "cec", Namespace: "default"}]
		require.NotNil(t, policy)
		require.False(t, policy.desiredPolicy.VersionHandle.IsValid())

		found = false
		for k, v := range policy.desiredPolicy.UpdatedMap(nil) {
			if k.Identity == identity.NumericIdentity(1234) && k.DestPort == 80 && !v.IsDeny() {
				found = true
			}
		}
		require.True(t, found)
	})
}
