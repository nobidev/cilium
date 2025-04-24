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
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/identity"
	ciliumio "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
)

func newMockPolicyRepository(t *testing.T) *policy.Repository {
	repo := policy.NewPolicyRepository(hivetest.Logger(t), nil, nil, nil, nil, api.NewPolicyMetricsNoop())
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
	err := labelsfilter.ParseLabelPrefixCfg(nil, nil, "")
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
	})
}

func Test_ingressPolicyManager_DeleteIngressPolicy(t *testing.T) {
	err := labelsfilter.ParseLabelPrefixCfg(nil, nil, "")
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

		err = m.DeleteIngressPolicy(context.Background(), resource.Key{Name: "cec", Namespace: "default"}, nil)
		require.NoError(t, err)
		require.Equal(t, 1, mockSDSServer.nrOfDeletions)
		require.Empty(t, mockSDSServer.policies)
	})
}
