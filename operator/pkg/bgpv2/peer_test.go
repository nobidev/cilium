// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bgpv2

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/meta"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/health"
	healthTypes "github.com/cilium/cilium/pkg/hive/health/types"
	"github.com/cilium/cilium/pkg/k8s"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8s_client "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_core_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_meta_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/option"
)

type peerConfigTestFixture struct {
	hive               *hive.Hive
	fakeClientSet      *k8s_client.FakeClientset
	peerConfigResource resource.Resource[*v2.CiliumBGPPeerConfig]

	db          *statedb.DB
	healthTable statedb.Table[healthTypes.Status]
}

func newPeerConfigTestFixture(t *testing.T, ctx context.Context, enableStatusReport bool) *peerConfigTestFixture {
	f := &peerConfigTestFixture{}

	hive := hive.New(
		cell.Module("test", "test",
			cell.Provide(
				k8s_client.NewFakeClientset,
				newSecretResource,
				k8s.CiliumBGPPeerConfigResource,
				func() *option.DaemonConfig {
					return &option.DaemonConfig{
						EnableBGPControlPlane:             true,
						BGPSecretsNamespace:               "kube-system",
						EnableBGPControlPlaneStatusReport: enableStatusReport,
					}
				},
			),
			cell.Invoke(
				registerPeerConfigStatusReconciler,
				func(
					fcs *k8s_client.FakeClientset,
					p resource.Resource[*v2.CiliumBGPPeerConfig],
					db *statedb.DB,
					h statedb.Table[healthTypes.Status],
				) {
					f.fakeClientSet = fcs
					f.peerConfigResource = p
					f.db = db
					f.healthTable = h
				},
			),
		),
	)
	f.hive = hive

	return f
}

func TestMissingAuthSecretCondition(t *testing.T) {
	secretName := "auth-secret"
	secretNamespace := "kube-system"
	peerConfigName := "peer-config0"

	secret := &slim_core_v1.Secret{
		ObjectMeta: slim_meta_v1.ObjectMeta{
			Name:      secretName,
			Namespace: secretNamespace,
		},
	}

	tests := []struct {
		name          string
		peerConfig    *v2.CiliumBGPPeerConfig
		expectedState meta_v1.ConditionStatus
	}{
		{
			name: "MissingAuthSecret False",
			peerConfig: &v2.CiliumBGPPeerConfig{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: peerConfigName,
				},
				Spec: v2.CiliumBGPPeerConfigSpec{
					AuthSecretRef: ptr.To(secretName),
				},
			},
			expectedState: meta_v1.ConditionFalse,
		},
		{
			name: "MissingAuthSecret False nil AuthSecretRef",
			peerConfig: &v2.CiliumBGPPeerConfig{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: peerConfigName,
				},
				Spec: v2.CiliumBGPPeerConfigSpec{},
			},
			expectedState: meta_v1.ConditionFalse,
		},
		{
			name: "MissingAuthSecret True",
			peerConfig: &v2.CiliumBGPPeerConfig{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: peerConfigName,
				},
				Spec: v2.CiliumBGPPeerConfigSpec{
					AuthSecretRef: ptr.To(secretName + "foo"),
				},
			},
			expectedState: meta_v1.ConditionTrue,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), TestTimeout)
			t.Cleanup(func() {
				cancel()
			})

			f := newPeerConfigTestFixture(t, ctx, true)

			f.hive.Start(slog.Default(), ctx)
			t.Cleanup(func() {
				f.hive.Stop(slog.Default(), ctx)
			})

			_, err := f.fakeClientSet.CiliumFakeClientset.CiliumV2().CiliumBGPPeerConfigs().Create(
				ctx, tt.peerConfig, meta_v1.CreateOptions{},
			)
			require.NoError(t, err)

			_, err = f.fakeClientSet.SlimFakeClientset.CoreV1().Secrets(secretNamespace).Create(
				ctx, secret, meta_v1.CreateOptions{},
			)
			require.NoError(t, err)

			peerConfigStore, err := f.peerConfigResource.Store(ctx)
			require.NoError(t, err)

			require.EventuallyWithT(t, func(ct *assert.CollectT) {
				pc, exists, err := peerConfigStore.GetByKey(resource.Key{
					Name: peerConfigName,
				})
				if !assert.NoError(ct, err, "Failed to get peer config") {
					return
				}
				if !assert.True(ct, exists, "Peer config not found") {
					return
				}
				cond := meta.FindStatusCondition(
					pc.Status.Conditions,
					v2.BGPPeerConfigConditionMissingAuthSecret,
				)
				if !assert.NotNil(ct, cond, "Condition not found") {
					return
				}
				assert.Equal(ct, tt.expectedState, cond.Status, "Unexpected condition status")
			}, time.Second*3, time.Millisecond*100)
		})
	}
}

func TestDisablePeerConfigStatusReport(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), TestTimeout)
	t.Cleanup(func() {
		cancel()
	})

	f := newPeerConfigTestFixture(t, ctx, false)

	logger := hivetest.Logger(t)

	f.hive.Start(logger, ctx)
	t.Cleanup(func() {
		f.hive.Stop(logger, ctx)
	})

	peerConfig := &v2.CiliumBGPPeerConfig{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "config0",
		},
		Spec: v2.CiliumBGPPeerConfigSpec{
			AuthSecretRef: ptr.To("secret0"),
		},
		Status: v2.CiliumBGPPeerConfigStatus{
			Conditions: []meta_v1.Condition{},
		},
	}

	// Fill with all known conditions
	for _, cond := range v2.AllBGPPeerConfigConditions {
		peerConfig.Status.Conditions = append(peerConfig.Status.Conditions, meta_v1.Condition{
			Type: cond,
		})
	}

	_, err := f.fakeClientSet.CiliumFakeClientset.CiliumV2().CiliumBGPPeerConfigs().Create(
		ctx, peerConfig, meta_v1.CreateOptions{},
	)
	require.NoError(t, err)

	peerConfigStore, err := f.peerConfigResource.Store(ctx)
	require.NoError(t, err)

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		pc, exists, err := peerConfigStore.GetByKey(resource.Key{
			Name: peerConfig.Name,
		})
		if !assert.NoError(ct, err, "Failed to get peer config") {
			return
		}
		if !assert.True(ct, exists, "Peer config not found") {
			return
		}
		assert.Empty(ct, pc.Status.Conditions, "Conditions are not cleared")

		rtxn := f.db.ReadTxn()

		o, _, found := f.healthTable.Get(rtxn, health.PrimaryIndex.Query(healthTypes.HealthID("test.job-cleanup-peer-config-status")))
		if !assert.True(ct, found, "Health status for the job is not found") {
			return
		}

		assert.Equal(ct, healthTypes.Level(healthTypes.LevelStopped), o.Level)
		assert.Equal(ct, "Cleanup job is done successfully", o.Message)
	}, time.Second*3, time.Millisecond*100)
}
