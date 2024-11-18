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
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/meta"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	slim_core_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_meta_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

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
		peerConfig    *v1alpha1.IsovalentBGPPeerConfig
		expectedState meta_v1.ConditionStatus
	}{
		{
			name: "MissingAuthSecret False",
			peerConfig: &v1alpha1.IsovalentBGPPeerConfig{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: peerConfigName,
				},
				Spec: v1alpha1.IsovalentBGPPeerConfigSpec{
					CiliumBGPPeerConfigSpec: v2alpha1.CiliumBGPPeerConfigSpec{
						AuthSecretRef: &secretName,
					},
				},
			},
			expectedState: meta_v1.ConditionFalse,
		},
		{
			name: "MissingAuthSecret False nil AuthSecretRef",
			peerConfig: &v1alpha1.IsovalentBGPPeerConfig{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: peerConfigName,
				},
				Spec: v1alpha1.IsovalentBGPPeerConfigSpec{},
			},
			expectedState: meta_v1.ConditionFalse,
		},
		{
			name: "MissingAuthSecret True",
			peerConfig: &v1alpha1.IsovalentBGPPeerConfig{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: peerConfigName,
				},
				Spec: v1alpha1.IsovalentBGPPeerConfigSpec{
					CiliumBGPPeerConfigSpec: v2alpha1.CiliumBGPPeerConfigSpec{
						AuthSecretRef: ptr.To(secretName + "foo"),
					},
				},
			},
			expectedState: meta_v1.ConditionTrue,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := require.New(t)
			testLogger := hivetest.Logger(t)

			ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
			t.Cleanup(func() {
				cancel()
			})

			f, ready := newFixture(ctx, req, fixtureConfig{})

			f.hive.Start(testLogger, ctx)
			t.Cleanup(func() {
				f.hive.Stop(testLogger, ctx)
			})

			ready()

			_, err := f.fakeClientSet.CiliumFakeClientset.IsovalentV1alpha1().IsovalentBGPPeerConfigs().Create(
				ctx, tt.peerConfig, meta_v1.CreateOptions{},
			)
			req.NoError(err)

			_, err = f.fakeClientSet.SlimFakeClientset.CoreV1().Secrets(secretNamespace).Create(
				ctx, secret, meta_v1.CreateOptions{},
			)
			req.NoError(err)

			req.EventuallyWithT(func(ct *assert.CollectT) {
				pc, err := f.isoPeerConfClient.Get(ctx, peerConfigName, meta_v1.GetOptions{})
				if !assert.NoError(ct, err, "Failed to get PeerConfig") {
					return
				}
				cond := meta.FindStatusCondition(
					pc.Status.Conditions,
					v1alpha1.BGPPeerConfigConditionMissingAuthSecret,
				)
				if !assert.NotNil(ct, cond, "Condition not found") {
					return
				}
				assert.Equal(ct, tt.expectedState, cond.Status, "Unexpected condition status")
			}, time.Second*3, time.Millisecond*100)
		})
	}
}

func TestMissingBFDProfileCondition(t *testing.T) {
	peerConfigName := "peer-config0"

	bfdProfile := &v1alpha1.IsovalentBFDProfile{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "bfd-profile0",
		},
	}

	tests := []struct {
		name          string
		peerConfig    *v1alpha1.IsovalentBGPPeerConfig
		expectedState meta_v1.ConditionStatus
		enableBFD     bool
	}{
		{
			name: "MissingBFDProfile False",
			peerConfig: &v1alpha1.IsovalentBGPPeerConfig{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: peerConfigName,
				},
				Spec: v1alpha1.IsovalentBGPPeerConfigSpec{
					BFDProfileRef: &bfdProfile.Name,
				},
			},
			expectedState: meta_v1.ConditionFalse,
			enableBFD:     true,
		},
		{
			name: "MissingBFDProfile False nil BFDProfileRef",
			peerConfig: &v1alpha1.IsovalentBGPPeerConfig{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: peerConfigName,
				},
				Spec: v1alpha1.IsovalentBGPPeerConfigSpec{},
			},
			expectedState: meta_v1.ConditionFalse,
			enableBFD:     true,
		},
		{
			name: "MissingBFDProfile True",
			peerConfig: &v1alpha1.IsovalentBGPPeerConfig{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: peerConfigName,
				},
				Spec: v1alpha1.IsovalentBGPPeerConfigSpec{
					BFDProfileRef: ptr.To(bfdProfile.Name + "foo"),
				},
			},
			expectedState: meta_v1.ConditionTrue,
			enableBFD:     true,
		},
		{
			name: "MissingBFDProfile False disable BFD",
			peerConfig: &v1alpha1.IsovalentBGPPeerConfig{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: peerConfigName,
				},
				Spec: v1alpha1.IsovalentBGPPeerConfigSpec{
					// This BFD profile doesn't exist, but
					// since the BFD itself is disabled,
					// the condition will be always false.
					BFDProfileRef: ptr.To(bfdProfile.Name + "foo"),
				},
			},
			expectedState: meta_v1.ConditionFalse,
			enableBFD:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := require.New(t)
			testLogger := hivetest.Logger(t)

			ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
			t.Cleanup(func() {
				cancel()
			})

			f, ready := newFixture(ctx, req, fixtureConfig{enableBFD: tt.enableBFD})

			f.hive.Start(testLogger, ctx)
			t.Cleanup(func() {
				f.hive.Stop(testLogger, ctx)
			})

			ready()

			_, err := f.fakeClientSet.CiliumFakeClientset.IsovalentV1alpha1().IsovalentBGPPeerConfigs().Create(
				ctx,
				tt.peerConfig,
				meta_v1.CreateOptions{},
			)
			req.NoError(err)

			_, err = f.fakeClientSet.CiliumFakeClientset.IsovalentV1alpha1().IsovalentBFDProfiles().Create(
				ctx,
				bfdProfile,
				meta_v1.CreateOptions{},
			)
			req.NoError(err)

			req.EventuallyWithT(func(ct *assert.CollectT) {
				pc, err := f.isoPeerConfClient.Get(ctx, peerConfigName, meta_v1.GetOptions{})
				if !assert.NoError(ct, err, "Failed to get PeerConfig") {
					return
				}
				cond := meta.FindStatusCondition(
					pc.Status.Conditions,
					v1alpha1.BGPPeerConfigConditionMissingBFDProfile,
				)
				if !assert.NotNil(ct, cond, "Condition not found") {
					return
				}
				assert.Equal(ct, tt.expectedState, cond.Status, "Unexpected condition status")
			}, time.Second*3, time.Millisecond*100)
		})
	}
}
