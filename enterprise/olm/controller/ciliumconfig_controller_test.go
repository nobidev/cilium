/*
Copyright (C) Isovalent, Inc. - All Rights Reserved.

NOTICE: All information contained herein is, and remains the property of
Isovalent Inc and its suppliers, if any. The intellectual and technical
concepts contained herein are proprietary to Isovalent Inc and its suppliers
and may be covered by U.S. and Foreign Patents, patents in process, and are
protected by trade secret or copyright law.  Dissemination of this information
or reproduction of this material is strictly forbidden unless prior written
permission is obtained from Isovalent Inc.
*/

package controller

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	amtypes "k8s.io/apimachinery/pkg/types"

	ciliumiov1alpha1 "github.com/isovalent/cilium/enterprise/olm/api/cilium.io/v1alpha1"
)

var ciliumConfig = ciliumiov1alpha1.CiliumConfig{
	ObjectMeta: metav1.ObjectMeta{
		Name: "config",
	},
	Spec: ciliumiov1alpha1.CiliumConfigSpec{
		RawExtension: runtime.RawExtension{
			Raw: []byte(`{"securityContext":{"privileged":true},"ipam":{"mode":"cluster-pool"},"cni":{"binPath":"/var/lib/cni/bin","confPath":"/var/run/multus/cni/net.d"},"enterprise":{"healthServerWithoutActiveChecks":{"enabled":false}}}`),
		},
	},
}

var updatedCiliumValues = []byte(`{"operator":{"replicas":1},"securityContext":{"privileged":true},"ipam":{"mode":"cluster-pool"},"cni":{"binPath":"/var/lib/cni/bin","confPath":"/var/run/multus/cni/net.d"},"enterprise":{"healthServerWithoutActiveChecks":{"enabled":false}}}`)

// ensureNamespace creates a namespace if it doesn't already exist
func ensureNamespace(ctx context.Context, t *testing.T, name string) {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}
	err := k8sClient.Create(ctx, ns)
	if err != nil && !apierrors.IsAlreadyExists(err) {
		require.NoError(t, err, "expect no error by creating the test namespace")
	}
}

func TestCiliumConfigController(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	setupEnvTest(ctx, t)

	// Run all tests as subtests sharing the same environment
	t.Run("BasicReconciliation", func(t *testing.T) {
		testBasicReconciliation(t, ctx)
	})

	t.Run("CiliumConfigDeletion", func(t *testing.T) {
		testCiliumConfigDeletion(t, ctx)
	})

	t.Run("ProcessingErrorCondition", func(t *testing.T) {
		testProcessingErrorCondition(t, ctx)
	})
}

func testBasicReconciliation(t *testing.T, ctx context.Context) {
	var err error

	// Ensure test namespace exists
	ensureNamespace(ctx, t, "cilium")

	// Check that helm resources are applied when the CiliumConfig is created
	err = k8sClient.Create(ctx, &ciliumConfig)
	require.NoError(t, err, "expect no error by creating a CiliumConfig")

	ccfg := ciliumiov1alpha1.CiliumConfig{}
	require.Eventuallyf(t, func() bool {
		err = k8sClient.Get(ctx, amtypes.NamespacedName{Name: ciliumConfig.Name}, &ccfg)
		require.NoError(t, err, "expect no error by retrieving the CiliumConfig")

		return meta.IsStatusConditionTrue(ccfg.Status.Conditions, ciliumiov1alpha1.APINotAvailableCondition) &&
			meta.IsStatusConditionFalse(ccfg.Status.Conditions, ciliumiov1alpha1.ProcessingErrorCondition) &&
			meta.IsStatusConditionFalse(ccfg.Status.Conditions, ciliumiov1alpha1.ValuesErrorsCondition)
	}, 10*time.Second, 100*time.Millisecond, "conditions not as expected")

	// Check that the cilium operator deployment has been created
	deplName := amtypes.NamespacedName{Namespace: "cilium", Name: "cilium-operator"}
	depl := appsv1.Deployment{}
	err = k8sClient.Get(ctx, deplName, &depl)
	require.NoError(t, err, "expect no error by retrieving cilium operator deployment after the CiliumConfig has been created")
	// Check that the default number of replicas has been configured
	require.Equal(t, int32(2), *depl.Spec.Replicas, "default number of replicas not as expected")

	// Check that helm resources are updated when the CiliumConfig is changed
	ccfg.Spec.Raw = updatedCiliumValues
	err = k8sClient.Update(ctx, &ccfg)
	require.NoError(t, err, "expect no error by updating the ciliumConfig")
	// Check that the number of replicas has been changed
	require.Eventuallyf(t, func() bool {
		err = k8sClient.Get(ctx, deplName, &depl)
		require.NoError(t, err, "expect no error by retrieving the CiliumConfig")
		return *depl.Spec.Replicas == int32(1)
	}, 3*time.Second, 10*time.Millisecond, "number of replicas not as expected")

	// Check that helm resources are reapplied when they are deleted out-of-band
	err = k8sClient.Delete(ctx, &depl)
	require.Eventuallyf(t, func() bool {
		err = k8sClient.Get(ctx, amtypes.NamespacedName{Namespace: "cilium", Name: "cilium-operator"}, &depl)
		if err == nil {
			return true
		}
		if !apierrors.IsNotFound(err) {
			require.Fail(t, "expect no error by retrieving the cilium operator deployment after the CiliumConfig has been updated: %w", err)
		}
		return false
	}, 3*time.Second, 10*time.Millisecond, "deployment not recreated after it has been deleted out-of-band")
}

// TestCiliumConfigDeletion tests that deleting CiliumConfig is handled gracefully
func testCiliumConfigDeletion(t *testing.T, ctx context.Context) {
	// Ensure test namespace exists
	ensureNamespace(ctx, t, "cilium")

	var err error

	// Create CiliumConfig
	testConfig := ciliumiov1alpha1.CiliumConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "deletion-config",
		},
		Spec: ciliumiov1alpha1.CiliumConfigSpec{
			RawExtension: runtime.RawExtension{
				Raw: []byte(`{"securityContext":{"privileged":true},"ipam":{"mode":"cluster-pool"},"cni":{"binPath":"/var/lib/cni/bin","confPath":"/var/run/multus/cni/net.d"},"enterprise":{"healthServerWithoutActiveChecks":{"enabled":false}}}`),
			},
		},
	}

	err = k8sClient.Create(ctx, &testConfig)
	require.NoError(t, err, "expect no error by creating a CiliumConfig")

	// Wait for reconciliation
	ccfg := ciliumiov1alpha1.CiliumConfig{}
	require.Eventuallyf(t, func() bool {
		err = k8sClient.Get(ctx, amtypes.NamespacedName{Name: testConfig.Name}, &ccfg)
		require.NoError(t, err, "expect no error by retrieving the CiliumConfig")

		return meta.IsStatusConditionFalse(ccfg.Status.Conditions, ciliumiov1alpha1.ProcessingErrorCondition)
	}, 10*time.Second, 100*time.Millisecond, "ProcessingErrorCondition should be false")

	// Delete the CiliumConfig
	err = k8sClient.Delete(ctx, &testConfig)
	require.NoError(t, err, "expect no error deleting CiliumConfig")

	// Verify it's deleted
	require.Eventually(t, func() bool {
		err = k8sClient.Get(ctx, amtypes.NamespacedName{Name: testConfig.Name}, &ccfg)
		return apierrors.IsNotFound(err)
	}, 5*time.Second, 100*time.Millisecond, "CiliumConfig should be deleted")
}

// testProcessingErrorCondition tests that ProcessingErrorCondition is set to True when processing fails
func testProcessingErrorCondition(t *testing.T, ctx context.Context) {
	// Ensure test namespace exists
	ensureNamespace(ctx, t, "cilium")

	var err error

	// Create CiliumConfig with values that will cause Helm template rendering to fail
	// Using a value that causes a template error - setting replicas to a non-numeric string
	failingConfig := ciliumiov1alpha1.CiliumConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "processing-error-config",
		},
		Spec: ciliumiov1alpha1.CiliumConfigSpec{
			RawExtension: runtime.RawExtension{
				// This will parse as valid YAML but cause Helm template rendering errors
				// Using an invalid type for a field that templates expect to be numeric
				Raw: []byte(`{"securityContext":{"privileged":true},"ipam":{"mode":"cluster-pool"},"cni":{"binPath":"/var/lib/cni/bin","confPath":"/var/run/multus/cni/net.d"},"operator":{"replicas":"not-a-number"},"enterprise":{"healthServerWithoutActiveChecks":{"enabled":false}}}`),
			},
		},
	}

	err = k8sClient.Create(ctx, &failingConfig)
	require.NoError(t, err, "expect no error by creating the CiliumConfig")

	// Check that ProcessingErrorCondition is set to True
	ccfg := ciliumiov1alpha1.CiliumConfig{}
	require.Eventuallyf(t, func() bool {
		err = k8sClient.Get(ctx, amtypes.NamespacedName{Name: failingConfig.Name}, &ccfg)
		require.NoError(t, err, "expect no error by retrieving the CiliumConfig")

		processingErrorCond := meta.FindStatusCondition(ccfg.Status.Conditions, ciliumiov1alpha1.ProcessingErrorCondition)
		if processingErrorCond == nil {
			return false
		}
		return processingErrorCond.Status == metav1.ConditionTrue &&
			processingErrorCond.Reason == ciliumiov1alpha1.HelmProcessingErrorReason
	}, 10*time.Second, 100*time.Millisecond, "ProcessingErrorCondition should be True with HelmProcessingErrorReason")

	// Verify ValuesErrorsCondition is False (values parsed successfully)
	require.Eventuallyf(t, func() bool {
		err = k8sClient.Get(ctx, amtypes.NamespacedName{Name: failingConfig.Name}, &ccfg)
		require.NoError(t, err, "expect no error by retrieving the CiliumConfig")

		valuesErrorCond := meta.FindStatusCondition(ccfg.Status.Conditions, ciliumiov1alpha1.ValuesErrorsCondition)
		if valuesErrorCond == nil {
			return false
		}
		return valuesErrorCond.Status == metav1.ConditionFalse &&
			valuesErrorCond.Reason == ciliumiov1alpha1.ValuesReadableReason
	}, 5*time.Second, 100*time.Millisecond, "ValuesErrorsCondition should be False since values were readable")
}
