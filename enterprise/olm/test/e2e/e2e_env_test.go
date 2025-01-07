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

package e2e_test

import (
	"context"
	"flag"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"

	appsv1 "k8s.io/api/apps/v1"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	amtypes "k8s.io/apimachinery/pkg/types"

	"k8s.io/kubectl/pkg/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	ciliumiov1alpha1 "github.com/isovalent/cilium/enterprise/olm/api/v1alpha1"
	"github.com/isovalent/cilium/enterprise/olm/manager"
	"github.com/isovalent/cilium/enterprise/olm/test/e2e"
)

var ciliumConfig = ciliumiov1alpha1.CiliumConfig{
	ObjectMeta: metav1.ObjectMeta{
		Name: "config",
	},
	Spec: ciliumiov1alpha1.CiliumConfigSpec{
		RawExtension: runtime.RawExtension{
			Raw: []byte(`{"securityContext": {"privileged": true}, "ipam":{"mode": "cluster-pool"}, "cni": {"binPath": "/var/lib/cni/bin", "confPath": "/var/run/multus/cni/net.d"}}`),
		},
	},
}

var updatedCiliumValues = []byte(`{"operator": {"replicas": 1}, "securityContext": {"privileged": true}, "ipam":{"mode": "cluster-pool"}, "cni": {"binPath": "/var/lib/cni/bin", "confPath": "/var/run/multus/cni/net.d"}}`)

func TestController(t *testing.T) {
	// Setup
	const ns = "cilium"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env := e2e.Cluster(ctx, t)
	kcfg := e2e.NewUser(t, env, "cluster-admin", []string{"system:masters"})
	flag.Set("kubeconfig", kcfg)
	flag.Set("helm-path", "../../manifests")
	k8sClient, err := client.New(env.Config, client.Options{Scheme: scheme.Scheme})
	require.NoError(t, err, "expect no error by creating a new client")
	require.NotNil(t, k8sClient)
	e2e.CreateNamespace(ctx, k8sClient, ns)
	envtest.WaitForCRDs(env.Config, []*apiextensionsv1.CustomResourceDefinition{
		{
			Spec: apiextensionsv1.CustomResourceDefinitionSpec{
				Group: "isovalent.io",
				Names: apiextensionsv1.CustomResourceDefinitionNames{
					Plural: "ciliumconfigs",
				},
				Versions: []apiextensionsv1.CustomResourceDefinitionVersion{
					{
						Name:    "v1alpha1",
						Storage: true,
						Served:  false,
					},
				},
			},
		}},
		envtest.CRDInstallOptions{MaxTime: 50 * time.Millisecond, PollInterval: 15 * time.Millisecond})

	// Check that helm resources are applied when the CiliumConfig is created
	err = k8sClient.Create(ctx, &ciliumConfig)
	require.NoError(t, err, "expect no error by creating a CiliumConfig")
	go startManager(ctx)
	ccfg := ciliumiov1alpha1.CiliumConfig{}
	ccfgName := amtypes.NamespacedName{
		Name: ciliumConfig.Name,
	}
	require.Eventuallyf(t, func() bool {
		err = k8sClient.Get(ctx, ccfgName, &ccfg)
		require.NoError(t, err, "expect no error by retrieving the CiliumConfig")
		t.Logf("conditions: %s", spew.Sdump(ccfg.Status.Conditions))
		return meta.IsStatusConditionTrue(ccfg.Status.Conditions, ciliumiov1alpha1.APINotAvailableCondition) &&
			meta.IsStatusConditionFalse(ccfg.Status.Conditions, ciliumiov1alpha1.ProcessingErrorCondition) &&
			meta.IsStatusConditionFalse(ccfg.Status.Conditions, ciliumiov1alpha1.ValuesErrorsCondition)
	}, 10*time.Second, 100*time.Millisecond, "conditions not as expected")
	depl := appsv1.Deployment{}
	deplName := amtypes.NamespacedName{
		Namespace: ns,
		Name:      "cilium-operator",
	}
	err = k8sClient.Get(ctx, deplName, &depl)
	require.NoError(t, err, "expect no error by retrieving cilium operator deployment after the CiliumConfig has been created")
	// Check that the default number of replicas has been configured
	require.Equal(t, int32(2), *depl.Spec.Replicas)

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
		err = k8sClient.Get(ctx, deplName, &depl)
		if err == nil {
			return true
		}
		if !apierrors.IsNotFound(err) {
			require.Fail(t, "expect no error by retrieving the cilium operator deployment after the CiliumConfig has been updated: %w", err)
		}
		return false
	}, 3*time.Second, 10*time.Millisecond, "deployment not recreated after it has been deleted out-of-band")
}

func startManager(ctx context.Context) {
	manager.Start(ctx)
}
