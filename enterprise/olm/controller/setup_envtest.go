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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	helmloader "helm.sh/helm/v3/pkg/chart/loader"
	"k8s.io/client-go/rest"
	"k8s.io/kubectl/pkg/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	ciliumiov1alpha1 "github.com/isovalent/cilium/enterprise/olm/api/cilium.io/v1alpha1"
	"github.com/isovalent/cilium/enterprise/olm/helm"
)

var (
	testEnv   *envtest.Environment
	cfg       *rest.Config
	k8sClient client.Client
)

// setupEnvTest sets up the environment for the tests
func setupEnvTest(ctx context.Context, t *testing.T) {
	// Set up logger
	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))

	testEnv = &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "config", "crd", "bases")},
		BinaryAssetsDirectory: os.Getenv("ENVTEST_PATH"),
		ErrorIfCRDPathMissing: true,
	}

	var err error

	cfg, err = testEnv.Start()
	require.NoError(t, err, "expect no error by starting the environment")
	require.NotNil(t, cfg)
	t.Cleanup(func() {
		err = testEnv.Stop()
		require.NoError(t, err, "expect no error by shuting down the API server and etcd")

	})

	err = ciliumiov1alpha1.AddToScheme(scheme.Scheme)
	require.NoError(t, err, "expect no error adding the ciliumconfig scheme")

	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme.Scheme})
	require.NoError(t, err, "expect no error by creating a new client")
	require.NotNil(t, k8sClient)

	k8sManager, err := ctrl.NewManager(cfg, ctrl.Options{Scheme: scheme.Scheme})
	require.NoError(t, err, "expect no error by creating a new manager")
	require.NotNil(t, k8sManager)

	chart, err := helmloader.LoadDir(filepath.Join("..", "manifests"))
	require.NoError(t, err, "expect no error by loading the chart")
	require.NotNil(t, chart)

	rm := k8sManager.GetRESTMapper()

	err = (&CiliumConfigReconciler{
		Client:           k8sManager.GetClient(),
		Scheme:           k8sManager.GetScheme(),
		Chart:            chart,
		Namespace:        "cilium",
		HelmClientGetter: helm.NewRESTClientGetter(cfg, &rm, "cilium"),
	}).SetupWithManager(k8sManager)
	require.NoError(t, err, "expect no error by setting up the controller with the manager")

	go func() {
		err = k8sManager.Start(ctx)
		require.NoError(t, err, "expect no error by starting the manager")
	}()
}
