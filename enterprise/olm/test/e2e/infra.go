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

package e2e

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/kubectl/pkg/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	ciliumiov1alpha1 "github.com/isovalent/cilium/enterprise/olm/api/cilium.io/v1alpha1"

	"github.com/isovalent/cilium/enterprise/olm/helm"
)

var testEnv *envtest.Environment

// Cluster provisions a new cluster or returns an existing one
func Cluster(ctx context.Context, t *testing.T) *envtest.Environment {
	// TODO: Add the possibility to use an existing cluster
	// for which the location of the kubeconfig file has been set through
	// an environment variable or a flag
	if testEnv != nil {
		return testEnv
	}
	testEnv = &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "config", "crd", "bases")},
		BinaryAssetsDirectory: os.Getenv("ENVTEST_PATH"),
		ErrorIfCRDPathMissing: true,
	}

	cfg, err := testEnv.Start()
	require.NoError(t, err, "expect no error by starting the environment")
	require.NotNil(t, cfg)
	t.Cleanup(func() {
		err = testEnv.Stop()
		require.NoError(t, err, "expect no error by shuting down the API server and etcd")

	})

	err = ciliumiov1alpha1.AddToScheme(scheme.Scheme)
	require.NoError(t, err, "expect no error adding the ciliumconfig scheme")

	k8sClient, err := client.New(cfg, client.Options{Scheme: scheme.Scheme})
	require.NoError(t, err, "expect no error by creating a new client")
	require.NotNil(t, k8sClient)

	roles, err := os.Open(filepath.Join("..", "..", "config", "rbac", "role.yaml"))
	require.NoError(t, err, "expect no error by reading the yaml file containing roles")
	defer roles.Close()
	uRoles, err := helm.Decode(bufio.NewReader(roles))
	require.NoError(t, err, "expect no error by decoding the yaml file containing roles")
	for _, u := range uRoles {
		err = k8sClient.Patch(ctx, u, client.Apply, client.FieldOwner("envtest"))
		require.NoError(t, err, "expect no error by applying roles")
	}
	bindings, err := os.Open(filepath.Join("..", "..", "config", "rbac", "role_binding.yaml"))
	require.NoError(t, err, "expect no error by reading the yaml file containing role bindings")
	defer roles.Close()
	uBindings, err := helm.Decode(bufio.NewReader(bindings))
	require.NoError(t, err, "expect no error by decoding the yaml file containing role bindings")
	for _, u := range uBindings {
		err = k8sClient.Patch(ctx, u, client.Apply, client.FieldOwner("envtest"))
		require.NoError(t, err, "expect no error by applying role bindings")
	}
	/*sa, err := os.Open(filepath.Join("..", "..", "config", "rbac", "service_account.yaml"))
	require.NoError(t, err, "expect no error by reading the yaml file containing the service account")
	defer roles.Close()
	uSA, err := helm.Decode(bufio.NewReader(sa))
	require.NoError(t, err, "expect no error by decoding the yaml file containing the service account")*/

	/*for _, u := range uSA {
		err = k8sClient.Patch(ctx, u, client.Apply, client.FieldOwner("envtest"))
		require.NoError(t, err, "expect no error by applying the service account")
	}*/
	return testEnv
}

func CreateNamespace(ctx context.Context, k8sClient client.Client, namespace string) {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: namespace,
		},
	}
	k8sClient.Create(ctx, ns)
}

func DeleteNamespace(ctx context.Context, k8sClient client.Client, namespace string) {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: namespace,
		},
	}
	k8sClient.Delete(ctx, ns)
}

func NewUser(t *testing.T, env *envtest.Environment, userName string, userGroups []string) string {
	user, err := env.AddUser(envtest.User{
		Name:   userName,
		Groups: userGroups,
	}, nil)
	require.NoError(t, err, "expect no error by creating users")

	kcfgFile, err := os.CreateTemp("", "envtest-kubeconfig-")
	require.NoError(t, err, "expect no error by creating a temporary file")
	t.Cleanup(func() {
		os.Remove(kcfgFile.Name())
		require.NoError(t, err, "expect no error by deleting the kubeconfig file")
	})
	kcfg, err := user.KubeConfig()
	require.NoError(t, err, "expect no error by getting a user kubeconfig")
	_, err = kcfgFile.Write(kcfg)
	require.NoError(t, err, "expect no error by writing the user kubeconfig")
	return kcfgFile.Name()
}
