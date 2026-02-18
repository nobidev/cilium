//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package ilb

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

const (
	backendClusterReadyTimeout = 5 * time.Minute
)

type backendKindCluster struct {
	Name string
}

func (r *lbTestScenario) createBackendKindCluster(clusterName string) *backendKindCluster {
	env := os.Environ()
	env = append(env, fmt.Sprintf("KIND_EXPERIMENTAL_DOCKER_NETWORK=%s", FlagNetworkName))

	// Create a temp file for the kubeconfig to prevent kind from overwriting the default kubeconfig
	tmpKubeconfig, err := os.CreateTemp("", "kind-kubeconfig-*")
	if err != nil {
		r.t.Failedf("failed to create temp kubeconfig file: %s", err)
	}
	tmpKubeconfig.Close()
	defer os.Remove(tmpKubeconfig.Name())

	cmd := exec.CommandContext(r.t.Context(), "kind", "create", "cluster", "--name", clusterName, "--kubeconfig", tmpKubeconfig.Name())
	cmd.Env = env

	output, err := cmd.CombinedOutput()
	if err != nil {
		r.t.Failedf("failed to create kind cluster %q: %s\nOutput: %s", clusterName, err, string(output))
	}

	cluster := &backendKindCluster{
		Name: clusterName,
	}

	r.t.RegisterCleanup(func(ctx context.Context) error {
		return r.deleteBackendKindCluster(clusterName)
	})

	return cluster
}

func (r *lbTestScenario) deleteBackendKindCluster(clusterName string) error {
	cmd := exec.CommandContext(r.t.Context(), "kind", "delete", "cluster", "--name", clusterName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if strings.Contains(string(output), "no clusters found") ||
			strings.Contains(string(output), "unknown cluster") {
			return nil
		}
		return fmt.Errorf("failed to delete kind cluster %q: %w\nOutput: %s", clusterName, err, string(output))
	}
	return nil
}

// getBackendKindClusterKubeconfig retrieves the kubeconfig for a kind cluster.
// TODO(ajs): Use a kubeconfig constructed by a Cilium CLI subcommand which
// installs an appropriate ServiceAccount on the cluster
func (r *lbTestScenario) getBackendKindClusterKubeconfig(clusterName string) string {
	cmd := exec.CommandContext(r.t.Context(), "kind", "get", "kubeconfig", "--name", clusterName)
	output, err := cmd.Output()
	if err != nil {
		r.t.Failedf("failed to get kubeconfig for kind cluster %q: %s", clusterName, err)
	}
	return string(output)
}

// getBackendKindClusterInternalKubeconfig retrieves the kubeconfig for a kind cluster
// with the server address modified to use the internal Docker network address.
// TODO(ajs): Remove this once Cilium CLI can install a kubeconfig.
func (r *lbTestScenario) getBackendKindClusterInternalKubeconfig(clusterName string) string {
	// Get the standard kubeconfig
	kubeconfig := r.getBackendKindClusterKubeconfig(clusterName)

	// Get the control plane container IP on the kind-cilium network.
	// We must look up the IP on the specific network rather than using
	// GetContainerIPs, which returns a random network's IP from the map.
	containerName := fmt.Sprintf("%s-control-plane", clusterName)
	ipv4, _, err := r.dockerCli.GetContainerIPsOnNetwork(r.t.Context(), containerName, FlagNetworkName)
	if err != nil {
		r.t.Failedf("failed to get container IP for %q on network %q: %s", containerName, FlagNetworkName, err)
	}

	// Replace the localhost:port with the container IP:6443
	lines := strings.Split(kubeconfig, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "server:") {
			lines[i] = fmt.Sprintf("    server: https://%s:6443", ipv4)
		}
	}

	return strings.Join(lines, "\n")
}

func (r *lbTestScenario) waitForBackendKindClusterReady(cluster *backendKindCluster) {
	containerName := fmt.Sprintf("%s-control-plane", cluster.Name)
	eventually(r.t, func() error {
		// Use docker exec to run kubectl inside the control-plane container
		// rather than running kubectl directly from the test runner. This is
		// necessary in CI where the backend kind cluster's API server port is
		// only accessible inside the LVH VM, not from the GHA runner.
		cmd := exec.CommandContext(r.t.Context(), "docker", "exec", containerName,
			"kubectl", "--kubeconfig=/etc/kubernetes/admin.conf",
			"get", "namespaces",
			"-o", "jsonpath={.items[0].metadata.name}")

		output, err := cmd.Output()
		if err != nil {
			return fmt.Errorf("API server not reachable: %w", err)
		}

		if len(output) == 0 {
			return fmt.Errorf("API server returned no namespaces")
		}

		return nil
	}, backendClusterReadyTimeout, pollInterval)
}

func (r *lbTestScenario) createLBK8sBackendClusterSecret(cluster *backendKindCluster, secretName string) *corev1.Secret {
	internalKubeconfig := r.getBackendKindClusterInternalKubeconfig(cluster.Name)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: r.k8sNamespace,
			Labels: map[string]string{
				TestResourceLabelName: "true",
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"kubeconfig": []byte(internalKubeconfig),
		},
	}

	if _, err := r.k8sCli.CoreV1().Secrets(r.k8sNamespace).Create(r.t.Context(), secret, metav1.CreateOptions{}); err != nil {
		r.t.Failedf("failed to create LBK8sBackendCluster secret: %s", err)
	}

	r.t.RegisterCleanup(func(ctx context.Context) error {
		if _, err := r.k8sCli.CoreV1().Secrets(r.k8sNamespace).Get(ctx, secretName, metav1.GetOptions{}); errors.IsNotFound(err) {
			return nil
		}
		return r.k8sCli.CoreV1().Secrets(r.k8sNamespace).Delete(ctx, secretName, metav1.DeleteOptions{GracePeriodSeconds: ptr.To[int64](0)})
	})

	return secret
}

func (r *lbTestScenario) createLBK8sBackendCluster(name string, secretName string, secretNamespace string) *isovalentv1alpha1.LBK8sBackendCluster {
	lbK8sBackendCluster := &isovalentv1alpha1.LBK8sBackendCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				TestResourceLabelName: "true",
			},
		},
		Spec: isovalentv1alpha1.LBK8sBackendClusterSpec{
			Authentication: isovalentv1alpha1.LBK8sBackendClusterAuth{
				SecretRef: isovalentv1alpha1.LBK8sBackendClusterSecretRef{
					Name:      secretName,
					Namespace: secretNamespace,
				},
			},
		},
	}

	if _, err := r.ciliumCli.IsovalentV1alpha1().LBK8sBackendClusters().Create(r.t.Context(), lbK8sBackendCluster, metav1.CreateOptions{}); err != nil {
		r.t.Failedf("failed to create LBK8sBackendCluster: %s", err)
	}

	r.t.RegisterCleanup(func(ctx context.Context) error {
		if _, err := r.ciliumCli.IsovalentV1alpha1().LBK8sBackendClusters().Get(ctx, name, metav1.GetOptions{}); errors.IsNotFound(err) {
			return nil
		}
		return r.ciliumCli.IsovalentV1alpha1().LBK8sBackendClusters().Delete(ctx, name, metav1.DeleteOptions{GracePeriodSeconds: ptr.To[int64](0)})
	})

	return lbK8sBackendCluster
}

func (r *lbTestScenario) waitForLBK8sBackendClusterConnected(name string) {
	eventually(r.t, func() error {
		lbK8sBackendCluster, err := r.ciliumCli.IsovalentV1alpha1().LBK8sBackendClusters().Get(r.t.Context(), name, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("failed to get LBK8sBackendCluster: %w", err)
		}

		if lbK8sBackendCluster.Status == nil {
			return fmt.Errorf("status not yet set")
		}

		// Verify the Connected condition
		var connectedCondition *metav1.Condition
		for i := range lbK8sBackendCluster.Status.Conditions {
			if lbK8sBackendCluster.Status.Conditions[i].Type == isovalentv1alpha1.ConditionTypeClusterConnected {
				connectedCondition = &lbK8sBackendCluster.Status.Conditions[i]
				break
			}
		}

		if connectedCondition == nil {
			return fmt.Errorf("Connected condition not found in status")
		}

		if connectedCondition.Status != metav1.ConditionTrue {
			return fmt.Errorf("Connected condition status is %q, expected %q (reason=%q, message=%q)",
				connectedCondition.Status, metav1.ConditionTrue,
				connectedCondition.Reason, connectedCondition.Message)
		}

		return nil
	}, longTimeout, pollInterval)
}

func (r *lbTestScenario) updateLBK8sBackendClusterSecret(cluster *backendKindCluster, secretName string) {
	internalKubeconfig := r.getBackendKindClusterInternalKubeconfig(cluster.Name)

	secret, err := r.k8sCli.CoreV1().Secrets(r.k8sNamespace).Get(r.t.Context(), secretName, metav1.GetOptions{})
	if err != nil {
		r.t.Failedf("failed to get LBK8sBackendCluster secret: %s", err)
	}

	secret.Data["kubeconfig"] = []byte(internalKubeconfig)

	if _, err := r.k8sCli.CoreV1().Secrets(r.k8sNamespace).Update(r.t.Context(), secret, metav1.UpdateOptions{}); err != nil {
		r.t.Failedf("failed to update LBK8sBackendCluster secret: %s", err)
	}
}

func (r *lbTestScenario) waitForLBK8sBackendClusterDisconnected(name string) {
	eventually(r.t, func() error {
		lbK8sBackendCluster, err := r.ciliumCli.IsovalentV1alpha1().LBK8sBackendClusters().Get(r.t.Context(), name, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("failed to get LBK8sBackendCluster: %w", err)
		}

		if lbK8sBackendCluster.Status == nil {
			return fmt.Errorf("status not yet set")
		}

		var connectedCondition *metav1.Condition
		for i := range lbK8sBackendCluster.Status.Conditions {
			if lbK8sBackendCluster.Status.Conditions[i].Type == isovalentv1alpha1.ConditionTypeClusterConnected {
				connectedCondition = &lbK8sBackendCluster.Status.Conditions[i]
				break
			}
		}

		if connectedCondition == nil {
			return fmt.Errorf("Connected condition not found in status")
		}

		if connectedCondition.Status != metav1.ConditionFalse {
			return fmt.Errorf("Connected condition status is %q, expected %q", connectedCondition.Status, metav1.ConditionFalse)
		}

		return nil
	}, longTimeout, pollInterval)
}
