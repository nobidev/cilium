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
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

const (
	backendClusterReadyTimeout = 5 * time.Minute

	ilbControlPlaneContainer = "kind-control-plane"
	containerCLIPath         = "/usr/local/bin/cilium"
	containerKubeconfig      = "/etc/kubernetes/admin.conf"
)

var ensureCLIInContainerOnce sync.Once

type backendKindCluster struct {
	Name     string
	IPFamily string
}

func (r *lbTestScenario) createBackendKindCluster(clusterName string) *backendKindCluster {
	return r.createBackendKindClusterWithIPFamily(clusterName, r.backendClusterIPFamily())
}

func (r *lbTestScenario) createBackendKindClusterWithIPFamily(clusterName, ipFamily string) *backendKindCluster {
	env := os.Environ()
	env = append(env, fmt.Sprintf("KIND_EXPERIMENTAL_DOCKER_NETWORK=%s", FlagNetworkName))

	// Create a temp file for the kubeconfig to prevent kind from overwriting the default kubeconfig
	tmpKubeconfig, err := os.CreateTemp("", "kind-kubeconfig-*")
	if err != nil {
		r.t.Failedf("failed to create temp kubeconfig file: %s", err)
	}
	tmpKubeconfig.Close()
	defer os.Remove(tmpKubeconfig.Name())

	args := []string{"create", "cluster", "--name", clusterName, "--kubeconfig", tmpKubeconfig.Name()}

	kindConfig := fmt.Sprintf(`kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
- role: worker
networking:
  ipFamily: %s
`, ipFamily)

	tmpConfig, err := os.CreateTemp("", "kind-config-*")
	if err != nil {
		r.t.Failedf("failed to create temp kind config file: %s", err)
	}
	if _, err := tmpConfig.WriteString(kindConfig); err != nil {
		tmpConfig.Close()
		r.t.Failedf("failed to write kind config: %s", err)
	}
	tmpConfig.Close()
	defer os.Remove(tmpConfig.Name())

	args = append(args, "--config", tmpConfig.Name())

	cmd := exec.CommandContext(r.t.Context(), "kind", args...)
	cmd.Env = env

	output, err := cmd.CombinedOutput()
	if err != nil {
		r.t.Failedf("failed to create kind cluster %q: %s\nOutput: %s", clusterName, err, string(output))
	}

	cluster := &backendKindCluster{
		Name:     clusterName,
		IPFamily: ipFamily,
	}

	r.t.RegisterCleanup(func(ctx context.Context) error {
		return r.deleteBackendKindCluster(clusterName)
	})

	return cluster
}

func (r *lbTestScenario) backendClusterIPFamily() string {
	switch {
	case r.t.IPv4Enabled() && r.t.IPv6Enabled():
		return "dual"
	case r.t.IPv6Enabled():
		return "ipv6"
	default:
		return "ipv4"
	}
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

func (r *lbTestScenario) getBackendKindClusterKubeconfig(clusterName string) string {
	cmd := exec.CommandContext(r.t.Context(), "kind", "get", "kubeconfig", "--name", clusterName)
	output, err := cmd.Output()
	if err != nil {
		r.t.Failedf("failed to get kubeconfig for kind cluster %q: %s", clusterName, err)
	}
	return string(output)
}

func (r *lbTestScenario) getBackendKindClusterInternalKubeconfig(cluster *backendKindCluster) string {
	kubeconfig := r.getBackendKindClusterKubeconfig(cluster.Name)

	// Look up the IP on the specific network rather than using
	// GetContainerIPs, which returns a random network's IP from the map.
	containerName := fmt.Sprintf("%s-control-plane", cluster.Name)
	ipv4, ipv6, err := r.dockerCli.GetContainerIPsOnNetwork(r.t.Context(), containerName, FlagNetworkName)
	if err != nil {
		r.t.Failedf("failed to get container IP for %q on network %q: %s", containerName, FlagNetworkName, err)
	}

	// Use IPv6 when the backend cluster is IPv6-only, because the API
	// server TLS certificate will only contain IPv6 SANs in that case.
	var serverAddr string
	switch {
	case cluster.IPFamily == "ipv6" && ipv6 != "":
		serverAddr = fmt.Sprintf("[%s]", ipv6)
	case ipv4 != "":
		serverAddr = ipv4
	default:
		serverAddr = fmt.Sprintf("[%s]", ipv6)
	}

	lines := strings.Split(kubeconfig, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "server:") {
			lines[i] = fmt.Sprintf("    server: https://%s:6443", serverAddr)
		}
	}

	return strings.Join(lines, "\n")
}

func (r *lbTestScenario) waitForBackendKindClusterReady(cluster *backendKindCluster) {
	containerName := fmt.Sprintf("%s-control-plane", cluster.Name)
	eventually(r.t, func() error {
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

func (r *lbTestScenario) ensureCLIInContainer() {
	ensureCLIInContainerOnce.Do(func() {
		cliPath, err := os.Executable()
		if err != nil {
			r.t.Failedf("failed to resolve current executable path: %s", err)
		}

		cmd := exec.CommandContext(r.t.Context(),
			"docker", "cp", cliPath, ilbControlPlaneContainer+":"+containerCLIPath)
		output, err := cmd.CombinedOutput()
		if err != nil {
			r.t.Failedf("failed to copy cilium binary to %s: %s\nOutput: %s",
				ilbControlPlaneContainer, err, string(output))
		}
	})
}

func (r *lbTestScenario) addK8sBackendCluster(cluster *backendKindCluster, clusterName string, extraArgs ...string) {
	r.ensureCLIInContainer()

	internalKubeconfig := r.getBackendKindClusterInternalKubeconfig(cluster)

	containerKubeconfigPath := fmt.Sprintf("/tmp/%s.kubeconfig", clusterName)

	writeCmd := exec.CommandContext(r.t.Context(),
		"docker", "exec", "-i", ilbControlPlaneContainer,
		"sh", "-c", fmt.Sprintf("cat > %s", containerKubeconfigPath))
	writeCmd.Stdin = strings.NewReader(internalKubeconfig)
	if output, err := writeCmd.CombinedOutput(); err != nil {
		r.t.Failedf("failed to write kubeconfig to container: %s\nOutput: %s", err, string(output))
	}

	cliArgs := []string{
		"lb", "k8s", "addcluster",
		"--external-cluster-name", clusterName,
		"--external-kubeconfig", containerKubeconfigPath,
		"--external-kubeconfig-context", "kind-" + cluster.Name,
		"--secret-namespace", r.k8sNamespace,
		"--kubeconfig", containerKubeconfig,
	}
	cliArgs = append(cliArgs, extraArgs...)

	dockerArgs := append([]string{"exec", ilbControlPlaneContainer, containerCLIPath}, cliArgs...)

	// The backend cluster's API server may take a moment to become reachable
	// on the Docker network after waitForBackendKindClusterReady succeeds.
	eventually(r.t, func() error {
		cmd := exec.CommandContext(r.t.Context(), "docker", dockerArgs...)
		output, err := cmd.CombinedOutput()
		if err != nil {
			r.t.Log("addcluster attempt failed, retrying: %s\nOutput: %s", err, string(output))
			return fmt.Errorf("cilium lb k8s addcluster failed for %q: %w\nOutput: %s",
				clusterName, err, string(output))
		}
		return nil
	}, backendClusterReadyTimeout, pollInterval)

	r.t.RegisterCleanup(func(ctx context.Context) error {
		return r.removeK8sBackendCluster(ctx, clusterName)
	})
}

func (r *lbTestScenario) removeK8sBackendCluster(ctx context.Context, clusterName string) error {
	r.ensureCLIInContainer()

	cliArgs := []string{
		"lb", "k8s", "deletecluster",
		"--external-cluster-name", clusterName,
		"--secret-namespace", r.k8sNamespace,
		"--kubeconfig", containerKubeconfig,
	}

	dockerArgs := append([]string{"exec", ilbControlPlaneContainer, containerCLIPath}, cliArgs...)

	cmd := exec.CommandContext(ctx, "docker", dockerArgs...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("cilium lb k8s deletecluster failed for %q: %w\nOutput: %s",
			clusterName, err, string(output))
	}
	return nil
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

func (r *lbTestScenario) createServiceInBackendCluster(cluster *backendKindCluster, namespace string, serviceName string, port int32) {
	serviceYAML := fmt.Sprintf(`
apiVersion: v1
kind: Namespace
metadata:
  name: %s
---
apiVersion: v1
kind: Service
metadata:
  name: %s
  namespace: %s
  labels:
    ilb-discovery: "true"
spec:
  type: LoadBalancer
  ports:
  - port: %d
    targetPort: 80
    protocol: TCP
  selector:
    app: test
`, namespace, serviceName, namespace, port)

	containerName := fmt.Sprintf("%s-control-plane", cluster.Name)
	cmd := exec.CommandContext(r.t.Context(), "docker", "exec", "-i", containerName,
		"kubectl", "--kubeconfig=/etc/kubernetes/admin.conf",
		"apply", "-f", "-")
	cmd.Stdin = strings.NewReader(serviceYAML)

	output, err := cmd.CombinedOutput()
	if err != nil {
		r.t.Failedf("failed to create service in backend cluster: %s\nOutput: %s", err, string(output))
	}

	r.t.RegisterCleanup(func(ctx context.Context) error {
		cmd := exec.CommandContext(ctx, "docker", "exec", containerName,
			"kubectl", "--kubeconfig=/etc/kubernetes/admin.conf",
			"delete", "namespace", namespace, "--ignore-not-found")
		_, _ = cmd.CombinedOutput()
		return nil
	})
}

func (r *lbTestScenario) waitForLBK8sBackendClusterServiceDiscovery(clusterName string, serviceNamespace string, serviceName string) *isovalentv1alpha1.LBK8sBackendClusterDiscoveredService {
	var discoveredSvc *isovalentv1alpha1.LBK8sBackendClusterDiscoveredService

	eventually(r.t, func() error {
		lbK8sBackendCluster, err := r.ciliumCli.IsovalentV1alpha1().LBK8sBackendClusters().Get(r.t.Context(), clusterName, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("failed to get LBK8sBackendCluster: %w", err)
		}

		for i := range lbK8sBackendCluster.Status.DiscoveredServices {
			svc := &lbK8sBackendCluster.Status.DiscoveredServices[i]
			if svc.RemoteNamespace == serviceNamespace && svc.RemoteName == serviceName {
				if svc.Status != string(isovalentv1alpha1.LBK8sBackendClusterDiscoveredServiceStatusSynced) {
					return fmt.Errorf("service status is %q, expected %q (error: %v)",
						svc.Status, isovalentv1alpha1.LBK8sBackendClusterDiscoveredServiceStatusSynced, svc.LastError)
				}
				discoveredSvc = svc
				return nil
			}
		}

		return fmt.Errorf("service %s/%s not found in discovered services (found %d services)",
			serviceNamespace, serviceName, len(lbK8sBackendCluster.Status.DiscoveredServices))
	}, longTimeout, pollInterval)

	return discoveredSvc
}

func (r *lbTestScenario) waitForServiceExternalIP(cluster *backendKindCluster, namespace string, serviceName string) string {
	var externalIP string

	containerName := fmt.Sprintf("%s-control-plane", cluster.Name)
	eventually(r.t, func() error {
		cmd := exec.CommandContext(r.t.Context(), "docker", "exec", containerName,
			"kubectl", "--kubeconfig=/etc/kubernetes/admin.conf",
			"get", "service", serviceName, "-n", namespace,
			"-o", "jsonpath={.status.loadBalancer.ingress[0].ip}")

		output, err := cmd.Output()
		if err != nil {
			return fmt.Errorf("failed to get service external IP: %w", err)
		}

		ip := strings.TrimSpace(string(output))
		if ip == "" {
			return fmt.Errorf("service does not have an external IP yet")
		}

		externalIP = ip
		return nil
	}, longTimeout, pollInterval)

	return externalIP
}

func (r *lbTestScenario) waitForServiceIngressIPv6(cluster *backendKindCluster, namespace string, serviceName string) string {
	var ipv6Addr string

	containerName := fmt.Sprintf("%s-control-plane", cluster.Name)
	eventually(r.t, func() error {
		cmd := exec.CommandContext(r.t.Context(), "docker", "exec", containerName,
			"kubectl", "--kubeconfig=/etc/kubernetes/admin.conf",
			"get", "service", serviceName, "-n", namespace,
			"-o", "jsonpath={.status.loadBalancer.ingress[*].ip}")

		output, err := cmd.Output()
		if err != nil {
			return fmt.Errorf("failed to get service ingress IPs: %w", err)
		}

		for ip := range strings.FieldsSeq(strings.TrimSpace(string(output))) {
			parsed := net.ParseIP(ip)
			if parsed != nil && parsed.To4() == nil {
				ipv6Addr = ip
				return nil
			}
		}

		return fmt.Errorf("service does not have an IPv6 ingress address yet")
	}, longTimeout, pollInterval)

	return ipv6Addr
}

func (r *lbTestScenario) getBackendNodeInternalIPs(cluster *backendKindCluster) (ipv4s []string, ipv6s []string) {
	containerName := fmt.Sprintf("%s-control-plane", cluster.Name)
	cmd := exec.CommandContext(r.t.Context(), "docker", "exec", containerName,
		"kubectl", "--kubeconfig=/etc/kubernetes/admin.conf",
		"get", "nodes",
		"-o", "json")

	output, err := cmd.Output()
	if err != nil {
		r.t.Failedf("failed to get backend node addresses: %s", err)
	}

	type nodeAddress struct {
		Type    string `json:"type"`
		Address string `json:"address"`
	}
	type nodeStatus struct {
		Addresses []nodeAddress `json:"addresses"`
	}
	type nodeItem struct {
		Status nodeStatus `json:"status"`
	}
	type nodeList struct {
		Items []nodeItem `json:"items"`
	}

	var nodes nodeList
	if err := json.Unmarshal(output, &nodes); err != nil {
		r.t.Failedf("failed to parse node list: %s", err)
	}

	for _, node := range nodes.Items {
		for _, addr := range node.Status.Addresses {
			if addr.Type != "InternalIP" {
				continue
			}
			parsed := net.ParseIP(addr.Address)
			if parsed == nil {
				continue
			}
			if parsed.To4() != nil {
				ipv4s = append(ipv4s, addr.Address)
			} else {
				ipv6s = append(ipv6s, addr.Address)
			}
		}
	}

	return ipv4s, ipv6s
}

func (r *lbTestScenario) waitForServiceAnnotation(cluster *backendKindCluster, namespace string, serviceName string, annotationKey string) string {
	var annotationValue string

	containerName := fmt.Sprintf("%s-control-plane", cluster.Name)
	eventually(r.t, func() error {
		cmd := exec.CommandContext(r.t.Context(), "docker", "exec", containerName,
			"kubectl", "--kubeconfig=/etc/kubernetes/admin.conf",
			"get", "service", serviceName, "-n", namespace,
			"-o", fmt.Sprintf(`go-template={{index .metadata.annotations "%s"}}`, annotationKey))

		output, err := cmd.Output()
		if err != nil {
			return fmt.Errorf("failed to get service annotation: %w", err)
		}

		val := strings.TrimSpace(string(output))
		if val == "" {
			return fmt.Errorf("service does not have annotation %q yet", annotationKey)
		}

		annotationValue = val
		return nil
	}, longTimeout, pollInterval)

	return annotationValue
}
