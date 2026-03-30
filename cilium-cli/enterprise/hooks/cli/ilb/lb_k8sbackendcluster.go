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
	"fmt"
	"net"
	"slices"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/versioncheck"
)

func TestLBK8sBackendClusterConnectivity(t T) {
	if skipIfOnSingleNode("backend kind clusters require a shared Docker network") {
		return
	}

	testName := "lbk8sbackend-connect"
	backendClusterName := "ilb-backend"

	ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
	dockerCli := NewDockerCli(t)

	// extlb is only supported in v1.19 and newer
	minVersion := ">=1.19.0"
	currentVersion := GetCiliumVersion(t, k8sCli)
	if !versioncheck.MustCompile(minVersion)(currentVersion) {
		fmt.Printf("skipping due to version mismatch - expected: %s - current: %s\n", minVersion, currentVersion.String())
		return
	}

	scenario := newLBTestScenario(t, testName, ciliumCli, k8sCli, dockerCli)

	t.Log("Creating backend kind cluster...")
	backendCluster := scenario.createBackendKindCluster(backendClusterName)

	t.Log("Waiting for backend cluster to be ready...")
	scenario.waitForBackendKindClusterReady(backendCluster)

	t.Log("Adding backend cluster via CLI...")
	lbK8sBackendClusterName := testName + "-cluster"
	scenario.addK8sBackendCluster(backendCluster, lbK8sBackendClusterName)

	t.Log("Waiting for LBK8sBackendCluster to connect...")
	scenario.waitForLBK8sBackendClusterConnected(lbK8sBackendClusterName)
}

func TestLBK8sBackendClusterMultiple(t T) {
	if skipIfOnSingleNode("backend kind clusters require a shared Docker network") {
		return
	}

	testName := "lbk8sbackend-multiple"

	ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
	dockerCli := NewDockerCli(t)

	// extlb is only supported in v1.19 and newer
	minVersion := ">=1.19.0"
	currentVersion := GetCiliumVersion(t, k8sCli)
	if !versioncheck.MustCompile(minVersion)(currentVersion) {
		fmt.Printf("skipping due to version mismatch - expected: %s - current: %s\n", minVersion, currentVersion.String())
		return
	}

	scenario := newLBTestScenario(t, testName, ciliumCli, k8sCli, dockerCli)

	t.Log("Creating first backend kind cluster...")
	backendCluster1 := scenario.createBackendKindCluster("ilb-backend-1")

	t.Log("Creating second backend kind cluster...")
	backendCluster2 := scenario.createBackendKindCluster("ilb-backend-2")

	t.Log("Waiting for backend clusters to be ready...")
	scenario.waitForBackendKindClusterReady(backendCluster1)
	scenario.waitForBackendKindClusterReady(backendCluster2)

	t.Log("Adding backend clusters via CLI...")
	lbK8sBackendClusterName1 := testName + "-cluster-1"
	lbK8sBackendClusterName2 := testName + "-cluster-2"
	scenario.addK8sBackendCluster(backendCluster1, lbK8sBackendClusterName1)
	scenario.addK8sBackendCluster(backendCluster2, lbK8sBackendClusterName2)

	t.Log("Waiting for LBK8sBackendClusters to connect...")
	scenario.waitForLBK8sBackendClusterConnected(lbK8sBackendClusterName1)
	scenario.waitForLBK8sBackendClusterConnected(lbK8sBackendClusterName2)
}

func TestLBK8sBackendClusterReconnect(t T) {
	if skipIfOnSingleNode("backend kind clusters require a shared Docker network") {
		return
	}

	testName := "lbk8sbackend-reconnect"
	backendClusterName := "ilb-backend-reconnect"

	ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
	dockerCli := NewDockerCli(t)

	// extlb is only supported in v1.19 and newer
	minVersion := ">=1.19.0"
	currentVersion := GetCiliumVersion(t, k8sCli)
	if !versioncheck.MustCompile(minVersion)(currentVersion) {
		fmt.Printf("skipping due to version mismatch - expected: %s - current: %s\n", minVersion, currentVersion.String())
		return
	}

	scenario := newLBTestScenario(t, testName, ciliumCli, k8sCli, dockerCli)

	t.Log("Creating backend kind cluster...")
	backendCluster := scenario.createBackendKindCluster(backendClusterName)

	t.Log("Waiting for backend cluster to be ready...")
	scenario.waitForBackendKindClusterReady(backendCluster)

	t.Log("Adding backend cluster via CLI...")
	lbK8sBackendClusterName := testName + "-cluster"
	scenario.addK8sBackendCluster(backendCluster, lbK8sBackendClusterName)

	t.Log("Waiting for LBK8sBackendCluster to connect...")
	scenario.waitForLBK8sBackendClusterConnected(lbK8sBackendClusterName)

	t.Log("Deleting backend kind cluster...")
	if err := scenario.deleteBackendKindCluster(backendCluster.Name); err != nil {
		t.Failedf("failed to delete backend kind cluster: %s", err)
	}

	t.Log("Waiting for LBK8sBackendCluster to disconnect...")
	scenario.waitForLBK8sBackendClusterDisconnected(lbK8sBackendClusterName)

	t.Log("Recreating backend kind cluster...")
	backendCluster = scenario.createBackendKindCluster(backendCluster.Name)

	t.Log("Waiting for backend cluster to be ready...")
	scenario.waitForBackendKindClusterReady(backendCluster)

	t.Log("Re-adding backend cluster via CLI to update credentials...")
	scenario.addK8sBackendCluster(backendCluster, lbK8sBackendClusterName)

	t.Log("Waiting for LBK8sBackendCluster to reconnect...")
	scenario.waitForLBK8sBackendClusterConnected(lbK8sBackendClusterName)
}

func TestLBK8sBackendClusterServiceDiscovery(t T) {
	if skipIfOnSingleNode("backend kind clusters require a shared Docker network") {
		return
	}

	testName := "lbk8sbackend-svc-disc"
	backendClusterName := "ilb-backend-svc-disc"

	ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
	dockerCli := NewDockerCli(t)

	// extlb is only supported in v1.19 and newer
	minVersion := ">=1.19.0"
	currentVersion := GetCiliumVersion(t, k8sCli)
	if !versioncheck.MustCompile(minVersion)(currentVersion) {
		fmt.Printf("skipping due to version mismatch - expected: %s - current: %s\n", minVersion, currentVersion.String())
		return
	}

	scenario := newLBTestScenario(t, testName, ciliumCli, k8sCli, dockerCli)

	t.Log("Creating backend kind cluster...")
	backendCluster := scenario.createBackendKindCluster(backendClusterName)

	t.Log("Waiting for backend cluster to be ready...")
	scenario.waitForBackendKindClusterReady(backendCluster)

	// Create a LoadBalancer service in the backend cluster before creating the LBK8sBackendCluster
	serviceNamespace := "test-svc-ns"
	serviceName := "test-service"
	servicePort := int32(8080)
	t.Log("Creating LoadBalancer service in backend cluster...")
	scenario.createServiceInBackendCluster(backendCluster, serviceNamespace, serviceName, servicePort)

	t.Log("Adding backend cluster via CLI with service discovery...")
	lbK8sBackendClusterName := testName + "-cluster"
	scenario.addK8sBackendCluster(backendCluster, lbK8sBackendClusterName,
		"--external-namespaces", serviceNamespace,
		"--target-namespace", scenario.k8sNamespace)

	t.Log("Waiting for LBK8sBackendCluster to connect...")
	scenario.waitForLBK8sBackendClusterConnected(lbK8sBackendClusterName)

	t.Log("Waiting for service to be discovered and synced...")
	discoveredSvc := scenario.waitForLBK8sBackendClusterServiceDiscovery(lbK8sBackendClusterName, serviceNamespace, serviceName)

	t.Log("Verifying ILB resources were created...")
	if len(discoveredSvc.LBVIPRefs) == 0 {
		t.Failedf("discovered service should have LBVIPRefs")
	}
	if len(discoveredSvc.LBServiceRefs) == 0 {
		t.Failedf("discovered service should have LBServiceRefs")
	}
	if len(discoveredSvc.LBBackendPoolRefs) == 0 {
		t.Failedf("discovered service should have LBBackendPoolRefs")
	}

	t.Log("Waiting for external IP to be written back to backend cluster service...")
	externalIP := scenario.waitForServiceExternalIP(backendCluster, serviceNamespace, serviceName)

	t.Log("Verifying external IP matches discovered service...")
	if discoveredSvc.ExternalIPv4 == nil || *discoveredSvc.ExternalIPv4 != externalIP {
		var discoveredIP string
		if discoveredSvc.ExternalIPv4 != nil {
			discoveredIP = *discoveredSvc.ExternalIPv4
		}
		t.Failedf("external IPv4 mismatch: discovered=%q, backend=%q", discoveredIP, externalIP)
	}

	if t.IPv6Enabled() {
		t.Log("Waiting for IPv6 ingress to be written back to backend cluster service...")
		externalIPv6 := scenario.waitForServiceIngressIPv6(backendCluster, serviceNamespace, serviceName)

		if discoveredSvc.ExternalIPv6 == nil || *discoveredSvc.ExternalIPv6 != externalIPv6 {
			var discoveredIPv6 string
			if discoveredSvc.ExternalIPv6 != nil {
				discoveredIPv6 = *discoveredSvc.ExternalIPv6
			}
			t.Failedf("external IPv6 mismatch: discovered=%q, backend=%q", discoveredIPv6, externalIPv6)
		}
	}

	t.Log("Verifying backend pool contains node IPs...")
	ipv4NodeIPs, ipv6NodeIPs := scenario.getBackendNodeInternalIPs(backendCluster)
	for _, poolRef := range discoveredSvc.LBBackendPoolRefs {
		pool, err := scenario.ciliumCli.IsovalentV1alpha1().LBBackendPools(poolRef.Namespace).Get(t.Context(), poolRef.Name, metav1.GetOptions{})
		if err != nil {
			t.Failedf("failed to get LBBackendPool %s/%s: %s", poolRef.Namespace, poolRef.Name, err)
		}

		var backendIPs []string
		for _, b := range pool.Spec.Backends {
			if b.IP != nil {
				backendIPs = append(backendIPs, *b.IP)
			}
		}

		for _, nodeIP := range ipv4NodeIPs {
			if !slices.Contains(backendIPs, nodeIP) {
				t.Failedf("backend pool %s/%s missing IPv4 node IP %s (backends: %v)",
					poolRef.Namespace, poolRef.Name, nodeIP, backendIPs)
			}
		}

		if t.IPv6Enabled() {
			for _, nodeIP := range ipv6NodeIPs {
				if !slices.Contains(backendIPs, nodeIP) {
					t.Failedf("backend pool %s/%s missing IPv6 node IP %s (backends: %v)",
						poolRef.Namespace, poolRef.Name, nodeIP, backendIPs)
				}
			}
		}
	}

	t.Log("Verifying annotation was written to backend cluster service...")
	annotationValue := scenario.waitForServiceAnnotation(backendCluster, serviceNamespace, serviceName, "lbk8sbackendcluster.isovalent.com/cluster")
	if annotationValue != lbK8sBackendClusterName {
		t.Failedf("annotation mismatch: expected=%q, got=%q", lbK8sBackendClusterName, annotationValue)
	}
}

func TestLBK8sBackendClusterIPv6OnlyBackend(t T) {
	if skipIfOnSingleNode("backend kind clusters require a shared Docker network") {
		return
	}

	testName := "lbk8sbackend-ipv6-be"
	backendClusterName := "ilb-backend-ipv6"

	ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
	dockerCli := NewDockerCli(t)

	minVersion := ">=1.19.0"
	currentVersion := GetCiliumVersion(t, k8sCli)
	if !versioncheck.MustCompile(minVersion)(currentVersion) {
		fmt.Printf("skipping due to version mismatch - expected: %s - current: %s\n", minVersion, currentVersion.String())
		return
	}

	if !t.IPv6Enabled() {
		fmt.Println("skipping: management cluster does not have IPv6 enabled")
		return
	}

	scenario := newLBTestScenario(t, testName, ciliumCli, k8sCli, dockerCli)

	t.Log("Creating IPv6-only backend kind cluster...")
	backendCluster := scenario.createBackendKindClusterWithIPFamily(backendClusterName, "ipv6")

	scenario.waitForBackendKindClusterReady(backendCluster)

	serviceNamespace := "test-svc-ns"
	serviceName := "test-service"
	servicePort := int32(8080)
	t.Log("Creating LoadBalancer service in backend cluster...")
	scenario.createServiceInBackendCluster(backendCluster, serviceNamespace, serviceName, servicePort)

	t.Log("Adding backend cluster via CLI with service discovery...")
	lbK8sBackendClusterName := testName + "-cluster"
	scenario.addK8sBackendCluster(backendCluster, lbK8sBackendClusterName,
		"--external-namespaces", serviceNamespace,
		"--target-namespace", scenario.k8sNamespace)

	t.Log("Waiting for LBK8sBackendCluster to connect...")
	scenario.waitForLBK8sBackendClusterConnected(lbK8sBackendClusterName)

	t.Log("Waiting for service to be discovered and synced...")
	discoveredSvc := scenario.waitForLBK8sBackendClusterServiceDiscovery(lbK8sBackendClusterName, serviceNamespace, serviceName)

	t.Log("Verifying ILB resources were created...")
	if len(discoveredSvc.LBVIPRefs) == 0 {
		t.Failedf("discovered service should have LBVIPRefs")
	}
	if len(discoveredSvc.LBServiceRefs) == 0 {
		t.Failedf("discovered service should have LBServiceRefs")
	}
	if len(discoveredSvc.LBBackendPoolRefs) == 0 {
		t.Failedf("discovered service should have LBBackendPoolRefs")
	}

	if discoveredSvc.ExternalIPv4 != nil {
		t.Failedf("expected no ExternalIPv4 for IPv6-only backend, got %q", *discoveredSvc.ExternalIPv4)
	}

	externalIPv6 := scenario.waitForServiceIngressIPv6(backendCluster, serviceNamespace, serviceName)

	t.Log("Verifying ingress IPv6 matches discovered service...")
	if discoveredSvc.ExternalIPv6 == nil || *discoveredSvc.ExternalIPv6 != externalIPv6 {
		var discoveredIPv6 string
		if discoveredSvc.ExternalIPv6 != nil {
			discoveredIPv6 = *discoveredSvc.ExternalIPv6
		}
		t.Failedf("external IPv6 mismatch: discovered=%q, backend=%q", discoveredIPv6, externalIPv6)
	}

	t.Log("Verifying backend pool contains only IPv6 node IPs...")
	ipv4NodeIPs, ipv6NodeIPs := scenario.getBackendNodeInternalIPs(backendCluster)
	if len(ipv4NodeIPs) != 0 {
		t.Failedf("expected no IPv4 node IPs for IPv6-only backend, got %v", ipv4NodeIPs)
	}
	for _, poolRef := range discoveredSvc.LBBackendPoolRefs {
		pool, err := scenario.ciliumCli.IsovalentV1alpha1().LBBackendPools(poolRef.Namespace).Get(t.Context(), poolRef.Name, metav1.GetOptions{})
		if err != nil {
			t.Failedf("failed to get LBBackendPool %s/%s: %s", poolRef.Namespace, poolRef.Name, err)
		}

		var backendIPs []string
		for _, b := range pool.Spec.Backends {
			if b.IP != nil {
				backendIPs = append(backendIPs, *b.IP)
			}
		}

		for _, nodeIP := range ipv6NodeIPs {
			if !slices.Contains(backendIPs, nodeIP) {
				t.Failedf("backend pool %s/%s missing IPv6 node IP %s (backends: %v)",
					poolRef.Namespace, poolRef.Name, nodeIP, backendIPs)
			}
		}
	}
}

func TestLBK8sBackendClusterDualStackBackend(t T) {
	if skipIfOnSingleNode("backend kind clusters require a shared Docker network") {
		return
	}

	testName := "lbk8sbackend-ds-be"
	backendClusterName := "ilb-backend-ds"

	ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
	dockerCli := NewDockerCli(t)

	minVersion := ">=1.19.0"
	currentVersion := GetCiliumVersion(t, k8sCli)
	if !versioncheck.MustCompile(minVersion)(currentVersion) {
		fmt.Printf("skipping due to version mismatch - expected: %s - current: %s\n", minVersion, currentVersion.String())
		return
	}

	scenario := newLBTestScenario(t, testName, ciliumCli, k8sCli, dockerCli)

	t.Log("Creating dual-stack backend kind cluster...")
	backendCluster := scenario.createBackendKindClusterWithIPFamily(backendClusterName, "dual")

	t.Log("Waiting for backend cluster to be ready...")
	scenario.waitForBackendKindClusterReady(backendCluster)

	serviceNamespace := "test-svc-ns"
	serviceName := "test-service"
	servicePort := int32(8080)
	t.Log("Creating LoadBalancer service in backend cluster...")
	scenario.createServiceInBackendCluster(backendCluster, serviceNamespace, serviceName, servicePort)

	t.Log("Adding backend cluster via CLI with service discovery...")
	lbK8sBackendClusterName := testName + "-cluster"
	scenario.addK8sBackendCluster(backendCluster, lbK8sBackendClusterName,
		"--external-namespaces", serviceNamespace,
		"--target-namespace", scenario.k8sNamespace)

	t.Log("Waiting for LBK8sBackendCluster to connect...")
	scenario.waitForLBK8sBackendClusterConnected(lbK8sBackendClusterName)

	t.Log("Waiting for service to be discovered and synced...")
	discoveredSvc := scenario.waitForLBK8sBackendClusterServiceDiscovery(lbK8sBackendClusterName, serviceNamespace, serviceName)

	t.Log("Verifying ILB resources were created...")
	if len(discoveredSvc.LBVIPRefs) == 0 {
		t.Failedf("discovered service should have LBVIPRefs")
	}
	if len(discoveredSvc.LBServiceRefs) == 0 {
		t.Failedf("discovered service should have LBServiceRefs")
	}
	if len(discoveredSvc.LBBackendPoolRefs) == 0 {
		t.Failedf("discovered service should have LBBackendPoolRefs")
	}

	t.Log("Waiting for IPv4 external IP to be written back to backend cluster service...")
	externalIP := scenario.waitForServiceExternalIP(backendCluster, serviceNamespace, serviceName)

	t.Log("Verifying IPv4 external IP matches discovered service...")
	if discoveredSvc.ExternalIPv4 == nil || *discoveredSvc.ExternalIPv4 != externalIP {
		var discoveredIP string
		if discoveredSvc.ExternalIPv4 != nil {
			discoveredIP = *discoveredSvc.ExternalIPv4
		}
		t.Failedf("external IPv4 mismatch: discovered=%q, backend=%q", discoveredIP, externalIP)
	}

	if t.IPv6Enabled() {
		t.Log("Waiting for IPv6 ingress to be written back to backend cluster service...")
		externalIPv6 := scenario.waitForServiceIngressIPv6(backendCluster, serviceNamespace, serviceName)

		t.Log("Verifying IPv6 matches discovered service...")
		if discoveredSvc.ExternalIPv6 == nil || *discoveredSvc.ExternalIPv6 != externalIPv6 {
			var discoveredIPv6 string
			if discoveredSvc.ExternalIPv6 != nil {
				discoveredIPv6 = *discoveredSvc.ExternalIPv6
			}
			t.Failedf("external IPv6 mismatch: discovered=%q, backend=%q", discoveredIPv6, externalIPv6)
		}
	} else {
		t.Log("ILB cluster is IPv4-only, verifying no IPv6 was allocated...")
		if discoveredSvc.ExternalIPv6 != nil {
			t.Failedf("expected no ExternalIPv6 on IPv4-only ILB cluster, got %q", *discoveredSvc.ExternalIPv6)
		}
	}

	t.Log("Verifying backend pools are separated by address family...")
	ipv4NodeIPs, ipv6NodeIPs := scenario.getBackendNodeInternalIPs(backendCluster)
	if len(ipv4NodeIPs) == 0 {
		t.Failedf("expected IPv4 node IPs from dual-stack backend, got none")
	}
	if len(ipv6NodeIPs) == 0 {
		t.Failedf("expected IPv6 node IPs from dual-stack backend, got none")
	}

	for _, poolRef := range discoveredSvc.LBBackendPoolRefs {
		pool, err := scenario.ciliumCli.IsovalentV1alpha1().LBBackendPools(poolRef.Namespace).Get(t.Context(), poolRef.Name, metav1.GetOptions{})
		if err != nil {
			t.Failedf("failed to get LBBackendPool %s/%s: %s", poolRef.Namespace, poolRef.Name, err)
		}

		var backendIPs []string
		for _, b := range pool.Spec.Backends {
			if b.IP != nil {
				backendIPs = append(backendIPs, *b.IP)
			}
		}

		// Each pool should contain IPs of exactly one family.
		hasV4, hasV6 := false, false
		for _, ip := range backendIPs {
			parsed := net.ParseIP(ip)
			if parsed == nil {
				continue
			}
			if parsed.To4() != nil {
				hasV4 = true
			} else {
				hasV6 = true
			}
		}
		if hasV4 && hasV6 {
			t.Failedf("backend pool %s/%s has mixed address families (backends: %v)",
				poolRef.Namespace, poolRef.Name, backendIPs)
		}

		if hasV4 {
			for _, nodeIP := range ipv4NodeIPs {
				if !slices.Contains(backendIPs, nodeIP) {
					t.Failedf("IPv4 backend pool %s/%s missing node IP %s (backends: %v)",
						poolRef.Namespace, poolRef.Name, nodeIP, backendIPs)
				}
			}
		}
		if hasV6 {
			for _, nodeIP := range ipv6NodeIPs {
				if !slices.Contains(backendIPs, nodeIP) {
					t.Failedf("IPv6 backend pool %s/%s missing node IP %s (backends: %v)",
						poolRef.Namespace, poolRef.Name, nodeIP, backendIPs)
				}
			}
		}
	}
}
