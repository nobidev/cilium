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

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestBGPHealthCheck(t T) {
	testName := "bgp-health-check"

	ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
	dockerCli := NewDockerCli(t)

	// 0. Setup test scenario (backends, clients & LB resources)
	scenario := newLBTestScenario(t, testName, ciliumCli, k8sCli, dockerCli)

	t.Log("Creating backend app...")
	backend := scenario.addBackendApplications(1, backendApplicationConfig{h2cEnabled: true})[0]

	t.Log("Creating client and add BGP peering ...")
	client := scenario.addFRRClients(1, frrClientConfig{})[0]

	t.Log("Creating LB VIP resources...")
	vip := lbVIP(testName)
	scenario.createLBVIP(vip)

	t.Log("Creating LB BackendPool resources...")
	backendPool := lbBackendPool(testName, withIPBackend(backend.ip, backend.port))
	scenario.createLBBackendPool(backendPool)

	t.Log("Creating LB Service resources...")
	service := lbService(testName, withHTTPProxyApplication(withHttpRoute(testName)))
	scenario.createLBService(service)

	t.Log("Waiting for full VIP connectivity...")
	vipIP := scenario.waitForFullVIPConnectivity(testName)

	// 1. HC Down
	t.Log("Setting T2 HC to fail...")
	backend.SetHC(t, hcFail)

	// 2. VIP shouldn't be advertised
	eventually(t, func() error {
		if err := client.EnsureRoute(t.Context(), vipIP+"/32"); err == nil {
			return fmt.Errorf("the route %s/32 still exists", vipIP)
		}
		return nil
	}, longTimeout, pollInterval)

	t.Log("VIP successfully removed")

	// 3. HC Up
	t.Log("Setting T2 HC to ok...")
	backend.SetHC(t, hcOK)

	// 4. VIP should be advertised
	eventually(t, func() error {
		if err := client.EnsureRoute(t.Context(), vipIP+"/32"); err != nil {
			return fmt.Errorf("the route %s/32 is missing %w", vipIP, err)
		}
		return nil
	}, longTimeout, pollInterval)

	t.Log("VIP successfully re-advertised")
}

func TestBGPHealthCheckSubset(t T) {
	testName := "bgp-health-check-subset"

	ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
	dockerCli := NewDockerCli(t)

	_, err := ciliumCli.IsovalentV1alpha1().LBDeployments("").List(t.Context(), metav1.ListOptions{})
	if err != nil {
		fmt.Printf("skipping due to LBDeployment not available: %s\n", err)
		return
	}

	nodeList, err := k8sCli.CoreV1().Nodes().List(t.Context(), metav1.ListOptions{
		LabelSelector: "service.cilium.io/node in (t1,t1-t2)",
	})
	if err != nil {
		t.Failedf("failed to list nodes: %v", err)
	}

	// select first T1 node only
	selectedNode := corev1.Node{}
	excludedNodes := []corev1.Node{}
	for i, n := range nodeList.Items {
		if i == 0 {
			selectedNode = n
			continue
		}

		excludedNodes = append(excludedNodes, n)
	}

	// 0. Setup test scenario (backends, clients & LB resources)
	scenario := newLBTestScenario(t, testName, ciliumCli, k8sCli, dockerCli)

	t.Log("Creating backend app...")
	backend := scenario.addBackendApplications(1, backendApplicationConfig{h2cEnabled: true})[0]

	t.Log("Creating client and add BGP peering ...")
	client := scenario.addFRRClients(1, frrClientConfig{})[0]

	t.Log("Creating LB VIP resources...")
	vip := lbVIP(testName)
	scenario.createLBVIP(vip)

	t.Log("Creating LB BackendPool resources...")
	backendPool := lbBackendPool(testName, withIPBackend(backend.ip, backend.port))
	scenario.createLBBackendPool(backendPool)

	t.Log("Creating LB Service resources...")
	service := lbService(testName, withLabels(map[string]string{"special-label": "special-label-value"}), withHTTPProxyApplication(withHttpRoute(testName)))
	scenario.createLBService(service)

	t.Log("Waiting for full VIP connectivity...")
	vipIP := scenario.waitForFullVIPConnectivity(testName)

	t.Log("Apply LBDeployment that selects only one T1 node...")
	lbDeployment := lbDeployment(testName, withT1Nodes(fmt.Sprintf("kubernetes.io/hostname in ( %s )", selectedNode.GetLabels()["kubernetes.io/hostname"])), WithServiceSelector("special-label == special-label-value"))
	scenario.createLBDeployment(lbDeployment)

	t.Log("Waiting until routes for VIP via unselected nodes are withdrawn...")
	eventually(t, func() error {
		for _, n := range excludedNodes {
			peerIP := getNodeIP(n)
			if err := client.EnsureRouteVia(t.Context(), vipIP+"/32", peerIP); err == nil {
				return fmt.Errorf("the route %s/32 via %s (%s) still exists", vipIP, peerIP, n.Name)
			}
		}
		return nil
	}, longTimeout, pollInterval)

	t.Log("Checking that route for VIP via selected node does still exist...")
	eventually(t, func() error {
		peerIP := getNodeIP(selectedNode)
		if err := client.EnsureRouteVia(t.Context(), vipIP+"/32", peerIP); err != nil {
			return fmt.Errorf("the route %s/32 via %s (%s) doesn't exist", vipIP, peerIP, selectedNode.Name)
		}
		return nil
	}, longTimeout, pollInterval)
}

func getNodeIP(n corev1.Node) string {
	for _, na := range n.Status.Addresses {
		if na.Type == corev1.NodeInternalIP {
			return na.Address
		}
	}

	return "unknown"
}
