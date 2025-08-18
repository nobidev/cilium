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

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

func TestTCPProxyT1OnlyPersistentBackend(t T) {
	testTCPProxyPersistentBackend(t, isovalentv1alpha1.LBTCPProxyForceDeploymentModeT1)
}

func TestTCPProxyT1T2PersistentBackend(t T) {
	testTCPProxyPersistentBackend(t, isovalentv1alpha1.LBTCPProxyForceDeploymentModeT2)
}

func TestTCPProxyAutoPersistentBackend(t T) {
	testTCPProxyPersistentBackend(t, isovalentv1alpha1.LBTCPProxyForceDeploymentModeAuto)
}

func testTCPProxyPersistentBackend(t T, forceDeploymentMode isovalentv1alpha1.LBTCPProxyForceDeploymentModeType) {
	if skipIfOnSingleNode(">1 FRR clients are not supported") {
		return
	}

	testName := fmt.Sprintf("tcp-proxy-persistent-backend-%s", forceDeploymentMode)

	ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
	dockerCli := NewDockerCli(t)

	scenario := newLBTestScenario(t, testName, ciliumCli, k8sCli, dockerCli)

	t.Log("Creating backend app...")

	scenario.addBackendApplications(2, backendApplicationConfig{h2cEnabled: true})

	t.Log("Creating client and add BGP peering...")

	clients := scenario.addFRRClients(2, frrClientConfig{})

	t.Log("Creating LB VIP resources...")

	vip := lbVIP(testName)
	scenario.createLBVIP(vip)

	t.Log("Creating LB BackendPool resources...")

	backends := []backendPoolOption{}
	backends = append(backends, withConsistentHashing())
	for _, b := range scenario.backendApps {
		backends = append(backends, withIPBackend(b.ip, b.port))
	}
	backendPool := lbBackendPool(testName, backends...)
	scenario.createLBBackendPool(backendPool)

	t.Log("Creating LB Service resources...")

	service := lbService(testName, withPort(80), withTCPProxyApplication(withTCPForceDeploymentMode(forceDeploymentMode), withTCPProxyRoute(backendPool.Name, withTCPProxyBackendPersistenceBySourceIP())))
	scenario.createLBService(service)

	t.Log("Waiting for full VIP connectivity...")
	vipIP := scenario.waitForFullVIPConnectivity(testName)

	// 1. Test persistent backend selection with source IP
	{
		testCmd := curlCmd(fmt.Sprintf("--max-time 10 -H 'Content-Type: application/json' http://%s:80/", vipIP))
		t.Log("Testing backend selection persistence of 100 requests: %q...", testCmd)
		testPersistenceWith100Requests(t, clients[0], testCmd)
	}

	{
		testCmd := curlCmd(fmt.Sprintf("--max-time 10 -H 'Content-Type: application/json' http://%s:80/", vipIP))
		t.Log("Testing backend selection persistence of 100 requests: %q...", testCmd)
		testPersistenceWith100Requests(t, clients[1], testCmd)
	}
}
