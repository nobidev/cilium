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
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

func TestTCPProxyPersistentBackend() {
	if skipIfOnSingleNode(">1 FRR clients are not supported") {
		return
	}

	ctx := context.Background()
	ns := "default"
	testName := "tcp-proxy-persistent-backend"

	ciliumCli, k8sCli := NewCiliumAndK8sCli()
	dockerCli := NewDockerCli()

	scenario := newLBTestScenario(testName, ns, ciliumCli, k8sCli, dockerCli)

	fmt.Println("Creating backend app...")

	scenario.addBackendApplications(ctx, 2, backendApplicationConfig{h2cEnabled: true})

	fmt.Println("Creating client and add BGP peering...")

	clients := scenario.addFRRClients(ctx, 2, frrClientConfig{})

	fmt.Println("Creating LB VIP resources...")

	vip := lbVIP(ns, testName)
	scenario.createLBVIP(ctx, vip)

	fmt.Println("Creating LB BackendPool resources...")

	backends := []backendPoolOption{}
	for _, b := range scenario.backendApps {
		backends = append(backends, withIPBackend(b.ip, b.port))
	}
	backendPool := lbBackendPool(ns, testName, backends...)
	backendPool.Spec.Loadbalancing = &isovalentv1alpha1.Loadbalancing{
		Algorithm: isovalentv1alpha1.LoadbalancingAlgorithm{
			ConsistentHashing: &isovalentv1alpha1.LoadbalancingAlgorithmConsistentHashing{},
		},
	}
	scenario.createLBBackendPool(ctx, backendPool)

	fmt.Println("Creating LB Service resources...")

	service := lbService(ns, testName, withPort(80), withTCPProxyApplication(withTCPProxyRoute(backendPool.Name, withTCPProxyBackendPersistenceBySourceIP())))
	scenario.createLBService(ctx, service)

	maybeSysdump(testName, "")

	fmt.Println("Waiting for full VIP connectivity...")
	vipIP := scenario.waitForFullVIPConnectivity(ctx, testName)

	// 1. Test persistent backend selection with source IP
	{
		testCmd := curlCmd(fmt.Sprintf("--max-time 10 -H 'Content-Type: application/json' http://%s:80/", vipIP))
		fmt.Printf("Testing backend selection persistence of 100 requests: %q...\n", testCmd)
		testPersistenceWith100Requests(ctx, clients[0], testCmd)
	}

	{
		testCmd := curlCmd(fmt.Sprintf("--max-time 10 -H 'Content-Type: application/json' http://%s:80/", vipIP))
		fmt.Printf("Testing backend selection persistence of 100 requests: %q...\n", testCmd)
		testPersistenceWith100Requests(ctx, clients[1], testCmd)
	}
}

func TestTCPProxyPersistentBackend_Fail_T1Only() {
	ctx := context.Background()
	ns := "default"
	testName := "tcp-proxy-persistent-backend-fail-t1-only"

	ciliumCli, _ := NewCiliumAndK8sCli()

	service := lbService(ns, testName, withPort(10080), withTCPProxyApplication(withTCPForceDeploymentMode(isovalentv1alpha1.LBTCPProxyForceDeploymentModeT1), withTCPProxyRoute("fake", withTCPProxyBackendPersistenceBySourceIP())))

	err := ciliumCli.CreateLBService(ctx, ns, service, metav1.CreateOptions{})
	if err == nil {
		fatalf("CreabeLBService should return an error")
	}

	if !strings.Contains(err.Error(), "Force deployment mode t1-only isn't compatible with persistent backends and rate limits") {
		fatalf("CreateLBService returned the wrong error")
	}
}
