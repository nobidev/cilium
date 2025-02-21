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
	"time"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

func TestHTTPPersistentBackendWithCookie(t T) {
	testName := "pers-backend-cookie-1"
	testK8sNamespace := "default"

	ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
	dockerCli := NewDockerCli(t)

	// 0. Setup test scenario (backends, clients & LB resources)
	scenario := newLBTestScenario(t, testName, testK8sNamespace, ciliumCli, k8sCli, dockerCli)

	fmt.Println("Creating backend apps...")
	scenario.addBackendApplications(2, backendApplicationConfig{})

	fmt.Println("Creating clients and add BGP peering ...")
	client := scenario.addFRRClients(1, frrClientConfig{})[0]

	fmt.Println("Creating LB VIP resources...")
	vip := lbVIP(testK8sNamespace, testName)
	scenario.createLBVIP(vip)

	fmt.Println("Creating LB BackendPool resources...")
	backends := []backendPoolOption{}
	for _, b := range scenario.backendApps {
		backends = append(backends, withIPBackend(b.ip, b.port))
	}
	backendPool := lbBackendPool(testK8sNamespace, testName, backends...)
	backendPool.Spec.Loadbalancing = &isovalentv1alpha1.Loadbalancing{
		Algorithm: isovalentv1alpha1.LoadbalancingAlgorithm{
			ConsistentHashing: &isovalentv1alpha1.LoadbalancingAlgorithmConsistentHashing{},
		},
	}
	scenario.createLBBackendPool(backendPool)

	fmt.Println("Creating LB Service resources...")
	service := lbService(testK8sNamespace, testName, withHTTPProxyApplication(withHttpRoute(testName, withHttpBackendPersistenceByCookie("session"))))
	scenario.createLBService(service)

	fmt.Println("Waiting for full VIP connectivity...")
	vipIP := scenario.waitForFullVIPConnectivity(testName)

	// 1. Test persistent backend selection with cookie
	{
		testCmd := curlCmd(fmt.Sprintf("--max-time 10 -H 'Content-Type: application/json' --cookie 'session=123' http://%s:80/test1", vipIP))
		fmt.Printf("Testing backend selection persistence of 100 requests: %q...\n", testCmd)
		testPersistenceWith100Requests(t, client, testCmd)
	}

	{
		testCmd := curlCmd(fmt.Sprintf("--max-time 10 -H 'Content-Type: application/json' --cookie 'session=234' http://%s:80/test2", vipIP))
		fmt.Printf("Testing backend selection persistence of 100 requests: %q...\n", testCmd)
		testPersistenceWith100Requests(t, client, testCmd)
	}
}

func TestHTTPPersistentBackendWithSourceIP(t T) {
	if skipIfOnSingleNode(">1 FRR clients are not supported") {
		return
	}

	testName := "pers-backend-sourceip-1"
	testK8sNamespace := "default"

	ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
	dockerCli := NewDockerCli(t)

	// 0. Setup test scenario (backends, clients & LB resources)
	scenario := newLBTestScenario(t, testName, testK8sNamespace, ciliumCli, k8sCli, dockerCli)

	fmt.Println("Creating backend apps...")
	scenario.addBackendApplications(2, backendApplicationConfig{})

	fmt.Println("Creating clients and add BGP peering ...")
	clients := scenario.addFRRClients(2, frrClientConfig{})

	fmt.Println("Creating LB VIP resources...")
	vip := lbVIP(testK8sNamespace, testName)
	scenario.createLBVIP(vip)

	fmt.Println("Creating LB BackendPool resources...")
	backends := []backendPoolOption{}
	for _, b := range scenario.backendApps {
		backends = append(backends, withIPBackend(b.ip, b.port))
	}
	backendPool := lbBackendPool(testK8sNamespace, testName, backends...)
	backendPool.Spec.Loadbalancing = &isovalentv1alpha1.Loadbalancing{
		Algorithm: isovalentv1alpha1.LoadbalancingAlgorithm{
			ConsistentHashing: &isovalentv1alpha1.LoadbalancingAlgorithmConsistentHashing{},
		},
	}
	scenario.createLBBackendPool(backendPool)

	fmt.Println("Creating LB Service resources...")
	service := lbService(testK8sNamespace, testName, withHTTPProxyApplication(withHttpRoute(testName, withHttpBackendPersistenceBySourceIP())))
	scenario.createLBService(service)

	fmt.Println("Waiting for full VIP connectivity...")
	vipIP := scenario.waitForFullVIPConnectivity(testName)

	// 1. Test persistent backend selection with source IP
	{
		testCmd := curlCmd(fmt.Sprintf("--max-time 10 -H 'Content-Type: application/json' http://%s:80/test1", vipIP))
		fmt.Printf("Testing backend selection persistence of 100 requests: %q...\n", testCmd)
		testPersistenceWith100Requests(t, clients[0], testCmd)
	}

	{
		testCmd := curlCmd(fmt.Sprintf("--max-time 10 -H 'Content-Type: application/json' http://%s:80/test2", vipIP))
		fmt.Printf("Testing backend selection persistence of 100 requests: %q...\n", testCmd)
		testPersistenceWith100Requests(t, clients[1], testCmd)
	}
}

func testPersistenceWith100Requests(t T, client *frrContainer, testCmd string) {
	successCount := 0
	previousServiceName := ""
	eventually(t, func() error {
		stdout, stderr, err := client.Exec(t.Context(), testCmd)
		if err != nil {
			return fmt.Errorf("curl failed (cmd: %q, stdout: %q, stderr: %q): %w", testCmd, stdout, stderr, err)
		}

		resp := toTestAppResponse(t, stdout)
		assertPersistentBackend(t, previousServiceName, resp.ServiceName)
		previousServiceName = resp.ServiceName

		successCount++
		if successCount == 100 {
			return nil
		}

		return fmt.Errorf("condition is not satisfied yet (%d/100)", successCount)
	}, longTimeout, time.Millisecond*1) // As fast as possible
}

func assertPersistentBackend(t T, previousServiceName string, currentServiceName string) {
	if currentServiceName == "" {
		t.Failedf("no service name provided")
	}
	if previousServiceName != "" && previousServiceName != currentServiceName {
		t.Failedf("request serviced by different backend %s != %s", previousServiceName, currentServiceName)
	}
}
