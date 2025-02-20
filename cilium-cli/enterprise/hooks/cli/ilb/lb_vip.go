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
)

func TestSharedVIP() {
	ctx := context.Background()
	testName := "shared-vip-1"
	testK8sNamespace := "default"

	ciliumCli, k8sCli := NewCiliumAndK8sCli()
	dockerCli := NewDockerCli()

	// 0. Setup test scenario (backends, clients & LB resources)
	scenario := newLBTestScenario(testName, testK8sNamespace, ciliumCli, k8sCli, dockerCli)

	fmt.Println("Creating backend apps...")
	scenario.addBackendApplications(ctx, 2, backendApplicationConfig{h2cEnabled: true})

	fmt.Println("Creating clients and add BGP peering ...")
	client := scenario.addFRRClients(ctx, 1, frrClientConfig{})[0]

	fmt.Println("Creating LB VIP resources...")
	sharedVIPName := testName + "-shared"
	vip := lbVIP(testK8sNamespace, sharedVIPName)
	scenario.createLBVIP(ctx, vip)

	fmt.Println("Creating LB BackendPool resources...")
	backends := []backendPoolOption{}
	for _, b := range scenario.backendApps {
		backends = append(backends, withIPBackend(b.ip, b.port))
	}
	backendPool := lbBackendPool(testK8sNamespace, testName, backends...)
	scenario.createLBBackendPool(ctx, backendPool)

	fmt.Println("Creating LB Service resources...")
	service1 := lbService(testK8sNamespace, testName+"-1", withVIPRef(sharedVIPName), withPort(80), withHTTPProxyApplication(withHttpRoute(testName)))
	scenario.createLBService(ctx, service1)

	service2 := lbService(testK8sNamespace, testName+"-2", withVIPRef(sharedVIPName), withPort(81), withHTTPProxyApplication(withHttpRoute(testName)))
	scenario.createLBService(ctx, service2)

	fmt.Println("Waiting for full VIP connectivity...")
	vipIP := scenario.waitForFullVIPConnectivity(ctx, sharedVIPName)

	// 1. Send two HTTP requests on VIP for both services
	{
		testCmd := curlCmdVerbose(fmt.Sprintf("--max-time 10 http://%s:80/", vipIP))
		fmt.Printf("Testing %q...\n", testCmd)
		stdout, stderr, err := client.Exec(ctx, testCmd)
		if err != nil {
			fatalf("curl failed (cmd: %q, stdout: %q, stderr: %q): %s", testCmd, stdout, stderr, err)
		}
	}

	{
		testCmd := curlCmdVerbose(fmt.Sprintf("--max-time 10 http://%s:81/", vipIP))
		fmt.Printf("Testing %q...\n", testCmd)
		stdout, stderr, err := client.Exec(ctx, testCmd)
		if err != nil {
			fatalf("curl failed (cmd: %q, stdout: %q, stderr: %q): %s", testCmd, stdout, stderr, err)
		}
	}
}

func TestRequestedVIP() {
	ctx := context.Background()
	testName := "requested-vip-1"
	testK8sNamespace := "default"

	ciliumCli, k8sCli := NewCiliumAndK8sCli()
	dockerCli := NewDockerCli()

	// 0. Setup test scenario (backends, clients & LB resources)
	scenario := newLBTestScenario(testName, testK8sNamespace, ciliumCli, k8sCli, dockerCli)

	fmt.Println("Creating backend apps...")
	scenario.addBackendApplications(ctx, 2, backendApplicationConfig{h2cEnabled: true})

	fmt.Println("Creating clients and add BGP peering ...")
	client := scenario.addFRRClients(ctx, 1, frrClientConfig{})[0]

	fmt.Println("Creating LB VIP resources...")
	requestedVIP := "100.64.0.250"
	vip := lbVIP(testK8sNamespace, testName, withRequestedIPv4(requestedVIP))
	scenario.createLBVIP(ctx, vip)

	fmt.Println("Creating LB BackendPool resources...")
	backends := []backendPoolOption{}
	for _, b := range scenario.backendApps {
		backends = append(backends, withIPBackend(b.ip, b.port))
	}
	backendPool := lbBackendPool(testK8sNamespace, testName, backends...)
	scenario.createLBBackendPool(ctx, backendPool)

	fmt.Println("Creating LB Service resources...")
	service1 := lbService(testK8sNamespace, testName, withHTTPProxyApplication(withHttpRoute(testName)))
	scenario.createLBService(ctx, service1)

	fmt.Println("Waiting for full VIP connectivity...")
	_ = scenario.waitForFullVIPConnectivity(ctx, testName)

	// 1. Send HTTP request to requested VIP
	testCmd := curlCmdVerbose(fmt.Sprintf("--max-time 10 http://%s:80/", requestedVIP))
	fmt.Printf("Testing %q...\n", testCmd)
	stdout, stderr, err := client.Exec(ctx, testCmd)
	if err != nil {
		fatalf("curl failed (cmd: %q, stdout: %q, stderr: %q): %s", testCmd, stdout, stderr, err)
	}
}
