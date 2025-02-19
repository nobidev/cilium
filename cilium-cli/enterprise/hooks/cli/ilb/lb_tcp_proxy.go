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

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

func TestTCPProxy() {
	fmt.Println("=== RUN   TestTCPProxy")

	for _, mode := range []isovalentv1alpha1.LBTCPProxyForceDeploymentModeType{isovalentv1alpha1.LBTCPProxyForceDeploymentModeT1, isovalentv1alpha1.LBTCPProxyForceDeploymentModeT2, isovalentv1alpha1.LBTCPProxyForceDeploymentModeAuto} {
		ciliumCli, k8sCli := NewCiliumAndK8sCli()
		dockerCli := NewDockerCli()

		testK8sNamespace := "default"

		fmt.Println("=== RUN   TestTCPProxy/Test TCPProxy force mode " + string(mode))

		ctx := context.Background()
		testName := "tcp-proxy-" + string(mode)

		// 0. Setup test scenario (backends, clients & LB resources)
		scenario := newLBTestScenario(testName, testK8sNamespace, ciliumCli, k8sCli, dockerCli)

		fmt.Println("Creating backend apps...")

		backendNum := 2
		// TCPProxy does not support backends with different ports, so create just 1 backend.
		if IsSingleNode() {
			backendNum = 1
		}
		scenario.addBackendApplications(ctx, backendNum, backendApplicationConfig{h2cEnabled: true})

		fmt.Println("Creating clients and add BGP peering ...")
		client := scenario.addFRRClients(ctx, 1, frrClientConfig{})[0]

		fmt.Println("Creating LB VIP resources...")
		vip := lbVIP(testK8sNamespace, testName)
		scenario.createLBVIP(ctx, vip)

		fmt.Println("Creating LB BackendPool resources...")
		backends := []backendPoolOption{}
		for _, b := range scenario.backendApps {
			backends = append(backends, withIPBackend(b.ip, b.port))
		}
		backendPool := lbBackendPool(testK8sNamespace, testName, backends...)
		scenario.createLBBackendPool(ctx, backendPool)

		fmt.Println("Creating LB Service resources...")
		service := lbService(testK8sNamespace, testName, withPort(80), withTCPProxyApplication(withTCPForceDeploymentMode(mode), withTCPProxyRoute(backendPool.Name)))
		scenario.createLBService(ctx, service)

		maybeSysdump(testName, "")

		fmt.Printf("Waiting for full VIP connectivity of %q...\n", testName)
		vipIP := scenario.waitForFullVIPConnectivity(ctx, testName)

		// 1. Send HTTP request to test basic client -> LB T1 -> LB T2 -> app connectivity
		testCmd := curlCmdVerbose(fmt.Sprintf("--max-time 10 http://%s:80/", vipIP))
		fmt.Printf("Testing %q...\n", testCmd)
		stdout, stderr, err := client.Exec(ctx, testCmd)
		if err != nil {
			fatalf("curl failed (cmd: %q, stdout: %q, stderr: %q): %s", testCmd, stdout, stderr, err)
		}
	}
}
