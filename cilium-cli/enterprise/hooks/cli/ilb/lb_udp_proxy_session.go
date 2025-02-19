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
	"time"
)

func TestUDPProxySession() {
	fmt.Println("=== RUN   TestUDPProxySession")

	for _, forceDeploymentMode := range allUdpForceDeploymentModes {
		ciliumCli, k8sCli := NewCiliumAndK8sCli()
		dockerCli := NewDockerCli()

		testK8sNamespace := "default"

		if skipIfOnSingleNode(">1 backends are not supported") {
			continue
		}

		fmt.Println("=== RUN   Test UDPProxySession force mode " + string(forceDeploymentMode))

		ctx := context.Background()
		testName := "udp-proxy-session-" + string(forceDeploymentMode)

		// 0. Setup test scenario (backends, clients & LB resources)
		scenario := newLBTestScenario(testName, testK8sNamespace, ciliumCli, k8sCli, dockerCli)

		fmt.Println("Creating backend apps...")

		scenario.addBackendApplications(ctx, 2, backendApplicationConfig{h2cEnabled: true})

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
		service := lbService(testK8sNamespace, testName, withPort(80), withUDPProxyApplication(withUDPForceDeploymentMode(forceDeploymentMode), withUDPProxyRoute(backendPool.Name)))
		scenario.createLBService(ctx, service)

		maybeSysdump(testName, "")

		fmt.Printf("Waiting for full VIP connectivity of %q...\n", testName)
		vipIP := scenario.waitForFullVIPConnectivity(ctx, testName)

		// Send UDP request to test basic `client -> LB T1 -> app` connectivity.
		// Do a few attempts, as neither UDP nor nc are reliable.
		testCmd := fmt.Sprintf("echo -n deadbeef | nc -n -v -u -w 1 -p 55555 %s 80", vipIP)
		fmt.Printf("Testing UDP session with 10 requests from same source port: %q...\n", testCmd)
		testUDPSessionWithNRequests(ctx, client, testCmd, 10)
	}
}

func testUDPSessionWithNRequests(ctx context.Context, client *frrContainer, testCmd string, total int) {
	successCount := 0
	previousServiceName := ""
	eventually(func() error {
		stdout, _, err := client.Exec(ctx, testCmd)
		if err != nil {
			// we never expect an error (netcat doesn't return error in case of timeout)
			return fmt.Errorf("unexpected error %w", err)
		}

		if stdout == "" {
			// e.g. technical issue - we're only interested in sessions (-> backend  selection)
			return fmt.Errorf("empty response %w", err)
		}

		resp := toTestAppUDPResponse(stdout)

		assertPersistentBackend(previousServiceName, resp.ServiceName)
		previousServiceName = resp.ServiceName

		successCount++
		if successCount == total {
			return nil
		}

		return fmt.Errorf("condition is not satisfied yet (%d/%d)", successCount, total)
	}, longTimeout, time.Millisecond*1) // As fast as possible
}
