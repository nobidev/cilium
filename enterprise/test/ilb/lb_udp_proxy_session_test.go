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
	"testing"
	"time"
)

func TestUDPProxySession(t *testing.T) {
	for _, forceDeploymentMode := range allUdpForceDeploymentModes {
		ciliumCli, k8sCli := newCiliumAndK8sCli(t)
		dockerCli := newDockerCli(t)

		testK8sNamespace := "default"

		t.Run("Test UDPProxy force mode "+string(forceDeploymentMode), func(t *testing.T) {
			skipIfOnSingleNode(t, ">1 backends are not supported")

			ctx := context.Background()
			testName := "udp-proxy-" + string(forceDeploymentMode)

			// 0. Setup test scenario (backends, clients & LB resources)
			scenario := newLBTestScenario(t, testName, testK8sNamespace, ciliumCli, k8sCli, dockerCli)

			t.Log("Creating backend apps...")

			scenario.addBackendApplications(ctx, 2, backendApplicationConfig{h2cEnabled: true})

			t.Log("Creating clients and add BGP peering ...")
			client := scenario.addFRRClients(ctx, 1, frrClientConfig{})[0]

			t.Logf("Creating LB VIP resources...")
			vip := lbVIP(testK8sNamespace, testName)
			scenario.createLBVIP(ctx, vip)

			t.Logf("Creating LB BackendPool resources...")
			backends := []backendPoolOption{}
			for _, b := range scenario.backendApps {
				backends = append(backends, withIPBackend(b.ip, b.port))
			}
			backendPool := lbBackendPool(testK8sNamespace, testName, backends...)
			scenario.createLBBackendPool(ctx, backendPool)

			t.Logf("Creating LB Service resources...")
			service := lbService(testK8sNamespace, testName, withPort(80), withUDPProxyApplication(withUDPForceDeploymentMode(forceDeploymentMode), withUDPProxyRoute(backendPool.Name)))
			scenario.createLBService(ctx, service)

			t.Logf("Waiting for full VIP connectivity of %q...", testName)
			vipIP := scenario.waitForFullVIPConnectivity(ctx, testName)

			maybeSysdump(t, testName, "")

			// Send UDP request to test basic `client -> LB T1 -> app` connectivity.
			// Do a few attempts, as neither UDP nor nc are reliable.
			testCmd := fmt.Sprintf("echo -n deadbeef | nc -n -v -u -w 1 -p 55555 %s 80", vipIP)
			t.Logf("Testing UDP session with 10 requests from same source port: %q...", testCmd)
			testUDPSessionWithNRequests(t, ctx, client, testCmd, 10)
		})
	}
}

func testUDPSessionWithNRequests(t *testing.T, ctx context.Context, client *frrContainer, testCmd string, total int) {
	successCount := 0
	previousServiceName := ""
	eventually(t, func() error {
		stdout, _, err := client.Exec(ctx, testCmd)
		if err != nil {
			// we never expect an error (netcat doesn't return error in case of timeout)
			return fmt.Errorf("unexpected error %w", err)
		}

		if stdout == "" {
			// e.g. technical issue - we're only interested in sessions (-> backend  selection)
			return fmt.Errorf("empty response %w", err)
		}

		resp := toTestAppUDPResponse(t, stdout)

		assertPersistentBackend(t, previousServiceName, resp.ServiceName)
		previousServiceName = resp.ServiceName

		successCount++
		if successCount == total {
			return nil
		}

		return fmt.Errorf("condition is not satisfied yet (%d/%d)", successCount, total)
	}, longTimeout, time.Millisecond*1) // As fast as possible
}
