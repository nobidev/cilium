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
)

func TestUDPProxyConnectionFiltering(t *testing.T) {
	for _, forceDeploymentMode := range allUdpForceDeploymentModes {

		ciliumCli, k8sCli := newCiliumAndK8sCli(t)
		dockerCli := newDockerCli(t)

		testK8sNamespace := "default"

		t.Run("Test UDPProxy force mode "+string(forceDeploymentMode), func(t *testing.T) {
			testCases := []struct {
				desc      string
				appOpt    func(clients []*frrContainer) udpRouteOption
				testCalls []udpTestCall
			}{
				{
					desc: "deny-by-sourceip",
					appOpt: func(clients []*frrContainer) udpRouteOption {
						return withUDPProxyConnectionFilteringDenyBySourceIP(clients[1].ip + "/32")
					},
					testCalls: []udpTestCall{
						{
							clientNr: 0,
							blocked:  false,
						},
						{
							clientNr: 1,
							blocked:  true,
						},
					},
				},
				{
					desc: "allow-by-sourceip",
					appOpt: func(clients []*frrContainer) udpRouteOption {
						return withUDPProxyConnectionFilteringAllowBySourceIP(clients[1].ip + "/32")
					},
					testCalls: []udpTestCall{
						{
							clientNr: 0,
							blocked:  true,
						},
						{
							clientNr: 1,
							blocked:  false,
						},
					},
				},
			}
			for _, tC := range testCases {
				t.Run(tC.desc, func(t *testing.T) {
					skipIfOnSingleNode(t, ">1 FRR clients are not supported")

					ctx := context.Background()
					testName := fmt.Sprintf("udp-proxy-connectionfiltering--%s-%s", string(forceDeploymentMode), tC.desc)

					// 0. Setup test scenario (backends, clients & LB resources)
					scenario := newLBTestScenario(t, testName, testK8sNamespace, ciliumCli, k8sCli, dockerCli)

					t.Log("Creating backend app...")

					backends := scenario.addBackendApplications(ctx, 1, backendApplicationConfig{h2cEnabled: true})

					t.Log("Creating client and add BGP peering...")

					clients := scenario.addFRRClients(ctx, 2, frrClientConfig{})

					t.Logf("Creating LB VIP resources...")

					vip := lbVIP(testK8sNamespace, testName)
					scenario.createLBVIP(ctx, vip)

					t.Log("Creating LB BackendPool resources...")

					backendPool := lbBackendPool(testK8sNamespace, testName, withIPBackend(backends[0].ip, backends[0].port))
					scenario.createLBBackendPool(ctx, backendPool)

					t.Log("Creating LB Service resources...")

					service := lbService(testK8sNamespace, testName, withPort(80), withUDPProxyApplication(withUDPForceDeploymentMode(forceDeploymentMode), withUDPProxyRoute(backendPool.Name, tC.appOpt(clients))))
					scenario.createLBService(ctx, service)

					t.Logf("Waiting for full VIP connectivity of %q...", testName)
					vipIP := scenario.waitForFullVIPConnectivity(ctx, testName)

					maybeSysdump(t, testName, "")

					for _, tt := range tC.testCalls {
						testCmd := fmt.Sprintf("echo -n deadbeef | nc -n -v -u -w 1 %s 80", vipIP)
						t.Logf("Testing %q...", testCmd)
						eventually(t, func() error {
							t.Logf("Sending UDP request: cmd='%q'", testCmd)

							stdout, stderr, err := clients[tt.clientNr].Exec(ctx, testCmd)
							if err != nil {
								// we never expect an error (netcat doesn't return error in case of timeout)
								return fmt.Errorf("unexpected error %w", err)
							}

							if !tt.blocked {
								resp := toTestAppUDPResponse(t, stdout)
								if resp.Response != "deadbeef" {
									return fmt.Errorf("UDP request returned unexpected response (cmd: %q, stdout: %q, stderr: %q, resp: %q): %w", testCmd, stdout, stderr, resp.Response, err)
								}
							} else if tt.blocked && stdout != "" {
								return fmt.Errorf("UDP request wasn't filtered (cmd: %q, stdout: %q, stderr: %q): %w", testCmd, stdout, stderr, err)
							}

							return nil
						}, shortTimeout, pollInterval)
					}
				})
			}
		})
	}
}

type udpTestCall struct {
	clientNr int
	blocked  bool
}
