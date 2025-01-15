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

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

func TestTCPProxyConnectionFiltering(t *testing.T) {
	for _, forceDeploymentMode := range []isovalentv1alpha1.LBTCPProxyForceDeploymentModeType{isovalentv1alpha1.LBTCPProxyForceDeploymentModeT1, isovalentv1alpha1.LBTCPProxyForceDeploymentModeT2, isovalentv1alpha1.LBTCPProxyForceDeploymentModeAuto} {

		ciliumCli, k8sCli := newCiliumAndK8sCli(t)
		dockerCli := newDockerCli(t)

		testK8sNamespace := "default"

		t.Run("Test TCPProxy force mode "+string(forceDeploymentMode), func(t *testing.T) {
			testCases := []struct {
				desc      string
				appOpt    func(clients []*frrContainer) tcpRouteOption
				testCalls []testCall
			}{
				{
					desc: "deny-by-sourceip",
					appOpt: func(clients []*frrContainer) tcpRouteOption {
						return withTCPProxyConnectionFilteringDenyBySourceIP(clients[1].ip + "/32")
					},
					testCalls: []testCall{
						{
							clientNr: 0,
							hostName: "secure.acme.io",
							path:     "/",
							blocked:  false,
						},
						{
							clientNr: 1,
							hostName: "secure.acme.io",
							path:     "/",
							blocked:  true,
						},
					},
				},
				{
					desc: "allow-by-sourceip",
					appOpt: func(clients []*frrContainer) tcpRouteOption {
						return withTCPProxyConnectionFilteringAllowBySourceIP(clients[1].ip + "/32")
					},
					testCalls: []testCall{
						{
							clientNr: 0,
							hostName: "secure.acme.io",
							path:     "/",
							blocked:  true,
						},
						{
							clientNr: 1,
							hostName: "secure.acme.io",
							path:     "/",
							blocked:  false,
						},
					},
				},
			}
			for _, tC := range testCases {
				t.Run(tC.desc, func(t *testing.T) {
					skipIfOnSingleNode(t, ">1 FRR clients are not supported")

					ctx := context.Background()
					testName := fmt.Sprintf("tcp-proxy-connectionfiltering--%s-%s", string(forceDeploymentMode), tC.desc)

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

					service := lbService(testK8sNamespace, testName, withPort(80), withTCPProxyApplication(withTCPForceDeploymentMode(forceDeploymentMode), withTCPProxyRoute(backendPool.Name, tC.appOpt(clients))))
					scenario.createLBService(ctx, service)

					t.Logf("Waiting for full VIP connectivity of %q...", testName)
					vipIP := scenario.waitForFullVIPConnectivity(ctx, testName)

					maybeSysdump(t, testName, "")

					for _, tt := range tC.testCalls {
						testCmd := curlCmdVerbose(fmt.Sprintf("--max-time 5 --resolve %s:80:%s http://%s:80/", tt.hostName, vipIP, tt.hostName))
						t.Logf("Testing %q...", testCmd)
						eventually(t, func() error {
							stdout, stderr, err := clients[tt.clientNr].Exec(ctx, testCmd)
							if !tt.blocked && err != nil {
								return fmt.Errorf("curl failed (cmd: %q, stdout: %q, stderr: %q): %w", testCmd, stdout, stderr, err)
							} else if tt.blocked && (err == nil || err.Error() != fmt.Sprintf("cmd failed: %d", getTCPCurlBlockErrorCode(forceDeploymentMode))) {
								return fmt.Errorf("curl request wasn't filtered (cmd: %q, stdout: %q, stderr: %q): %w", testCmd, stdout, stderr, err)
							}

							return nil
						}, shortTimeout, pollInterval)
					}
				})
			}
		})
	}
}

func getTCPCurlBlockErrorCode(mode isovalentv1alpha1.LBTCPProxyForceDeploymentModeType) int {
	switch mode {
	case isovalentv1alpha1.LBTCPProxyForceDeploymentModeT2:
		return 52 // empty reply
	default: // t1, auto
		return 28 // timeout
	}
}
