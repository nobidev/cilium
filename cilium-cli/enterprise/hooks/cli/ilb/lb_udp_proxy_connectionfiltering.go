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

func TestUDPProxyT1OnlyConnectionFiltering() {
	testUDPProxyConnectionFiltering(isovalentv1alpha1.LBUDPProxyForceDeploymentModeT1)
}

func TestUDPProxyT1T2ConnectionFiltering() {
	testUDPProxyConnectionFiltering(isovalentv1alpha1.LBUDPProxyForceDeploymentModeT2)
}

func TestUDPProxyAutoConnectionFiltering() {
	testUDPProxyConnectionFiltering(isovalentv1alpha1.LBUDPProxyForceDeploymentModeAuto)
}

func testUDPProxyConnectionFiltering(forceDeploymentMode isovalentv1alpha1.LBUDPProxyForceDeploymentModeType) {
	ciliumCli, k8sCli := NewCiliumAndK8sCli()
	dockerCli := NewDockerCli()

	testK8sNamespace := "default"

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
		fmt.Printf("Checking %s\n", tC.desc)

		if skipIfOnSingleNode(">1 FRR clients are not supported") {
			continue
		}

		ctx := context.Background()
		testName := fmt.Sprintf("udp-proxy-connectionfiltering-%s-%s", string(forceDeploymentMode), tC.desc)

		// 0. Setup test scenario (backends, clients & LB resources)
		scenario := newLBTestScenario(testName, testK8sNamespace, ciliumCli, k8sCli, dockerCli)

		fmt.Println("Creating backend app...")

		backends := scenario.addBackendApplications(ctx, 1, backendApplicationConfig{h2cEnabled: true})

		fmt.Println("Creating client and add BGP peering...")

		clients := scenario.addFRRClients(ctx, 2, frrClientConfig{})

		fmt.Println("Creating LB VIP resources...")

		vip := lbVIP(testK8sNamespace, testName)
		scenario.createLBVIP(ctx, vip)

		fmt.Println("Creating LB BackendPool resources...")

		backendPool := lbBackendPool(testK8sNamespace, testName, withIPBackend(backends[0].ip, backends[0].port))
		scenario.createLBBackendPool(ctx, backendPool)

		fmt.Println("Creating LB Service resources...")

		service := lbService(testK8sNamespace, testName, withPort(80), withUDPProxyApplication(withUDPForceDeploymentMode(forceDeploymentMode), withUDPProxyRoute(backendPool.Name, tC.appOpt(clients))))
		scenario.createLBService(ctx, service)

		maybeSysdump(testName, "")

		fmt.Println("Waiting for full VIP connectivity...")
		vipIP := scenario.waitForFullVIPConnectivity(ctx, testName)

		for _, tt := range tC.testCalls {
			testCmd := fmt.Sprintf("echo -n deadbeef | nc -n -v -u -w 1 %s 80", vipIP)
			fmt.Printf("Testing %q...\n", testCmd)
			eventually(func() error {
				fmt.Printf("Sending UDP request: cmd=%q\n", testCmd)

				stdout, stderr, err := clients[tt.clientNr].Exec(ctx, testCmd)
				if err != nil {
					// we never expect an error (netcat doesn't return error in case of timeout)
					return fmt.Errorf("unexpected error %w", err)
				}

				if !tt.blocked {
					resp := toTestAppUDPResponse(stdout)
					if resp.Response != "deadbeef" {
						return fmt.Errorf("UDP request returned unexpected response (cmd: %q, stdout: %q, stderr: %q, resp: %q): %w", testCmd, stdout, stderr, resp.Response, err)
					}
				} else if tt.blocked && stdout != "" {
					return fmt.Errorf("UDP request wasn't filtered (cmd: %q, stdout: %q, stderr: %q): %w", testCmd, stdout, stderr, err)
				}

				return nil
			}, shortTimeout, pollInterval)
		}
	}
}

type udpTestCall struct {
	clientNr int
	blocked  bool
}
