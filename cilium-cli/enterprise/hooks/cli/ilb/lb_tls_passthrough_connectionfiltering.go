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
)

func TestTLSPassthroughConnectionFiltering(t T) {
	testCases := []struct {
		desc      string
		appOpt    func(clients []*frrContainer) tlsPassthroughRouteOption
		testCalls []testCall
	}{
		{
			desc: "deny-by-sourceip",
			appOpt: func(clients []*frrContainer) tlsPassthroughRouteOption {
				return withTLSPassthroughConnectionFilteringDenyBySourceIP(clients[1].ip + "/32")
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
			appOpt: func(clients []*frrContainer) tlsPassthroughRouteOption {
				return withTLSPassthroughConnectionFilteringAllowBySourceIP(clients[1].ip + "/32")
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
		if skipIfOnSingleNode(">1 FRR clients are not supported") {
			continue
		}

		fmt.Printf("Checking %s\n", tC.desc)

		testName := fmt.Sprintf("tls-passthrough-connectionfiltering-%s", tC.desc)
		testK8sNamespace := "default"

		ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
		dockerCli := NewDockerCli(t)

		// 0. Setup test scenario (backends, clients & LB resources)
		scenario := newLBTestScenario(t, testName, testK8sNamespace, ciliumCli, k8sCli, dockerCli)

		fmt.Println("Creating cert and secret...")
		scenario.createBackendServerCertificate("secure.acme.io")

		fmt.Println("Creating backend apps...")
		backend := scenario.addBackendApplications(1, backendApplicationConfig{tlsCertHostname: "secure.acme.io", listenPort: 8080})[0]

		fmt.Println("Creating clients and add BGP peering ...")
		clients := scenario.addFRRClients(2, frrClientConfig{trustedCertsHostnames: []string{"secure.acme.io"}})

		fmt.Println("Creating LB VIP resources...")
		vip := lbVIP(testK8sNamespace, testName)
		scenario.createLBVIP(vip)

		fmt.Println("Creating LB BackendPool resources...")
		backendPool1 := lbBackendPool(testK8sNamespace, testName, withIPBackend(backend.ip, 8080), withHealthCheckTLS())
		scenario.createLBBackendPool(backendPool1)

		fmt.Println("Creating LB Service resources...")
		service := lbService(testK8sNamespace, testName, withTLSPassthroughApplication(
			withTLSPassthroughRoute(testName, tC.appOpt(clients)),
		))
		scenario.createLBService(service)

		fmt.Println("Waiting for full VIP connectivity...")
		vipIP := scenario.waitForFullVIPConnectivity(testName)

		for _, tt := range tC.testCalls {
			testCmd := curlCmdVerbose(fmt.Sprintf("--max-time 10 --cacert /tmp/%s --resolve %s:80:%s https://%s:80/", tt.hostName+".crt", tt.hostName, vipIP, tt.hostName))
			fmt.Printf("Testing %q...\n", testCmd)
			eventually(t, func() error {
				stdout, stderr, err := clients[tt.clientNr].Exec(t.Context(), testCmd)
				if !tt.blocked && err != nil {
					return fmt.Errorf("curl failed (cmd: %q, stdout: %q, stderr: %q): %w", testCmd, stdout, stderr, err)
				} else if tt.blocked && (err == nil || err.Error() != "cmd failed: 35") {
					return fmt.Errorf("curl request wasn't filtered (cmd: %q, stdout: %q, stderr: %q): %w", testCmd, stdout, stderr, err)
				}

				return nil
			}, shortTimeout, pollInterval)
		}
	}
}
