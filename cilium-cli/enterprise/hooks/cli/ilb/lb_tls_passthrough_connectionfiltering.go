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

		t.RunTestCase(func(t T) {
			t.Log("Checking %s", tC.desc)

			testName := fmt.Sprintf("tls-passthrough-connectionfiltering-%s", tC.desc)

			ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
			dockerCli := NewDockerCli(t)

			// 0. Setup test scenario (backends, clients & LB resources)
			scenario := newLBTestScenario(t, testName, ciliumCli, k8sCli, dockerCli)

			t.Log("Creating cert and secret...")
			scenario.createBackendServerCertificate("secure.acme.io")

			t.Log("Creating backend apps...")
			backend := scenario.addBackendApplications(1, backendApplicationConfig{tlsCertHostname: "secure.acme.io", listenPort: 8080})[0]

			t.Log("Creating clients and add BGP peering ...")
			clients := scenario.addFRRClients(2, frrClientConfig{trustedCertsHostnames: []string{"secure.acme.io"}})

			t.Log("Creating LB VIP resources...")
			vip := lbVIP(testName)
			scenario.createLBVIP(vip)

			t.Log("Creating LB BackendPool resources...")
			backendPool1 := lbBackendPool(testName, withIPBackend(backend.ip, 8080), withHealthCheckTLS())
			scenario.createLBBackendPool(backendPool1)

			t.Log("Creating LB Service resources...")
			service := lbService(testName, withTLSPassthroughApplication(
				withTLSPassthroughRoute(testName, tC.appOpt(clients)),
			))
			scenario.createLBService(service)

			t.Log("Waiting for full VIP connectivity...")
			vipIP := scenario.waitForFullVIPConnectivity(testName)

			for _, tt := range tC.testCalls {
				testCmd := curlCmdVerbose(fmt.Sprintf("--max-time 10 --cacert /tmp/%s --resolve %s:80:%s https://%s:80/", tt.hostName+".crt", tt.hostName, vipIP, tt.hostName))
				t.Log("Testing %q...", testCmd)
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
		})

	}
}
