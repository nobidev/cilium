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

func TestHTTPSConnectionFiltering(t T) {
	testCases := []struct {
		desc      string
		appOpt    func(clients []*frrContainer) httpsApplicationOption
		testCalls []testCall
	}{
		{
			desc: "deny-by-sourceip",
			appOpt: func(clients []*frrContainer) httpsApplicationOption {
				return withHttpsConnectionFilteringDenyBySourceIP(clients[1].ipv4 + "/32")
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
			appOpt: func(clients []*frrContainer) httpsApplicationOption {
				return withHttpsConnectionFilteringAllowBySourceIP(clients[1].ipv4 + "/32")
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

			testName := fmt.Sprintf("https-connectionfiltering-%s", tC.desc)

			ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
			dockerCli := NewDockerCli(t)

			// 0. Setup test scenario (backends, clients & LB resources)
			scenario := newLBTestScenario(t, testName, ciliumCli, k8sCli, dockerCli)

			t.Log("Creating cert and secret...")
			scenario.createLBServerCertificate(testName, "secure.acme.io")

			t.Log("Creating backend apps...")
			scenario.addBackendApplications(2, backendApplicationConfig{h2cEnabled: true})

			t.Log("Creating clients and add BGP peering ...")
			clients := scenario.addFRRClients(2, frrClientConfig{trustedCertsHostnames: []string{"secure.acme.io"}})

			t.Log("Creating LB VIP resources...")
			vip := lbVIP(testName)
			scenario.createLBVIP(vip)

			t.Log("Creating LB BackendPool resources...")
			backends := []backendPoolOption{}
			for _, b := range scenario.backendApps {
				backends = append(backends, withIPBackend(b.ipv4, b.port))
			}
			backendPool := lbBackendPool(testName, backends...)
			scenario.createLBBackendPool(backendPool)

			t.Log("Creating LB Service resources...")
			opts := []httpsApplicationOption{}
			opts = append(opts, withHttpsRoute(testName, withHttpsHostname("secure.acme.io")))
			opts = append(opts, withCertificate(testName))
			opts = append(opts, tC.appOpt(clients))
			service := lbService(testName, withPort(443), withHTTPSProxyApplication(opts...))
			scenario.createLBService(service)

			t.Log("Waiting for full VIP connectivity...")
			vipIP := scenario.waitForFullVIPConnectivity(testName)

			for _, tt := range tC.testCalls {
				testCmd := curlCmdVerbose(fmt.Sprintf("--max-time 10 --cacert /tmp/%s.crt --resolve %s:443:%s https://%s:443%s", tt.hostName, tt.hostName, vipIP, tt.hostName, tt.path))
				t.Log("Testing %q...", testCmd)
				eventually(t, func() error {
					stdout, stderr, err := clients[tt.clientNr].Exec(t.Context(), testCmd)
					if !tt.blocked && err != nil {
						return fmt.Errorf("curl failed (cmd: %q, stdout: %q, stderr: %q): %w", testCmd, stdout, stderr, err)
					} else if tt.blocked && (err == nil || err.Error() != "cmd failed: 16") {
						return fmt.Errorf("curl request wasn't filtered (cmd: %q, stdout: %q, stderr: %q): %w", testCmd, stdout, stderr, err)
					}

					return nil
				}, shortTimeout, pollInterval)
			}
		})
	}
}
