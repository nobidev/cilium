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

func TestTLSProxyConnectionFiltering(t T) {
	testCases := []struct {
		desc      string
		appOpt    func(clients []*frrContainer) tlsRouteOption
		testCalls []testCall
	}{
		{
			desc: "deny-by-sourceip",
			appOpt: func(clients []*frrContainer) tlsRouteOption {
				return withTLSProxyConnectionFilteringDenyBySourceIP(clients[1].ip + "/32")
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
			appOpt: func(clients []*frrContainer) tlsRouteOption {
				return withTLSProxyConnectionFilteringAllowBySourceIP(clients[1].ip + "/32")
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

		testName := fmt.Sprintf("tls-proxy-connectionfiltering-%s", tC.desc)
		testK8sNamespace := "default"

		ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
		dockerCli := NewDockerCli(t)

		// 0. Setup test scenario (backends, clients & LB resources)
		scenario := newLBTestScenario(t, testName, testK8sNamespace, ciliumCli, k8sCli, dockerCli)

		fmt.Println("Creating cert and secret...")

		scenario.createLBServerCertificate(testName, "secure.acme.io")

		fmt.Println("Creating backend app...")

		backends := scenario.addBackendApplications(1, backendApplicationConfig{h2cEnabled: true})

		fmt.Println("Creating client and add BGP peering...")

		clients := scenario.addFRRClients(2, frrClientConfig{trustedCertsHostnames: []string{"secure.acme.io"}})

		fmt.Println("Creating LB VIP resources...")

		vip := lbVIP(testK8sNamespace, testName)
		scenario.createLBVIP(vip)

		fmt.Println("Creating LB BackendPool resources...")

		backendPool := lbBackendPool(testK8sNamespace, testName, withIPBackend(backends[0].ip, backends[0].port))
		scenario.createLBBackendPool(backendPool)

		fmt.Println("Creating LB Service resources...")

		opts := []tlsRouteOption{}
		opts = append(opts, withHostname("secure.acme.io"))
		opts = append(opts, tC.appOpt(clients))
		service := lbService(testK8sNamespace, testName, withPort(10080), withTLSProxyApplication(withTLSCertificate(testName), withTLSProxyRoute(backendPool.Name, opts...)))
		scenario.createLBService(service)

		fmt.Println("Waiting for full VIP connectivity...")
		vipIP := scenario.waitForFullVIPConnectivity(testName)

		for _, tt := range tC.testCalls {
			testCmd := curlCmdVerbose(fmt.Sprintf("--max-time 10 --cacert /tmp/%s.crt --resolve %s:10080:%s https://%s:10080/", tt.hostName, tt.hostName, vipIP, tt.hostName))
			fmt.Printf("Testing %q...\n", testCmd)
			eventually(t, func() error {
				stdout, stderr, err := clients[tt.clientNr].Exec(t.Context(), testCmd)
				if !tt.blocked && err != nil {
					return fmt.Errorf("curl failed (cmd: %q, stdout: %q, stderr: %q): %w", testCmd, stdout, stderr, err)
				} else if tt.blocked && (err == nil || err.Error() != "cmd failed: 52") {
					return fmt.Errorf("curl request wasn't filtered (cmd: %q, stdout: %q, stderr: %q): %w", testCmd, stdout, stderr, err)
				}

				return nil
			}, shortTimeout, pollInterval)
		}
	}
}
