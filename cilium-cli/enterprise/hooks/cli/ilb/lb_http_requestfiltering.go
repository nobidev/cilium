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
)

func TestHTTPRequestFiltering() {
	testCases := []struct {
		desc      string
		appOpt    func(clients []*frrContainer) httpApplicationRouteOption
		testCalls []testCall
	}{
		{
			desc: "deny-by-exact-path",
			appOpt: func(clients []*frrContainer) httpApplicationRouteOption {
				return withHttpRequestFilteringDenyByExactPath("/admin")
			},
			testCalls: []testCall{
				{
					clientNr: 0,
					hostName: "insecure.acme.io",
					path:     "/",
					blocked:  false,
				},
				{
					clientNr: 0,
					hostName: "insecure.acme.io",
					path:     "/admin/users",
					blocked:  false,
				},
				{
					clientNr: 0,
					hostName: "insecure.acme.io",
					path:     "/admin",
					blocked:  true,
				},
			},
		},
		{
			desc: "deny-by-prefix-path",
			appOpt: func(clients []*frrContainer) httpApplicationRouteOption {
				return withHttpRequestFilteringDenyByPrefixPath("/admin")
			},
			testCalls: []testCall{
				{
					clientNr: 0,
					hostName: "insecure.acme.io",
					path:     "/path",
					blocked:  false,
				},
				{
					clientNr: 0,
					hostName: "insecure.acme.io",
					path:     "/admin",
					blocked:  true,
				},
				{
					clientNr: 0,
					hostName: "insecure.acme.io",
					path:     "/admin/users",
					blocked:  true,
				},
			},
		},
		{
			desc: "deny-by-exact-hostname",
			appOpt: func(clients []*frrContainer) httpApplicationRouteOption {
				return withHttpRequestFilteringDenyByExactHostname("insecure2.acme.io")
			},
			testCalls: []testCall{
				{
					clientNr: 0,
					hostName: "insecure.acme.io",
					path:     "/",
					blocked:  false,
				},
				{
					clientNr: 0,
					hostName: "admin.insecure2.acme.io",
					path:     "/",
					blocked:  false,
				},
				{
					clientNr: 0,
					hostName: "insecure2.acme.io",
					path:     "/",
					blocked:  true,
				},
			},
		},
		{
			desc: "deny-by-suffix-hostname",
			appOpt: func(clients []*frrContainer) httpApplicationRouteOption {
				return withHttpRequestFilteringDenyBySuffixHostname("insecure.acme.io")
			},
			testCalls: []testCall{
				{
					clientNr: 0,
					hostName: "secure.acme.io",
					path:     "/",
					blocked:  false,
				},
				{
					clientNr: 0,
					hostName: "insecure.acme.io",
					path:     "/",
					blocked:  true,
				},
				{
					clientNr: 0,
					hostName: "admin.insecure.acme.io",
					path:     "/",
					blocked:  true,
				},
			},
		},
		{
			desc: "deny-by-sourceip",
			appOpt: func(clients []*frrContainer) httpApplicationRouteOption {
				return withHttpRequestFilteringDenyBySourceIP(clients[1].ip + "/32")
			},
			testCalls: []testCall{
				{
					clientNr: 0,
					hostName: "insecure.acme.io",
					path:     "/",
					blocked:  false,
				},
				{
					clientNr: 1,
					hostName: "insecure.acme.io",
					path:     "/",
					blocked:  true,
				},
			},
		},
		{
			desc: "deny-by-sourceip-hostname-path",
			appOpt: func(clients []*frrContainer) httpApplicationRouteOption {
				return withHttpRequestFilteringDenyBySourceIPExactHostnameExactPath(clients[1].ip+"/32", "insecure2.acme.io", "/admin")
			},
			testCalls: []testCall{
				{
					clientNr: 0,
					hostName: "insecure.acme.io",
					path:     "/",
					blocked:  false,
				},
				{
					clientNr: 1,
					hostName: "insecure.acme.io",
					path:     "/",
					blocked:  false,
				},
				{
					clientNr: 1,
					hostName: "insecure2.acme.io",
					path:     "/",
					blocked:  false,
				},
				{
					clientNr: 1,
					hostName: "insecure.acme.io",
					path:     "/admin",
					blocked:  false,
				},
				{
					clientNr: 0,
					hostName: "insecure2.acme.io",
					path:     "/admin",
					blocked:  false,
				},
				{
					clientNr: 1,
					hostName: "insecure2.acme.io",
					path:     "/admin",
					blocked:  true,
				},
			},
		},
		{
			desc: "allow-by-sourceip-hostname-path",
			appOpt: func(clients []*frrContainer) httpApplicationRouteOption {
				return withHttpRequestFilteringAllowBySourceIPExactHostnameExactPath(clients[1].ip+"/32", "insecure2.acme.io", "/admin")
			},
			testCalls: []testCall{
				{
					clientNr: 0,
					hostName: "insecure.acme.io",
					path:     "/",
					blocked:  true,
				},
				{
					clientNr: 0,
					hostName: "insecure2.acme.io",
					path:     "/admin",
					blocked:  true,
				},
				{
					clientNr: 1,
					hostName: "insecure2.acme.io",
					path:     "/admin",
					blocked:  false,
				},
			},
		},
	}
	for _, tC := range testCases {
		if skipIfOnSingleNode(">1 FRR clients are not supported") {
			continue
		}

		fmt.Printf("=== RUN   TestHTTPRequestFiltering/%s\n", tC.desc)

		ctx := context.Background()
		testName := fmt.Sprintf("http-requestfiltering-%s", tC.desc)
		testK8sNamespace := "default"

		ciliumCli, k8sCli := NewCiliumAndK8sCli()
		dockerCli := NewDockerCli()

		// 0. Setup test scenario (backends, clients & LB resources)
		scenario := newLBTestScenario(testName, testK8sNamespace, ciliumCli, k8sCli, dockerCli)

		fmt.Println("Creating backend apps...")
		scenario.addBackendApplications(ctx, 2, backendApplicationConfig{h2cEnabled: true})

		fmt.Println("Creating clients and add BGP peering ...")
		clients := scenario.addFRRClients(ctx, 2, frrClientConfig{})

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
		service := lbService(testK8sNamespace, testName, withHTTPProxyApplication(withHttpRoute(testName, tC.appOpt(clients))))
		scenario.createLBService(ctx, service)

		maybeSysdump(testName, "")

		fmt.Println("Waiting for full VIP connectivity...")
		vipIP := scenario.waitForFullVIPConnectivity(ctx, testName)

		for _, tt := range tC.testCalls {
			testCmd := curlCmdVerbose(fmt.Sprintf("--max-time 10 --resolve %s:80:%s http://%s:80%s", tt.hostName, vipIP, tt.hostName, tt.path))
			fmt.Printf("Testing %q...\n", testCmd)
			eventually(func() error {
				stdout, stderr, err := clients[tt.clientNr].Exec(ctx, testCmd)
				if !tt.blocked && err != nil {
					return fmt.Errorf("curl failed (cmd: %q, stdout: %q, stderr: %q): %w", testCmd, stdout, stderr, err)
				} else if tt.blocked && (err == nil || err.Error() != "cmd failed: 22") {
					return fmt.Errorf("curl request wasn't filtered (cmd: %q, stdout: %q, stderr: %q): %w", testCmd, stdout, stderr, err)
				}

				return nil
			}, shortTimeout, pollInterval)
		}
	}
}
