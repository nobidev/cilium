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

	"github.com/cilium/cilium/pkg/versioncheck"
)

func TestHTTPRequestFiltering(t T) {
	ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
	dockerCli := NewDockerCli(t)

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
				return withHttpRequestFilteringDenyBySourceIP(clients[1].ipv4 + "/32")
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
				return withHttpRequestFilteringDenyBySourceIPExactHostnameExactPath(clients[1].ipv4+"/32", "insecure2.acme.io", "/admin")
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
				return withHttpRequestFilteringAllowBySourceIPExactHostnameExactPath(clients[1].ipv4+"/32", "insecure2.acme.io", "/admin")
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

	ciliumVersionSupportsHeaderBasedRequestFiltering := false

	minVersion := ">=1.18.0"
	currentVersion := GetCiliumVersion(t, k8sCli)
	if versioncheck.MustCompile(minVersion)(currentVersion) {
		ciliumVersionSupportsHeaderBasedRequestFiltering = true
	} else {
		fmt.Printf("skipping header based request filtering due to version mismatch - expected: %s - current: %s\n", minVersion, currentVersion.String())
	}

	if ciliumVersionSupportsHeaderBasedRequestFiltering {
		testCases = append(testCases, []struct {
			desc      string
			appOpt    func(clients []*frrContainer) httpApplicationRouteOption
			testCalls []testCall
		}{
			{
				desc: "allow-by-exact-headers",
				appOpt: func(clients []*frrContainer) httpApplicationRouteOption {
					return withHttpRequestFilteringAllowByExactHeader(map[string]string{
						"test-name1": "test-value1",
						"test-name2": "test-value2",
					})
				},
				testCalls: []testCall{
					{
						clientNr: 0,
						hostName: "insecure.acme.io",
						path:     "/",
						headers:  map[string]string{},
						blocked:  true,
					},
					{
						clientNr: 0,
						hostName: "insecure.acme.io",
						path:     "/",
						headers: map[string]string{
							"test-name1": "test-value1",
						},
						blocked: true,
					},
					{
						clientNr: 0,
						hostName: "insecure.acme.io",
						path:     "/",
						headers: map[string]string{
							"test-name1": "test-value1",
							"test-name2": "test-value2",
						},
						blocked: false,
					},
				},
			},
			{
				desc: "allow-by-prefix-headers",
				appOpt: func(clients []*frrContainer) httpApplicationRouteOption {
					return withHttpRequestFilteringAllowByPrefixHeader(map[string]string{
						"test-name1": "test-value1",
						"test-name2": "test-value2",
					})
				},
				testCalls: []testCall{
					{
						clientNr: 0,
						hostName: "insecure.acme.io",
						path:     "/",
						headers:  map[string]string{},
						blocked:  true,
					},
					{
						clientNr: 0,
						hostName: "insecure.acme.io",
						path:     "/",
						headers: map[string]string{
							"test-name1": "test-value1",
						},
						blocked: true,
					},
					{
						clientNr: 0,
						hostName: "insecure.acme.io",
						path:     "/",
						headers: map[string]string{
							"test-name1": "test-value1",
							"test-name2": "test-value2",
						},
						blocked: false,
					},
					{
						clientNr: 0,
						hostName: "insecure.acme.io",
						path:     "/",
						headers: map[string]string{
							"test-name1": "test-value111111",
							"test-name2": "test-value222222",
						},
						blocked: false,
					},
					{
						clientNr: 0,
						hostName: "insecure.acme.io",
						path:     "/",
						headers: map[string]string{
							"test-name1": "1test-value1",
							"test-name2": "2test-value2",
						},
						blocked: true,
					},
				},
			},
			{
				desc: "allow-by-regex-headers",
				appOpt: func(clients []*frrContainer) httpApplicationRouteOption {
					return withHttpRequestFilteringAllowByRegexHeader(map[string]string{
						"test-name1": ".*test-value1.*",
						"test-name2": ".*test-value2.*",
					})
				},
				testCalls: []testCall{
					{
						clientNr: 0,
						hostName: "insecure.acme.io",
						path:     "/",
						headers:  map[string]string{},
						blocked:  true,
					},
					{
						clientNr: 0,
						hostName: "insecure.acme.io",
						path:     "/",
						headers: map[string]string{
							"test-name1": "test-value1",
						},
						blocked: true,
					},
					{
						clientNr: 0,
						hostName: "insecure.acme.io",
						path:     "/",
						headers: map[string]string{
							"test-name1": "test-value1",
							"test-name2": "test-value2",
						},
						blocked: false,
					},
					{
						clientNr: 0,
						hostName: "insecure.acme.io",
						path:     "/",
						headers: map[string]string{
							"test-name1": "test-value111111",
							"test-name2": "test-value222222",
						},
						blocked: false,
					},
					{
						clientNr: 0,
						hostName: "insecure.acme.io",
						path:     "/",
						headers: map[string]string{
							"test-name1": "1test-value11",
							"test-name2": "2test-value22",
						},
						blocked: false,
					},
				},
			},
		}...)
	}

	for _, tC := range testCases {
		if skipIfOnSingleNode(">1 FRR clients are not supported") {
			continue
		}

		t.RunTestCase(func(t T) {
			t.Log("Checking %s", tC.desc)

			testName := fmt.Sprintf("http-requestfiltering-%s", tC.desc)

			// 0. Setup test scenario (backends, clients & LB resources)
			scenario := newLBTestScenario(t, testName, ciliumCli, k8sCli, dockerCli)

			t.Log("Creating backend apps...")
			scenario.addBackendApplications(2, backendApplicationConfig{h2cEnabled: true})

			t.Log("Creating clients and add BGP peering ...")
			clients := scenario.addFRRClients(2, frrClientConfig{})

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
			service := lbService(testName, withHTTPProxyApplication(withHttpRoute(testName, tC.appOpt(clients))))
			scenario.createLBService(service)

			t.Log("Waiting for full VIP connectivity...")
			vipIP := scenario.waitForFullVIPConnectivity(testName)

			for _, tt := range tC.testCalls {
				testCmd := curlCmdVerbose(fmt.Sprintf("--max-time 10 --resolve %s:80:%s http://%s:80%s", tt.hostName, vipIP, tt.hostName, tt.path))
				for k, v := range tt.headers {
					testCmd += fmt.Sprintf(" -H '%s:%s'", k, v)
				}
				t.Log("Testing %q...", testCmd)
				eventually(t, func() error {
					stdout, stderr, err := clients[tt.clientNr].Exec(t.Context(), testCmd)
					if !tt.blocked && err != nil {
						return fmt.Errorf("curl failed (cmd: %q, stdout: %q, stderr: %q): %w", testCmd, stdout, stderr, err)
					} else if tt.blocked && (err == nil || err.Error() != "cmd failed: 22") {
						return fmt.Errorf("curl request wasn't filtered (cmd: %q, stdout: %q, stderr: %q): %w", testCmd, stdout, stderr, err)
					}

					return nil
				}, shortTimeout, pollInterval)
			}
		})

	}
}
