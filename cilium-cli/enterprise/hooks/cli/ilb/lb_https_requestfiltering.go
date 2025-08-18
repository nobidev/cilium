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

func TestHTTPSRequestFiltering(t T) {
	ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
	dockerCli := NewDockerCli(t)

	testCases := []struct {
		desc      string
		appOpt    func(clients []*frrContainer) httpsApplicationRouteOption
		testCalls []testCall
	}{
		{
			desc: "deny-by-exact-path",
			appOpt: func(clients []*frrContainer) httpsApplicationRouteOption {
				return withHttpsRequestFilteringDenyByExactPath("/admin")
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
					hostName: "secure.acme.io",
					path:     "/admin/users",
					blocked:  false,
				},
				{
					clientNr: 0,
					hostName: "secure.acme.io",
					path:     "/admin",
					blocked:  true,
				},
			},
		},
		{
			desc: "deny-by-prefix-path",
			appOpt: func(clients []*frrContainer) httpsApplicationRouteOption {
				return withHttpsRequestFilteringDenyByPrefixPath("/admin")
			},
			testCalls: []testCall{
				{
					clientNr: 0,
					hostName: "secure.acme.io",
					path:     "/path",
					blocked:  false,
				},
				{
					clientNr: 0,
					hostName: "secure.acme.io",
					path:     "/admin",
					blocked:  true,
				},
				{
					clientNr: 0,
					hostName: "secure.acme.io",
					path:     "/admin/users",
					blocked:  true,
				},
			},
		},
		{
			desc: "deny-by-exact-hostname",
			appOpt: func(clients []*frrContainer) httpsApplicationRouteOption {
				return withHttpsRequestFilteringDenyByExactHostname("secure2.acme.io")
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
					hostName: "admin.secure2.acme.io",
					path:     "/",
					blocked:  false,
				},
				{
					clientNr: 0,
					hostName: "secure2.acme.io",
					path:     "/",
					blocked:  true,
				},
			},
		},
		{
			desc: "deny-by-suffix-hostname",
			appOpt: func(clients []*frrContainer) httpsApplicationRouteOption {
				return withHttpsRequestFilteringDenyBySuffixHostname("moresecure.acme.io")
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
					hostName: "moresecure.acme.io",
					path:     "/",
					blocked:  true,
				},
				{
					clientNr: 0,
					hostName: "admin.moresecure.acme.io",
					path:     "/",
					blocked:  true,
				},
			},
		},
		{
			desc: "deny-by-sourceip",
			appOpt: func(clients []*frrContainer) httpsApplicationRouteOption {
				return withHttpsRequestFilteringDenyBySourceIP(clients[1].ip + "/32")
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
			desc: "deny-by-sourceip-hostname-path",
			appOpt: func(clients []*frrContainer) httpsApplicationRouteOption {
				return withHttpsRequestFilteringDenyBySourceIPExactHostnameExactPath(clients[1].ip+"/32", "secure2.acme.io", "/admin")
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
					blocked:  false,
				},
				{
					clientNr: 1,
					hostName: "secure2.acme.io",
					path:     "/",
					blocked:  false,
				},
				{
					clientNr: 1,
					hostName: "secure.acme.io",
					path:     "/admin",
					blocked:  false,
				},
				{
					clientNr: 0,
					hostName: "secure2.acme.io",
					path:     "/admin",
					blocked:  false,
				},
				{
					clientNr: 1,
					hostName: "secure2.acme.io",
					path:     "/admin",
					blocked:  true,
				},
			},
		},
		{
			desc: "allow-by-sourceip-hostname-path",
			appOpt: func(clients []*frrContainer) httpsApplicationRouteOption {
				return withHttpsRequestFilteringAllowBySourceIPExactHostnameExactPath(clients[1].ip+"/32", "secure2.acme.io", "/admin")
			},
			testCalls: []testCall{
				{
					clientNr: 0,
					hostName: "secure.acme.io",
					path:     "/",
					blocked:  true,
				},
				{
					clientNr: 0,
					hostName: "secure2.acme.io",
					path:     "/admin",
					blocked:  true,
				},
				{
					clientNr: 1,
					hostName: "secure2.acme.io",
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
			appOpt    func(clients []*frrContainer) httpsApplicationRouteOption
			testCalls []testCall
		}{
			{
				desc: "allow-by-exact-headers",
				appOpt: func(clients []*frrContainer) httpsApplicationRouteOption {
					return withHttpsRequestFilteringAllowByExactHeader(map[string]string{
						"test-name1": "test-value1",
						"test-name2": "test-value2",
					})
				},
				testCalls: []testCall{
					{
						clientNr: 0,
						hostName: "secure.acme.io",
						path:     "/",
						headers:  map[string]string{},
						blocked:  true,
					},
					{
						clientNr: 0,
						hostName: "secure.acme.io",
						path:     "/",
						headers: map[string]string{
							"test-name1": "test-value1",
						},
						blocked: true,
					},
					{
						clientNr: 0,
						hostName: "secure.acme.io",
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
				appOpt: func(clients []*frrContainer) httpsApplicationRouteOption {
					return withHttpsRequestFilteringAllowByPrefixHeader(map[string]string{
						"test-name1": "test-value1",
						"test-name2": "test-value2",
					})
				},
				testCalls: []testCall{
					{
						clientNr: 0,
						hostName: "secure.acme.io",
						path:     "/",
						headers:  map[string]string{},
						blocked:  true,
					},
					{
						clientNr: 0,
						hostName: "secure.acme.io",
						path:     "/",
						headers: map[string]string{
							"test-name1": "test-value1",
						},
						blocked: true,
					},
					{
						clientNr: 0,
						hostName: "secure.acme.io",
						path:     "/",
						headers: map[string]string{
							"test-name1": "test-value1",
							"test-name2": "test-value2",
						},
						blocked: false,
					},
					{
						clientNr: 0,
						hostName: "secure.acme.io",
						path:     "/",
						headers: map[string]string{
							"test-name1": "test-value111111",
							"test-name2": "test-value222222",
						},
						blocked: false,
					},
					{
						clientNr: 0,
						hostName: "secure.acme.io",
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
				appOpt: func(clients []*frrContainer) httpsApplicationRouteOption {
					return withHttpsRequestFilteringAllowByRegexHeader(map[string]string{
						"test-name1": ".*test-value1.*",
						"test-name2": ".*test-value2.*",
					})
				},
				testCalls: []testCall{
					{
						clientNr: 0,
						hostName: "secure.acme.io",
						path:     "/",
						headers:  map[string]string{},
						blocked:  true,
					},
					{
						clientNr: 0,
						hostName: "secure.acme.io",
						path:     "/",
						headers: map[string]string{
							"test-name1": "test-value1",
						},
						blocked: true,
					},
					{
						clientNr: 0,
						hostName: "secure.acme.io",
						path:     "/",
						headers: map[string]string{
							"test-name1": "test-value1",
							"test-name2": "test-value2",
						},
						blocked: false,
					},
					{
						clientNr: 0,
						hostName: "secure.acme.io",
						path:     "/",
						headers: map[string]string{
							"test-name1": "test-value111111",
							"test-name2": "test-value222222",
						},
						blocked: false,
					},
					{
						clientNr: 0,
						hostName: "secure.acme.io",
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

			testName := fmt.Sprintf("https-requestfiltering-%s", tC.desc)

			// 0. Setup test scenario (backends, clients & LB resources)
			scenario := newLBTestScenario(t, testName, ciliumCli, k8sCli, dockerCli)

			t.Log("Creating cert and secret...")
			scenario.createLBServerCertificate(testName+"-1", "secure.acme.io")
			scenario.createLBServerCertificate(testName+"-2", "admin.secure.acme.io")
			scenario.createLBServerCertificate(testName+"-3", "moresecure.acme.io")
			scenario.createLBServerCertificate(testName+"-4", "admin.moresecure.acme.io")
			scenario.createLBServerCertificate(testName+"-5", "secure2.acme.io")
			scenario.createLBServerCertificate(testName+"-6", "admin.secure2.acme.io")

			t.Log("Creating backend apps...")
			scenario.addBackendApplications(2, backendApplicationConfig{h2cEnabled: true})

			t.Log("Creating clients and add BGP peering ...")
			clients := scenario.addFRRClients(2, frrClientConfig{trustedCertsHostnames: []string{"secure.acme.io", "admin.secure.acme.io", "moresecure.acme.io", "admin.moresecure.acme.io", "secure2.acme.io", "admin.secure2.acme.io"}})

			t.Log("Creating LB VIP resources...")
			vip := lbVIP(testName)
			scenario.createLBVIP(vip)

			t.Log("Creating LB BackendPool resources...")
			backends := []backendPoolOption{}
			for _, b := range scenario.backendApps {
				backends = append(backends, withIPBackend(b.ip, b.port))
			}
			backendPool := lbBackendPool(testName, backends...)
			scenario.createLBBackendPool(backendPool)

			t.Log("Creating LB Service resources...")
			opts := []httpsApplicationOption{}
			opts = append(opts, withHttpsRoute(testName, withHttpsHostname("*.acme.io"), tC.appOpt(clients)))
			opts = append(opts, withCertificate(testName+"-1"))
			opts = append(opts, withCertificate(testName+"-2"))
			opts = append(opts, withCertificate(testName+"-3"))
			opts = append(opts, withCertificate(testName+"-4"))
			opts = append(opts, withCertificate(testName+"-5"))
			opts = append(opts, withCertificate(testName+"-6"))
			service := lbService(testName, withPort(443), withHTTPSProxyApplication(opts...))
			scenario.createLBService(service)

			t.Log("Waiting for full VIP connectivity...")
			vipIP := scenario.waitForFullVIPConnectivity(testName)

			for _, tt := range tC.testCalls {
				testCmd := curlCmdVerbose(fmt.Sprintf("--max-time 1 --cacert /tmp/%s.crt --resolve %s:443:%s https://%s:443%s", tt.hostName, tt.hostName, vipIP, tt.hostName, tt.path))
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
				}, longTimeout, pollInterval)
			}
		})

	}
}
