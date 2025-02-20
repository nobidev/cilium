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
	"strings"
)

type testClientIPCall struct {
	blocked bool
}

type runIfFunc func() bool

func TestHTTPClientIP() {
	testCases := []struct {
		desc      string
		appOpt    func(clients []*frrContainer) httpApplicationOption
		runIfs    map[string]runIfFunc
		testCalls []testClientIPCall
	}{
		// Test cases for use-remote-address=true and xff-num-trusted-hops=0
		{
			desc: "remote-deny-by-sourceip",
			appOpt: func(clients []*frrContainer) httpApplicationOption {
				return withHttpConnectionFilteringDenyBySourceIP(clients[0].ip + "/32")
			},
			runIfs: map[string]runIfFunc{
				"use-remote-address must be enabled":    useRemoteAddressEnabled,
				"xff-num-trusted-hops must be disabled": xffNumTrustedHopsDisabled,
			},
			testCalls: []testClientIPCall{
				{blocked: true},
			},
		},
		{
			desc: "remote-allow-by-sourceip",
			appOpt: func(clients []*frrContainer) httpApplicationOption {
				return withHttpConnectionFilteringAllowBySourceIP(clients[0].ip + "/32")
			},
			runIfs: map[string]runIfFunc{
				"use-remote-address must be enabled":    useRemoteAddressEnabled,
				"xff-num-trusted-hops must be disabled": xffNumTrustedHopsDisabled,
			},
			testCalls: []testClientIPCall{
				{blocked: false},
			},
		},

		// Test cases for use-remote-address=true + xff-num-trusted-hops > 0
		{
			desc: "remote-hops-deny-by-sourceip",
			appOpt: func(clients []*frrContainer) httpApplicationOption {
				// Due to https://github.com/envoyproxy/envoy/issues/33662,
				// The remote ip is not correctly set in the XFF header when xff-num-trusted-hops > 0
				return withHttpConnectionFilteringDenyBySourceIP(clients[0].ip + "/32")
			},
			runIfs: map[string]runIfFunc{
				"use-remote-address must be enabled":   useRemoteAddressEnabled,
				"xff-num-trusted-hops must be enabled": xffNumTrustedHopsEnabled,
			},
			testCalls: []testClientIPCall{
				{blocked: true},
			},
		},
		{
			desc: "remote-hops-allow-by-sourceip",
			appOpt: func(clients []*frrContainer) httpApplicationOption {
				// Due to https://github.com/envoyproxy/envoy/issues/33662,
				// The remote ip is not correctly set in the XFF header when xff-num-trusted-hops > 0
				return withHttpConnectionFilteringAllowBySourceIP(clients[0].ip + "/32")
			},
			runIfs: map[string]runIfFunc{
				"use-remote-address must be enabled":   useRemoteAddressEnabled,
				"xff-num-trusted-hops must be enabled": xffNumTrustedHopsEnabled,
			},
			testCalls: []testClientIPCall{
				{blocked: false},
			},
		},

		// Test cases for use-remote-address=false + xff-num-trusted-hops > 0
		{
			desc: "hops-deny-by-sourceip",
			appOpt: func(clients []*frrContainer) httpApplicationOption {
				// Due to https://github.com/envoyproxy/envoy/issues/33662,
				// The remote ip is not correctly set in the XFF header when xff-num-trusted-hops > 0
				return withHttpConnectionFilteringDenyBySourceIP(clients[0].ip + "/32")
			},
			runIfs: map[string]runIfFunc{
				"use-remote-address must be disabled":  useRemoteAddressDisabled,
				"xff-num-trusted-hops must be enabled": xffNumTrustedHopsEnabled,
			},
			testCalls: []testClientIPCall{
				{blocked: true},
			},
		},
		{
			desc: "hops-allow-by-sourceip",
			appOpt: func(clients []*frrContainer) httpApplicationOption {
				// Due to https://github.com/envoyproxy/envoy/issues/33662,
				// The remote ip is not correctly set in the XFF header when xff-num-trusted-hops > 0
				return withHttpConnectionFilteringAllowBySourceIP(clients[0].ip + "/32")
			},
			runIfs: map[string]runIfFunc{
				"use-remote-address must be disabled":  useRemoteAddressDisabled,
				"xff-num-trusted-hops must be enabled": xffNumTrustedHopsEnabled,
			},
			testCalls: []testClientIPCall{
				{blocked: false},
			},
		},
	}

nextTest:
	for _, tC := range testCases {
		fmt.Printf("=== RUN   TestHTTPClientIP/%s\n", tC.desc)

		for _, runIf := range tC.runIfs {
			if !runIf() {
				fmt.Println("skipping test because of runIfs condition")
				continue nextTest
			}
		}

		ctx := context.Background()
		testName := fmt.Sprintf("http-clientip-%s", tC.desc)
		testK8sNamespace := "default"

		ciliumCli, k8sCli := NewCiliumAndK8sCli()
		dockerCli := NewDockerCli()

		// 0. Setup test scenario (backends, clients & LB resources)
		scenario := newLBTestScenario(testName, testK8sNamespace, ciliumCli, k8sCli, dockerCli)

		fmt.Println("Creating backend apps...")
		scenario.addBackendApplications(ctx, 1, backendApplicationConfig{h2cEnabled: true})

		fmt.Println("Creating clients and add BGP peering ...")
		clients := scenario.addFRRClients(ctx, 1, frrClientConfig{})

		fmt.Println("Creating LB VIP resources...")
		vip := lbVIP(testK8sNamespace, testName)
		scenario.createLBVIP(ctx, vip)

		fmt.Println("Creating LB BackendPool resources...")
		var backends []backendPoolOption
		for _, b := range scenario.backendApps {
			backends = append(backends, withIPBackend(b.ip, b.port))
		}
		backendPool := lbBackendPool(testK8sNamespace, testName, backends...)
		scenario.createLBBackendPool(ctx, backendPool)

		fmt.Println("Creating LB Service resources...")
		opts := []httpApplicationOption{}
		opts = append(opts, withHttpRoute(testName))
		opts = append(opts, tC.appOpt(clients))
		service := lbService(testK8sNamespace, testName, withHTTPProxyApplication(opts...))
		scenario.createLBService(ctx, service)

		maybeSysdump(testName, "")

		fmt.Println("Waiting for full VIP connectivity...")
		vipIP := scenario.waitForFullVIPConnectivity(ctx, testName)

		for _, tt := range tC.testCalls {
			testCmd := curlCmd(fmt.Sprintf("--max-time 10 %s --resolve insecure.acme.io:80:%s http://insecure.acme.io:80/", generateHeaders(FlagXffNumTrustedHops), vipIP))
			fmt.Printf("Testing %q...\n", testCmd)
			eventually(func() error {
				stdout, stderr, err := clients[0].Exec(ctx, testCmd)
				if tt.blocked {
					if err == nil || (err.Error() != "cmd failed: 52" && err.Error() != "cmd failed: 22") {
						return fmt.Errorf("curl request wasn't filtered (cmd: %q, stdout: %q, stderr: %q): %w", testCmd, stdout, stderr, err)
					}
				} else {
					if err != nil {
						return fmt.Errorf("curl failed (cmd: %q, stdout: %q, stderr: %q): %w", testCmd, stdout, stderr, err)
					}
					resp := toTestAppResponse(stdout)
					fmt.Printf("Response: %+v\n", resp)
					if useRemoteAddressEnabled() && !strings.Contains(resp.XFF, clients[0].ip) {
						return fmt.Errorf("expected %q not to contain %q", resp.XFF, clients[0].ip)
					}
				}

				return nil
			}, shortTimeout, pollInterval)
		}
	}
}

// generateHeaders generates headers including X-Forwarded-For IPs
// The list of IP addresses is generated from 1.0.0.0 to 1.0.0.<numOfIps+1>
func generateHeaders(numOfIps int) string {
	var xffIPs []string
	// Generate numOfIps + 1 IPs
	for i := 0; i <= numOfIps; i++ {
		xffIPs = append(xffIPs, fmt.Sprintf("1.0.0.%d", i))
	}

	headers := map[string]string{
		"Content-Type":    "application/json",
		"X-Forwarded-For": strings.Join(xffIPs, ", "),
	}

	var res string
	for k, v := range headers {
		res += fmt.Sprintf(" -H '%s: %s'", k, v)
	}

	return res
}
