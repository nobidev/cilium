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
)

func TestHTTPConnectionFiltering(t *testing.T) {
	testCases := []struct {
		desc      string
		appOpt    func(clients []*frrContainer) httpApplicationOption
		testCalls []testCall
	}{
		{
			desc: "deny-by-sourceip",
			appOpt: func(clients []*frrContainer) httpApplicationOption {
				return withHttpConnectionFilteringDenyBySourceIP(clients[1].ip + "/32")
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
			desc: "allow-by-sourceip",
			appOpt: func(clients []*frrContainer) httpApplicationOption {
				return withHttpConnectionFilteringAllowBySourceIP(clients[1].ip + "/32")
			},
			testCalls: []testCall{
				{
					clientNr: 0,
					hostName: "insecure.acme.io",
					path:     "/",
					blocked:  true,
				},
				{
					clientNr: 1,
					hostName: "insecure.acme.io",
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
			testName := fmt.Sprintf("http-connectionfiltering-%s", tC.desc)
			testK8sNamespace := "default"

			ciliumCli, k8sCli := newCiliumAndK8sCli(t)
			dockerCli := newDockerCli(t)

			// 0. Setup test scenario (backends, clients & LB resources)
			scenario := newLBTestScenario(t, testName, testK8sNamespace, ciliumCli, k8sCli, dockerCli)

			t.Log("Creating backend apps...")
			scenario.addBackendApplications(ctx, 2, backendApplicationConfig{h2cEnabled: true})

			t.Log("Creating clients and add BGP peering ...")
			clients := scenario.addFRRClients(ctx, 2, frrClientConfig{})

			t.Logf("Creating LB VIP resources...")
			vip := lbVIP(testK8sNamespace, testName)
			scenario.createLBVIP(ctx, vip)

			t.Logf("Creating LB BackendPool resources...")
			backends := []backendPoolOption{}
			for _, b := range scenario.backendApps {
				backends = append(backends, withIPBackend(b.ip, b.port))
			}
			backendPool := lbBackendPool(testK8sNamespace, testName, backends...)
			scenario.createLBBackendPool(ctx, backendPool)

			t.Logf("Creating LB Service resources...")
			opts := []httpApplicationOption{}
			opts = append(opts, withHttpRoute(testName))
			opts = append(opts, tC.appOpt(clients))
			service := lbService(testK8sNamespace, testName, withHTTPProxyApplication(opts...))
			scenario.createLBService(ctx, service)

			t.Logf("Waiting for full VIP connectivity of %q...", testName)
			vipIP := scenario.waitForFullVIPConnectivity(ctx, testName)

			for _, tt := range tC.testCalls {
				testCmd := curlCmdVerbose(fmt.Sprintf("--max-time 10 --resolve %s:80:%s http://%s:80%s", tt.hostName, vipIP, tt.hostName, tt.path))
				t.Logf("Testing %q...", testCmd)
				eventually(t, func() error {
					stdout, stderr, err := clients[tt.clientNr].Exec(ctx, testCmd)
					if !tt.blocked && err != nil {
						return fmt.Errorf("curl failed (cmd: %q, stdout: %q, stderr: %q): %w", testCmd, stdout, stderr, err)
					} else if tt.blocked && (err == nil || err.Error() != "cmd failed: 52") {
						return fmt.Errorf("curl request wasn't filtered (cmd: %q, stdout: %q, stderr: %q): %w", testCmd, stdout, stderr, err)
					}

					return nil
				}, shortTimeout, pollInterval)
			}
		})
	}
}
