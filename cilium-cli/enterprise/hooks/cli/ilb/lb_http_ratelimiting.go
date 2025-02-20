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

	"k8s.io/utils/ptr"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

func TestHTTPRouteRatelimiting() {
	ctx := context.Background()
	testName := "http-proxy-route-ratelimiting"
	testK8sNamespace := "default"
	hostName := "insecure.acme.io"

	ciliumCli, k8sCli := NewCiliumAndK8sCli()
	dockerCli := NewDockerCli()

	// 0. Setup test scenario (backends, clients & LB resources)
	scenario := newLBTestScenario(testName, testK8sNamespace, ciliumCli, k8sCli, dockerCli)

	fmt.Println("Creating backend apps...")
	scenario.addBackendApplications(ctx, 2, backendApplicationConfig{h2cEnabled: true})

	fmt.Println("Creating clients and add BGP peering ...")
	client := scenario.addFRRClients(ctx, 1, frrClientConfig{})[0]

	fmt.Println("Creating LB VIP resources...")
	vip := lbVIP(testK8sNamespace, testName)
	scenario.createLBVIP(ctx, vip)

	fmt.Println("Creating LB BackendPool resources...")
	backends := []backendPoolOption{}
	for _, b := range scenario.backendApps {
		backends = append(backends, withIPBackend(b.ip, 8080))
	}
	backendPool := lbBackendPool(testK8sNamespace, testName, backends...)
	scenario.createLBBackendPool(ctx, backendPool)

	fmt.Println("Creating LB Service resources...")
	service := lbService(testK8sNamespace, testName, withHTTPProxyApplication(withHttpRoute(testName, withHttpRequestRateLimiting(5, 60))))

	// Prepending admin http route (prepending because routes are in order on the same virtualhost)
	service.Spec.Applications.HTTPProxy.Routes = append([]isovalentv1alpha1.LBServiceHTTPRoute{{
		Match: &isovalentv1alpha1.LBServiceHTTPRouteMatch{
			Path: &isovalentv1alpha1.LBServiceHTTPPath{
				Exact: ptr.To("/admin"),
			},
		},
		BackendRef: isovalentv1alpha1.LBServiceBackendRef{
			Name: testName,
		},
	}}, service.Spec.Applications.HTTPProxy.Routes...)

	scenario.createLBService(ctx, service)

	fmt.Println("Waiting for full VIP connectivity...")
	vipIP := scenario.waitForFullVIPConnectivity(ctx, testName)

	testCmd := curlCmdVerbose(fmt.Sprintf("--max-time 10 --resolve %s:80:%s http://%s:80%s", hostName, vipIP, hostName, "/"))

	{
		fmt.Printf("Testing %q that first request succeeds ...\n", testCmd)
		stdout, stderr, err := client.Exec(ctx, testCmd)
		if err != nil {
			fatalf("curl failed (cmd: %q, stdout: %q, stderr: %q): %s", testCmd, stdout, stderr, err)
		}
	}

	fmt.Printf("Testing %q and expecting rate limit (HTTP 429) eventually ...\n", testCmd)
	eventually(func() error {
		stdout, stderr, err := client.Exec(ctx, testCmd)
		if err != nil {
			if err.Error() != "cmd failed: 22" {
				return fmt.Errorf("curl failed unexpectedly (cmd: %q, stdout: %q, stderr: %q): %w", testCmd, stdout, stderr, err)
			}

			// due to local rate limit and T1->T2 loadbalancing, requests must start hitting the connection ratelimit eventually
			return nil // rate limited with HTTP 429
		}

		return fmt.Errorf("curl not rate limited (cmd: %q, stdout: %q, stderr: %q): %w", testCmd, stdout, stderr, err)
	}, longTimeout, pollInterval)

	{
		testCmdAdmin := curlCmdVerbose(fmt.Sprintf("--max-time 10 --resolve %s:80:%s http://%s:80%s", hostName, vipIP, hostName, "/admin"))
		fmt.Printf("Testing %q that should still be possible even  after hitting the ratelimit ...\n", testCmdAdmin)
		stdout, stderr, err := client.Exec(ctx, testCmdAdmin)
		if err != nil {
			fatalf("curl failed (cmd: %q, stdout: %q, stderr: %q): %s", testCmdAdmin, stdout, stderr, err)
		}
	}
}

func TestHTTPApplicationRatelimiting() {
	ctx := context.Background()
	testName := "http-proxy-application-ratelimiting"
	testK8sNamespace := "default"
	hostName := "insecure.acme.io"

	ciliumCli, k8sCli := NewCiliumAndK8sCli()
	dockerCli := NewDockerCli()

	// 0. Setup test scenario (backends, clients & LB resources)
	scenario := newLBTestScenario(testName, testK8sNamespace, ciliumCli, k8sCli, dockerCli)

	fmt.Println("Creating backend apps...")
	scenario.addBackendApplications(ctx, 2, backendApplicationConfig{h2cEnabled: true})

	fmt.Println("Creating clients and add BGP peering ...")
	client := scenario.addFRRClients(ctx, 1, frrClientConfig{})[0]

	fmt.Println("Creating LB VIP resources...")
	vip := lbVIP(testK8sNamespace, testName)
	scenario.createLBVIP(ctx, vip)

	fmt.Println("Creating LB BackendPool resources...")
	backends := []backendPoolOption{}
	for _, b := range scenario.backendApps {
		backends = append(backends, withIPBackend(b.ip, 8080))
	}
	backendPool := lbBackendPool(testK8sNamespace, testName, backends...)
	scenario.createLBBackendPool(ctx, backendPool)

	fmt.Println("Creating LB Service resources...")
	service := lbService(testK8sNamespace, testName, withHTTPProxyApplication(withHttpConnectionRateLimiting(5, 60), withHttpRoute(testName)))
	scenario.createLBService(ctx, service)

	fmt.Println("Waiting for full VIP connectivity...")
	vipIP := scenario.waitForFullVIPConnectivity(ctx, testName)

	testCmd := curlCmdVerbose(fmt.Sprintf("--max-time 10 --resolve %s:80:%s http://%s:80%s", hostName, vipIP, hostName, "/"))

	{
		fmt.Printf("Testing %q that first request succeeds ...\n", testCmd)
		stdout, stderr, err := client.Exec(ctx, testCmd)
		if err != nil {
			fatalf("curl failed (cmd: %q, stdout: %q, stderr: %q): %s", testCmd, stdout, stderr, err)
		}
	}

	fmt.Printf("Testing %q and expecting connection rate limit eventually ...\n", testCmd)
	eventually(func() error {
		stdout, stderr, err := client.Exec(ctx, testCmd)
		if err != nil {
			if err.Error() != "cmd failed: 56" {
				return fmt.Errorf("curl failed unexpectedly (cmd: %q, stdout: %q, stderr: %q): %w", testCmd, stdout, stderr, err)
			}

			// due to local rate limit and T1->T2 loadbalancing, requests must start hitting the connection ratelimit eventually
			return nil // rate limited
		}

		return fmt.Errorf("curl not rate limited (cmd: %q, stdout: %q, stderr: %q): %w", testCmd, stdout, stderr, err)
	}, longTimeout, pollInterval)
}
