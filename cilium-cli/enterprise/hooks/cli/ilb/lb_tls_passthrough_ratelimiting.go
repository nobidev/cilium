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
	"time"
)

func TestTLSPassthroughRatelimiting() {
	fmt.Println("=== RUN   TestTLSPassthroughRatelimiting")

	ctx := context.Background()
	testName := "https-passthrough-ratelimiting"
	testK8sNamespace := "default"
	hostName1 := "passthrough.acme.io"
	hostName2 := "passthrough-2.acme.io"

	ciliumCli, k8sCli := NewCiliumAndK8sCli()
	dockerCli := NewDockerCli()

	// 0. Setup test scenario (backends, clients & LB resources)
	scenario := newLBTestScenario(testName, testK8sNamespace, ciliumCli, k8sCli, dockerCli)

	fmt.Println("Creating cert and secret...")
	scenario.createBackendServerCertificate(ctx, hostName1)
	scenario.createBackendServerCertificate(ctx, hostName2)

	fmt.Println("Creating backend apps...")
	backend1 := scenario.addBackendApplications(ctx, 1, backendApplicationConfig{tlsCertHostname: hostName1, listenPort: 8080})[0]
	backend2 := scenario.addBackendApplications(ctx, 1, backendApplicationConfig{tlsCertHostname: hostName2, listenPort: 8081})[0]

	fmt.Println("Creating clients and add BGP peering ...")
	client := scenario.addFRRClients(ctx, 1, frrClientConfig{trustedCertsHostnames: []string{hostName1, hostName2}})[0]

	fmt.Println("Creating LB VIP resources...")
	vip := lbVIP(testK8sNamespace, testName)
	scenario.createLBVIP(ctx, vip)

	fmt.Println("Creating LB BackendPool resources...")
	backendPool1 := lbBackendPool(testK8sNamespace, testName+"-1", withIPBackend(backend1.ip, 8080), withHealthCheckTLS())
	scenario.createLBBackendPool(ctx, backendPool1)

	backendPool2 := lbBackendPool(testK8sNamespace, testName+"-2", withIPBackend(backend2.ip, 8081), withHealthCheckTLS())
	scenario.createLBBackendPool(ctx, backendPool2)

	fmt.Println("Creating LB Service resources...")
	service := lbService(testK8sNamespace, testName, withTLSPassthroughApplication(
		withTLSPassthroughRoute(testName+"-1", withTLSPassthroughHostname(hostName1), withTLSPassthroughConnectionRateLimiting(5, 60)),
		withTLSPassthroughRoute(testName+"-2"),
	))
	scenario.createLBService(ctx, service)

	fmt.Printf("Waiting for full VIP connectivity of %q...\n", testName)
	vipIP := scenario.waitForFullVIPConnectivity(ctx, testName)

	maybeSysdump(testName, "")

	// 1. Send HTTPs request
	testCmd1 := curlCmdVerbose(fmt.Sprintf("--max-time 10 --cacert /tmp/%s --resolve %s:80:%s https://%s:80/", hostName1+".crt", hostName1, vipIP, hostName1))
	testCmd2 := curlCmdVerbose(fmt.Sprintf("--max-time 10 --cacert /tmp/%s --resolve %s:80:%s https://%s:80/", hostName2+".crt", hostName2, vipIP, hostName2))
	for _, testCmd := range []string{testCmd1, testCmd2} {
		fmt.Printf("Testing %q...\n", testCmd)
		stdout, stderr, err := client.Exec(ctx, testCmd)
		if err != nil {
			fatalf("curl failed (cmd: %q, stdout: %q, stderr: %q): %s", testCmd, stdout, stderr, err)
		}
	}

	fmt.Printf("Testing %q and expecting connection rate limit eventually ...\n", testCmd1)
	eventually(func() error {
		stdout, stderr, err := client.Exec(ctx, testCmd1)
		if err != nil {
			if err.Error() != "cmd failed: 35" {
				return fmt.Errorf("curl failed unexpectedly (cmd: %q, stdout: %q, stderr: %q): %w", testCmd1, stdout, stderr, err)
			}

			// due to local rate limit and T1->T2 loadbalancing, requests must start hitting the connection ratelimit eventually
			return nil // rate limited
		}

		return fmt.Errorf("curl not rate limited (cmd: %q, stdout: %q, stderr: %q): %w", testCmd1, stdout, stderr, err)
	}, longTimeout, pollInterval)

	fmt.Printf("Testing %q and and not expecting connection rate limit ...\n", testCmd2)
	successCount := 0
	eventually(func() error {
		stdout, stderr, err := client.Exec(ctx, testCmd2)
		if err != nil {
			return fmt.Errorf("curl unexpectedly failed (cmd: %q, stdout: %q, stderr: %q): %w", testCmd2, stdout, stderr, err)
		}

		successCount++
		if successCount == 100 {
			return nil
		}

		return fmt.Errorf("condition is not satisfied yet (%d/100)", successCount)
	}, shortTimeout, 1*time.Millisecond) // As fast as possible
}
