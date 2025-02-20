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

func TestTLSProxyRatelimiting() {
	ctx := context.Background()
	ns := "default"
	testName := "tls-proxy-ratelimiting"
	serviceHostName := "secure.acme.io"
	clientCAName := "acme.io"
	clientHostName := "client.acme.io"

	ciliumCli, k8sCli := NewCiliumAndK8sCli()
	dockerCli := NewDockerCli()

	scenario := newLBTestScenario(testName, ns, ciliumCli, k8sCli, dockerCli)

	fmt.Println("Creating cert and secret...")

	scenario.createLBServerCertificate(ctx, testName, serviceHostName)
	scenario.createLBClientCertificate(ctx, clientCAName, clientHostName)

	fmt.Println("Creating backend app...")

	backends := scenario.addBackendApplications(ctx, 1, backendApplicationConfig{h2cEnabled: true})

	fmt.Println("Creating client and add BGP peering...")

	client := scenario.addFRRClients(ctx, 1, frrClientConfig{trustedCertsHostnames: []string{serviceHostName}})[0]

	fmt.Println("Creating LB VIP resources...")

	vip := lbVIP(ns, testName)
	scenario.createLBVIP(ctx, vip)

	fmt.Println("Creating LB BackendPool resources...")

	backendPool := lbBackendPool(ns, testName, withIPBackend(backends[0].ip, backends[0].port))
	scenario.createLBBackendPool(ctx, backendPool)

	fmt.Println("Creating LB Service resources...")

	service := lbService(ns, testName, withPort(10080), withTLSProxyApplication(withTLSCertificate(testName), withTLSProxyRoute(backendPool.Name, withHostname(serviceHostName), withTLSProxyConnectionRateLimiting(5, 60))))
	scenario.createLBService(ctx, service)

	maybeSysdump(testName, "")

	fmt.Println("Waiting for full VIP connectivity...")
	vipIP := scenario.waitForFullVIPConnectivity(ctx, testName)

	// 3. Test basic connectivity
	testCmd := curlCmdVerbose(fmt.Sprintf("--max-time 10 --cacert /tmp/%s.crt --resolve secure.acme.io:10080:%s https://secure.acme.io:10080/", serviceHostName, vipIP))

	fmt.Printf("Testing %q...\n", testCmd)

	eventually(func() error {
		stdout, stderr, err := client.Exec(ctx, testCmd)
		if err != nil {
			// Enrich error with curl output
			err = fmt.Errorf("curl failed (cmd: %q, stdout: %q, stderr: %q): %w", testCmd, stdout, stderr, err)
		}
		return err
	}, 10*time.Second, 100*time.Millisecond)

	fmt.Printf("Testing %q and expecting connection rate limit eventually ...\n", testCmd)
	eventually(func() error {
		stdout, stderr, err := client.Exec(ctx, testCmd)
		if err != nil {
			if err.Error() != "cmd failed: 35" {
				return fmt.Errorf("curl failed unexpectedly (cmd: %q, stdout: %q, stderr: %q): %w", testCmd, stdout, stderr, err)
			}

			// due to local rate limit and T1->T2 loadbalancing, requests must start hitting the connection ratelimit eventually
			return nil // rate limited
		}

		return fmt.Errorf("curl not rate limited (cmd: %q, stdout: %q, stderr: %q): %w", testCmd, stdout, stderr, err)
	}, longTimeout, pollInterval)
}
