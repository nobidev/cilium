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
	"time"
)

func TestTLSProxyRatelimiting(t T) {
	testName := "tls-proxy-ratelimiting"
	serviceHostName := "secure.acme.io"
	clientCAName := "acme.io"
	clientHostName := "client.acme.io"

	ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
	dockerCli := NewDockerCli(t)

	scenario := newLBTestScenario(t, testName, ciliumCli, k8sCli, dockerCli)

	t.Log("Creating cert and secret...")

	scenario.createLBServerCertificate(testName, serviceHostName)
	scenario.createLBClientCertificate(clientCAName, clientHostName)

	t.Log("Creating backend app...")

	backends := scenario.addBackendApplications(1, backendApplicationConfig{h2cEnabled: true})

	t.Log("Creating client and add BGP peering...")

	client := scenario.addFRRClients(1, frrClientConfig{trustedCertsHostnames: []string{serviceHostName}})[0]

	t.Log("Creating LB VIP resources...")

	vip := lbVIP(testName)
	scenario.createLBVIP(vip)

	t.Log("Creating LB BackendPool resources...")

	backendPool := lbBackendPool(testName, withIPBackend(backends[0].ipv4, backends[0].port))
	scenario.createLBBackendPool(backendPool)

	t.Log("Creating LB Service resources...")

	service := lbService(testName, withPort(10080), withTLSProxyApplication(withTLSCertificate(testName), withTLSProxyRoute(backendPool.Name, withHostname(serviceHostName), withTLSProxyConnectionRateLimiting(5, 60))))
	scenario.createLBService(service)

	t.Log("Waiting for full VIP connectivity...")
	vipIP := scenario.waitForFullVIPConnectivity(testName)

	// 3. Test basic connectivity
	testCmd := curlCmdVerbose(fmt.Sprintf("--max-time 10 --cacert /tmp/%s.crt --resolve secure.acme.io:10080:%s https://secure.acme.io:10080/", serviceHostName, vipIP))

	t.Log("Testing %q...", testCmd)

	eventually(t, func() error {
		stdout, stderr, err := client.Exec(t.Context(), testCmd)
		if err != nil {
			// Enrich error with curl output
			err = fmt.Errorf("curl failed (cmd: %q, stdout: %q, stderr: %q): %w", testCmd, stdout, stderr, err)
		}
		return err
	}, 10*time.Second, 100*time.Millisecond)

	t.Log("Testing %q and expecting connection rate limit eventually ...", testCmd)
	eventually(t, func() error {
		stdout, stderr, err := client.Exec(t.Context(), testCmd)
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
