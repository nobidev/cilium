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
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

func TestTCPProxyRatelimiting(t T) {
	testName := "tcp-proxy-ratelimiting"

	ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
	dockerCli := NewDockerCli(t)

	scenario := newLBTestScenario(t, testName, ciliumCli, k8sCli, dockerCli)

	t.Log("Creating backend app...")

	backends := scenario.addBackendApplications(1, backendApplicationConfig{h2cEnabled: true})

	t.Log("Creating client and add BGP peering...")

	client := scenario.addFRRClients(1, frrClientConfig{})[0]

	t.Log("Creating LB VIP resources...")

	vip := lbVIP(testName)
	scenario.createLBVIP(vip)

	t.Log("Creating LB BackendPool resources...")

	backendPool := lbBackendPool(testName, withIPBackend(backends[0].ip, backends[0].port))
	scenario.createLBBackendPool(backendPool)

	t.Log("Creating LB Service resources...")

	service := lbService(testName, withPort(10080), withTCPProxyApplication(withTCPProxyRoute(backendPool.Name, withTCPProxyConnectionRateLimiting(5, 60))))
	scenario.createLBService(service)

	t.Log("Waiting for full VIP connectivity...")
	vipIP := scenario.waitForFullVIPConnectivity(testName)

	// 3. Test basic connectivity
	testCmd := curlCmdVerbose(fmt.Sprintf("--max-time 10 --resolve tcp.acme.io:10080:%s http://tcp.acme.io:10080/", vipIP))

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
			if err.Error() != "cmd failed: 56" {
				return fmt.Errorf("curl failed unexpectedly (cmd: %q, stdout: %q, stderr: %q): %w", testCmd, stdout, stderr, err)
			}

			// due to local rate limit and T1->T2 loadbalancing, requests must start hitting the connection ratelimit eventually
			return nil // rate limited
		}

		return fmt.Errorf("curl not rate limited (cmd: %q, stdout: %q, stderr: %q): %w", testCmd, stdout, stderr, err)
	}, longTimeout, pollInterval)
}

func TestTCPProxyRatelimiting_Fail_T1Only(t T) {
	testName := "tcp-proxy-ratelimiting-fail-t1-only"

	ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
	dockerCli := NewDockerCli(t)

	// for namespace creation
	scenario := newLBTestScenario(t, testName, ciliumCli, k8sCli, dockerCli)

	service := lbService(testName, withPort(10080), withTCPProxyApplication(withTCPForceDeploymentMode(isovalentv1alpha1.LBTCPProxyForceDeploymentModeT1), withTCPProxyRoute("fake", withTCPProxyConnectionRateLimiting(5, 60))))

	err := ciliumCli.CreateLBService(t.Context(), scenario.k8sNamespace, service, metav1.CreateOptions{})
	if err == nil {
		t.Failedf("CreateLBService should return an error")
	}

	if !strings.Contains(err.Error(), "Force deployment mode t1-only isn't compatible with rate limits") {
		t.Failedf("CreateLBService returned the wrong error: %s", err.Error())
	}
}
