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
)

func TestT2HealthCheckHTTP(t T) {
	testName := "t2-healthcheck-http"

	ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
	dockerCli := NewDockerCli(t)

	// 0. Setup test scenario (backends, clients & LB resources)
	scenario := newLBTestScenario(t, testName, ciliumCli, k8sCli, dockerCli)

	t.Log("Creating backend apps...")
	scenario.addBackendApplications(2, backendApplicationConfig{h2cEnabled: true})

	t.Log("Creating clients and add BGP peering ...")
	client := scenario.addFRRClients(1, frrClientConfig{})[0]

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
	service := lbService(testName, withPort(81), withHTTPProxyApplication(
		withHttpRoute(testName),
	))
	scenario.createLBService(service)

	t.Log("Waiting for full VIP connectivity...")
	vipIP := scenario.waitForFullVIPConnectivity(testName)

	// 1. Send HTTP request to test basic client -> LB T1 -> LB T2 -> app connectivity
	testCmd := curlCmdVerbose(fmt.Sprintf("--max-time 10 http://%s:81/", vipIP))
	t.Log("Testing %q...", testCmd)
	stdout, stderr, err := client.Exec(t.Context(), testCmd)
	if err != nil {
		t.Failedf("curl failed (cmd: %q, stdout: %q, stderr: %q): %s", testCmd, stdout, stderr, err)
	}

	// 2. Healthcheck (T2) testing

	// 2.1. Force both app's HC to fail

	t.Log("Setting T2 HC to fail...")

	for _, b := range scenario.backendApps {
		b.SetHC(t, hcFail)
	}

	// 2.2. Wait until curl fails due to failing HCs

	t.Log("Waiting for curl to fails...")

	eventually(t, func() error {
		_, _, err := client.Exec(t.Context(), testCmd)
		if err != nil {
			return nil
		}
		return fmt.Errorf("curl request still succeeds (expect to fail)")
	}, longTimeout, longPollInterval)

	t.Log("Setting T2 HC to pass...")

	// 2.3. Bring back both backends

	for _, b := range scenario.backendApps {
		b.SetHC(t, hcOK)
	}

	t.Log("Waiting for curl to pass...")

	// 2.4. Expect to pass

	eventually(t, func() error {
		_, _, err := client.Exec(t.Context(), testCmd)
		if err != nil {
			return fmt.Errorf("curl request still fails (expect to succeed")
		}
		return nil
	}, longTimeout, longPollInterval)

	// TODO(brb) bring back only one backend
}
