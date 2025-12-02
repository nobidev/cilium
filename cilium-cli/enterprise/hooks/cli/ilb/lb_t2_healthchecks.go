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

	"k8s.io/utils/ptr"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/versioncheck"
)

func TestT2HealthCheckHTTP(t T) {
	testT2HealthCheckHTTP(t, "t2-healthcheck-http", 8080, 0)
}

func TestT2HealthCheckCustomPortHTTP(t T) {
	testT2HealthCheckHTTP(t, "t2-healthcheck-custom-port-http", 8181, 8080)
}

func TestT2HealthCheckTCP(t T) {
	testT2HealthCheckTCP(t, "t2-healthcheck-tcp", 8080, 0)
}

func TestT2HealthCheckCustomPortTCP(t T) {
	testT2HealthCheckTCP(t, "t2-healthcheck-custom-port-tcp", 8181, 8080)
}

func testT2HealthCheckHTTP(t T, testName string, listenPort, healthCheckPort uint32) {
	ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
	dockerCli := NewDockerCli(t)

	// 0. Setup test scenario (backends, clients & LB resources)
	scenario := newLBTestScenario(t, testName, ciliumCli, k8sCli, dockerCli)

	t.Log("Creating backend apps...")
	scenario.addBackendApplications(2, backendApplicationConfig{
		h2cEnabled:      true,
		listenPort:      listenPort,
		healthCheckPort: healthCheckPort,
	})

	t.Log("Creating clients and add BGP peering ...")
	client := scenario.addFRRClients(1, frrClientConfig{})[0]

	t.Log("Creating LB VIP resources...")
	vip := lbVIP(testName)
	scenario.createLBVIP(vip)

	t.Log("Creating LB BackendPool resources...")
	backends := []backendPoolOption{}
	for _, b := range scenario.backendApps {
		backends = append(backends, withIPBackend(b.ipv4, b.port), withHealthCheckPort(int32(healthCheckPort)))
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

func testT2HealthCheckTCP(t T, testName string, listenPort, healthCheckPort uint32) {
	ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
	dockerCli := NewDockerCli(t)

	// health checks with custom payload are only supported in v1.18 and newer
	minVersion := ">=1.18.0"
	currentVersion := GetCiliumVersion(t, k8sCli)
	if !versioncheck.MustCompile(minVersion)(currentVersion) {
		fmt.Printf("skipping due to version mismatch - expected: %s - current: %s\n", minVersion, currentVersion.String())
		return
	}

	// 0. Setup test scenario (backends, clients & LB resources)
	scenario := newLBTestScenario(t, testName, ciliumCli, k8sCli, dockerCli)

	t.Log("Creating backend apps...")
	scenario.addBackendApplications(2, backendApplicationConfig{
		h2cEnabled:      true,
		listenPort:      listenPort,
		healthCheckPort: healthCheckPort,
		envVars:         map[string]string{"TCP_ONLY_ENABLED": "true"},
	})

	t.Log("Creating clients and add BGP peering ...")
	client := scenario.addFRRClients(1, frrClientConfig{})[0]

	t.Log("Creating LB VIP resources...")
	vip := lbVIP(testName)
	scenario.createLBVIP(vip)

	t.Log("Creating LB BackendPool resources...")
	backends := []backendPoolOption{}
	backends = append(backends, withTCPHealthCheck(ptr.To("TEST"), ptr.To(":TEST")))
	for _, b := range scenario.backendApps {
		backends = append(backends, withIPBackend(b.ipv4, b.port), withHealthCheckPort(int32(healthCheckPort)))
	}
	backendPool := lbBackendPool(testName, backends...)
	scenario.createLBBackendPool(backendPool)

	t.Log("Creating LB Service resources...")
	service := lbService(testName, withPort(81), withTCPProxyApplication(withTCPForceDeploymentMode(isovalentv1alpha1.LBTCPProxyForceDeploymentModeT2), withTCPProxyRoute(backendPool.Name)))
	scenario.createLBService(service)

	t.Log("Waiting for full VIP connectivity...")
	vipIP := scenario.waitForFullVIPConnectivity(testName)

	// Establish TCP connection and send data to test basic `client -> LB T1 -> app` connectivity.
	cmd := fmt.Sprintf("echo -n deadbeef | nc -n -v -w 10 %s 81", vipIP)

	t.Log("Sending TCP request: cmd=%q", cmd)

	stdout, stderr, err := client.Exec(t.Context(), cmd)
	if err != nil {
		t.Failedf("remote exec failed: cmd='%q' stdout='%q' stderr='%q': '%w'", cmd, stdout, stderr, err)
	}

	resp := toTestAppL4Response(t, stdout)
	if resp.Response != "deadbeef" {
		t.Failedf("remote exec returned unexpected result: cmd='%q' stdout='%q' stderr='%q', resp='%q'", cmd, stdout, stderr, resp.Response)
	}

	// 2. Healthcheck (T2) testing

	// 2.1. Force both app's HC to fail

	t.Log("Setting T2 HC to fail...")

	for _, b := range scenario.backendApps {
		b.SetHC(t, hcFail)
	}

	// 2.2. Wait until curl fails due to failing HCs

	t.Log("Waiting connections to fails...")

	eventually(t, func() error {
		cmd := fmt.Sprintf("echo -n deadbeef | nc -n -v -w 10 %s 81", vipIP)

		t.Log("Sending TCP request: cmd=%q", cmd)

		_, _, err := client.Exec(t.Context(), cmd)
		if err != nil {
			return nil
		}

		return fmt.Errorf("tcp connections still succeeds (expect to fail)")
	}, longTimeout, longPollInterval)

	t.Log("Setting T2 HC to pass...")

	// 2.3. Bring back both backends

	for _, b := range scenario.backendApps {
		b.SetHC(t, hcOK)
	}

	t.Log("Waiting for connections to pass...")

	// 2.4. Expect to pass
	//
	eventually(t, func() error {
		cmd := fmt.Sprintf("echo -n deadbeef | nc -n -v -w 10 %s 81", vipIP)

		t.Log("Sending TCP request: cmd=%q", cmd)

		stdout, stderr, err := client.Exec(t.Context(), cmd)
		if err != nil {
			return fmt.Errorf("remote exec failed: cmd='%q' stdout='%q' stderr='%q': '%w'", cmd, stdout, stderr, err)
		}

		resp := toTestAppL4Response(t, stdout)
		if resp.Response != "deadbeef" {
			return fmt.Errorf("remote exec returned unexpected result: cmd='%q' stdout='%q' stderr='%q', resp='%q'", cmd, stdout, stderr, resp.Response)
		}

		return nil
	}, longTimeout, longPollInterval)
}
