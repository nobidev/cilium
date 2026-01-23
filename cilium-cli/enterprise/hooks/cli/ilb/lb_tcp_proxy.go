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

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/versioncheck"
)

func TestTCPProxyT1Only(t T) {
	testTCPProxy(t, "tcp-proxy-t1-only", isovalentv1alpha1.LBTCPProxyForceDeploymentModeT1, 8080, 0)
}

func TestTCPProxyT1OnlyHealthCheckCustomPort(t T) {
	testTCPProxy(t, "tcp-proxy-t1-only-health-check-custom-port", isovalentv1alpha1.LBTCPProxyForceDeploymentModeT1, 8181, 8080)
}

func TestTCPProxyT1T2(t T) {
	testTCPProxy(t, "tcp-proxy-t1-t2", isovalentv1alpha1.LBTCPProxyForceDeploymentModeT2, 8080, 0)
}

func TestTCPProxyAuto(t T) {
	testTCPProxy(t, "tcp-proxy-auto", isovalentv1alpha1.LBTCPProxyForceDeploymentModeAuto, 8080, 0)
}

func testTCPProxy(t T, testName string, mode isovalentv1alpha1.LBTCPProxyForceDeploymentModeType, listenPort, healthCheckPort uint32) {
	ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
	dockerCli := NewDockerCli(t)

	// custom health check port is only supported in v1.18 and newer
	if healthCheckPort != 0 {
		minVersion := ">=1.18.0"
		currentVersion := GetCiliumVersion(t, k8sCli)
		if !versioncheck.MustCompile(minVersion)(currentVersion) {
			fmt.Printf("skipping due to version mismatch - expected: %s - current: %s\n", minVersion, currentVersion.String())
			return
		}
	}

	t.RunTestCase(func(t T) {
		// 0. Setup test scenario (backends, clients & LB resources)
		scenario := newLBTestScenario(t, testName, ciliumCli, k8sCli, dockerCli)

		t.Log("Creating backend apps...")

		backendNum := 2
		// TCPProxy does not support backends with different ports, so create just 1 backend.
		if IsSingleNode() {
			backendNum = 1
		}
		scenario.addBackendApplications(backendNum,
			backendApplicationConfig{
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
		service := lbService(testName, withPort(80), withTCPProxyApplication(withTCPForceDeploymentMode(mode), withTCPProxyRoute(backendPool.Name)))
		scenario.createLBService(service)

		t.Log("Waiting for full VIP connectivity...")
		vipIP := scenario.waitForFullVIPConnectivity(testName)

		// 1. Send HTTP request to test basic client -> LB T1 -> LB T2 -> app connectivity
		testCmd := curlCmdVerbose(fmt.Sprintf("--max-time 10 http://%s:80/", vipIP))
		t.Log("Testing %q...", testCmd)
		stdout, stderr, err := client.Exec(t.Context(), testCmd)
		if err != nil {
			t.Failedf("curl failed (cmd: %q, stdout: %q, stderr: %q): %s", testCmd, stdout, stderr, err)
		}
	})
}
