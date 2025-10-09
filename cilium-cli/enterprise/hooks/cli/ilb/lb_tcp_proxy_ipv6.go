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

func TestTCPProxyIPv6VIPIPv6BackendT1Only(t T) {
	testTCPProxyIPv6(t, isovalentv1alpha1.LBTCPProxyForceDeploymentModeT1, true, true)
}

func TestTCPProxyIPv6VIPIPv6BackendT1T2(t T) {
	testTCPProxyIPv6(t, isovalentv1alpha1.LBTCPProxyForceDeploymentModeT2, true, true)
}

func TestTCPProxyIPv6VIPIPv6BackendAuto(t T) {
	testTCPProxyIPv6(t, isovalentv1alpha1.LBTCPProxyForceDeploymentModeAuto, true, true)
}

func TestTCPProxyIPv6VIPIPv4BackendT1T2(t T) {
	testTCPProxyIPv6(t, isovalentv1alpha1.LBTCPProxyForceDeploymentModeT2, true, false)
}

func TestTCPProxyIPv6VIPIPv4BackendAuto(t T) {
	testTCPProxyIPv6(t, isovalentv1alpha1.LBTCPProxyForceDeploymentModeAuto, true, false)
}

func TestTCPProxyIPv4VIPIPv6BackendT1T2(t T) {
	testTCPProxyIPv6(t, isovalentv1alpha1.LBTCPProxyForceDeploymentModeT2, false, true)
}

func TestTCPProxyIPv4VIPIPv6BackendAuto(t T) {
	testTCPProxyIPv6(t, isovalentv1alpha1.LBTCPProxyForceDeploymentModeAuto, false, true)
}

func testTCPProxyIPv6(t T, mode isovalentv1alpha1.LBTCPProxyForceDeploymentModeType, ipv6VIP bool, ipv6Backend bool) {
	ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
	dockerCli := NewDockerCli(t)

	// IPv6 is only supported in v1.18 and newer
	minVersion := ">=1.18.0"
	currentVersion := GetCiliumVersion(t, k8sCli)
	if !versioncheck.MustCompile(minVersion)(currentVersion) {
		fmt.Printf("skipping due to version mismatch - expected: %s - current: %s\n", minVersion, currentVersion.String())
		return
	}

	if !t.IPv6Enabled() {
		fmt.Println("skipping because IPv6 isn't enabled")
		return
	}

	t.RunTestCase(func(t T) {
		testName := fmt.Sprintf("tcp-proxy-ipv6-%s-%t-%t", string(mode), ipv6VIP, ipv6Backend)

		// 0. Setup test scenario (backends, clients & LB resources)
		scenario := newLBTestScenario(t, testName, ciliumCli, k8sCli, dockerCli)

		t.Log("Creating backend apps...")

		backendNum := 2
		// TCPProxy does not support backends with different ports, so create just 1 backend.
		if IsSingleNode() {
			backendNum = 1
		}
		scenario.addBackendApplications(backendNum, backendApplicationConfig{h2cEnabled: true})

		t.Log("Creating clients and add BGP peering ...")
		client := scenario.addFRRClients(1, frrClientConfig{})[0]

		t.Log("Creating LB VIP resources...")

		options := []vipOption{}
		if ipv6VIP {
			options = append(options, withAddressFamily(isovalentv1alpha1.AddressFamilyIPv6))
		}
		vip := lbVIP(testName, options...)
		scenario.createLBVIP(vip)

		t.Log("Creating LB BackendPool resources...")
		backends := []backendPoolOption{}
		for _, b := range scenario.backendApps {
			ip := b.ipv4
			if ipv6Backend {
				ip = b.ipv6
			}
			backends = append(backends, withIPBackend(ip, b.port))
		}
		backendPool := lbBackendPool(testName, backends...)
		scenario.createLBBackendPool(backendPool)

		t.Log("Creating LB Service resources...")
		service := lbService(testName, withPort(80), withTCPProxyApplication(withTCPForceDeploymentMode(mode), withTCPProxyRoute(backendPool.Name)))
		scenario.createLBService(service)

		t.Log("Waiting for full VIP connectivity...")
		v := scenario.waitForFullVIPConnectivityInclIPv6(testName)

		// 1. Send HTTP request to test basic client -> LB T1 -> LB T2 -> app connectivity
		ipString := v.IPv4Formatted()
		curlIPFamilyFlag := "-4"
		if ipv6VIP {
			ipString = v.IPv6Formatted()
			curlIPFamilyFlag = "-6"
		}

		testCmd := curlCmdVerbose(fmt.Sprintf("--max-time 10 %s http://%s:80/", curlIPFamilyFlag, ipString))
		t.Log("Testing %q...", testCmd)
		stdout, stderr, err := client.Exec(t.Context(), testCmd)
		if err != nil {
			t.Failedf("curl failed (cmd: %q, stdout: %q, stderr: %q): %s", testCmd, stdout, stderr, err)
		}
	})
}
