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

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/versioncheck"
)

func TestUDPProxyIPv6VIPIPv6BackendT1Only(t T) {
	testUDPProxyIPv6(t, isovalentv1alpha1.LBUDPProxyForceDeploymentModeT1, true, true)
}

func TestUDPProxyIPv6VIPIPv6BackendT1T2(t T) {
	testUDPProxyIPv6(t, isovalentv1alpha1.LBUDPProxyForceDeploymentModeT2, true, true)
}

func TestUDPProxyIPv6VIPIPv6BackendAuto(t T) {
	testUDPProxyIPv6(t, isovalentv1alpha1.LBUDPProxyForceDeploymentModeAuto, true, true)
}

func TestUDPProxyIPv6VIPIPv4BackendT1T2(t T) {
	testUDPProxyIPv6(t, isovalentv1alpha1.LBUDPProxyForceDeploymentModeT2, true, false)
}

func TestUDPProxyIPv6VIPIPv4BackendAuto(t T) {
	testUDPProxyIPv6(t, isovalentv1alpha1.LBUDPProxyForceDeploymentModeAuto, true, false)
}

func TestUDPProxyIPv4VIPIPv6BackendT1T2(t T) {
	testUDPProxyIPv6(t, isovalentv1alpha1.LBUDPProxyForceDeploymentModeT2, false, true)
}

func TestUDPProxyIPv4VIPIPv6BackendAuto(t T) {
	testUDPProxyIPv6(t, isovalentv1alpha1.LBUDPProxyForceDeploymentModeAuto, false, true)
}

func testUDPProxyIPv6(t T, forceDeploymentMode isovalentv1alpha1.LBUDPProxyForceDeploymentModeType, ipv6VIP bool, ipv6Backend bool) {
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

	testName := fmt.Sprintf("udp-proxy-ipv6-%s-%t-%t", string(forceDeploymentMode), ipv6VIP, ipv6Backend)

	// 0. Setup test scenario (backends, clients & LB resources)
	scenario := newLBTestScenario(t, testName, ciliumCli, k8sCli, dockerCli)

	t.Log("Creating backend apps...")

	backendNum := 2
	// UDPProxy does not support backends with different ports, so create just 1 backend.
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
	service := lbService(testName, withPort(80), withUDPProxyApplication(withUDPForceDeploymentMode(forceDeploymentMode), withUDPProxyRoute(backendPool.Name)))
	scenario.createLBService(service)

	t.Log("Waiting for full VIP connectivity...")
	v := scenario.waitForFullVIPConnectivityInclIPv6(testName)

	// Send UDP request to test basic `client -> LB T1 -> app` connectivity.
	// Do a few attempts, as neither UDP nor nc are reliable.

	ipString := v.IPv4Formatted()
	socatProtocolIPFamilyPrefix := "udp4"
	if ipv6VIP {
		ipString = v.IPv6Formatted()
		socatProtocolIPFamilyPrefix = "udp6"
	}

	eventually(t, func() error {
		cmd := fmt.Sprintf("echo -n deadbeef | socat -t 1 - %s:%s:80", socatProtocolIPFamilyPrefix, ipString)

		t.Log("Sending UDP request: cmd=%q", cmd)

		stdout, stderr, err := client.Exec(t.Context(), cmd)
		if err != nil {
			return fmt.Errorf("remote exec failed: cmd='%q' stdout='%q' stderr='%q': '%w'", cmd, stdout, stderr, err)
		}

		resp := toTestAppL4Response(t, stdout)
		if resp.Response == "deadbeef" {
			return nil
		}

		return fmt.Errorf("remote exec returned unexpected result: cmd='%q' stdout='%q' stderr='%q', resp='%q'", cmd, stdout, stderr, resp.Response)
	}, 10*time.Second, 1*time.Second)
}
