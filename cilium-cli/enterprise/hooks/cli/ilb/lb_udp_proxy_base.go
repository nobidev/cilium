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
)

func TestUDPProxyT1Only(t T) {
	testUDPProxy(t, isovalentv1alpha1.LBUDPProxyForceDeploymentModeT1)
}

func TestUDPProxyT1T2(t T) {
	testUDPProxy(t, isovalentv1alpha1.LBUDPProxyForceDeploymentModeT2)
}

func TestUDPProxyAuto(t T) {
	testUDPProxy(t, isovalentv1alpha1.LBUDPProxyForceDeploymentModeAuto)
}

func testUDPProxy(t T, forceDeploymentMode isovalentv1alpha1.LBUDPProxyForceDeploymentModeType) {
	ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
	dockerCli := NewDockerCli(t)

	testName := "udp-proxy-" + string(forceDeploymentMode)

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
	service := lbService(testName, withPort(80), withUDPProxyApplication(withUDPForceDeploymentMode(forceDeploymentMode), withUDPProxyRoute(backendPool.Name)))
	scenario.createLBService(service)

	t.Log("Waiting for full VIP connectivity...")
	vipIP := scenario.waitForFullVIPConnectivity(testName)

	// Send UDP request to test basic `client -> LB T1 -> app` connectivity.
	// Do a few attempts, as neither UDP nor nc are reliable.
	eventually(t, func() error {
		cmd := fmt.Sprintf("echo -n deadbeef | nc -n -v -u -w 1 %s 80", vipIP)

		t.Log("Sending UDP request: cmd=%q", cmd)

		stdout, stderr, err := client.Exec(t.Context(), cmd)
		if err != nil {
			return fmt.Errorf("remote exec failed: cmd='%q' stdout='%q' stderr='%q': '%w'", cmd, stdout, stderr, err)
		}

		resp := toTestAppUDPResponse(t, stdout)
		if resp.Response == "deadbeef" {
			return nil
		}

		return fmt.Errorf("remote exec returned unexpected result: cmd='%q' stdout='%q' stderr='%q', resp='%q'", cmd, stdout, stderr, resp.Response)
	}, 10*time.Second, 1*time.Second)
}
