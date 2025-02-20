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

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

var allUdpForceDeploymentModes = []isovalentv1alpha1.LBUDPProxyForceDeploymentModeType{isovalentv1alpha1.LBUDPProxyForceDeploymentModeT1, isovalentv1alpha1.LBUDPProxyForceDeploymentModeT2, isovalentv1alpha1.LBUDPProxyForceDeploymentModeAuto}

func TestUDPProxy() {
	for _, forceDeploymentMode := range allUdpForceDeploymentModes {
		ciliumCli, k8sCli := NewCiliumAndK8sCli()
		dockerCli := NewDockerCli()

		testK8sNamespace := "default"

		fmt.Println("=== RUN   TestUDPProxy/Test UDPProxy force mode " + string(forceDeploymentMode))
		ctx := context.Background()
		testName := "udp-proxy-" + string(forceDeploymentMode)

		// 0. Setup test scenario (backends, clients & LB resources)
		scenario := newLBTestScenario(testName, testK8sNamespace, ciliumCli, k8sCli, dockerCli)

		fmt.Println("Creating backend apps...")

		backendNum := 2
		// UDPProxy does not support backends with different ports, so create just 1 backend.
		if IsSingleNode() {
			backendNum = 1
		}
		scenario.addBackendApplications(ctx, backendNum, backendApplicationConfig{h2cEnabled: true})

		fmt.Println("Creating clients and add BGP peering ...")
		client := scenario.addFRRClients(ctx, 1, frrClientConfig{})[0]

		fmt.Println("Creating LB VIP resources...")
		vip := lbVIP(testK8sNamespace, testName)
		scenario.createLBVIP(ctx, vip)

		fmt.Println("Creating LB BackendPool resources...")
		backends := []backendPoolOption{}
		for _, b := range scenario.backendApps {
			backends = append(backends, withIPBackend(b.ip, b.port))
		}
		backendPool := lbBackendPool(testK8sNamespace, testName, backends...)
		scenario.createLBBackendPool(ctx, backendPool)

		fmt.Println("Creating LB Service resources...")
		service := lbService(testK8sNamespace, testName, withPort(80), withUDPProxyApplication(withUDPForceDeploymentMode(forceDeploymentMode), withUDPProxyRoute(backendPool.Name)))
		scenario.createLBService(ctx, service)

		maybeSysdump(testName, "")

		fmt.Printf("Waiting for full VIP connectivity of %q...\n", testName)
		vipIP := scenario.waitForFullVIPConnectivity(ctx, testName)

		// Send UDP request to test basic `client -> LB T1 -> app` connectivity.
		// Do a few attempts, as neither UDP nor nc are reliable.
		eventually(func() error {
			cmd := fmt.Sprintf("echo -n deadbeef | nc -n -v -u -w 1 %s 80", vipIP)

			fmt.Printf("Sending UDP request: cmd='%q'\n", cmd)

			stdout, stderr, err := client.Exec(ctx, cmd)
			if err != nil {
				return fmt.Errorf("remote exec failed: cmd='%q' stdout='%q' stderr='%q': '%w'", cmd, stdout, stderr, err)
			}

			resp := toTestAppUDPResponse(stdout)
			if resp.Response == "deadbeef" {
				return nil
			}

			return fmt.Errorf("remote exec returned unexpected result: cmd='%q' stdout='%q' stderr='%q', resp='%q'", cmd, stdout, stderr, resp.Response)
		}, 10*time.Second, 1*time.Second)
	}
}
