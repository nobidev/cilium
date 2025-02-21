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

func TestBGPHealthCheck(t T) {
	testName := "bgp-health-check"
	testK8sNamespace := "default"

	ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
	dockerCli := NewDockerCli(t)

	// 0. Setup test scenario (backends, clients & LB resources)
	scenario := newLBTestScenario(t, testName, testK8sNamespace, ciliumCli, k8sCli, dockerCli)

	fmt.Println("Creating backend app...")
	backend := scenario.addBackendApplications(1, backendApplicationConfig{h2cEnabled: true})[0]

	fmt.Println("Creating client and add BGP peering ...")
	client := scenario.addFRRClients(1, frrClientConfig{})[0]

	fmt.Println("Creating LB VIP resources...")
	vip := lbVIP(testK8sNamespace, testName)
	scenario.createLBVIP(vip)

	fmt.Println("Creating LB BackendPool resources...")
	backendPool := lbBackendPool(testK8sNamespace, testName, withIPBackend(backend.ip, backend.port))
	scenario.createLBBackendPool(backendPool)

	fmt.Println("Creating LB Service resources...")
	service := lbService(testK8sNamespace, testName, withHTTPProxyApplication(withHttpRoute(testName)))
	scenario.createLBService(service)

	fmt.Println("Waiting for full VIP connectivity...")
	vipIP := scenario.waitForFullVIPConnectivity(testName)

	// 1. HC Down
	fmt.Println("Setting T2 HC to fail...")
	backend.SetHC(t, hcFail)

	// 2. VIP shouldn't be advertised
	eventually(t, func() error {
		if err := client.EnsureRoute(t.Context(), vipIP+"/32"); err == nil {
			return fmt.Errorf("the route %s/32 still exists", vipIP)
		}
		return nil
	}, shortTimeout, pollInterval)

	fmt.Println("VIP successfully removed")

	// 3. HC Up
	fmt.Println("Setting T2 HC to ok...")
	backend.SetHC(t, hcOK)

	// 4. VIP should be advertised
	eventually(t, func() error {
		if err := client.EnsureRoute(t.Context(), vipIP+"/32"); err != nil {
			return fmt.Errorf("the route %s/32 is missing %w", vipIP, err)
		}
		return nil
	}, shortTimeout, pollInterval)

	fmt.Println("VIP successfully re-advertised")
}
