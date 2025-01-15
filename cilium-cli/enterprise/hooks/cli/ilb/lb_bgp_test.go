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
	"testing"
)

func TestBGPHealthCheck(t *testing.T) {
	ctx := context.Background()
	testName := "bgp-health-check"
	testK8sNamespace := "default"

	ciliumCli, k8sCli := newCiliumAndK8sCli(t)
	dockerCli := newDockerCli(t)

	// 0. Setup test scenario (backends, clients & LB resources)
	scenario := newLBTestScenario(t, testName, testK8sNamespace, ciliumCli, k8sCli, dockerCli)

	t.Log("Creating backend app...")
	backend := scenario.addBackendApplications(ctx, 1, backendApplicationConfig{h2cEnabled: true})[0]

	t.Log("Creating client and add BGP peering ...")
	client := scenario.addFRRClients(ctx, 1, frrClientConfig{})[0]

	t.Logf("Creating LB VIP resources...")
	vip := lbVIP(testK8sNamespace, testName)
	scenario.createLBVIP(ctx, vip)

	t.Logf("Creating LB BackendPool resources...")
	backendPool := lbBackendPool(testK8sNamespace, testName, withIPBackend(backend.ip, backend.port))
	scenario.createLBBackendPool(ctx, backendPool)

	t.Logf("Creating LB Service resources...")
	service := lbService(testK8sNamespace, testName, withHTTPProxyApplication(withHttpRoute(testName)))
	scenario.createLBService(ctx, service)

	t.Logf("Waiting for full VIP connectivity of %q...", testName)
	vipIP := scenario.waitForFullVIPConnectivity(ctx, testName)

	maybeSysdump(t, testName, "")

	// 1. HC Down
	t.Logf("Setting T2 HC to fail...")
	backend.SetHC(ctx, hcFail)

	// 2. VIP shouldn't be advertised
	eventually(t, func() error {
		if err := client.EnsureRoute(ctx, vipIP+"/32"); err == nil {
			return fmt.Errorf("the route %s/32 still exists", vipIP)
		}
		return nil
	}, shortTimeout, pollInterval)

	t.Log("VIP successfully removed")

	// 3. HC Up
	t.Logf("Setting T2 HC to ok...")
	backend.SetHC(ctx, hcOK)

	// 4. VIP should be advertised
	eventually(t, func() error {
		if err := client.EnsureRoute(ctx, vipIP+"/32"); err != nil {
			return fmt.Errorf("the route %s/32 is missing %w", vipIP, err)
		}
		return nil
	}, shortTimeout, pollInterval)

	t.Log("VIP successfully re-advertised")
}
