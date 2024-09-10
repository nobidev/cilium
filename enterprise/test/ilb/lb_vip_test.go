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

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

func TestSharedVIP(t *testing.T) {
	ctx := context.Background()
	testName := "shared-vip-1"
	testK8sNamespace := "default"

	ciliumCli, k8sCli := newCiliumAndK8sCli(t)
	dockerCli := newDockerCli(t)

	// 0. Setup test scenario (backends, clients & LB resources)
	scenario := newLBTestScenario(t, testName, testK8sNamespace, ciliumCli, k8sCli, dockerCli)

	t.Log("Creating backend apps...")
	scenario.addBackendApplications(ctx, 2, backendApplicationConfig{h2cEnabled: true})

	t.Log("Creating clients and add BGP peering ...")
	scenario.addFRRClients(ctx, 1, frrClientConfig{})

	clientName := testName + "-client-0"

	t.Logf("Creating LB VIP resources...")
	vip := lbVIP(testK8sNamespace, testName, "")
	scenario.createLBVIP(ctx, vip)

	t.Logf("Creating LB BackendPool resources...")
	backends := []isovalentv1alpha1.Backend{}
	for _, b := range scenario.backendApps {
		backends = append(backends, isovalentv1alpha1.Backend{
			IP:   b.ip,
			Port: 8080,
		})
	}
	backendPool := lbBackendPool(testK8sNamespace, testName, "/health", 10, backends, nil)
	scenario.createLBBackendPool(ctx, backendPool)

	t.Logf("Creating LB Service resources...")
	service1 := lbService(testK8sNamespace, testName+"-1", testName, 80, lbServiceApplicationsHTTP(testName, "", ""))
	scenario.createLBService(ctx, service1)

	service2 := lbService(testK8sNamespace, testName+"-2", testName, 81, lbServiceApplicationsHTTP(testName, "", ""))
	scenario.createLBService(ctx, service2)

	t.Logf("Waiting for full VIP connectivity of %q...", testName)
	vipIP := scenario.waitForFullVIPConnectivity(ctx, testName)

	// 1. Send two HTTP requests on VIP for both services
	{
		testCmd := curlCmdVerbose(fmt.Sprintf("-m 2 http://%s:80/", vipIP))
		t.Logf("Testing %q...", testCmd)
		stdout, stderr, err := dockerCli.clientExec(ctx, clientName, testCmd)
		if err != nil {
			t.Fatalf("curl failed (cmd: %q, stdout: %q, stderr: %q): %s", testCmd, stdout, stderr, err)
		}
	}

	{
		testCmd := curlCmdVerbose(fmt.Sprintf("-m 2 http://%s:81/", vipIP))
		t.Logf("Testing %q...", testCmd)
		stdout, stderr, err := dockerCli.clientExec(ctx, clientName, testCmd)
		if err != nil {
			t.Fatalf("curl failed (cmd: %q, stdout: %q, stderr: %q): %s", testCmd, stdout, stderr, err)
		}
	}
}

func TestRequestedVIP(t *testing.T) {
	ctx := context.Background()
	testName := "requested-vip-1"
	testK8sNamespace := "default"

	ciliumCli, k8sCli := newCiliumAndK8sCli(t)
	dockerCli := newDockerCli(t)

	// 0. Setup test scenario (backends, clients & LB resources)
	scenario := newLBTestScenario(t, testName, testK8sNamespace, ciliumCli, k8sCli, dockerCli)

	t.Log("Creating backend apps...")
	scenario.addBackendApplications(ctx, 2, backendApplicationConfig{h2cEnabled: true})

	t.Log("Creating clients and add BGP peering ...")
	scenario.addFRRClients(ctx, 1, frrClientConfig{})

	clientName := testName + "-client-0"

	t.Logf("Creating LB VIP resources...")
	requestedVIP := "100.64.0.250"
	vip := lbVIP(testK8sNamespace, testName, requestedVIP)
	scenario.createLBVIP(ctx, vip)

	t.Logf("Creating LB BackendPool resources...")
	backends := []isovalentv1alpha1.Backend{}
	for _, b := range scenario.backendApps {
		backends = append(backends, isovalentv1alpha1.Backend{
			IP:   b.ip,
			Port: 8080,
		})
	}
	backendPool := lbBackendPool(testK8sNamespace, testName, "/health", 10, backends, nil)
	scenario.createLBBackendPool(ctx, backendPool)

	t.Logf("Creating LB Service resources...")
	service1 := lbService(testK8sNamespace, testName, testName, 80, lbServiceApplicationsHTTP(testName, "", ""))
	scenario.createLBService(ctx, service1)

	t.Logf("Waiting for full VIP connectivity of %q...", testName)
	_ = scenario.waitForFullVIPConnectivity(ctx, testName)

	// 1. Send HTTP request to requested VIP
	testCmd := curlCmdVerbose(fmt.Sprintf("-m 2 http://%s:80/", requestedVIP))
	t.Logf("Testing %q...", testCmd)
	stdout, stderr, err := dockerCli.clientExec(ctx, clientName, testCmd)
	if err != nil {
		t.Fatalf("curl failed (cmd: %q, stdout: %q, stderr: %q): %s", testCmd, stdout, stderr, err)
	}
}
