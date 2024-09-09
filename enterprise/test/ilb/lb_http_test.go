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

func TestHTTPAndT2HealthChecks(t *testing.T) {
	ctx := context.Background()
	testName := "http-1"
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
	service := lbService(testK8sNamespace, testName, testName, 81, lbServiceApplicationsHTTP(testName, "", ""))
	scenario.createLBService(ctx, service)

	t.Logf("Waiting for full VIP connectivity of %q...", testName)
	vipIP := scenario.waitForFullVIPConnectivity(ctx, testName)

	// 1. Send HTTP request to test basic client -> LB T1 -> LB T2 -> app connectivity
	testCmd := curlCmdVerbose(fmt.Sprintf("-m 2 http://%s:81/", vipIP))
	t.Logf("Testing %q...", testCmd)
	stdout, stderr, err := dockerCli.clientExec(ctx, clientName, testCmd)
	if err != nil {
		t.Fatalf("curl failed (cmd: %q, stdout: %q, stderr: %q): %s", testCmd, stdout, stderr, err)
	}

	// 2. Healthcheck (T2) testing

	// 2.1. Force both app's HC to fail

	t.Logf("Setting T2 HC to fail...")

	for _, b := range scenario.backendApps {
		if err := dockerCli.controlBackendHC(ctx, clientName, b.ip, hcFail); err != nil {
			t.Fatalf("failed to set HC to fail (%s): %s", b.ip, err)
		}
	}

	// 2.2. Wait until curl fails due to failing HCs

	t.Logf("Waiting for curl to fails...")

	eventually(t, func() error {
		_, _, err := dockerCli.clientExec(ctx, clientName, testCmd)
		if err != nil {
			return nil
		}
		return fmt.Errorf("curl request still succeeds (expect to fail)")
	}, longTimeout, longPollInterval)

	t.Logf("Setting T2 HC to pass...")

	// 2.3. Bring back both backends

	for _, b := range scenario.backendApps {
		if err := dockerCli.controlBackendHC(ctx, clientName, b.ip, hcOK); err != nil {
			t.Fatalf("failed to set HC to pass (%s): %s", b.ip, err)
		}
	}

	t.Logf("Waiting for curl to pass...")

	// 2.4. Expect to pass

	eventually(t, func() error {
		_, _, err := dockerCli.clientExec(ctx, clientName, testCmd)
		if err != nil {
			return fmt.Errorf("curl request still fails (expect to succeed")
		}
		return nil
	}, longTimeout, longPollInterval)

	// TODO(brb) bring back only one backend
}

func TestHTTP2(t *testing.T) {
	ctx := context.Background()
	testName := "http2-1"
	testK8sNamespace := "default"
	hostName := "mixed.acme.io"

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
	service := lbService(testK8sNamespace, testName, testName, 80, lbServiceApplicationsHTTP(testName, hostName, ""))
	scenario.createLBService(ctx, service)

	t.Logf("Waiting for full VIP connectivity of %q...", testName)
	vipIP := scenario.waitForFullVIPConnectivity(ctx, testName)

	// 1. Send HTTP request to test basic client -> LB T1 -> LB T2 -> app connectivity
	testCmd := curlCmdVerbose(fmt.Sprintf("--http2-prior-knowledge -o/dev/null -w '%%{http_version}' --resolve mixed.acme.io:80:%s http://mixed.acme.io:80/", vipIP))
	t.Logf("Testing %q...", testCmd)
	stdout, stderr, err := dockerCli.clientExec(ctx, clientName, testCmd)
	if err != nil {
		t.Fatalf("curl failed (cmd: %q, stdout: %q, stderr: %q): %s", testCmd, stdout, stderr, err)
	}

	// Check HTTP H2
	if stdout != "2" {
		t.Fatalf("Expected HTTP 2, got: %s", stdout)
	}
}

func TestHTTPPath(t *testing.T) {
	ctx := context.Background()
	testName := "http-path-1"
	testK8sNamespace := "default"
	hostName := "insecure.acme.io"
	path := "/api/foo-insecure"

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
	service := lbService(testK8sNamespace, testName, testName, 80, lbServiceApplicationsHTTP(testName, hostName, path))
	scenario.createLBService(ctx, service)

	t.Logf("Waiting for full VIP connectivity of %q...", testName)
	vipIP := scenario.waitForFullVIPConnectivity(ctx, testName)

	// 1. Send HTTP request to test basic client -> LB T1 -> LB T2 -> app connectivity
	{
		testCmd := curlCmdVerbose(fmt.Sprintf("--resolve %s:80:%s http://%s:80%s", hostName, vipIP, hostName, path))
		t.Logf("Testing %q...", testCmd)
		stdout, stderr, err := dockerCli.clientExec(ctx, clientName, testCmd)
		if err != nil {
			t.Fatalf("curl failed (cmd: %q, stdout: %q, stderr: %q): %s", testCmd, stdout, stderr, err)
		}
	}

	{
		testCmd := curlCmdVerbose(fmt.Sprintf("--resolve %s:80:%s http://%s:80%s", hostName, vipIP, hostName, "/other"))
		t.Logf("Testing failure on other path %q...", testCmd)
		stdout, stderr, err := dockerCli.clientExec(ctx, clientName, testCmd)
		if err == nil {
			t.Fatalf("curl didn't fail (cmd: %q, stdout: %q, stderr: %q): %s", testCmd, stdout, stderr, err)
		}
	}
}
