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
	client := scenario.addFRRClients(ctx, 1, frrClientConfig{})[0]

	t.Logf("Creating LB VIP resources...")
	vip := lbVIP(testK8sNamespace, testName)
	scenario.createLBVIP(ctx, vip)

	t.Logf("Creating LB BackendPool resources...")
	backends := []backendPoolOption{}
	for _, b := range scenario.backendApps {
		backends = append(backends, withIPBackend(b.ip, b.port))
	}
	backendPool := lbBackendPool(testK8sNamespace, testName, backends...)
	scenario.createLBBackendPool(ctx, backendPool)

	t.Logf("Creating LB Service resources...")
	service := lbService(testK8sNamespace, testName, withPort(81), withHTTPProxyApplication(
		withHttpRoute(testName),
	))
	scenario.createLBService(ctx, service)

	t.Logf("Waiting for full VIP connectivity of %q...", testName)
	vipIP := scenario.waitForFullVIPConnectivity(ctx, testName)

	// 1. Send HTTP request to test basic client -> LB T1 -> LB T2 -> app connectivity
	testCmd := curlCmdVerbose(fmt.Sprintf("--max-time 10 http://%s:81/", vipIP))
	t.Logf("Testing %q...", testCmd)
	stdout, stderr, err := client.Exec(ctx, testCmd)
	if err != nil {
		t.Fatalf("curl failed (cmd: %q, stdout: %q, stderr: %q): %s", testCmd, stdout, stderr, err)
	}

	// 2. Healthcheck (T2) testing

	// 2.1. Force both app's HC to fail

	t.Logf("Setting T2 HC to fail...")

	for _, b := range scenario.backendApps {
		b.SetHC(ctx, hcFail)
	}

	// 2.2. Wait until curl fails due to failing HCs

	t.Logf("Waiting for curl to fails...")

	eventually(t, func() error {
		_, _, err := client.Exec(ctx, testCmd)
		if err != nil {
			return nil
		}
		return fmt.Errorf("curl request still succeeds (expect to fail)")
	}, longTimeout, longPollInterval)

	t.Logf("Setting T2 HC to pass...")

	// 2.3. Bring back both backends

	for _, b := range scenario.backendApps {
		b.SetHC(ctx, hcOK)
	}

	t.Logf("Waiting for curl to pass...")

	// 2.4. Expect to pass

	eventually(t, func() error {
		_, _, err := client.Exec(ctx, testCmd)
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
	client := scenario.addFRRClients(ctx, 1, frrClientConfig{})[0]

	t.Logf("Creating LB VIP resources...")
	vip := lbVIP(testK8sNamespace, testName)
	scenario.createLBVIP(ctx, vip)

	t.Logf("Creating LB BackendPool resources...")
	backends := []backendPoolOption{}
	for _, b := range scenario.backendApps {
		backends = append(backends, withIPBackend(b.ip, b.port))
	}
	backendPool := lbBackendPool(testK8sNamespace, testName, backends...)
	scenario.createLBBackendPool(ctx, backendPool)

	t.Logf("Creating LB Service resources...")
	service := lbService(testK8sNamespace, testName, withHTTPProxyApplication(
		withHttpRoute(testName, withHttpHostname(hostName)),
	))
	scenario.createLBService(ctx, service)

	t.Logf("Waiting for full VIP connectivity of %q...", testName)
	vipIP := scenario.waitForFullVIPConnectivity(ctx, testName)

	// 1. Send HTTP request to test basic client -> LB T1 -> LB T2 -> app connectivity
	testCmd := curlCmdVerbose(fmt.Sprintf("--max-time 10 --http2-prior-knowledge -o/dev/null -w '%%{http_version}' --resolve mixed.acme.io:80:%s http://mixed.acme.io:80/", vipIP))
	t.Logf("Testing %q...", testCmd)
	stdout, stderr, err := client.Exec(ctx, testCmd)
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
	client := scenario.addFRRClients(ctx, 1, frrClientConfig{})[0]

	t.Logf("Creating LB VIP resources...")
	vip := lbVIP(testK8sNamespace, testName)
	scenario.createLBVIP(ctx, vip)

	t.Logf("Creating LB BackendPool resources...")
	backends := []backendPoolOption{}
	for _, b := range scenario.backendApps {
		backends = append(backends, withIPBackend(b.ip, b.port))
	}
	backendPool := lbBackendPool(testK8sNamespace, testName, backends...)
	scenario.createLBBackendPool(ctx, backendPool)

	t.Logf("Creating LB Service resources...")
	service := lbService(testK8sNamespace, testName, withHTTPProxyApplication(
		withHttpRoute(testName, withHttpHostname(hostName), withHttpPath(path)),
	))
	scenario.createLBService(ctx, service)

	t.Logf("Waiting for full VIP connectivity of %q...", testName)
	vipIP := scenario.waitForFullVIPConnectivity(ctx, testName)

	// 1. Send HTTP request to test basic client -> LB T1 -> LB T2 -> app connectivity
	{
		testCmd := curlCmdVerbose(fmt.Sprintf("--max-time 10 --resolve %s:80:%s http://%s:80%s", hostName, vipIP, hostName, path))
		t.Logf("Testing %q...", testCmd)
		stdout, stderr, err := client.Exec(ctx, testCmd)
		if err != nil {
			t.Fatalf("curl failed (cmd: %q, stdout: %q, stderr: %q): %s", testCmd, stdout, stderr, err)
		}
	}

	{
		testCmd := curlCmdVerbose(fmt.Sprintf("--max-time 10 --resolve %s:80:%s http://%s:80%s", hostName, vipIP, hostName, "/other"))
		t.Logf("Testing failure on other path %q...", testCmd)
		stdout, stderr, err := client.Exec(ctx, testCmd)
		if err == nil {
			t.Fatalf("curl didn't fail (cmd: %q, stdout: %q, stderr: %q): %s", testCmd, stdout, stderr, err)
		}
	}
}

func TestHTTPRoutes(t *testing.T) {
	ctx := context.Background()
	testName := "http-routes"
	testK8sNamespace := "default"

	ciliumCli, k8sCli := newCiliumAndK8sCli(t)
	dockerCli := newDockerCli(t)

	serviceBackendMappings := map[string]struct {
		hostname         string
		testCallHostname string
		path             string
	}{
		"-0": {hostname: "first.acme.io", testCallHostname: "first.acme.io", path: "first"},
		"-1": {hostname: "first.acme.io", testCallHostname: "first.acme.io", path: "second"},
		"-2": {hostname: "second.acme.io", testCallHostname: "second.acme.io", path: "third"},
		"-3": {hostname: "*.second.acme.io", testCallHostname: "sub.second.acme.io", path: "fourth"},
	}

	// 0. Setup test scenario (backends, clients & LB resources)
	scenario := newLBTestScenario(t, testName, testK8sNamespace, ciliumCli, k8sCli, dockerCli)

	t.Log("Creating backend apps...")
	scenario.addBackendApplications(ctx, 4, backendApplicationConfig{h2cEnabled: true})

	t.Log("Creating clients and add BGP peering ...")
	client := scenario.addFRRClients(ctx, 1, frrClientConfig{})[0]

	t.Logf("Creating LB VIP resources...")
	vip := lbVIP(testK8sNamespace, testName)
	scenario.createLBVIP(ctx, vip)

	t.Logf("Creating LB BackendPool resources...")
	// one backendpool per backend app
	for postfix := range serviceBackendMappings {
		backend := scenario.backendApps[testName+"-app"+postfix]
		scenario.createLBBackendPool(ctx, lbBackendPool(testK8sNamespace, testName+postfix, withIPBackend(backend.ip, backend.port)))
	}

	t.Logf("Creating LB Service resources...")
	// one route per backendpool (backend app)
	routes := []httpApplicationOption{}
	for postfix, rhost := range serviceBackendMappings {
		routes = append(routes, withHttpRoute(testName+postfix, withHttpHostname(rhost.hostname), withHttpPath(fmt.Sprintf("/%s", rhost.path))))
	}
	service := lbService(testK8sNamespace, testName, withHTTPProxyApplication(routes...))
	scenario.createLBService(ctx, service)

	t.Logf("Waiting for full VIP connectivity of %q...", testName)
	vipIP := scenario.waitForFullVIPConnectivity(ctx, testName)

	// calling each route once
	for postfix, rhost := range serviceBackendMappings {
		testCmd := curlCmd(fmt.Sprintf("--max-time 10 -H 'Content-Type: application/json' --resolve %s:80:%s http://%s:80%s", rhost.testCallHostname, vipIP, rhost.testCallHostname, fmt.Sprintf("/%s", rhost.path)))
		t.Logf("Testing %q...", testCmd)
		stdout, stderr, err := client.Exec(ctx, testCmd)
		if err != nil {
			t.Fatalf("curl failed (cmd: %q, stdout: %q, stderr: %q): %s", testCmd, stdout, stderr, err)
		}

		t.Log("Check that request is handled by the correct backend")
		appResponse := toTestAppResponse(t, stdout)
		if appResponse.ServiceName != testName+"-app"+postfix {
			t.Fatalf("request not handled by the expected backend %s != %s (cmd: %q, stdout: %q, stderr: %q): %s", appResponse.ServiceName, testName+"-app"+postfix, testCmd, stdout, stderr, err)
		}
	}
}
