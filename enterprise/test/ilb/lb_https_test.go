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

func TestHTTPS(t *testing.T) {
	ctx := context.Background()
	testName := "https-1"
	testK8sNamespace := "default"
	hostName := "secure.acme.io"

	ciliumCli, k8sCli := newCiliumAndK8sCli(t)
	dockerCli := newDockerCli(t)

	// 0. Setup test scenario (backends, clients & LB resources)
	scenario := newLBTestScenario(t, testName, testK8sNamespace, ciliumCli, k8sCli, dockerCli)

	t.Log("Creating cert and secret...")
	scenario.createLBServerCertificate(ctx, hostName)

	t.Log("Creating backend apps...")
	scenario.addBackendApplications(ctx, 2, backendApplicationConfig{h2cEnabled: true})

	t.Log("Creating clients and add BGP peering ...")
	scenario.addFRRClients(ctx, 1, frrClientConfig{trustedCertsHostnames: []string{hostName}})

	clientName := testName + "-client-0"

	t.Logf("Creating LB VIP resources...")
	vip := lbVIP(testK8sNamespace, testName)
	scenario.createLBVIP(ctx, vip)

	t.Logf("Creating LB BackendPool resources...")
	backends := []backendPoolOption{}
	for _, b := range scenario.backendApps {
		backends = append(backends, withBackend(b.ip, 8080))
	}
	backendPool := lbBackendPool(testK8sNamespace, testName, backends...)
	scenario.createLBBackendPool(ctx, backendPool)

	t.Logf("Creating LB Service resources...")
	service := lbService(testK8sNamespace, testName, withPort(443), withHTTPSProxyApplication(testName, testName, hostName))
	scenario.createLBService(ctx, service)

	t.Logf("Waiting for full VIP connectivity of %q...", testName)
	vipIP := scenario.waitForFullVIPConnectivity(ctx, testName)

	// 1. Send HTTPs request
	testCmd := curlCmdVerbose(fmt.Sprintf("--cacert /tmp/"+hostName+".crt --resolve secure.acme.io:443:%s https://secure.acme.io:443/", vipIP))
	t.Logf("Testing %q...", testCmd)
	stdout, stderr, err := dockerCli.clientExec(ctx, clientName, testCmd)
	if err != nil {
		t.Fatalf("curl failed (cmd: %q, stdout: %q, stderr: %q): %s", testCmd, stdout, stderr, err)
	}
}

func TestHTTP2S(t *testing.T) {
	ctx := context.Background()
	testName := "http2s-1"
	testK8sNamespace := "default"
	hostName := "secure-http2.acme.io"

	ciliumCli, k8sCli := newCiliumAndK8sCli(t)
	dockerCli := newDockerCli(t)

	// 0. Setup test scenario (backends, clients & LB resources)
	scenario := newLBTestScenario(t, testName, testK8sNamespace, ciliumCli, k8sCli, dockerCli)

	t.Log("Creating cert and secret...")
	scenario.createLBServerCertificate(ctx, hostName)

	t.Log("Creating backend apps...")
	scenario.addBackendApplications(ctx, 2, backendApplicationConfig{h2cEnabled: true})

	t.Log("Creating clients and add BGP peering ...")
	scenario.addFRRClients(ctx, 1, frrClientConfig{trustedCertsHostnames: []string{hostName}})

	clientName := testName + "-client-0"

	t.Logf("Creating LB VIP resources...")
	vip := lbVIP(testK8sNamespace, testName)
	scenario.createLBVIP(ctx, vip)

	t.Logf("Creating LB BackendPool resources...")
	backends := []backendPoolOption{}
	for _, b := range scenario.backendApps {
		backends = append(backends, withBackend(b.ip, 8080))
	}
	backendPool := lbBackendPool(testK8sNamespace, testName, backends...)
	scenario.createLBBackendPool(ctx, backendPool)

	t.Logf("Creating LB Service resources...")
	service := lbService(testK8sNamespace, testName, withPort(443), withHTTPSProxyApplication(testName, testName, hostName, withHTTPSH2(true), withHTTPSH11(true)))
	scenario.createLBService(ctx, service)

	t.Logf("Waiting for full VIP connectivity of %q...", testName)
	vipIP := scenario.waitForFullVIPConnectivity(ctx, testName)

	// 1. Send HTTPs request
	testCmd := curlCmd(fmt.Sprintf("-o/dev/null -w '%%{http_version}' --cacert /tmp/%s --resolve %s:443:%s https://%s:443/", hostName+".crt", hostName, vipIP, hostName))
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
