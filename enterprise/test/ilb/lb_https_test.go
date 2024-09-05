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

	"github.com/cilium/cilium/operator/pkg/model"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

func TestHTTPS(t *testing.T) {
	ctx := context.Background()
	name := "https-1"
	ns := "default"
	hostName := "secure.acme.io"

	ciliumCli, k8sCli := newCiliumAndK8sCli(t)
	dockerCli := newDockerCli(t)

	// 0. Setup test scenario (backends, clients & LB resources)
	scenario := newLBTestScenario(t, name, ns, ciliumCli, k8sCli, dockerCli)

	t.Log("Creating cert and secret...")
	scenario.createServerCertificate(ctx, hostName)

	t.Log("Creating backend apps...")
	scenario.addBackendApplications(ctx, 2, []string{"H2C_ENABLED=true"})

	t.Log("Creating clients and add BGP peering ...")
	scenario.addFrrClients(ctx, 1, []string{}, []string{hostName})

	clientName := name + "-client-0"

	t.Logf("Creating LB VIP resources...")
	vip := lbVIP(ns, name, "")
	scenario.createLBVIP(ctx, vip)

	t.Logf("Creating LB BackendPool resources...")
	backends := []isovalentv1alpha1.Backend{}
	for _, b := range scenario.backendApps {
		backends = append(backends, isovalentv1alpha1.Backend{
			IP:   b.ip,
			Port: 8080,
		})
	}
	backendPool := lbBackendPool(ns, name, "/health", 10, backends)
	scenario.createLBBackendPool(ctx, backendPool)

	t.Logf("Creating LB Service resources...")
	service := lbService(ns, name, name, 443, lbServiceApplicationsHTTPSProxy(name, name, hostName, nil))
	scenario.createLBService(ctx, service)

	t.Logf("Waiting for full VIP connectivity of %q...", name)
	vipIP := scenario.waitForFullVIPConnectivity(ctx)

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
	name := "http2s-1"
	ns := "default"
	hostName := "secure-http2.acme.io"

	ciliumCli, k8sCli := newCiliumAndK8sCli(t)
	dockerCli := newDockerCli(t)

	// 0. Setup test scenario (backends, clients & LB resources)
	scenario := newLBTestScenario(t, name, ns, ciliumCli, k8sCli, dockerCli)

	t.Log("Creating cert and secret...")
	scenario.createServerCertificate(ctx, hostName)

	t.Log("Creating backend apps...")
	scenario.addBackendApplications(ctx, 2, []string{"H2C_ENABLED=true"})

	t.Log("Creating clients and add BGP peering ...")
	scenario.addFrrClients(ctx, 1, []string{}, []string{hostName})

	clientName := name + "-client-0"

	t.Logf("Creating LB VIP resources...")
	vip := lbVIP(ns, name, "")
	scenario.createLBVIP(ctx, vip)

	t.Logf("Creating LB BackendPool resources...")
	backends := []isovalentv1alpha1.Backend{}
	for _, b := range scenario.backendApps {
		backends = append(backends, isovalentv1alpha1.Backend{
			IP:   b.ip,
			Port: 8080,
		})
	}
	backendPool := lbBackendPool(ns, name, "/health", 10, backends)
	scenario.createLBBackendPool(ctx, backendPool)

	t.Logf("Creating LB Service resources...")
	cfg := &isovalentv1alpha1.LBServiceHTTPConfig{
		EnableHTTP11: model.AddressOf(true),
		EnableHTTP2:  model.AddressOf(true),
	}
	service := lbService(ns, name, name, 443, lbServiceApplicationsHTTPSProxy(name, name, hostName, cfg))
	scenario.createLBService(ctx, service)

	t.Logf("Waiting for full VIP connectivity of %q...", name)
	vipIP := scenario.waitForFullVIPConnectivity(ctx)

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
