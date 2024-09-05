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

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/inctimer"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

func TestHTTPAndT2HealthChecks(t *testing.T) {
	ctx := context.Background()
	name := "http-1"
	ns := "default"

	ciliumCli, _ := newCiliumAndK8sCli(t)
	dockerCli := newDockerCli(t)

	scenario := newLBTestScenario(t, name, ns, ciliumCli, dockerCli)

	// 0. Create LB backend apps
	t.Log("Creating backend apps...")

	scenario.addBackendApplications(ctx, 2, []string{"H2C_ENABLED=true"})

	// 1. Create FRR client
	t.Log("Creating clients and add BGP peering ...")

	clientName := name + "-client-0"
	scenario.addFrrClients(ctx, 1, []string{})

	// 2. Create LBVIP
	t.Logf("Creating LB service objects...")

	vip := lbVIP(name, "")
	if err := ciliumCli.CreateLBVIP(ctx, ns, vip, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			t.Fatalf("cannot create LB VIP (%s): %s", name, err)
		}
	}
	maybeCleanupT(func() error {
		return ciliumCli.DeleteLBVIP(context.Background(), ns, name, metav1.DeleteOptions{})
	}, t)

	// 3. Create LBBackendPool

	backends := []isovalentv1alpha1.Backend{}
	for _, b := range scenario.backendApps {
		backends = append(backends, isovalentv1alpha1.Backend{
			IP:   b.ip,
			Port: 8080,
		})
	}
	backendPool := lbBackendPool(name, "/health", 10, backends)

	if err := ciliumCli.CreateLBBackend(ctx, ns, backendPool, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			t.Fatalf("cannot create LB Backend Pool (%s): %s", name, err)
		}
	}
	maybeCleanupT(func() error {
		return ciliumCli.DeleteLBBackend(context.Background(), ns, name, metav1.DeleteOptions{})
	}, t)

	// 4. Create LBService

	service := lbService(name, name, 81, lbServiceApplicationsHTTP(name, "", ""))

	if err := ciliumCli.CreateLBService(ctx, ns, service, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			t.Fatalf("cannot create LB Service (%s): %s", name, err)
		}
	}
	maybeCleanupT(func() error {
		return ciliumCli.DeleteLBService(context.Background(), ns, name, metav1.DeleteOptions{})
	}, t)

	// 5. Send HTTP request to test basic client -> LB T1 -> LB T2 -> app connectivity

	t.Logf("Waiting for VIP of %q...", name)

	vipIP, err := ciliumCli.WaitForLBVIP(ctx, ns, name)
	if err != nil {
		t.Fatalf("failed to wait for VIP (%s): %s", name, err)
	}

	err = dockerCli.waitForIPRoute(ctx, clientName, vipIP)
	if err != nil {
		t.Fatalf("failed to wait for IP route in client (%s): %s", clientName, err)
	}

	testCmd := curlCmdVerbose(fmt.Sprintf("-m 2 http://%s:81/", vipIP))
	t.Logf("Testing %q...", testCmd)
	stdout, stderr, err := dockerCli.clientExec(ctx, clientName, testCmd)
	if err != nil {
		t.Fatalf("curl failed (cmd: %q, stdout: %q, stderr: %q): %s", testCmd, stdout, stderr, err)
	}

	// 6. Healthcheck (T2) testing

	// 6.1. Force both app's HC to fail

	t.Logf("Setting T2 HC to fail...")

	for _, b := range scenario.backendApps {
		if err := dockerCli.controlBackendHC(ctx, clientName, b.ip, hcFail); err != nil {
			t.Fatalf("failed to set HC to fail (%s): %s", b.ip, err)
		}
	}

	// 6.2. Wait until curl fails due to failing HCs

	t.Logf("Waiting for curl to fails...")

	ctx, cancel := context.WithTimeout(ctx, longTimeout)
	defer cancel()

	for {
		_, _, err := dockerCli.clientExec(ctx, clientName, testCmd)
		if err != nil {
			break
		}

		select {
		case <-inctimer.After(longPollInterval):
		case <-ctx.Done():
			t.Fatalf("Timeout reached waiting for curl to fail")
		}
	}

	t.Logf("Setting T2 HC to pass...")

	// 3. Bring back both backends

	for _, b := range scenario.backendApps {
		if err := dockerCli.controlBackendHC(ctx, clientName, b.ip, hcOK); err != nil {
			t.Fatalf("failed to set HC to pass (%s): %s", b.ip, err)
		}
	}

	t.Logf("Waiting for curl to pass...")

	// 4. Expect to pass

	ctx, cancel = context.WithTimeout(ctx, longTimeout)
	defer cancel()

	for {
		_, _, err := dockerCli.clientExec(ctx, clientName, testCmd)
		if err == nil {
			break
		}

		select {
		case <-inctimer.After(longPollInterval):
		case <-ctx.Done():
			t.Fatalf("Timeout reached waiting for curl to pass")
		}
	}

	// TODO(brb) bring back only one backend
}

func TestHTTP2(t *testing.T) {
	ctx := context.Background()
	name := "http2-1"
	ns := "default"
	hostName := "mixed.acme.io"

	ciliumCli, _ := newCiliumAndK8sCli(t)
	dockerCli := newDockerCli(t)

	t.Log("Creating client and apps...")

	// 0. Create LB backend apps

	app1IP := ""
	app2IP := ""
	for _, app := range []struct {
		name string
		ip   *string
	}{
		{name: name + "-app-1", ip: &app1IP},
		{name: name + "-app-2", ip: &app2IP},
	} {
		env := []string{
			"SERVICE_NAME=" + app.name,
			"INSTANCE_NAME=" + app.name,
			"H2C_ENABLED=true",
		}
		id, ip, err := dockerCli.createContainer(ctx, app.name, appImage, env, containerNetwork, false)
		if err != nil {
			t.Fatalf("cannot create app container (%s): %s", app.name, err)
		}
		*app.ip = ip
		maybeCleanupT(func() error { return dockerCli.deleteContainer(context.Background(), id) }, t)
	}

	// 1. Create FRR client

	clientName := name + "-client"
	env := []string{
		"NEIGHBORS=" + getBGPNeighborString(t, dockerCli),
	}
	_, clientIP, err := dockerCli.createContainer(ctx, clientName, clientImage, env, containerNetwork, true)
	if err != nil {
		t.Fatalf("cannot create client container (%s): %s", clientName, err)
	}
	maybeCleanupT(func() error { return dockerCli.deleteContainer(context.Background(), clientName) }, t)

	if err := ciliumCli.doBGPPeeringForClient(ctx, clientIP); err != nil {
		t.Fatalf("failed to BGP peer (%s): %s", clientName, err)
	}
	maybeCleanupT(func() error { return ciliumCli.undoBGPPeeringForClient(context.Background(), clientIP) }, t)

	t.Logf("Creating LB service objects...")

	// 2. Create LBVIP

	vip := lbVIP(name, "")
	if err := ciliumCli.CreateLBVIP(ctx, ns, vip, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			t.Fatalf("cannot create LB VIP (%s): %s", name, err)
		}
	}
	maybeCleanupT(func() error {
		return ciliumCli.DeleteLBVIP(context.Background(), ns, name, metav1.DeleteOptions{})
	}, t)

	// 3. Create LBBackendPool

	backends := []isovalentv1alpha1.Backend{
		{IP: app1IP, Port: 8080},
		{IP: app2IP, Port: 8080},
	}
	backendPool := lbBackendPool(name, "/health", 10, backends)

	if err := ciliumCli.CreateLBBackend(ctx, ns, backendPool, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			t.Fatalf("cannot create LB Backend Pool (%s): %s", name, err)
		}
	}
	maybeCleanupT(func() error {
		return ciliumCli.DeleteLBBackend(context.Background(), ns, name, metav1.DeleteOptions{})
	}, t)

	// 4. Create LBService

	service := lbService(name, name, 80, lbServiceApplicationsHTTP(name, hostName, ""))

	if err := ciliumCli.CreateLBService(ctx, ns, service, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			t.Fatalf("cannot create LB Service (%s): %s", name, err)
		}
	}
	maybeCleanupT(func() error {
		return ciliumCli.DeleteLBService(context.Background(), ns, name, metav1.DeleteOptions{})
	}, t)

	// 5. Send HTTP request to test basic client -> LB T1 -> LB T2 -> app connectivity

	t.Logf("Waiting for VIP of %q...", name)

	ip, err := ciliumCli.WaitForLBVIP(ctx, ns, name)
	if err != nil {
		t.Fatalf("failed to wait for VIP (%s): %s", name, err)
	}

	err = dockerCli.waitForIPRoute(ctx, clientName, ip)
	if err != nil {
		t.Fatalf("failed to wait for IP route in client (%s): %s", clientName, err)
	}

	testCmd := curlCmdVerbose(fmt.Sprintf("--http2-prior-knowledge -o/dev/null -w '%%{http_version}' --resolve mixed.acme.io:80:%s http://mixed.acme.io:80/", ip))
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
	name := "http-path-1"
	ns := "default"
	hostName := "insecure.acme.io"
	path := "/api/foo-insecure"

	ciliumCli, _ := newCiliumAndK8sCli(t)
	dockerCli := newDockerCli(t)

	t.Log("Creating client and apps...")

	// 0. Create LB backend apps

	app1IP := ""
	app2IP := ""
	for _, app := range []struct {
		name string
		ip   *string
	}{
		{name: name + "-app-1", ip: &app1IP},
		{name: name + "-app-2", ip: &app2IP},
	} {
		env := []string{
			"SERVICE_NAME=" + app.name,
			"INSTANCE_NAME=" + app.name,
			"H2C_ENABLED=true",
		}
		id, ip, err := dockerCli.createContainer(ctx, app.name, appImage, env, containerNetwork, false)
		if err != nil {
			t.Fatalf("cannot create app container (%s): %s", app.name, err)
		}
		*app.ip = ip
		maybeCleanupT(func() error { return dockerCli.deleteContainer(context.Background(), id) }, t)
	}

	// 1. Create FRR client

	clientName := name + "-client"
	env := []string{
		"NEIGHBORS=" + getBGPNeighborString(t, dockerCli),
	}
	_, clientIP, err := dockerCli.createContainer(ctx, clientName, clientImage, env, containerNetwork, true)
	if err != nil {
		t.Fatalf("cannot create client container (%s): %s", clientName, err)
	}
	maybeCleanupT(func() error { return dockerCli.deleteContainer(context.Background(), clientName) }, t)

	if err := ciliumCli.doBGPPeeringForClient(ctx, clientIP); err != nil {
		t.Fatalf("failed to BGP peer (%s): %s", clientName, err)
	}
	maybeCleanupT(func() error { return ciliumCli.undoBGPPeeringForClient(context.Background(), clientIP) }, t)

	t.Logf("Creating LB service objects...")

	// 2. Create LBVIP

	vip := lbVIP(name, "")
	if err := ciliumCli.CreateLBVIP(ctx, ns, vip, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			t.Fatalf("cannot create LB VIP (%s): %s", name, err)
		}
	}
	maybeCleanupT(func() error {
		return ciliumCli.DeleteLBVIP(context.Background(), ns, name, metav1.DeleteOptions{})
	}, t)

	// 3. Create LBBackendPool

	backends := []isovalentv1alpha1.Backend{
		{IP: app1IP, Port: 8080},
		{IP: app2IP, Port: 8080},
	}
	backendPool := lbBackendPool(name, "/health", 10, backends)

	if err := ciliumCli.CreateLBBackend(ctx, ns, backendPool, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			t.Fatalf("cannot create LB Backend Pool (%s): %s", name, err)
		}
	}
	maybeCleanupT(func() error {
		return ciliumCli.DeleteLBBackend(context.Background(), ns, name, metav1.DeleteOptions{})
	}, t)

	// 4. Create LBService

	service := lbService(name, name, 80, lbServiceApplicationsHTTP(name, hostName, path))

	if err := ciliumCli.CreateLBService(ctx, ns, service, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			t.Fatalf("cannot create LB Service (%s): %s", name, err)
		}
	}
	maybeCleanupT(func() error {
		return ciliumCli.DeleteLBService(context.Background(), ns, name, metav1.DeleteOptions{})
	}, t)

	// 5. Send HTTP request to test basic client -> LB T1 -> LB T2 -> app connectivity

	t.Logf("Waiting for VIP of %q...", name)

	ip, err := ciliumCli.WaitForLBVIP(ctx, ns, name)
	if err != nil {
		t.Fatalf("failed to wait for VIP (%s): %s", name, err)
	}

	err = dockerCli.waitForIPRoute(ctx, clientName, ip)
	if err != nil {
		t.Fatalf("failed to wait for IP route in client (%s): %s", clientName, err)
	}

	testCmd := curlCmdVerbose(fmt.Sprintf("--resolve %s:80:%s http://%s:80%s", hostName, ip, hostName, path))
	t.Logf("Testing %q...", testCmd)
	stdout, stderr, err := dockerCli.clientExec(ctx, clientName, testCmd)
	if err != nil {
		t.Fatalf("curl failed (cmd: %q, stdout: %q, stderr: %q): %s", testCmd, stdout, stderr, err)
	}
}
