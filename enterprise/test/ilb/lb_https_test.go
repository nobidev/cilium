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

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

func TestHTTPS(t *testing.T) {
	ctx := context.Background()
	name := "https-1"
	ns := "default"
	hostName := "secure.acme.io"
	certFile := name + ".crt"

	ciliumCli, k8sCli := newCiliumAndK8sCli(t)
	dockerCli := newDockerCli(t)

	// 0. Generate certificate and create K8s secret

	t.Log("Creating cert and secret...")

	key, cert, err := genSelfSignedX509(hostName)
	if err != nil {
		t.Fatalf("failed to gen x509: %s", err)
	}

	sec := secret(name, key.Bytes(), cert.Bytes())
	if _, err := k8sCli.CoreV1().Secrets(ns).Create(ctx, sec, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			t.Fatalf("failed to create secret (%s): %s", name, err)
		}
	}
	maybeCleanupT(func() error {
		return k8sCli.CoreV1().Secrets(ns).Delete(ctx, name, metav1.DeleteOptions{})
	}, t)

	// 1. Create LB backend apps

	t.Log("Creating client and apps...")

	app1IP := ""
	app2IP := ""

	for _, app := range []struct {
		name string
		ip   *string
	}{
		{name: "https-1-app-1", ip: &app1IP},
		{name: "https-1-app-2", ip: &app2IP},
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
		maybeCleanupT(func() error { return dockerCli.deleteContainer(ctx, id) }, t)
	}

	// 2. Create FRR client

	clientName := name + "-client"
	env := []string{
		"NEIGHBORS=" + getBGPNeighborString(t, dockerCli),
	}
	clientID, clientIP, err := dockerCli.createContainer(ctx, clientName, clientImage, env, containerNetwork, true)
	if err != nil {
		t.Fatalf("cannot create client container (%s): %s", clientName, err)
	}
	maybeCleanupT(func() error { return dockerCli.deleteContainer(ctx, clientName) }, t)

	if err := dockerCli.copyToContainer(ctx, clientID, cert.Bytes(), certFile, "/tmp"); err != nil {
		t.Fatalf("failed to copy cert to client container: %s", err)
	}

	if err := ciliumCli.doBGPPeeringForClient(ctx, clientIP); err != nil {
		t.Fatalf("failed to BGP peer (%s): %s", clientName, err)
	}
	maybeCleanupT(func() error { return ciliumCli.undoBGPPeeringForClient(ctx, clientIP) }, t)

	t.Logf("Creating LB service objects...")

	// 3. Create LBVIP

	vip := lbVIP(name, "")
	if err := ciliumCli.CreateLBVIP(ctx, ns, vip, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			t.Fatalf("cannot create LB VIP (%s): %s", name, err)
		}
	}
	maybeCleanupT(func() error { return ciliumCli.DeleteLBVIP(ctx, ns, name, metav1.DeleteOptions{}) }, t)

	// 4. Create LBBackendPool

	backends := []isovalentv1alpha1.Backend{
		{IP: app1IP, Port: 8080},
		{IP: app2IP, Port: 8080},
	}
	backendPool := lbBackendPool(name, "/health", 10, backends)

	if err := ciliumCli.CreateLBBackendPool(ctx, ns, backendPool, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			t.Fatalf("cannot create LB Backend Pool (%s): %s", name, err)
		}
	}
	maybeCleanupT(func() error { return ciliumCli.DeleteLBBackendPool(ctx, ns, name, metav1.DeleteOptions{}) }, t)

	// 5. Create LBService

	svc := lbService(name, name, 443, lbServiceApplicationsHTTPSProxy(name, name, hostName, nil))

	if err := ciliumCli.CreateLBService(ctx, ns, svc, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			t.Fatalf("cannot create LB Frontend (%s): %s", name, err)
		}
	}
	maybeCleanupT(func() error { return ciliumCli.DeleteLBService(ctx, ns, name, metav1.DeleteOptions{}) }, t)

	// 6. Send HTTPs request

	t.Logf("Waiting for VIP of %q...", name)

	ip, err := ciliumCli.WaitForLBVIP(ctx, ns, name)
	if err != nil {
		t.Fatalf("failed to wait for VIP (%s): %s", name, err)
	}

	err = dockerCli.waitForIPRoute(ctx, clientName, ip)
	if err != nil {
		t.Fatalf("failed to wait for IP route in client (%s): %s", clientName, err)
	}

	testCmd := curlCmdVerbose(fmt.Sprintf("--cacert /tmp/https-1.crt --resolve secure.acme.io:443:%s https://secure.acme.io:443/", ip))
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
	certFile := name + ".crt"

	ciliumCli, k8sCli := newCiliumAndK8sCli(t)
	dockerCli := newDockerCli(t)

	// 0. Generate certificate and create K8s secret

	t.Log("Creating cert and secret...")

	key, cert, err := genSelfSignedX509(hostName)
	if err != nil {
		t.Fatalf("failed to gen x509: %s", err)
	}

	sec := secret(name, key.Bytes(), cert.Bytes())
	if _, err := k8sCli.CoreV1().Secrets(ns).Create(ctx, sec, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			t.Fatalf("failed to create secret (%s): %s", name, err)
		}
	}
	maybeCleanupT(func() error {
		return k8sCli.CoreV1().Secrets(ns).Delete(ctx, name, metav1.DeleteOptions{})
	}, t)

	// 1. Create LB backend apps

	t.Log("Creating client and apps...")

	app1IP := ""
	app2IP := ""

	for _, app := range []struct {
		name string
		ip   *string
	}{
		{name: "https-1-app-1", ip: &app1IP},
		{name: "https-1-app-2", ip: &app2IP},
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
		maybeCleanupT(func() error { return dockerCli.deleteContainer(ctx, id) }, t)
	}

	// 2. Create FRR client

	clientName := name + "-client"
	env := []string{
		"NEIGHBORS=" + getBGPNeighborString(t, dockerCli),
	}
	clientID, clientIP, err := dockerCli.createContainer(ctx, clientName, clientImage, env, containerNetwork, true)
	if err != nil {
		t.Fatalf("cannot create client container (%s): %s", clientName, err)
	}
	maybeCleanupT(func() error { return dockerCli.deleteContainer(ctx, clientName) }, t)

	if err := dockerCli.copyToContainer(ctx, clientID, cert.Bytes(), certFile, "/tmp"); err != nil {
		t.Fatalf("failed to copy cert to client container: %s", err)
	}

	if err := ciliumCli.doBGPPeeringForClient(ctx, clientIP); err != nil {
		t.Fatalf("failed to BGP peer (%s): %s", clientName, err)
	}
	maybeCleanupT(func() error { return ciliumCli.undoBGPPeeringForClient(ctx, clientIP) }, t)

	t.Logf("Creating LB service objects...")

	// 3. Create LBVIP

	vip := lbVIP(name, "")
	if err := ciliumCli.CreateLBVIP(ctx, ns, vip, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			t.Fatalf("cannot create LB VIP (%s): %s", name, err)
		}
	}
	maybeCleanupT(func() error { return ciliumCli.DeleteLBVIP(ctx, ns, name, metav1.DeleteOptions{}) }, t)

	// 4. Create LBBackendPool

	backends := []isovalentv1alpha1.Backend{
		{IP: app1IP, Port: 8080},
		{IP: app2IP, Port: 8080},
	}
	backendPool := lbBackendPool(name, "/health", 10, backends)

	if err := ciliumCli.CreateLBBackendPool(ctx, ns, backendPool, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			t.Fatalf("cannot create LB Backend Pool (%s): %s", name, err)
		}
	}
	maybeCleanupT(func() error { return ciliumCli.DeleteLBBackendPool(ctx, ns, name, metav1.DeleteOptions{}) }, t)

	// 5. Create LBService

	veryTrue := true
	cfg := &isovalentv1alpha1.LBServiceHTTPConfig{
		EnableHTTP11: &veryTrue,
		EnableHTTP2:  &veryTrue,
	}
	svc := lbService(name, name, 443, lbServiceApplicationsHTTPSProxy(name, name, hostName, cfg))

	if err := ciliumCli.CreateLBService(ctx, ns, svc, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			t.Fatalf("cannot create LB Frontend (%s): %s", name, err)
		}
	}
	maybeCleanupT(func() error { return ciliumCli.DeleteLBService(ctx, ns, name, metav1.DeleteOptions{}) }, t)

	// 6. Send HTTPs request

	t.Logf("Waiting for VIP of %q...", name)

	ip, err := ciliumCli.WaitForLBVIP(ctx, ns, name)
	if err != nil {
		t.Fatalf("failed to wait for VIP (%s): %s", name, err)
	}

	err = dockerCli.waitForIPRoute(ctx, clientName, ip)
	if err != nil {
		t.Fatalf("failed to wait for IP route in client (%s): %s", clientName, err)
	}

	testCmd := curlCmd(fmt.Sprintf("-o/dev/null -w '%%{http_version}' --cacert /tmp/%s --resolve %s:443:%s https://%s:443/", certFile, hostName, ip, hostName))
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
