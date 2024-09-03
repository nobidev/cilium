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
	_ "embed"
	"flag"
	"fmt"
	"os"
	"testing"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/inctimer"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	scheme "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/scheme"
	k8s "github.com/cilium/cilium/pkg/k8s/slim/k8s/clientset"
)

//go:embed manifests/lb-vips.yaml
var yamlLBVIPs string

//go:embed manifests/lb-services.yaml
var yamlLBService string

//go:embed manifests/lb-backends.yaml
var yamlLBBackends string

const (
	defaultNamespace = "default"

	clientContainerName = "frr"

	containerNetwork = "kind-cilium"

	appImage    = "quay.io/isovalent-dev/lb-healthcheck-app:v0.0.4"
	clientImage = "quay.io/isovalent-dev/lb-frr-client:v0.0.1"

	lbIPPoolName = "lb-pool"
)

type lbTests struct {
	ciliumCli *ciliumCli
	dockerCli *dockerCli

	vips       map[int]string
	backendIPs map[int]string

	t *testing.T
}

func (lbt *lbTests) installLBObjs(ctx context.Context, t *testing.T) {
	// 1. Install LB VIPS

	lbVIPs, err := yamlToObjects[*isovalentv1alpha1.LBVIP](yamlLBVIPs, scheme.Scheme)
	if err != nil {
		t.Fatalf("Failed to deserialize LB VIP: %s", err)
	}

	for _, obj := range lbVIPs {
		lbt.ciliumCli.DeleteLBVIP(ctx, defaultNamespace, obj.GetObjectMeta().GetName(), metav1.DeleteOptions{})

		t.Logf("Creating LB VIP %s...", obj.GetObjectMeta().GetName())
		if err := lbt.ciliumCli.CreateLBVIP(ctx, defaultNamespace, obj, metav1.CreateOptions{}); err != nil {
			t.Fatalf("Failed to create LB VIP: %s", err)
		}
	}

	// 2. Install LB Services

	services, err := yamlToObjects[*isovalentv1alpha1.LBService](yamlLBService, scheme.Scheme)
	if err != nil {
		t.Fatalf("Failed to deserialize LB Service: %s", err)
	}

	for _, obj := range services {
		lbt.ciliumCli.DeleteLBService(ctx, defaultNamespace, obj.GetObjectMeta().GetName(), metav1.DeleteOptions{})

		t.Logf("Creating LB Service %s...", obj.GetObjectMeta().GetName())
		if err := lbt.ciliumCli.CreateLBService(ctx, "default", obj, metav1.CreateOptions{}); err != nil {
			t.Fatalf("Failed to create LB VIP: %s", err)
		}
	}

	// 3. Install LB Backends

	backends, err := yamlToObjects[*isovalentv1alpha1.LBBackendPool](yamlLBBackends, scheme.Scheme)
	if err != nil {
		t.Fatalf("Failed to deserialize LB Backend: %s", err)
	}

	for i := 1; i <= 5; i++ {
		ip, err := lbt.dockerCli.GetContainerIP(ctx, fmt.Sprintf("app%d", i))
		if err != nil {
			t.Fatalf("Failed to retrieve container app%d IP: %s", i, err)
		}
		if ip == "" {
			t.Fatalf("app%d does not have any IP addr", i)
		}
		lbt.backendIPs[i] = ip
	}

	backends[0].Spec.Backends[0].IP = lbt.backendIPs[1]
	backends[0].Spec.Backends[1].IP = lbt.backendIPs[2]

	backends[1].Spec.Backends[0].IP = lbt.backendIPs[1]
	backends[1].Spec.Backends[1].IP = lbt.backendIPs[3]

	backends[2].Spec.Backends[0].IP = lbt.backendIPs[2]
	backends[2].Spec.Backends[1].IP = lbt.backendIPs[3]

	backends[3].Spec.Backends[0].IP = lbt.backendIPs[2]
	backends[3].Spec.Backends[1].IP = lbt.backendIPs[3]

	backends[4].Spec.Backends[0].IP = lbt.backendIPs[2]
	backends[4].Spec.Backends[1].IP = lbt.backendIPs[3]

	backends[5].Spec.Backends[0].IP = lbt.backendIPs[4]

	backends[6].Spec.Backends[0].IP = lbt.backendIPs[5]

	for _, obj := range backends {
		lbt.ciliumCli.DeleteLBBackend(ctx, defaultNamespace, obj.GetObjectMeta().GetName(), metav1.DeleteOptions{})

		t.Logf("Creating LB Backend %s...", obj.GetObjectMeta().GetName())
		if err := lbt.ciliumCli.CreateLBBackend(ctx, "default", obj, metav1.CreateOptions{}); err != nil {
			t.Fatalf("Failed to create LB Backend: %s", err)
		}
	}

	// 4. Wait for LB VIPs

	for i := 1; i <= len(services); i++ {
		name := fmt.Sprintf("lb-%d", i)
		t.Logf("Waiting for LB VIP %s...", name)
		vip, err := lbt.ciliumCli.WaitForLBVIP(ctx, defaultNamespace, name)
		if err != nil {
			t.Fatalf("Failed to wait for LB VIP %s: %s", name, err)
		}
		lbt.vips[i] = vip
	}

}

func (lbt *lbTests) testBasicLBConnectivity(ctx context.Context, t *testing.T) {
	// Basic connectivity to apps through LB
	testCmds := []string{
		curlCmdVerbose(fmt.Sprintf("--resolve insecure.acme.io:80:%s http://insecure.acme.io:80/api/foo-insecure", lbt.vips[2])),
		curlCmdVerbose(fmt.Sprintf("--cacert /tmp/tls-secure80.crt --resolve secure-80.acme.io:80:%s https://secure-80.acme.io:80/", lbt.vips[5])),
		curlCmdVerbose(fmt.Sprintf("--cacert /tmp/tls-secure-backend.crt --resolve passthrough.acme.io:80:%s https://passthrough.acme.io:80/", lbt.vips[6])),
		curlCmdVerbose(fmt.Sprintf("--cacert /tmp/tls-secure-backend2.crt --resolve passthrough-2.acme.io:80:%s https://passthrough-2.acme.io:80/", lbt.vips[6])),
	}

	for _, cmd := range testCmds {
		stdout, stderr, err := lbt.dockerCli.clientExec(ctx, clientContainerName, cmd)
		fmt.Println(stdout, stderr)
		if err != nil {
			t.Fatalf("Failed cmd: %s (stdout: %s, stderr: %s)", err, stdout, stderr)
		}
	}

	// Check that HTTP 2 is used to connect to apps through LB
	testHTTP2Cmds := []string{
		curlCmd(fmt.Sprintf("-o/dev/null -w '%%{http_version}' --cacert /tmp/tls-secure-http2.crt --resolve secure-http2.acme.io:443:%s https://secure-http2.acme.io:443/", lbt.vips[7])),
	}

	for _, cmd := range testHTTP2Cmds {
		stdout, stderr, err := lbt.dockerCli.clientExec(ctx, clientContainerName, cmd)
		if err != nil {
			t.Fatalf("Failed cmd: %s (stdout: %s, stderr: %s)", err, stdout, stderr)
		}
		// Check HTTP H2
		if stdout != "2" {
			t.Fatalf("Expected HTTP 2, got: %s", stdout)
		}
	}
}

func TestLB(t *testing.T) {
	ctx := context.Background()

	lbt := &lbTests{
		ciliumCli:  suite.ciliumCli,
		dockerCli:  suite.dockerCli,
		vips:       map[int]string{}, // lb-${int} => ip
		backendIPs: map[int]string{}, // app${int} => ip
		t:          t,
	}

	lbt.installLBObjs(ctx, t)

	lbt.testBasicLBConnectivity(ctx, t)
}

type testSuite struct {
	ciliumCli *ciliumCli
	dockerCli *dockerCli
	k8sCli    *k8s.Clientset

	lbT1IP string
}

var suite testSuite

var cleanup = flag.Bool("cleanup", true, "Cleanup created resources after each test case run")

func TestMain(m *testing.M) {
	if os.Getenv("LOADBALANCER_TESTS") != "true" {
		fmt.Println("Skipping due to LOADBALANCER_TESTS!=true")
		return
	}

	flag.Parse()

	ciliumCli, k8sCli, err := newCiliumAndK8sCli()
	if err != nil {
		panic(fmt.Sprintf("Failed to create Cilium client: %s", err))
	}
	suite.ciliumCli = ciliumCli
	suite.k8sCli = k8sCli

	dockerCli, err := newDockerCli()
	if err != nil {
		panic(fmt.Sprintf("Failed to create Docker client: %s", err))
	}
	suite.dockerCli = dockerCli

	for _, img := range []string{appImage, clientImage} {
		if err := dockerCli.ensureImage(context.Background(), img); err != nil {
			panic(fmt.Sprintf("Failed to ensure Docker image %s: %s", img, err))
		}
	}

	// Derive T1 LB IP addr

	// TODO maybe use "kubectl get nodes"
	suite.lbT1IP, err = suite.dockerCli.GetContainerIP(context.Background(), "kind-control-plane")
	if err != nil {
		panic(fmt.Sprintf("Failed to retrieve T1 LB IP: %s", err))
	}

	// Create LBIPPool (it is shared among all test cases)

	lbIPPool := lbIPPool(lbIPPoolName, "100.64.0.0/24")
	if err := suite.ciliumCli.ensureLBIPPool(context.Background(), lbIPPool); err != nil {
		panic(fmt.Sprintf("Failed to ensure LBIPPool (%s): %s", lbIPPoolName, err))
	}
	defer maybeCleanup(func() error {
		return suite.ciliumCli.DeleteLBIPPool(context.Background(), lbIPPoolName, metav1.DeleteOptions{})
	})

	// Create CiliumBGPPeeringPolicy and BFD (each test case will append its peer to it)
	if err := suite.ciliumCli.ensureBGPPeeringPolicyAndBFD(context.Background()); err != nil {
		panic(fmt.Sprintf("Failed to install BGP peering: %s", err))
	}
	defer maybeCleanup(func() error {
		return suite.ciliumCli.deleteBGPPeeringPolicyAndBFD(context.Background())
	})

	// Run tests

	m.Run()
}

func maybeCleanupT(f func() error, t *testing.T) {
	if *cleanup {
		t.Cleanup(func() {
			if err := f(); err != nil {
				fmt.Printf("cleanup failed %s\n", err)
			}
		})
	}
}

func maybeCleanup(f func() error) {
	if *cleanup {
		if err := f(); err != nil {
			fmt.Printf("cleanup failed: %s\n", err)
		}
	}
}

func TestHTTPSConnectivity(t *testing.T) {
	ctx := context.Background()
	name := "https-1"
	ns := "default"
	hostName := "secure.acme.io"
	keyFile := name + ".key"
	certFile := name + ".crt"

	// 0. Generate certificate and create K8s secret

	t.Log("Creating cert and secret...")

	key, cert, err := genSelfSignedX509(hostName)
	if err != nil {
		t.Fatalf("failed to gen x509: %s", err)
	}
	maybeCleanupT(func() error { return deleteFiles(keyFile, certFile) }, t)

	sec := secret(name, key.Bytes(), cert.Bytes())
	if _, err := suite.k8sCli.CoreV1().Secrets(ns).Create(ctx, sec, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			t.Fatalf("failed to create secret (%s): %s", name, err)
		}
	}
	maybeCleanupT(func() error {
		return suite.k8sCli.CoreV1().Secrets(ns).Delete(ctx, name, metav1.DeleteOptions{})
	}, t)

	// 1. Create LB backend apps

	t.Log("Creating client and apps...")

	app1 := "https-1-app-1"
	app2 := "https-1-app-2"
	app1IP := ""
	app2IP := ""
	iter := []struct {
		name string
		ip   *string
	}{
		{name: app1, ip: &app1IP},
		{name: app2, ip: &app2IP},
	}

	for i, app := range iter {
		env := []string{
			"SERVICE_NAME=" + app.name,
			"INSTANCE_NAME=" + app.name,
			"H2C_ENABLED=true",
		}
		_, ip, err := suite.dockerCli.createContainer(ctx, app.name, appImage, env, containerNetwork, false)
		if err != nil {
			t.Fatalf("cannot create app container (%s): %s", app.name, err)
		}
		*app.ip = ip
		maybeCleanupT(func() error { return suite.dockerCli.deleteContainer(ctx, iter[i].name) }, t)
	}

	// 2. Create FRR client

	clientName := name + "-client"
	env := []string{
		"NEIGHBOR=" + suite.lbT1IP,
	}
	clientID, clientIP, err := suite.dockerCli.createContainer(ctx, clientName, clientImage, env, containerNetwork, true)
	if err != nil {
		t.Fatalf("cannot create client container (%s): %s", clientName, err)
	}
	maybeCleanupT(func() error { return suite.dockerCli.deleteContainer(ctx, clientName) }, t)

	if err := suite.dockerCli.copyToContainer(ctx, clientID, cert.Bytes(), certFile, "/tmp"); err != nil {
		t.Fatalf("failed to copy cert to client container: %s", err)
	}

	if err := suite.ciliumCli.doBGPPeeringForClient(ctx, clientIP); err != nil {
		t.Fatalf("failed to BGP peer (%s): %s", clientName, err)
	}
	maybeCleanupT(func() error { return suite.ciliumCli.undoBGPPeeringForClient(ctx, clientIP) }, t)

	t.Logf("Creating LB service objects...")

	// 3. Create LBVIP

	vip := lbVIP(name, "")
	if err := suite.ciliumCli.CreateLBVIP(ctx, ns, vip, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			t.Fatalf("cannot create LB VIP (%s): %s", name, err)
		}
	}
	maybeCleanupT(func() error { return suite.ciliumCli.DeleteLBVIP(ctx, ns, name, metav1.DeleteOptions{}) }, t)

	// 4. Create LBBackendPool

	backends := []isovalentv1alpha1.Backend{
		{IP: app1IP, Port: 8080},
		{IP: app2IP, Port: 8080},
	}
	backendPool := lbBackendPool(name, "/health", 10, backends)

	if err := suite.ciliumCli.CreateLBBackend(ctx, ns, backendPool, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			t.Fatalf("cannot create LB Backend Pool (%s): %s", name, err)
		}
	}
	maybeCleanupT(func() error { return suite.ciliumCli.DeleteLBBackend(ctx, ns, name, metav1.DeleteOptions{}) }, t)

	// 5. Create LBFrontend

	svc := lbService(name, name, 443, lbServiceApplicationsHTTPSProxy(name, name, hostName))

	if err := suite.ciliumCli.CreateLBService(ctx, ns, svc, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			t.Fatalf("cannot create LB Frontend (%s): %s", name, err)
		}
	}
	maybeCleanupT(func() error { return suite.ciliumCli.DeleteLBService(ctx, ns, name, metav1.DeleteOptions{}) }, t)

	// 6. Send HTTPs request

	t.Logf("Waiting for VIP of %q...", name)

	ip, err := suite.ciliumCli.WaitForLBVIP(ctx, ns, name)
	if err != nil {
		t.Fatalf("failed to wait for VIP (%s): %s", name, err)
	}

	err = suite.dockerCli.waitForIPRoute(ctx, clientName, ip)
	if err != nil {
		t.Fatalf("failed to wait for IP route in client (%s): %s", clientName, err)
	}

	testCmd := curlCmdVerbose(fmt.Sprintf("--cacert /tmp/https-1.crt --resolve secure.acme.io:443:%s https://secure.acme.io:443/", ip))
	t.Logf("Testing %q...", testCmd)
	stdout, stderr, err := suite.dockerCli.clientExec(ctx, clientName, testCmd)
	if err != nil {
		t.Fatalf("curl failed (cmd: %q, stdout: %q, stderr: %q): %s", testCmd, stdout, stderr, err)
	}
}

func TestHTTPConnectivity(t *testing.T) {
	ctx := context.Background()
	name := "http-1"
	ns := "default"

	t.Log("Creating client and apps...")

	// 0. Create LB backend apps

	app1 := "http-1-app-1"
	app2 := "http-1-app-2"
	app1IP := ""
	app2IP := ""
	iter := []struct {
		name string
		ip   *string
	}{
		{name: app1, ip: &app1IP},
		{name: app2, ip: &app2IP},
	}
	for i, app := range iter {
		env := []string{
			"SERVICE_NAME=" + app.name,
			"INSTANCE_NAME=" + app.name,
			"H2C_ENABLED=true",
		}
		_, ip, err := suite.dockerCli.createContainer(ctx, app.name, appImage, env, containerNetwork, false)
		if err != nil {
			t.Fatalf("cannot create app container (%s): %s", app.name, err)
		}
		*app.ip = ip
		maybeCleanupT(func() error { return suite.dockerCli.deleteContainer(context.Background(), iter[i].name) }, t)
	}

	// 1. Create FRR client

	clientName := name + "-client"
	env := []string{
		"NEIGHBOR=" + suite.lbT1IP,
	}
	_, clientIP, err := suite.dockerCli.createContainer(ctx, clientName, clientImage, env, containerNetwork, true)
	if err != nil {
		t.Fatalf("cannot create client container (%s): %s", clientName, err)
	}
	maybeCleanupT(func() error { return suite.dockerCli.deleteContainer(context.Background(), clientName) }, t)

	if err := suite.ciliumCli.doBGPPeeringForClient(ctx, clientIP); err != nil {
		t.Fatalf("failed to BGP peer (%s): %s", clientName, err)
	}
	maybeCleanupT(func() error { return suite.ciliumCli.undoBGPPeeringForClient(context.Background(), clientIP) }, t)

	t.Logf("Creating LB service objects...")

	// 2. Create LBVIP

	vip := lbVIP(name, "")
	if err := suite.ciliumCli.CreateLBVIP(ctx, ns, vip, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			t.Fatalf("cannot create LB VIP (%s): %s", name, err)
		}
	}
	maybeCleanupT(func() error {
		return suite.ciliumCli.DeleteLBVIP(context.Background(), ns, name, metav1.DeleteOptions{})
	}, t)

	// 3. Create LBBackendPool

	backends := []isovalentv1alpha1.Backend{
		{IP: app1IP, Port: 8080},
		{IP: app2IP, Port: 8080},
	}
	backendPool := lbBackendPool(name, "/health", 10, backends)

	if err := suite.ciliumCli.CreateLBBackend(ctx, ns, backendPool, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			t.Fatalf("cannot create LB Backend Pool (%s): %s", name, err)
		}
	}
	maybeCleanupT(func() error {
		return suite.ciliumCli.DeleteLBBackend(context.Background(), ns, name, metav1.DeleteOptions{})
	}, t)

	// 4. Create LBService

	service := lbService(name, name, 81, lbServiceApplicationsHTTP(name, ""))

	if err := suite.ciliumCli.CreateLBService(ctx, ns, service, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			t.Fatalf("cannot create LB Service (%s): %s", name, err)
		}
	}
	maybeCleanupT(func() error {
		return suite.ciliumCli.DeleteLBService(context.Background(), ns, name, metav1.DeleteOptions{})
	}, t)

	// 5. Send HTTP request to test basic client -> LB T1 -> LB T2 -> app connectivity

	t.Logf("Waiting for VIP of %q...", name)

	ip, err := suite.ciliumCli.WaitForLBVIP(ctx, ns, name)
	if err != nil {
		t.Fatalf("failed to wait for VIP (%s): %s", name, err)
	}

	err = suite.dockerCli.waitForIPRoute(ctx, clientName, ip)
	if err != nil {
		t.Fatalf("failed to wait for IP route in client (%s): %s", clientName, err)
	}

	testCmd := curlCmdVerbose(fmt.Sprintf("-m 2 http://%s:81/", ip))
	t.Logf("Testing %q...", testCmd)
	stdout, stderr, err := suite.dockerCli.clientExec(ctx, clientName, testCmd)
	if err != nil {
		t.Fatalf("curl failed (cmd: %q, stdout: %q, stderr: %q): %s", testCmd, stdout, stderr, err)
	}

	// 6. Healthcheck (T2) testing

	// 6.1. Force both app's HC to fail

	t.Logf("Setting T2 HC to fail...")

	for _, ip := range []string{app1IP, app2IP} {
		if err := suite.dockerCli.controlBackendHC(ctx, clientName, ip, hcFail); err != nil {
			t.Fatalf("failed to set HC to fail (%s): %s", ip, err)
		}
	}

	// 6.2. Wait until curl fails due to failing HCs

	t.Logf("Waiting for curl to fails...")

	ctx, cancel := context.WithTimeout(ctx, longTimeout)
	defer cancel()

	for {
		_, _, err := suite.dockerCli.clientExec(ctx, clientName, testCmd)
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

	for _, ip := range []string{app1IP, app2IP} {
		if err := suite.dockerCli.controlBackendHC(ctx, clientName, ip, hcOK); err != nil {
			t.Fatalf("failed to set HC to pass (%s): %s", ip, err)
		}
	}

	t.Logf("Waiting for curl to pass...")

	// 4. Expect to pass

	ctx, cancel = context.WithTimeout(ctx, longTimeout)
	defer cancel()

	for {
		_, _, err := suite.dockerCli.clientExec(ctx, clientContainerName, testCmd)
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

func TestHTTP2Connectivity(t *testing.T) {
	ctx := context.Background()
	name := "http2-1"
	ns := "default"
	hostName := "mixed.acme.io"

	t.Log("Creating client and apps...")

	// 0. Create LB backend apps

	app1 := name + "-app-1"
	app2 := name + "-app-2"
	app1IP := ""
	app2IP := ""
	iter := []struct {
		name string
		ip   *string
	}{
		{name: app1, ip: &app1IP},
		{name: app2, ip: &app2IP},
	}
	for i, app := range iter {
		env := []string{
			"SERVICE_NAME=" + app.name,
			"INSTANCE_NAME=" + app.name,
			"H2C_ENABLED=true",
		}
		_, ip, err := suite.dockerCli.createContainer(ctx, app.name, appImage, env, containerNetwork, false)
		if err != nil {
			t.Fatalf("cannot create app container (%s): %s", app.name, err)
		}
		*app.ip = ip
		maybeCleanupT(func() error { return suite.dockerCli.deleteContainer(context.Background(), iter[i].name) }, t)
	}

	// 1. Create FRR client

	clientName := name + "-client"
	env := []string{
		"NEIGHBOR=" + suite.lbT1IP,
	}
	_, clientIP, err := suite.dockerCli.createContainer(ctx, clientName, clientImage, env, containerNetwork, true)
	if err != nil {
		t.Fatalf("cannot create client container (%s): %s", clientName, err)
	}
	maybeCleanupT(func() error { return suite.dockerCli.deleteContainer(context.Background(), clientName) }, t)

	if err := suite.ciliumCli.doBGPPeeringForClient(ctx, clientIP); err != nil {
		t.Fatalf("failed to BGP peer (%s): %s", clientName, err)
	}
	maybeCleanupT(func() error { return suite.ciliumCli.undoBGPPeeringForClient(context.Background(), clientIP) }, t)

	t.Logf("Creating LB service objects...")

	// 2. Create LBVIP

	vip := lbVIP(name, "")
	if err := suite.ciliumCli.CreateLBVIP(ctx, ns, vip, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			t.Fatalf("cannot create LB VIP (%s): %s", name, err)
		}
	}
	maybeCleanupT(func() error {
		return suite.ciliumCli.DeleteLBVIP(context.Background(), ns, name, metav1.DeleteOptions{})
	}, t)

	// 3. Create LBBackendPool

	backends := []isovalentv1alpha1.Backend{
		{IP: app1IP, Port: 8080},
		{IP: app2IP, Port: 8080},
	}
	backendPool := lbBackendPool(name, "/health", 10, backends)

	if err := suite.ciliumCli.CreateLBBackend(ctx, ns, backendPool, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			t.Fatalf("cannot create LB Backend Pool (%s): %s", name, err)
		}
	}
	maybeCleanupT(func() error {
		return suite.ciliumCli.DeleteLBBackend(context.Background(), ns, name, metav1.DeleteOptions{})
	}, t)

	// 4. Create LBService

	service := lbService(name, name, 80, lbServiceApplicationsHTTP(name, hostName))

	if err := suite.ciliumCli.CreateLBService(ctx, ns, service, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			t.Fatalf("cannot create LB Service (%s): %s", name, err)
		}
	}
	maybeCleanupT(func() error {
		return suite.ciliumCli.DeleteLBService(context.Background(), ns, name, metav1.DeleteOptions{})
	}, t)

	// 5. Send HTTP request to test basic client -> LB T1 -> LB T2 -> app connectivity

	t.Logf("Waiting for VIP of %q...", name)

	ip, err := suite.ciliumCli.WaitForLBVIP(ctx, ns, name)
	if err != nil {
		t.Fatalf("failed to wait for VIP (%s): %s", name, err)
	}

	err = suite.dockerCli.waitForIPRoute(ctx, clientName, ip)
	if err != nil {
		t.Fatalf("failed to wait for IP route in client (%s): %s", clientName, err)
	}

	testCmd := curlCmdVerbose(fmt.Sprintf("--http2-prior-knowledge -o/dev/null -w '%%{http_version}' --resolve mixed.acme.io:80:%s http://mixed.acme.io:80/", ip))
	t.Logf("Testing %q...", testCmd)
	stdout, stderr, err := suite.dockerCli.clientExec(ctx, clientName, testCmd)
	if err != nil {
		t.Fatalf("curl failed (cmd: %q, stdout: %q, stderr: %q): %s", testCmd, stdout, stderr, err)
	}

	// Check HTTP H2
	if stdout != "2" {
		t.Fatalf("Expected HTTP 2, got: %s", stdout)
	}
}
