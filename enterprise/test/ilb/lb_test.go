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
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/inctimer"
	ciliumv2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	scheme "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/scheme"
)

//go:embed manifests/lb-vips.yaml
var yamlLBVIPs string

//go:embed manifests/lb-frontends.yaml
var yamlLBFrontends string

//go:embed manifests/lb-backends.yaml
var yamlLBBackends string

//go:embed manifests/lb-ippools.yaml
var yamlLBIPPools string

const (
	defaultNamespace = "default"

	clientContainerName = "frr"

	containerNetwork = "kind-cilium"

	appImage    = "quay.io/isovalent-dev/lb-healthcheck-app:v0.0.4"
	clientImage = "quay.io/isovalent-dev/lb-frr-client:v0.0.1"
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

	// 2. Install LB Frontends

	frontends, err := yamlToObjects[*isovalentv1alpha1.LBFrontend](yamlLBFrontends, scheme.Scheme)
	if err != nil {
		t.Fatalf("Failed to deserialize LB Frontend: %s", err)
	}

	for _, obj := range frontends {
		lbt.ciliumCli.DeleteLBFrontend(ctx, defaultNamespace, obj.GetObjectMeta().GetName(), metav1.DeleteOptions{})

		t.Logf("Creating LB Frontend %s...", obj.GetObjectMeta().GetName())
		if err := lbt.ciliumCli.CreateLBFrontend(ctx, "default", obj, metav1.CreateOptions{}); err != nil {
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

	// 4. Install LB IPPOOLS

	lbIPPools, err := yamlToObjects[*ciliumv2alpha1.CiliumLoadBalancerIPPool](yamlLBIPPools, scheme.Scheme)
	if err != nil {
		t.Fatalf("Failed to deserialize LB IP Pool: %s", err)
	}

	for _, obj := range lbIPPools {
		t.Logf("Creating LB IP Pool %s...", obj.GetObjectMeta().GetName())
		if err := lbt.ciliumCli.CreateLBIPPool(ctx, obj, metav1.CreateOptions{}); err != nil {
			t.Logf("Failed to create LB IP Pool: %s", err)
		}
	}

	// 5. Wait for LB VIPs

	for i := 1; i <= len(frontends); i++ {
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
		curlCmdVerbose(fmt.Sprintf("--cacert /tmp/tls-secure.crt --resolve secure.acme.io:443:%s https://secure.acme.io:443/", lbt.vips[1])),
		curlCmdVerbose(fmt.Sprintf("--resolve insecure.acme.io:80:%s http://insecure.acme.io:80/api/foo-insecure", lbt.vips[2])),
		curlCmdVerbose(fmt.Sprintf("--resolve mixed.acme.io:80:%s http://mixed.acme.io:80/", lbt.vips[4])),
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
		curlCmd(fmt.Sprintf("--http2-prior-knowledge -o/dev/null -w '%%{http_version}' --resolve mixed.acme.io:80:%s http://mixed.acme.io:80/", lbt.vips[4])),
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

// HC from LB T2 to backend app
func (lbt *lbTests) testBackendHealthChecking(ctx context.Context, t *testing.T) {
	// 1. Make lb-1 both backends' HC to fail (app1 and app2)

	// TODO(brb) add method to change HC status

	for _, ip := range []string{lbt.backendIPs[1], lbt.backendIPs[2]} {
		stdout, stderr, err := lbt.dockerCli.clientExec(ctx, clientContainerName,
			fmt.Sprintf("curl --silent -X POST http://%s:8080/control/healthcheck/fail", ip))
		if err != nil {
			t.Fatalf("Failed cmd: %s (stdout: %s, stderr: %s)", err, stdout, stderr)
		}
		if strings.TrimSpace(stdout) != "healthcheck OK: false" {
			t.Fatalf("Expected different output, got %q", stdout)
		}
	}

	// 2. Wait until curl fails due to failing HCs

	ctx, cancel := context.WithTimeout(ctx, longTimeout)
	defer cancel()

	for {
		cmd := curlCmd(fmt.Sprintf("-w %%{http_code} --cacert /tmp/tls-secure.crt --resolve secure.acme.io:443:%s https://secure.acme.io:443/", lbt.vips[1]))
		_, _, err := lbt.dockerCli.clientExec(ctx, clientContainerName, cmd)
		if err != nil {
			break
		}

		select {
		case <-inctimer.After(longPollInterval):
		case <-ctx.Done():
			t.Fatalf("Timeout reached waiting for curl to fail")
		}
	}

	// 3. Bring back both backends

	for _, ip := range []string{lbt.backendIPs[1], lbt.backendIPs[2]} {
		stdout, stderr, err := lbt.dockerCli.clientExec(ctx, clientContainerName,
			fmt.Sprintf("curl --silent -X POST http://%s:8080/control/healthcheck/ok", ip))
		if err != nil {
			t.Fatalf("Failed cmd: %s (stdout: %s, stderr: %s)", err, stdout, stderr)
		}
		if strings.TrimSpace(stdout) != "healthcheck OK: true" {
			t.Fatalf("Expected different output, got %q", stdout)
		}
	}

	// 4. Expect to pass

	ctx, cancel = context.WithTimeout(ctx, longTimeout)
	defer cancel()

	for {
		cmd := curlCmd(fmt.Sprintf("-w %%{http_code} --cacert /tmp/tls-secure.crt --resolve secure.acme.io:443:%s https://secure.acme.io:443/", lbt.vips[1]))
		_, _, err := lbt.dockerCli.clientExec(ctx, clientContainerName, cmd)
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
	// TODO(brb) defer lbt.cleanup()

	lbt.testBasicLBConnectivity(ctx, t)
	lbt.testBackendHealthChecking(ctx, t)
}

type testSuite struct {
	ciliumCli *ciliumCli
	dockerCli *dockerCli
}

var suite testSuite

var cleanup = flag.Bool("cleanup", true, "Cleanup created resources after each test case run")

func TestMain(m *testing.M) {
	if os.Getenv("LOADBALANCER_TESTS") != "true" {
		fmt.Println("Skipping due to LOADBALANCER_TESTS!=true")
		return
	}

	flag.Parse()

	ciliumCli, err := newCiliumCli()
	if err != nil {
		panic(fmt.Sprintf("Failed to create Cilium client: %s", err))
	}
	suite.ciliumCli = ciliumCli

	dockerCli, err := newDockerCli()
	if err != nil {
		panic(fmt.Sprintf("Failed to create Docker client: %s", err))
	}
	suite.dockerCli = dockerCli

	for _, img := range []string{appImage, clientImage} {
		if err := dockerCli.ensureImage(context.TODO(), img); err != nil {
			panic(fmt.Sprintf("Failed to ensure Docker image %s: %s", img, err))
		}
	}

	m.Run()
}

func maybeCleanup(f func() error, t *testing.T) {
	if *cleanup {
		t.Cleanup(func() {
			if err := f(); err != nil {
				fmt.Printf("cleanup failed: %s\n", err)
			}
		})
	}
}

func TestHTTPConnectivity(t *testing.T) {
	ctx := context.TODO()
	name := "http-1"
	ns := "default"

	t.Log("Creating client and apps...")

	// 0. Create LB backend apps

	app1 := "http-1-app-1"
	app2 := "http-1-app-2"
	for _, app := range []string{app1, app2} {
		env := []string{
			"SERVICE_NAME=" + app,
			"INSTANCE_NAME=" + app,
			"H2C_ENABLED=true",
		}
		if err := suite.dockerCli.createContainer(ctx, app, appImage, env, containerNetwork, false); err != nil {
			t.Fatalf("cannot create app container (%s): %s", app, err)
		}
		maybeCleanup(func() error { return suite.dockerCli.deleteContainer(ctx, app) }, t)
	}

	// 1. Create FRR client

	lbT1IP, err := suite.dockerCli.GetContainerIP(ctx, "kind-control-plane") // TODO use kubectl get nodes
	if err != nil {
		t.Fatalf("failed to retrieve T1 LB IP: %s", err)
	}
	clientName := name + "-client"
	env := []string{
		"NEIGHBOR=" + lbT1IP,
	}
	if err := suite.dockerCli.createContainer(ctx, clientName, clientImage, env, containerNetwork, true); err != nil {
		t.Fatalf("cannot create client container (%s): %s", clientName, err)
	}
	maybeCleanup(func() error { return suite.dockerCli.deleteContainer(ctx, clientName) }, t)

	clientIP, err := suite.dockerCli.GetContainerIP(ctx, clientName)
	if err != nil {
		t.Fatalf("failed to retrieve container IP (%s): %s", clientName, err)
	}

	if err := suite.ciliumCli.doBGPPeeringForClient(ctx, clientIP); err != nil {
		t.Fatalf("failed to BGP peer (%s): %s", clientName, err)
	}
	maybeCleanup(func() error { return suite.ciliumCli.undoBGPPeeringForClient(ctx, clientIP) }, t)

	t.Logf("Creating LB service objects...")

	// 2. Create LBIPPool

	lbIPPool := lbIPPool(name, "100.64.0.0/24")
	if err := suite.ciliumCli.ensureLBIPPool(ctx, lbIPPool); err != nil {
		t.Fatalf("cannot ensure LBIPPool (%s): %s", name, err)
	}
	maybeCleanup(func() error { return suite.ciliumCli.DeleteLBIPPool(ctx, name, metav1.DeleteOptions{}) }, t)

	// 3. Create LBVIP

	vip := lbVIP(name, "")
	if err := suite.ciliumCli.CreateLBVIP(ctx, ns, vip, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			t.Fatalf("cannot create LB VIP (%s): %s", name, err)
		}
	}
	maybeCleanup(func() error { return suite.ciliumCli.DeleteLBVIP(ctx, ns, name, metav1.DeleteOptions{}) }, t)

	app1IP, err := suite.dockerCli.GetContainerIP(ctx, app1)
	if err != nil {
		t.Fatalf("failed to retrieve container IP (%s): %s", app1, err)
	}
	app2IP, err := suite.dockerCli.GetContainerIP(ctx, app2)
	if err != nil {
		t.Fatalf("failed to retrieve container IP (%s): %s", app2, err)
	}

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
	maybeCleanup(func() error { return suite.ciliumCli.DeleteLBBackend(ctx, ns, name, metav1.DeleteOptions{}) }, t)

	// 5. Create LBFrontend

	frontend := lbFrontend(name, name, 81, lbFrontendApplicationsHTTP(name))

	if err := suite.ciliumCli.CreateLBFrontend(ctx, ns, frontend, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			t.Fatalf("cannot create LB Frontend (%s): %s", name, err)
		}
	}
	maybeCleanup(func() error { return suite.ciliumCli.DeleteLBFrontend(ctx, ns, name, metav1.DeleteOptions{}) }, t)

	// 6. Send HTTP request

	t.Logf("Waiting for VIP of %q...", name)

	ip, err := suite.ciliumCli.WaitForLBVIP(ctx, ns, name)
	if err != nil {
		t.Fatalf("failed to wait for VIP (%s): %s", name, err)
	}

	err = suite.dockerCli.waitForIPRoute(ctx, clientName, ip)
	if err != nil {
		t.Fatalf("failed to wait for IP route in client (%s): %s", clientName, err)
	}

	testCmd := curlCmdVerbose(fmt.Sprintf("http://%s:81/", ip))
	t.Logf("Testing %q...", testCmd)
	stdout, stderr, err := suite.dockerCli.clientExec(ctx, clientName, testCmd)
	if err != nil {
		t.Fatalf("curl failed (cmd: %q, stdout: %q, stderr: %q): %s", testCmd, stdout, stderr, err)
	}
}
