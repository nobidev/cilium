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
	"encoding/base64"
	"fmt"
	"testing"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

func TestTLSPassthrough(t *testing.T) {
	ctx := context.Background()
	name := "https-passthrough-1"
	ns := "default"
	hostName1 := "passthrough.acme.io"
	hostName2 := "passthrough-2.acme.io"
	certFile1 := name + "-1.crt"
	certFile2 := name + "-2.crt"

	// 0. Generate certificates

	t.Log("Creating certs...")

	key1, cert1, err := genSelfSignedX509(hostName1)
	if err != nil {
		t.Fatalf("failed to gen x509: %s", err)
	}
	key1_64 := base64.StdEncoding.EncodeToString(key1.Bytes())
	cert1_64 := base64.StdEncoding.EncodeToString(cert1.Bytes())
	key2, cert2, err := genSelfSignedX509(hostName2)
	if err != nil {
		t.Fatalf("failed to gen x509: %s", err)
	}
	key2_64 := base64.StdEncoding.EncodeToString(key2.Bytes())
	cert2_64 := base64.StdEncoding.EncodeToString(cert2.Bytes())

	// 1. Create LB backend apps

	t.Log("Creating client and apps...")

	app1 := name + "-app-1"
	app2 := name + "-app-2"
	app1IP := ""
	app2IP := ""
	iter := []struct {
		name string
		ip   *string
		key  string
		cert string
	}{
		{name: app1, ip: &app1IP, key: key1_64, cert: cert1_64},
		{name: app2, ip: &app2IP, key: key2_64, cert: cert2_64},
	}

	for i, app := range iter {
		env := []string{
			"SERVICE_NAME=" + app.name,
			"INSTANCE_NAME=" + app.name,
			"TLS_KEY_BASE64=" + app.key,
			"TLS_CERT_BASE64=" + app.cert,
			"TLS_ENABLED=true",
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

	if err := suite.dockerCli.copyToContainer(ctx, clientID, cert1.Bytes(), certFile1, "/tmp"); err != nil {
		t.Fatalf("failed to copy cert to client container: %s", err)
	}
	if err := suite.dockerCli.copyToContainer(ctx, clientID, cert2.Bytes(), certFile2, "/tmp"); err != nil {
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

	for i, ip := range []string{app1IP, app2IP} {
		backends := []isovalentv1alpha1.Backend{{IP: ip, Port: 8080}}
		poolName := fmt.Sprintf("%s-%d", name, i+1)
		backendPool := lbBackendPool(poolName, "/health", 10, backends)

		if err := suite.ciliumCli.CreateLBBackend(ctx, ns, backendPool, metav1.CreateOptions{}); err != nil {
			if !errors.IsAlreadyExists(err) {
				t.Fatalf("cannot create LB Backend Pool (%s): %s", poolName, err)
			}
		}
		maybeCleanupT(func() error { return suite.ciliumCli.DeleteLBBackend(ctx, ns, poolName, metav1.DeleteOptions{}) }, t)
	}

	// 5. Create LBService

	routes := []isovalentv1alpha1.LBServiceTLSPassthroughRoute{
		{
			Match: &isovalentv1alpha1.LBServiceTLSPassthroughRouteMatch{
				HostNames: []isovalentv1alpha1.LBServiceHostName{
					isovalentv1alpha1.LBServiceHostName(hostName1),
				},
			},
			BackendRef: isovalentv1alpha1.LBServiceBackendRef{
				Name: name + "-1",
			},
		},
		{
			BackendRef: isovalentv1alpha1.LBServiceBackendRef{
				Name: name + "-2",
			},
		},
	}
	svc := lbService(name, name, 80, lbServiceApplicationsTLSPassthrough(routes))

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

	testCmd1 := curlCmdVerbose(fmt.Sprintf("--cacert /tmp/%s --resolve %s:80:%s https://%s:80/", certFile1, hostName1, ip, hostName1))
	testCmd2 := curlCmdVerbose(fmt.Sprintf("--cacert /tmp/%s --resolve %s:80:%s https://%s:80/", certFile2, hostName2, ip, hostName2))
	for _, testCmd := range []string{testCmd1, testCmd2} {
		t.Logf("Testing %q...", testCmd)
		stdout, stderr, err := suite.dockerCli.clientExec(ctx, clientName, testCmd)
		if err != nil {
			t.Fatalf("curl failed (cmd: %q, stdout: %q, stderr: %q): %s", testCmd, stdout, stderr, err)
		}
	}
}
