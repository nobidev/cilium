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

func TestHTTPBasicAuth(t *testing.T) {
	ctx := context.Background()
	testName := "basic-auth-http"
	testK8sNamespace := "default"

	ciliumCli, k8sCli := newCiliumAndK8sCli(t)
	dockerCli := newDockerCli(t)

	scenario := newLBTestScenario(t, testName, testK8sNamespace, ciliumCli, k8sCli, dockerCli)

	t.Log("Creating backend apps...")
	backend := scenario.addBackendApplications(ctx, 1, backendApplicationConfig{h2cEnabled: true})[0]

	t.Log("Creating clients and add BGP peering ...")
	client := scenario.addFRRClients(ctx, 1, frrClientConfig{})[0]

	t.Logf("Creating LB VIP resources...")
	vip := lbVIP(testK8sNamespace, testName)
	scenario.createLBVIP(ctx, vip)

	t.Logf("Creating LB BackendPool resources...")
	scenario.createLBBackendPool(ctx, lbBackendPool(testK8sNamespace, testName, withIPBackend(backend.ip, backend.port)))

	t.Log("Creating basic auth secret...")
	creds := []basicAuthCredential{
		{
			username: "user0",
			password: "password0",
		},
		{
			username: "user1",
			password: "password1",
		},
	}
	secretName := scenario.createBasicAuthSecret(ctx, creds)

	t.Logf("Creating LB Service resources...")
	service := lbService(testK8sNamespace, testName, withHTTPProxyApplication(
		// Enable application-wide basic auth
		withHttpBasicAuth(secretName),
		// Set per-route exception
		withHttpRoute(testName,
			withHttpPath("/no-auth"),
			withHttpRouteBasicAuth(true),
		),
		// Default route
		withHttpRoute(testName),
	))
	scenario.createLBService(ctx, service)

	t.Logf("Waiting for full VIP connectivity of %q...", testName)
	vipIP := scenario.waitForFullVIPConnectivity(ctx, testName)

	t.Run("ValidCredentials", func(t *testing.T) {
		for _, cred := range creds {
			cmd := curlCmd(fmt.Sprintf("-m 1 --basic -u %s:%s http://%s/needs-auth", cred.username, cred.password, vipIP))
			stdout, stderr, err := client.Exec(ctx, cmd)
			if err != nil {
				t.Fatalf("unexpected error: %v\nstdout: %q\nstderr: %q", err, stdout, stderr)
			}
		}
	})

	t.Run("NoCredential", func(t *testing.T) {
		stdout, stderr, err := client.Exec(ctx, curlCmd(fmt.Sprintf("-m 1 -w '%%{response_code}' http://%s/needs-auth", vipIP)))
		if err == nil {
			t.Fatalf("unauthenticated access succeeded\nstdout: %q\nstderr: %q", stdout, stderr)
		}
		if stdout != "401" {
			t.Fatalf("unexpected error: %v\nstdout: %q\nstderr: %q", err, stdout, stderr)
		}
	})

	t.Run("InvalidCredential", func(t *testing.T) {
		stdout, stderr, err := client.Exec(ctx, curlCmd(fmt.Sprintf("-m 1  -w '%%{response_code}' --basic -u unknown:unknown http://%s/needs-auth", vipIP)))
		if err == nil {
			t.Fatalf("unauthenticated access succeeded\nstdout: %q\nstderr: %q", stdout, stderr)
		}
		if stdout != "401" {
			t.Fatalf("unexpected error: %v\nstdout: %q\nstderr: %q", err, stdout, stderr)
		}
	})

	t.Run("PerRouteException", func(t *testing.T) {
		// Ensure the per-route exception is working
		stdout, stderr, err := client.Exec(ctx, curlCmd(fmt.Sprintf("-m 1 http://%s/no-auth", vipIP)))
		if err != nil {
			t.Fatalf("unexpected error: %v\nstdout: %q\nstderr: %q", err, stdout, stderr)
		}
	})
}
