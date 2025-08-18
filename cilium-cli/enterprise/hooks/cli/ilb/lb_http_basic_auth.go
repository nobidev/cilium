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
	"fmt"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

func TestHTTPBasicAuth(t T) {
	testBasicAuth(t, "http")
}

func TestHTTPSBasicAuth(t T) {
	testBasicAuth(t, "https")
}

func testBasicAuth(t T, proto string) {
	testName := "basic-auth-" + proto
	hostName := "basic-auth.acme.io"

	ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
	dockerCli := NewDockerCli(t)

	scenario := newLBTestScenario(t, testName, ciliumCli, k8sCli, dockerCli)

	if proto == "https" {
		t.Log("Creating cert and secret...")
		scenario.createLBServerCertificate(testName, hostName)
	}

	t.Log("Creating backend apps...")
	backend := scenario.addBackendApplications(1, backendApplicationConfig{h2cEnabled: true})[0]

	t.Log("Creating clients and add BGP peering ...")

	var client *frrContainer
	if proto == "http" {
		client = scenario.addFRRClients(1, frrClientConfig{})[0]
	} else {
		client = scenario.addFRRClients(1, frrClientConfig{trustedCertsHostnames: []string{hostName}})[0]
	}

	t.Log("Creating LB VIP resources...")
	vip := lbVIP(testName)
	scenario.createLBVIP(vip)

	t.Log("Creating LB BackendPool resources...")
	scenario.createLBBackendPool(lbBackendPool(testName, withIPBackend(backend.ip, backend.port)))

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
	secretName := scenario.createBasicAuthSecret(creds)

	t.Log("Creating LB Service resources...")

	var service *isovalentv1alpha1.LBService
	if proto == "http" {
		// HTTP
		service = lbService(testName, withHTTPProxyApplication(
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
	} else {
		// HTTPS
		service = lbService(testName,
			withPort(443),
			withHTTPSProxyApplication(
				// Enable application-wide basic auth
				withHttpsBasicAuth(secretName),
				// Set per-route exception
				withHttpsRoute(testName,
					withHttpsPath("/no-auth"),
					withHttpsRouteBasicAuth(true),
				),
				// Default route
				withHttpsRoute(testName),
				withCertificate(testName),
			),
		)
	}
	scenario.createLBService(service)

	t.Log("Waiting for full VIP connectivity...")
	vipIP := scenario.waitForFullVIPConnectivity(testName)

	var curlOpt string
	if proto == "http" {
		curlOpt = fmt.Sprintf("--resolve %s:80:%s", hostName, vipIP)
	} else {
		curlOpt = fmt.Sprintf("--cacert /tmp/%s.crt --resolve %s:443:%s", hostName, hostName, vipIP)
	}

	t.Log("Checking valid credentials")
	for _, cred := range creds {
		cmd := curlCmd(fmt.Sprintf("--max-time 10 %s --basic -u %s:%s %s://%s/needs-auth", curlOpt, cred.username, cred.password, proto, hostName))
		stdout, stderr, err := client.Exec(t.Context(), cmd)
		if err != nil {
			t.Failedf("unexpected error: %v\nstdout: %q\nstderr: %q", err, stdout, stderr)
		}
	}

	t.Log("Checking without credentials")
	stdout, stderr, err := client.Exec(t.Context(), curlCmd(fmt.Sprintf("--max-time 10 %s -w '%%{response_code}' %s://%s/needs-auth", curlOpt, proto, hostName)))
	if err == nil {
		t.Failedf("unauthenticated access succeeded\nstdout: %q\nstderr: %q", stdout, stderr)
	}
	if stdout != "401" {
		t.Failedf("unexpected error: %v\nstdout: %q\nstderr: %q", err, stdout, stderr)
	}

	t.Log("Checking invalid credentials")
	stdout, stderr, err = client.Exec(t.Context(), curlCmd(fmt.Sprintf("--max-time 10 %s -w '%%{response_code}' --basic -u unknown:unknown %s://%s/needs-auth", curlOpt, proto, hostName)))
	if err == nil {
		t.Failedf("unauthenticated access succeeded\nstdout: %q\nstderr: %q", stdout, stderr)
	}
	if stdout != "401" {
		t.Failedf("unexpected error: %v\nstdout: %q\nstderr: %q", err, stdout, stderr)
	}

	t.Log("Checking per-route exception")
	// Ensure the per-route exception is working
	stdout, stderr, err = client.Exec(t.Context(), curlCmd(fmt.Sprintf("--max-time 10 %s %s://%s/no-auth", curlOpt, proto, hostName)))
	if err != nil {
		t.Failedf("unexpected error: %v\nstdout: %q\nstderr: %q", err, stdout, stderr)
	}
}
