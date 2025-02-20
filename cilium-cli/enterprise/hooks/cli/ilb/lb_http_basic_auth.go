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

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

func TestHTTPBasicAuth() {
	testBasicAuth("http")
}

func TestHTTPSBasicAuth() {
	testBasicAuth("https")
}

func testBasicAuth(proto string) {
	ctx := context.Background()
	testName := "basic-auth-" + proto
	testK8sNamespace := "default"
	hostName := "basic-auth.acme.io"

	ciliumCli, k8sCli := NewCiliumAndK8sCli()
	dockerCli := NewDockerCli()

	scenario := newLBTestScenario(testName, testK8sNamespace, ciliumCli, k8sCli, dockerCli)

	if proto == "https" {
		fmt.Println("Creating cert and secret...")
		scenario.createLBServerCertificate(ctx, testName, hostName)
	}

	fmt.Println("Creating backend apps...")
	backend := scenario.addBackendApplications(ctx, 1, backendApplicationConfig{h2cEnabled: true})[0]

	fmt.Println("Creating clients and add BGP peering ...")

	var client *frrContainer
	if proto == "http" {
		client = scenario.addFRRClients(ctx, 1, frrClientConfig{})[0]
	} else {
		client = scenario.addFRRClients(ctx, 1, frrClientConfig{trustedCertsHostnames: []string{hostName}})[0]
	}

	fmt.Println("Creating LB VIP resources...")
	vip := lbVIP(testK8sNamespace, testName)
	scenario.createLBVIP(ctx, vip)

	fmt.Println("Creating LB BackendPool resources...")
	scenario.createLBBackendPool(ctx, lbBackendPool(testK8sNamespace, testName, withIPBackend(backend.ip, backend.port)))

	fmt.Println("Creating basic auth secret...")
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

	fmt.Println("Creating LB Service resources...")

	var service *isovalentv1alpha1.LBService
	if proto == "http" {
		// HTTP
		service = lbService(testK8sNamespace, testName, withHTTPProxyApplication(
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
		service = lbService(testK8sNamespace, testName,
			withPort(443),
			withHTTPSProxyApplication(
				// Enable application-wide basic auth
				withHttpsBasicAuth(secretName),
				// Set per-route exception
				withHttpsRoute(testName,
					withHttpPath("/no-auth"),
					withHttpRouteBasicAuth(true),
				),
				// Default route
				withHttpsRoute(testName),
				withCertificate(testName),
			),
		)
	}
	scenario.createLBService(ctx, service)

	fmt.Println("Waiting for full VIP connectivity...")
	vipIP := scenario.waitForFullVIPConnectivity(ctx, testName)

	var curlOpt string
	if proto == "http" {
		curlOpt = fmt.Sprintf("--resolve %s:80:%s", hostName, vipIP)
	} else {
		curlOpt = fmt.Sprintf("--cacert /tmp/%s.crt --resolve %s:443:%s", hostName, hostName, vipIP)
	}

	fmt.Println("Checking valid credentials")
	for _, cred := range creds {
		cmd := curlCmd(fmt.Sprintf("--max-time 10 %s --basic -u %s:%s %s://%s/needs-auth", curlOpt, cred.username, cred.password, proto, hostName))
		stdout, stderr, err := client.Exec(ctx, cmd)
		if err != nil {
			fatalf("unexpected error: %v\nstdout: %q\nstderr: %q", err, stdout, stderr)
		}
	}

	fmt.Println("Checking without credentials")
	stdout, stderr, err := client.Exec(ctx, curlCmd(fmt.Sprintf("--max-time 10 %s -w '%%{response_code}' %s://%s/needs-auth", curlOpt, proto, hostName)))
	if err == nil {
		fatalf("unauthenticated access succeeded\nstdout: %q\nstderr: %q", stdout, stderr)
	}
	if stdout != "401" {
		fatalf("unexpected error: %v\nstdout: %q\nstderr: %q", err, stdout, stderr)
	}

	fmt.Println("Checking invalid credentials")
	stdout, stderr, err = client.Exec(ctx, curlCmd(fmt.Sprintf("--max-time 10 %s -w '%%{response_code}' --basic -u unknown:unknown %s://%s/needs-auth", curlOpt, proto, hostName)))
	if err == nil {
		fatalf("unauthenticated access succeeded\nstdout: %q\nstderr: %q", stdout, stderr)
	}
	if stdout != "401" {
		fatalf("unexpected error: %v\nstdout: %q\nstderr: %q", err, stdout, stderr)
	}

	fmt.Println("Checking per-route exception")
	// Ensure the per-route exception is working
	stdout, stderr, err = client.Exec(ctx, curlCmd(fmt.Sprintf("--max-time 10 %s %s://%s/no-auth", curlOpt, proto, hostName)))
	if err != nil {
		fatalf("unexpected error: %v\nstdout: %q\nstderr: %q", err, stdout, stderr)
	}
}
