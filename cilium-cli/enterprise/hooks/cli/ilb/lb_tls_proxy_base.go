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
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

func TestTLSProxyTCPBackend() {
	fmt.Println("=== RUN   TestTLSProxyTCPBackend")

	ctx := context.Background()
	ns := "default"
	testName := "tls-proxy-tcp-backend"
	serviceHostName := "secure.acme.io"
	clientCAName := "acme.io"
	clientHostName := "client.acme.io"

	ciliumCli, k8sCli := NewCiliumAndK8sCli()
	dockerCli := NewDockerCli()

	scenario := newLBTestScenario(testName, ns, ciliumCli, k8sCli, dockerCli)

	fmt.Println("Creating cert and secret...")

	scenario.createLBServerCertificate(ctx, testName, serviceHostName)
	scenario.createLBClientCertificate(ctx, clientCAName, clientHostName)

	fmt.Println("Creating backend app...")

	backends := scenario.addBackendApplications(ctx, 1, backendApplicationConfig{h2cEnabled: true})

	fmt.Println("Creating client and add BGP peering...")

	client := scenario.addFRRClients(ctx, 1, frrClientConfig{trustedCertsHostnames: []string{serviceHostName}})[0]

	fmt.Println("Creating LB VIP resources...")

	vip := lbVIP(ns, testName)
	scenario.createLBVIP(ctx, vip)

	// FIXME: Don't expose internal naming convention. Get it from the scenario instead.
	clientCASecretName := testName + "-client-ca"

	fmt.Println("Creating LB BackendPool resources...")

	backendPool := lbBackendPool(ns, testName, withIPBackend(backends[0].ip, backends[0].port))
	scenario.createLBBackendPool(ctx, backendPool)

	fmt.Println("Creating LB Service resources...")

	service := lbService(ns, testName, withPort(10080), withTLSProxyApplication(withTLSCertificate(testName), withTLSProxyRoute(backendPool.Name, withHostname(serviceHostName))))
	scenario.createLBService(ctx, service)

	maybeSysdump(testName, "")

	fmt.Printf("Waiting for full VIP connectivity of %q...\n", testName)
	vipIP := scenario.waitForFullVIPConnectivity(ctx, testName)

	// 3. Test basic connectivity
	fmt.Println("=== RUN   TestTLSProxyTCPBackend/Basic Connectivity")
	testCmd := curlCmdVerbose(fmt.Sprintf("--max-time 10 --cacert /tmp/%s.crt --resolve secure.acme.io:10080:%s https://secure.acme.io:10080/", serviceHostName, vipIP))

	fmt.Printf("Testing %q...\n", testCmd)

	eventually(func() error {
		stdout, stderr, err := client.Exec(ctx, testCmd)
		if err != nil {
			// Enrich error with curl output
			err = fmt.Errorf("curl failed (cmd: %q, stdout: %q, stderr: %q): %w", testCmd, stdout, stderr, err)
		}
		return err
	}, 10*time.Second, 100*time.Millisecond)

	// 4. Test mTLS connectivity
	fmt.Println("=== RUN   TestTLSProxyTCPBackend/mTLS Connectivity")
	curSvc, err := ciliumCli.GetLBService(ctx, ns, testName, metav1.GetOptions{})
	if err != nil {
		fatalf("failed to get LB service (%s): %s", testName, err)
	}

	// Add validation context to the TLS config and update
	curSvc.Spec.Applications.TLSProxy.TLSConfig.Validation = &isovalentv1alpha1.LBTLSValidationConfig{
		SecretRef: isovalentv1alpha1.LBServiceSecretRef{
			Name: clientCASecretName,
		},
	}

	if err := ciliumCli.UpdateLBService(ctx, ns, curSvc, metav1.UpdateOptions{}); err != nil {
		fatalf("failed to update LB service (%s): %s", testName, err)
	}

	testCmd = curlCmdVerbose(fmt.Sprintf("--max-time 10 --cert /tmp/%s.crt --key /tmp/%s.key --cacert /tmp/%s.crt --resolve secure.acme.io:10080:%s https://secure.acme.io:10080/",
		clientHostName, clientHostName, serviceHostName, vipIP))

	fmt.Printf("Testing %q...\n", testCmd)

	eventually(func() error {
		stdout, stderr, err := client.Exec(ctx, testCmd)
		if err != nil {
			// Enrich error with curl output
			err = fmt.Errorf("curl failed (cmd: %q, stdout: %q, stderr: %q): %w", testCmd, stdout, stderr, err)
		}
		return err
	}, 10*time.Second, 100*time.Millisecond)
}

func TestTLSProxyTLSBackend() {
	fmt.Println("=== RUN   TestTLSProxyTLSBackend")

	ctx := context.Background()
	ns := "default"
	testName := "tls-proxy-tls-backend"
	serviceHostName := "secure.acme.io"
	clientCAName := "acme.io"
	clientHostName := "client.acme.io"

	ciliumCli, k8sCli := NewCiliumAndK8sCli()
	dockerCli := NewDockerCli()

	scenario := newLBTestScenario(testName, ns, ciliumCli, k8sCli, dockerCli)

	fmt.Println("Creating cert and secret...")

	scenario.createLBServerCertificate(ctx, testName, serviceHostName)
	scenario.createLBClientCertificate(ctx, clientCAName, clientHostName)

	fmt.Println("Creating client and add BGP peering...")

	client := scenario.addFRRClients(ctx, 1, frrClientConfig{trustedCertsHostnames: []string{serviceHostName}})[0]

	fmt.Println("Creating LB VIP resources...")

	vip := lbVIP(ns, testName)
	scenario.createLBVIP(ctx, vip)

	fmt.Println("Creating backend certificate...")

	backendHostName := "secure-backend.acme.io"
	scenario.createBackendServerCertificate(ctx, backendHostName)

	fmt.Println("Creating backend app...")

	backends := scenario.addBackendApplications(ctx, 1, backendApplicationConfig{tlsCertHostname: backendHostName})

	// FIXME: Don't expose internal naming convention. Get it from the scenario instead.
	caCertSecretName := testName + "-client-ca"

	fmt.Println("Creating LB BackendPool resources...")

	backendPool := lbBackendPool(ns, testName, withIPBackend(backends[0].ip, backends[0].port), withBackendTLS(), withHealthCheckTLS())
	scenario.createLBBackendPool(ctx, backendPool)

	fmt.Println("Creating LB Service resources...")

	service := lbService(ns, testName, withPort(10443), withTLSProxyApplication(withTLSCertificate(testName), withTLSProxyRoute(backendPool.Name, withHostname(serviceHostName))))
	scenario.createLBService(ctx, service)

	maybeSysdump(testName, "")

	fmt.Printf("Waiting for full VIP connectivity of %q...\n", testName)
	vipIP := scenario.waitForFullVIPConnectivity(ctx, testName)

	// 3. Test basic connectivity
	fmt.Println("=== RUN   TestTLSProxyTLSBackend/Basic Connectivity")
	testCmd := curlCmdVerbose(fmt.Sprintf("--max-time 10 --cacert /tmp/%s.crt --resolve secure.acme.io:10443:%s https://secure.acme.io:10443/", serviceHostName, vipIP))

	fmt.Printf("Testing %q...\n", testCmd)

	eventually(func() error {
		stdout, stderr, err := client.Exec(ctx, testCmd)
		if err != nil {
			// Enrich error with curl output
			return fmt.Errorf("curl failed (cmd: %q, stdout: %q, stderr: %q): %w", testCmd, stdout, stderr, err)
		}
		return nil
	}, 10*time.Second, 100*time.Millisecond)

	// 4. Test mTLS connectivity
	fmt.Println("=== RUN   TestTLSProxyTLSBackend/mTLS Connectivity")
	curSvc, err := ciliumCli.GetLBService(ctx, ns, testName, metav1.GetOptions{})
	if err != nil {
		fatalf("failed to get LB service (%s): %s", testName, err)
	}

	// curl's TLS1.3 implementation doesn't return handshake error
	// (35) on certificate validation failure. TLS1.2 does, so
	// easier to handle.
	curSvc.Spec.Applications.TLSProxy.TLSConfig.MaxTLSVersion = ptr.To(isovalentv1alpha1.LBTLSProtocolVersion("TLSv1_2"))

	// Add validation context to the TLS config and update
	curSvc.Spec.Applications.TLSProxy.TLSConfig.Validation = &isovalentv1alpha1.LBTLSValidationConfig{
		SecretRef: isovalentv1alpha1.LBServiceSecretRef{
			Name: caCertSecretName,
		},
	}

	if err := ciliumCli.UpdateLBService(ctx, ns, curSvc, metav1.UpdateOptions{}); err != nil {
		fatalf("failed to update LB service (%s): %s", testName, err)
	}

	failTestCmd := curlCmdVerbose(fmt.Sprintf("--max-time 10 --cacert /tmp/%s.crt --resolve secure.acme.io:10443:%s https://secure.acme.io:10443/", serviceHostName, vipIP))

	fmt.Printf("Testing %q...\n", failTestCmd)

	eventually(func() error {
		stdout, stderr, err := client.Exec(ctx, failTestCmd)
		if err == nil {
			// Enrich error with curl output
			return fmt.Errorf("curl should have failed but succeeded (cmd: %q, stdout: %q, stderr: %q)", failTestCmd, stdout, stderr)
		} else {
			if err.Error() != "cmd failed: 35" {
				return fmt.Errorf("curl failed with unexpected error (cmd: %q, stdout: %q, stderr: %q): %w", failTestCmd, stdout, stderr, err)
			}
		}
		return nil
	}, 10*time.Second, 100*time.Millisecond)

	testCmd = curlCmdVerbose(fmt.Sprintf("--max-time 10 --cert /tmp/%s.crt --key /tmp/%s.key --cacert /tmp/%s.crt --resolve secure.acme.io:10443:%s https://secure.acme.io:10443/",
		clientHostName, clientHostName, serviceHostName, vipIP))

	fmt.Printf("Testing %q...\n", testCmd)

	eventually(func() error {
		stdout, stderr, err := client.Exec(ctx, testCmd)
		if err != nil {
			// Enrich error with curl output
			return fmt.Errorf("curl failed (cmd: %q, stdout: %q, stderr: %q): %w", testCmd, stdout, stderr, err)
		}
		return nil
	}, 10*time.Second, 100*time.Millisecond)
}
