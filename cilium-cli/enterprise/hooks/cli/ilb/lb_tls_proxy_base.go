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
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

func TestTLSProxyTCPBackend(t T) {
	testName := "tls-proxy-tcp-backend"
	serviceHostName := "secure.acme.io"
	clientCAName := "acme.io"
	clientHostName := "client.acme.io"

	ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
	dockerCli := NewDockerCli(t)

	scenario := newLBTestScenario(t, testName, ciliumCli, k8sCli, dockerCli)

	t.Log("Creating cert and secret...")

	scenario.createLBServerCertificate(testName, serviceHostName)
	scenario.createLBClientCertificate(clientCAName, clientHostName)

	t.Log("Creating backend app...")

	backends := scenario.addBackendApplications(1, backendApplicationConfig{h2cEnabled: true})

	t.Log("Creating client and add BGP peering...")

	client := scenario.addFRRClients(1, frrClientConfig{trustedCertsHostnames: []string{serviceHostName}})[0]

	t.Log("Creating LB VIP resources...")

	vip := lbVIP(testName)
	scenario.createLBVIP(vip)

	// FIXME: Don't expose internal naming convention. Get it from the scenario instead.
	clientCASecretName := testName + "-client-ca"

	t.Log("Creating LB BackendPool resources...")

	backendPool := lbBackendPool(testName, withIPBackend(backends[0].ip, backends[0].port))
	scenario.createLBBackendPool(backendPool)

	t.Log("Creating LB Service resources...")

	service := lbService(testName, withPort(10080), withTLSProxyApplication(withTLSCertificate(testName), withTLSProxyRoute(backendPool.Name, withHostname(serviceHostName))))
	scenario.createLBService(service)

	t.Log("Waiting for full VIP connectivity...")
	vipIP := scenario.waitForFullVIPConnectivity(testName)

	// 3. Test basic connectivity
	t.Log("Checking Basic Connectivity")
	testCmd := curlCmdVerbose(fmt.Sprintf("--max-time 10 --cacert /tmp/%s.crt --resolve secure.acme.io:10080:%s https://secure.acme.io:10080/", serviceHostName, vipIP))

	t.Log("Testing %q...", testCmd)

	eventually(t, func() error {
		stdout, stderr, err := client.Exec(t.Context(), testCmd)
		if err != nil {
			// Enrich error with curl output
			err = fmt.Errorf("curl failed (cmd: %q, stdout: %q, stderr: %q): %w", testCmd, stdout, stderr, err)
		}
		return err
	}, 10*time.Second, 100*time.Millisecond)

	// 4. Test mTLS connectivity
	t.Log("Checking mTLS Connectivity")
	curSvc, err := ciliumCli.GetLBService(t.Context(), scenario.k8sNamespace, testName, metav1.GetOptions{})
	if err != nil {
		t.Failedf("failed to get LB service (%s): %s", testName, err)
	}

	// Add validation context to the TLS config and update
	curSvc.Spec.Applications.TLSProxy.TLSConfig.Validation = &isovalentv1alpha1.LBTLSValidationConfig{
		SecretRef: isovalentv1alpha1.LBServiceSecretRef{
			Name: clientCASecretName,
		},
	}

	if err := ciliumCli.UpdateLBService(t.Context(), scenario.k8sNamespace, curSvc, metav1.UpdateOptions{}); err != nil {
		t.Failedf("failed to update LB service (%s): %s", testName, err)
	}

	testCmd = curlCmdVerbose(fmt.Sprintf("--max-time 10 --cert /tmp/%s.crt --key /tmp/%s.key --cacert /tmp/%s.crt --resolve secure.acme.io:10080:%s https://secure.acme.io:10080/",
		clientHostName, clientHostName, serviceHostName, vipIP))

	t.Log("Testing %q...", testCmd)

	eventually(t, func() error {
		stdout, stderr, err := client.Exec(t.Context(), testCmd)
		if err != nil {
			// Enrich error with curl output
			err = fmt.Errorf("curl failed (cmd: %q, stdout: %q, stderr: %q): %w", testCmd, stdout, stderr, err)
		}
		return err
	}, 10*time.Second, 100*time.Millisecond)
}

func TestTLSProxyTLSBackend(t T) {
	testName := "tls-proxy-tls-backend"
	serviceHostName := "secure.acme.io"
	clientCAName := "acme.io"
	clientHostName := "client.acme.io"

	ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
	dockerCli := NewDockerCli(t)

	scenario := newLBTestScenario(t, testName, ciliumCli, k8sCli, dockerCli)

	t.Log("Creating cert and secret...")

	scenario.createLBServerCertificate(testName, serviceHostName)
	scenario.createLBClientCertificate(clientCAName, clientHostName)

	t.Log("Creating client and add BGP peering...")

	client := scenario.addFRRClients(1, frrClientConfig{trustedCertsHostnames: []string{serviceHostName}})[0]

	t.Log("Creating LB VIP resources...")

	vip := lbVIP(testName)
	scenario.createLBVIP(vip)

	t.Log("Creating backend certificate...")

	backendHostName := "secure-backend.acme.io"
	scenario.createBackendServerCertificate(backendHostName)

	t.Log("Creating backend app...")

	backends := scenario.addBackendApplications(1, backendApplicationConfig{tlsCertHostname: backendHostName})

	// FIXME: Don't expose internal naming convention. Get it from the scenario instead.
	caCertSecretName := testName + "-client-ca"

	t.Log("Creating LB BackendPool resources...")

	backendPool := lbBackendPool(testName, withIPBackend(backends[0].ip, backends[0].port), withBackendTLS(), withHealthCheckTLS())
	scenario.createLBBackendPool(backendPool)

	t.Log("Creating LB Service resources...")

	service := lbService(testName, withPort(10443), withTLSProxyApplication(withTLSCertificate(testName), withTLSProxyRoute(backendPool.Name, withHostname(serviceHostName))))
	scenario.createLBService(service)

	t.Log("Waiting for full VIP connectivity...")
	vipIP := scenario.waitForFullVIPConnectivity(testName)

	// 3. Test basic connectivity
	t.Log("Checking Basic Connectivity")
	testCmd := curlCmdVerbose(fmt.Sprintf("--max-time 10 --cacert /tmp/%s.crt --resolve secure.acme.io:10443:%s https://secure.acme.io:10443/", serviceHostName, vipIP))

	t.Log("Testing %q...", testCmd)

	eventually(t, func() error {
		stdout, stderr, err := client.Exec(t.Context(), testCmd)
		if err != nil {
			// Enrich error with curl output
			return fmt.Errorf("curl failed (cmd: %q, stdout: %q, stderr: %q): %w", testCmd, stdout, stderr, err)
		}
		return nil
	}, 10*time.Second, 100*time.Millisecond)

	// 4. Test mTLS connectivity
	t.Log("Checking mTLS Connectivity")
	curSvc, err := ciliumCli.GetLBService(t.Context(), scenario.k8sNamespace, testName, metav1.GetOptions{})
	if err != nil {
		t.Failedf("failed to get LB service (%s): %s", testName, err)
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
		SubjectAlternativeNames: []isovalentv1alpha1.LBTLSValidationConfigSAN{
			{
				Exact: "client.acme.io",
			},
		},
	}

	if err := ciliumCli.UpdateLBService(t.Context(), scenario.k8sNamespace, curSvc, metav1.UpdateOptions{}); err != nil {
		t.Failedf("failed to update LB service (%s): %s", testName, err)
	}

	failTestCmd := curlCmdVerbose(fmt.Sprintf("--max-time 10 --cacert /tmp/%s.crt --resolve secure.acme.io:10443:%s https://secure.acme.io:10443/", serviceHostName, vipIP))

	t.Log("Testing %q...", failTestCmd)

	eventually(t, func() error {
		stdout, stderr, err := client.Exec(t.Context(), failTestCmd)
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

	t.Log("Testing %q...", testCmd)

	eventually(t, func() error {
		stdout, stderr, err := client.Exec(t.Context(), testCmd)
		if err != nil {
			// Enrich error with curl output
			return fmt.Errorf("curl failed (cmd: %q, stdout: %q, stderr: %q): %w", testCmd, stdout, stderr, err)
		}
		return nil
	}, 10*time.Second, 100*time.Millisecond)
}
